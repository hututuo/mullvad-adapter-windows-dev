#!/usr/bin/env ruby
# frozen_string_literal: true

require 'yaml'
require 'json'
require 'optparse'
require 'fileutils'
require 'time'

options = {
  source: File.expand_path('~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/profiles/iKuuuV2Stable.yaml'),
  adapter_port: 17_890,
  control_port: 17_893,
  output: nil,
  manifest: nil,
  strip_legacy: false
}

OptionParser.new do |p|
  p.on('--source PATH') { |v| options[:source] = File.expand_path(v) }
  p.on('--output PATH') { |v| options[:output] = File.expand_path(v) }
  p.on('--manifest PATH') { |v| options[:manifest] = File.expand_path(v) }
  p.on('--adapter-port PORT', Integer) { |v| options[:adapter_port] = v }
  p.on('--control-port PORT', Integer) { |v| options[:control_port] = v }
  p.on('--strip-legacy', 'remove in-core Mullvad WG/SS nodes and legacy city/relay groups') { options[:strip_legacy] = true }
end.parse!

abort '--output is required' unless options[:output]
options[:manifest] ||= options[:output] + '.manifest.json'

config = YAML.load_file(options[:source]) || {}
config = Marshal.load(Marshal.dump(config))

adapter_name = 'Mullvad-本地适配器'
listener_name = 'mullvad-adapter-control-egress'
google_doh = 'https://8.8.8.8/dns-query#普通外网出口'

proxies = Array(config['proxies'])
groups = Array(config['proxy-groups'])
legacy_proxy_names = proxies.filter_map do |proxy|
  next unless proxy.is_a?(Hash)
  name = proxy['name'].to_s
  name if name.start_with?('Mullvad-') && name != adapter_name
end
legacy_group_names = groups.filter_map do |group|
  next unless group.is_a?(Hash)
  name = group['name'].to_s
  name if name.start_with?('Mullvad-') || name == 'Mullvad手动'
end

if options[:strip_legacy]
  proxies.reject! { |proxy| proxy.is_a?(Hash) && legacy_proxy_names.include?(proxy['name'].to_s) }
  groups.reject! { |group| group.is_a?(Hash) && legacy_group_names.include?(group['name'].to_s) }
  groups.each do |group|
    next unless group.is_a?(Hash)
    if group['proxies'].is_a?(Array)
      group['proxies'] = group['proxies'].reject do |member|
        legacy_proxy_names.include?(member.to_s) || legacy_group_names.include?(member.to_s)
      end
    end
    fallback = group['empty-fallback'].to_s
    if legacy_proxy_names.include?(fallback) || legacy_group_names.include?(fallback)
      # Mihomo's empty-fallback expects a concrete proxy, not another group.
      # Remove the legacy fallback here; the Mullvad root group gets the local
      # adapter proxy explicitly below.
      group.delete('empty-fallback')
    end
  end
end

proxies.reject! { |proxy| proxy.is_a?(Hash) && proxy['name'] == adapter_name }
proxies << {
  'name' => adapter_name,
  'type' => 'socks5',
  'server' => '127.0.0.1',
  'port' => options[:adapter_port],
  'udp' => true
}
config['proxies'] = proxies

mullvad_group = groups.find { |group| group.is_a?(Hash) && group['name'] == 'Mullvad节点' }
abort 'Mullvad节点 group not found' unless mullvad_group
if options[:strip_legacy]
  mullvad_group['proxies'] = [adapter_name]
  mullvad_group['empty-fallback'] = adapter_name
else
  mullvad_group['proxies'] = (Array(mullvad_group['proxies']) - [adapter_name]) + [adapter_name]
end

global_group = groups.find { |group| group.is_a?(Hash) && group['name'] == 'GLOBAL' }
if global_group && options[:strip_legacy]
  global_group['proxies'] = (Array(global_group['proxies']) + ['Mullvad节点']).uniq
end

ordinary_group = groups.find { |group| group.is_a?(Hash) && group['name'] == '普通外网出口' }
abort '普通外网出口 group not found' unless ordinary_group
config['proxy-groups'] = groups

listeners = Array(config['listeners'])
listeners.reject! { |listener| listener.is_a?(Hash) && listener['name'] == listener_name }
listeners << {
  'name' => listener_name,
  'type' => 'http',
  'port' => options[:control_port],
  'listen' => '127.0.0.1',
  'proxy' => '普通外网出口'
}
config['listeners'] = listeners

dns = config['dns'] ||= {}
dns['nameserver'] = (Array(dns['nameserver']) + [google_doh]).uniq
policy = dns['nameserver-policy'] ||= {}
foreign_key = 'geosite:geolocation-!cn'
policy[foreign_key] = (Array(policy[foreign_key]) + [
  'https://1.1.1.1/dns-query#普通外网出口',
  google_doh
]).uniq

rules = Array(config['rules'])
control_rule = 'DOMAIN-SUFFIX,mullvad.net,普通外网出口'
rules.unshift(control_rule) unless rules.include?(control_rule)
config['rules'] = rules

# Fail closed on dangling proxy/group references after legacy removal.
known = proxies.map { |proxy| proxy['name'].to_s } + groups.map { |group| group['name'].to_s } +
        Array(config['proxy-providers']).map { |name, _| name.to_s } + %w[DIRECT REJECT REJECT-DROP PASS]
dangling = []
groups.each do |group|
  Array(group['proxies']).each do |member|
    dangling << [group['name'], member] unless known.include?(member.to_s)
  end
  fallback = group['empty-fallback'].to_s
  dangling << [group['name'], "empty-fallback=#{fallback}"] if !fallback.empty? && !known.include?(fallback)
end
abort "dangling group references: #{dangling.inspect}" unless dangling.empty?

FileUtils.mkdir_p(File.dirname(options[:output]))
serialized = YAML.dump(JSON.parse(JSON.generate(config)), line_width: -1)
File.write(options[:output], serialized)
File.chmod(0o600, options[:output])

manifest = {
  generated_at: Time.now.iso8601,
  source: options[:source],
  output: options[:output],
  production_modified: false,
  strip_legacy: options[:strip_legacy],
  removed_legacy_proxies: options[:strip_legacy] ? legacy_proxy_names.length : 0,
  removed_legacy_groups: options[:strip_legacy] ? legacy_group_names.length : 0,
  adapter_node: { name: adapter_name, host: '127.0.0.1', port: options[:adapter_port] },
  control_listener: { name: listener_name, host: '127.0.0.1', port: options[:control_port], proxy: '普通外网出口' },
  dns_foreign_doh: Array(dns['nameserver']),
  mullvad_group_members: Array(mullvad_group['proxies']).length,
  proxies: proxies.length,
  groups: groups.length,
  rules: rules.length
}
File.write(options[:manifest], JSON.pretty_generate(manifest))
File.chmod(0o600, options[:manifest])
puts JSON.generate(manifest.reject { |key, _| %i[source output].include?(key) })
