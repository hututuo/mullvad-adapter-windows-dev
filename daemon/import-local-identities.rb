# frozen_string_literal: true

# Explicit one-time local migration. The additional account is read from stdin,
# never argv. This script never contacts Mullvad, creates/revokes devices, starts
# an engine, selects an identity or overwrites an existing profile store.
require_relative 'mullvad_adapter'
options = {}
OptionParser.new do |parser|
  parser.banner = 'Usage: import-local-identities.rb --state-dir PATH --device-json PATH < account-number-file'
  parser.on('--state-dir PATH') { |path| options[:state_dir] = File.expand_path(path) }
  parser.on('--device-json PATH') { |path| options[:device_json] = File.expand_path(path) }
end.parse!
begin
  raise ArgumentError unless options[:state_dir] && options[:device_json]
  adapter = MullvadAdapter.new(state_dir: options[:state_dir])
  adapter.send(:assert_private_directory!, options[:state_dir])
  adapter.send(:load_template)
  number = adapter.send(:normalize_account, STDIN.read(128))
  old_account = JSON.parse(adapter.send(:read_private_identity_file, File.join(options[:state_dir], 'account.json'))).fetch('account_number')
  official = JSON.parse(adapter.send(:read_private_identity_file, options[:device_json]))
  new_template = { 'private-key' => official.fetch('private_key'), 'ip' => official.fetch('ipv4_address').delete_suffix('/32'),
                   'ipv6' => official.fetch('ipv6_address').delete_suffix('/128') }
  profiles = [adapter.send(:identity_profile_record, number: old_account, template: adapter.instance_variable_get(:@template)),
              adapter.send(:identity_profile_record, number: number, template: new_template, device: official)]
  raise ArgumentError unless profiles.map { |profile| profile['public_key'] }.uniq.length == 2
  data = { schema: 1, revision: 1, active_id: nil, profiles: profiles }
  adapter.send(:write_private_identity_once, adapter.send(:identity_profiles_path), JSON.generate(data))
  result = adapter.send(:saved_identity_snapshot)
  puts JSON.generate(result.slice(:identity_switch_supported, :active_identity_id).merge(
    saved_identities: result[:saved_identities].map { |identity| identity.slice(:account_suffix, :device_name, :name_source, :current) },
    network_changed: false))
rescue StandardError
  warn '本机身份导入未确认完成；原文件保留。请检查路径、文件权限与账号/密钥/官方地址匹配，不要覆盖重试。'
  exit 1
end
