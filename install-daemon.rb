#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'digest'
require 'fileutils'
require 'net/http'
require 'open3'
require 'optparse'
require 'rbconfig'
require 'time'
require 'socket'

options = {}
OptionParser.new do |parser|
  parser.banner = 'Usage: install-daemon.rb --check | --install --canary-report PATH --backup-dir PATH | --rollback BACKUP_DIR'
  parser.on('--check') { options[:check] = true }
  parser.on('--install') { options[:install] = true }
  parser.on('--canary-report PATH') { |value| options[:canary] = File.expand_path(value) }
  parser.on('--backup-dir PATH') { |value| options[:backup] = File.expand_path(value) }
  parser.on('--rollback PATH') { |value| options[:rollback] = File.expand_path(value) }
end.parse!
abort 'choose --check, --install or --rollback' unless options.values_at(:check, :install, :rollback).count { |v| v } == 1

source = File.join(__dir__, 'daemon', 'mullvad_adapter.rb')
installed = File.expand_path('~/.local/libexec/mullvad-local-adapter')
helper_source = File.join(__dir__, 'helpers', 'pq-negotiator', 'bin', 'mullvad-pq-negotiator')
helper_installed = File.expand_path('~/.local/libexec/mullvad-pq-negotiator')
plist = File.expand_path('~/Library/LaunchAgents/local.mullvad.adapter.plist')
domain = "gui/#{Process.uid}"
service = "#{domain}/local.mullvad.adapter"
report = { started_at: Time.now.iso8601 }

def live_status
  Net::HTTP.start('127.0.0.1', 17_891, nil, open_timeout: 1, read_timeout: 2) do |http|
    JSON.parse(http.get('/status').body)
  end
rescue StandardError
  nil
end

def copy_atomic(source, target)
  temporary = "#{target}.candidate-#{Process.pid}"
  FileUtils.cp(source, temporary)
  File.chmod(0o755, temporary)
  File.rename(temporary, target)
ensure
  FileUtils.rm_f(temporary) if defined?(temporary)
end

def restart_service(domain, service, plist)
  _out, bootout_error, bootout = Open3.capture3('/bin/launchctl', 'bootout', service)
  if !bootout.success? && !bootout_error.include?('Could not find service') && !bootout_error.include?('No such process')
    raise "launchd bootout failed: #{bootout_error.strip}"
  end
  deadline = Time.now + 15
  loop do
    ports_free = [17_890, 17_892, 17_910, 17_911, 17_920, 17_921].all? do |port|
      begin
        Socket.tcp('127.0.0.1', port, connect_timeout: 0.2).close
        false
      rescue Errno::ECONNREFUSED
        true
      end
    end
    # launchd can release the listeners before removing the old service record.
    # A bootstrap during that gap fails with EIO even though all ports are free.
    _state, _err, registered = Open3.capture3('/bin/launchctl', 'print', service)
    break if ports_free && !registered.success?
    raise 'old adapter processes still own ports; refusing to overlap instances' if Time.now > deadline
    sleep 0.2
  end
  _out, error, status = Open3.capture3('/bin/launchctl', 'bootstrap', domain, plist)
  raise "launchd bootstrap failed: #{error.strip}" unless status.success?
end

def wait_ready(expected_sha: nil, expected_helper_sha: nil, helper_path: nil)
  deadline = Time.now + 90
  loop do
    state = live_status
    active_worker = state && state.fetch('workers', {})[state['active_slot']]
    helper_matches = expected_helper_sha.nil? ||
      (File.file?(helper_path) && Digest::SHA256.file(helper_path).hexdigest == expected_helper_sha &&
       (!active_worker || !active_worker['post_quantum'] || active_worker['pq_helper_sha256'] == expected_helper_sha))
    if helper_matches && state && state['service_readiness'] == 'ready' && state.dig('front', 'ready') == true &&
       (!expected_sha || state['source_sha256'] == expected_sha)
      output, _error, result = Open3.capture3(
        'curl', '-q', '-sS', '--noproxy', '', '--proxy', 'socks5h://127.0.0.1:17890',
        '--max-time', '8', '-o', '/dev/null', '-w', '%{http_code}', 'https://www.gstatic.com/generate_204'
      )
      return state if result.success? && output == '204'
    end
    raise 'daemon or real front HTTPS did not become ready within 90 seconds' if Time.now > deadline
    sleep 1
  end
end

if options[:rollback]
  policy_path = File.expand_path('~/Library/Application Support/MullvadLocalAdapter/protection.json')
  if File.file?(policy_path)
    policy = JSON.parse(File.read(policy_path))
    abort 'disable required multihop/PQ through the current app before rolling back to an older daemon' if policy['multihop'] || policy['post_quantum']
  end
  backup = File.join(options[:rollback], 'installed-daemon')
  abort 'rollback baseline missing' unless File.file?(backup)
  abort 'rollback source syntax failed' unless system(RbConfig.ruby, '-c', backup)
  copy_atomic(backup, installed)
  previous_helper = File.join(options[:rollback], 'installed-pq-helper')
  copy_atomic(previous_helper, helper_installed) if File.file?(previous_helper)
  restart_service(domain, service, plist)
  state = wait_ready
  puts JSON.generate(rolled_back: true, relay: state['active_relay'], readiness: state['service_readiness'])
  exit
end

abort 'daemon syntax failed' unless system(RbConfig.ruby, '-c', source)
test_glob = File.join(__dir__, 'daemon', 'test_*.rb')
abort 'regression tests failed' unless system(RbConfig.ruby, '-e', 'ARGV.each { |f| require f }', *Dir[test_glob].sort)
source_sha = Digest::SHA256.file(source).hexdigest
abort 'compiled PQ helper missing from this candidate' unless File.executable?(helper_source)
helper_info, _helper_error, helper_status = Open3.capture3([helper_source, helper_source], '--version')
abort 'PQ helper identity check failed' unless helper_status.success? &&
  JSON.parse(helper_info).values_at('component', 'schema', 'upstream_sha') ==
    ['mullvad-pq-negotiator', 1, '19fb87407f4b81fe15372c2c7f8a20e7ab4eb220']
helper_sha = Digest::SHA256.file(helper_source).hexdigest
if options[:check]
  puts JSON.generate(check: 'PASS', source_sha256: source_sha, pq_helper_sha256: helper_sha, installed_helper_matches: File.file?(helper_installed) && Digest::SHA256.file(helper_installed).hexdigest == helper_sha, installed_matches: Digest::SHA256.file(installed).hexdigest == source_sha)
  exit
end
abort '--canary-report and --backup-dir are required' unless options[:canary] && options[:backup]
canary = JSON.parse(File.read(options[:canary]))
abort 'canary must match source/helper and pass protected acceptance gates' unless canary['source_sha256'] == source_sha &&
  canary['post_quantum'] == true && canary['pq_helper_sha256'] == helper_sha &&
  %w[ready config_validated rollback_verified worker_crash_recovered production_relay_unchanged].all? { |key| canary[key] == true }
state = live_status
abort 'another adapter action is running' if state&.dig('routing_policy', 'pending_action')
FileUtils.mkdir_p(options[:backup], mode: 0o700)
backup = File.join(options[:backup], 'installed-daemon')
if File.exist?(backup)
  # A failed install may already have rolled back. Reuse its original baseline
  # only when the currently installed bytes still match it exactly.
  abort 'backup exists and does not match current install' unless Digest::SHA256.file(backup).hexdigest == Digest::SHA256.file(installed).hexdigest
else
  FileUtils.cp(installed, backup, preserve: true)
  FileUtils.cp(helper_installed, File.join(options[:backup], 'installed-pq-helper'), preserve: true) if File.file?(helper_installed)
  FileUtils.cp(plist, File.join(options[:backup], 'daemon.plist'), preserve: true)
end
report.merge!(source_sha256: source_sha, pq_helper_sha256: helper_sha, previous_sha256: Digest::SHA256.file(backup).hexdigest)
begin
  copy_atomic(helper_source, helper_installed)
  copy_atomic(source, installed)
  restart_service(domain, service, plist)
  current = wait_ready(expected_sha: source_sha, expected_helper_sha: helper_sha, helper_path: helper_installed)
  report.merge!(installed: true, readiness: current['service_readiness'], relay: current['active_relay'], real_https: 'PASS')
rescue StandardError => e
  report[:error] = e.message
  copy_atomic(backup, installed)
  old_helper = File.join(options[:backup], 'installed-pq-helper')
  copy_atomic(old_helper, helper_installed) if File.file?(old_helper)
  begin
    restart_service(domain, service, plist)
    report[:rollback_ready] = wait_ready['service_readiness'] == 'ready'
  rescue StandardError => rollback_error
    report[:rollback_error] = rollback_error.message
  end
ensure
  report[:finished_at] = Time.now.iso8601
  File.write(File.join(options[:backup], 'deployment.json'), JSON.pretty_generate(report))
  puts JSON.generate(report)
end
exit(report[:installed] ? 0 : 1)
