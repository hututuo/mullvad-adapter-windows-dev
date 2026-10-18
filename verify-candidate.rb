#!/usr/bin/env ruby
# frozen_string_literal: true

# Explicit, sequential real-network acceptance on a different relay and ports.
# Never changes production launchd, selectors, routes, DNS or device identity.
require_relative 'daemon/mullvad_adapter'

options = { hold: 0 }
OptionParser.new do |parser|
  parser.on('--relay NAME') { |value| options[:relay] = value }
  parser.on('--output PATH') { |value| options[:output] = File.expand_path(value) }
  parser.on('--post-quantum') { options[:post_quantum] = true }
  parser.on('--hold SECONDS', Integer) { |value| options[:hold] = value }
end.parse!
abort 'Usage: verify-candidate.rb --relay NAME --output NEW_DIRECTORY [--hold SECONDS]' unless options[:relay] && options[:output]
abort 'output already exists' if File.exist?(options[:output])

def production_status
  JSON.parse(Net::HTTP.start('127.0.0.1', 17_891, nil, open_timeout: 1, read_timeout: 2) { |http| http.get('/status') }.body)
end

def assert_unused_relay!(name)
  status = production_status
  occupied = status.fetch('workers', {}).values.reject { |worker| worker['state'] == 'stopped' }.flat_map { |worker| [worker['relay'], worker['entry_relay']].compact }
  raise 'candidate relay is owned by production; choose another relay' if occupied.include?(name)
end

class CandidateAdapter < MullvadAdapter
  attr_accessor :inject_direct_failure
  attr_reader :config_checks

  def validate_runtime_config(path, dir)
    super
    @config_checks = (@config_checks || 0) + 1
  end

  def start_worker(slot, relay, transport_mode: 'ss', ss_candidate: nil)
    assert_unused_relay!(relay['hostname'])
    raise 'injected direct start failure for rollback acceptance' if inject_direct_failure && transport_mode == 'ipv4'
    super
  end
end

baseline = production_status
assert_unused_relay!(options[:relay])
FileUtils.mkdir_p(options[:output], mode: 0o700)
source_state = MullvadAdapter::DEFAULTS[:state_dir]
%w[wireguard-template.json relays-cache.json ss-endpoints.json].each do |name|
  source = File.join(source_state, name)
  next unless File.file?(source)
  FileUtils.cp(source, File.join(options[:output], name))
  File.chmod(0o600, File.join(options[:output], name))
end
adapter = CandidateAdapter.new(
  state_dir: options[:output], api_port: 18_891, front_mixed: 18_890,
  front_controller: 18_892, worker_port_base: 18_910, validate_configs: true
)
report = { source_sha256: MullvadAdapter::SOURCE_SHA256, relay: options[:relay], production_modified: false, post_quantum: !!options[:post_quantum] }
if options[:post_quantum]
  helper = MullvadAdapter::DEFAULTS[:pq_helper]
  abort 'packaged PQ helper missing' unless File.executable?(helper)
  report[:pq_helper_sha256] = Digest::SHA256.file(helper).hexdigest
  adapter.instance_variable_set(:@protection_profile, { multihop: false, entry_city: nil, post_quantum: true }.freeze)
end
begin
  adapter.send(:prepare_state_dir)
  adapter.send(:load_template)
  adapter.send(:load_cached_metadata)
  adapter.send(:load_ss_endpoint_history)
  adapter.send(:trap_signals)
  adapter.send(:start_api_server)
  adapter.send(:ensure_front)
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  raise 'candidate activation failed' unless adapter.send(:activate, options[:relay], reason: 'select', transport_preference: 'ss')
  initial = adapter.send(:snapshot)
  raise 'candidate not ready' unless initial[:service_readiness] == 'ready'
  report[:activation_ms] = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
  report[:canary_ms] = initial.dig(:last_canary, :duration_ms)
  report[:front_https] = adapter.send(:curl_proxy_test, 18_890, MullvadAdapter::HOST_CANARY, 8)[:status]
  raise 'candidate front HTTPS failed' unless report[:front_https] == 'pass'
  adapter.inject_direct_failure = true
  switched = adapter.send(:activate, options[:relay], reason: 'reconnect', transport_preference: 'ipv4')
  rolled_back = adapter.send(:snapshot)
  report[:rollback_verified] = !switched && rolled_back[:switch_reason] == 'reconnect-rollback' && rolled_back[:service_readiness] == 'ready'
  raise 'rollback did not restore the previous connection' unless report[:rollback_verified]
  adapter.inject_direct_failure = false

  slot = rolled_back[:active_slot]
  old_pid = adapter.instance_variable_get(:@workers).fetch(slot).fetch(:pid)
  Process.kill('TERM', old_pid)
  sleep 0.3
  adapter.send(:supervise_worker_runtime)
  recovered = adapter.send(:snapshot)
  new_pid = adapter.instance_variable_get(:@workers).fetch(recovered[:active_slot]).fetch(:pid)
  report[:worker_crash_recovered] = old_pid != new_pid && recovered[:service_readiness] == 'ready'
  raise 'worker crash recovery failed' unless report[:worker_crash_recovered]
  report[:diagnosis] = adapter.send(:diagnose_network)
  report[:config_checks] = adapter.config_checks
  report[:config_validated] = adapter.config_checks.to_i >= 3
  report[:ready] = true
  report[:production_relay_unchanged] = baseline['active_relay'] == production_status['active_relay']
  report[:checked_at] = Time.now.iso8601
  File.write(File.join(options[:output], 'acceptance.json'), JSON.pretty_generate(report))
  puts JSON.generate(report.reject { |key, _| key == :diagnosis })
  STDOUT.flush
  options[:hold].times do
    break if adapter.instance_variable_get(:@stop_requested)
    sleep 1
  end
ensure
  adapter.send(:shutdown)
  FileUtils.rm_f(File.join(options[:output], 'wireguard-template.json'))
end
