# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'stringio'
require_relative 'mullvad_adapter'

# Exercises actual policy/transaction code with fake processes and probe I/O.
class ReliabilityAdapter < MullvadAdapter
  attr_reader :events
  attr_accessor :fail_mode, :fail_selector, :bad_candidate, :candidate_calls

  def initialize(dir)
    super(state_dir: dir)
    @events = []
    @candidate_calls = 0
    @metadata = {
      'wireguard' => {
        'port_ranges' => [[1, 65_535]], 'shadowsocks_port_ranges' => [[20_484, 20_484]],
        'relays' => %w[one two three four five].map do |name|
          { 'hostname' => name, 'active' => true, 'location' => 'us-sjc', 'public_key' => "public-#{name}",
            'ipv4_addr_in' => '192.0.2.1', 'ipv6_addr_in' => '2001:db8::1',
            'shadowsocks_extra_addr_in' => %w[192.0.2.2 192.0.2.3] }
        end
      }
    }
  end

  def seed_active
    worker = start_worker('a', find_relay('one'))
    commit_active('a', 'one', worker, good_canary, 'startup', old_slot: nil, transport_preference: 'ss')
  end

  def good_canary
    { at: Time.now.iso8601, duration_ms: 1, ip_data: { status: 'pass' },
      inner_dns: { status: 'pass' }, https_data: { status: 'pass' } }
  end

  def start_worker(slot, relay, transport_mode: 'ss', ss_candidate: nil)
    @events << [:start, slot, relay['hostname'], transport_mode]
    raise 'injected start failure' if transport_mode == fail_mode
    raise 'peer overlap' if @workers.values.any? { |w| w[:relay] == relay['hostname'] }
    raise 'slot overlap' if @workers[slot]
    @candidate_calls += 1
    worker = { pid: 99_999, slot: slot, relay: relay['hostname'], instance_token: SecureRandom.uuid,
               transport_mode: transport_mode, transport: transport_mode, mixed_port: 17_910,
               endpoint: ss_candidate&.first || '192.0.2.2', started_at: Time.now.iso8601 }
    @workers[slot] = worker
    @worker_state_tokens[slot] = worker[:instance_token]
    @state[:workers][slot] = public_worker_state(worker).merge(state: 'candidate')
    worker
  end

  def stop_pid(pid)
    @events << [:stop, pid]
  end

  def run_canary(slot)
    if @workers[slot][:relay] == bad_candidate
      { ip_data: { status: 'fail' }, inner_dns: { status: 'fail' }, https_data: { status: 'skip' } }
    else
      good_canary
    end
  end

  def select_front(slot)
    @events << [:select, slot]
    raise 'injected selector failure' if fail_selector == slot
    true
  end

  def front_connections_for(_slot) = 0
  def start_drain(_slot); end
end

class MullvadReliabilityTest < Minitest::Test
  def test_event_log_redacts_credentials_and_rotates
    @adapter.send(:log_event, 'test', password: 'structured-secret',
      message: 'private_key=raw-secret Bearer header-secret https://user:pass@example.test 1234 5678 9012 3456')
    path = File.join(@dir, 'logs', 'events.jsonl')
    content = File.read(path)
    %w[structured-secret raw-secret header-secret user:pass].each { |secret| refute_includes content, secret }
    refute_includes content, '1234 5678 9012 3456'
    assert_equal 'test', JSON.parse(content)['event']
    assert_equal 0o600, File.stat(path).mode & 0o777
    File.write(path, 'x' * MullvadAdapter::EVENT_LOG_FILE_BYTES)
    @adapter.send(:log_event, 'after-rotation')
    assert_equal MullvadAdapter::EVENT_LOG_FILE_BYTES, File.size(path + '.1')
    assert_equal 'after-rotation', JSON.parse(File.read(path))['event']
  end

  def test_event_log_preserves_day_old_evidence_until_capacity_is_needed
    path = File.join(@dir, 'logs', 'events.jsonl')
    FileUtils.mkdir_p(File.dirname(path))
    old = JSON.generate(at: (Time.now - 86_400).iso8601, event: 'yesterday') + "\n"
    File.write(path, old)
    @adapter.send(:log_event, 'today')
    assert File.read(path).start_with?(old)
    refute File.exist?(path + '.1')
  end

  def test_rotation_bounds_total_bytes_and_retains_newest_records
    path = File.join(@dir, 'logs', 'events.jsonl')
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path + '.1', 'old archive')
    File.write(path, 'x' * (MullvadAdapter::EVENT_LOG_FILE_BYTES - 1))
    @adapter.send(:log_event, 'newest')
    assert_operator File.size(path) + File.size(path + '.1'), :<=, 20_000_000
    assert_equal 'newest', JSON.parse(File.read(path))['event']
    refute_includes File.read(path + '.1'), 'old archive'
    @adapter.send(:log_event, 'large', values: Array.new(6_000, 'z' * 2_000))
    assert_operator File.size(path) + File.size(path + '.1'), :<=, 20_000_000
    assert_equal 'oversized-event', JSON.parse(File.readlines(path).last)['event']
  end

  def setup
    @dir = Dir.mktmpdir('mullvad-reliability')
    @adapter = ReliabilityAdapter.new(@dir)
  end

  def teardown
    Thread.current[:adapter_operation_id] = nil
    FileUtils.rm_rf(@dir)
  end

  def test_failed_explicit_direct_reconnect_reaches_rollback
    @adapter.seed_active
    @adapter.fail_mode = 'ipv4'
    refute @adapter.send(:activate, 'one', reason: 'reconnect', transport_preference: 'ipv4')
    status = @adapter.send(:snapshot)
    assert_equal 'one', status[:active_relay]
    assert_equal 'ss', status[:active_transport_mode]
    assert_equal 'ready', status[:service_readiness]
    assert_equal 'reconnect-rollback', status[:switch_reason]
    assert_equal 1, @adapter.instance_variable_get(:@workers).length
  end

  def test_failed_candidate_keeps_active_evidence
    @adapter.seed_active
    original = @adapter.send(:snapshot)[:last_canary]
    @adapter.bad_candidate = 'two'
    refute @adapter.send(:activate, 'two', reason: 'select')
    assert_equal original, @adapter.send(:snapshot)[:last_canary]
    assert_equal 'ready', @adapter.send(:snapshot)[:service_readiness]
    assert_equal ['a'], @adapter.instance_variable_get(:@workers).keys
  end

  def test_failed_front_commit_cleans_candidate_and_restores_old_selector
    @adapter.seed_active
    @adapter.fail_selector = 'b'
    refute @adapter.send(:activate, 'two', reason: 'select')
    assert_equal ['a'], @adapter.instance_variable_get(:@workers).keys
    assert_equal [:select, 'a'], @adapter.events.last
    assert_equal 'one', @adapter.send(:snapshot)[:active_relay]
    @adapter.fail_selector = nil
    assert @adapter.send(:activate, 'two', reason: 'select'), 'a later switch must not be wedged by an orphan'
  end

  def test_supervisor_checks_worker_even_when_front_raises
    seen = []
    @adapter.define_singleton_method(:supervise_front_runtime) { raise 'front down' }
    @adapter.define_singleton_method(:supervise_worker_runtime) { seen << :worker }
    @adapter.define_singleton_method(:retry_disconnected_runtime) { seen << :retry }
    capture_io { @adapter.send(:supervise_runtime_once) }
    assert_equal %i[worker retry], seen
  end

  def test_front_repair_does_not_claim_pass_without_data_verification
    @adapter.seed_active
    @adapter.instance_variable_get(:@options)[:front_data_probe_interval] = 0
    @adapter.define_singleton_method(:curl_proxy_ip_test) do |port, *_|
      { status: port == 17_890 ? 'fail' : 'pass', detail: 'injected' }
    end
    @adapter.define_singleton_method(:ensure_front) { @front_pid = 111 }
    2.times { @adapter.send(:supervise_front_data_path, 'a', @adapter.instance_variable_get(:@workers)['a']) }
    assert_equal 'fail', @adapter.send(:snapshot).dig(:front, :data_path, :status)
  end

  def test_front_incident_records_failure_repair_and_failed_verification
    @adapter.seed_active
    @adapter.instance_variable_get(:@options)[:front_data_probe_interval] = 0
    @adapter.define_singleton_method(:curl_proxy_ip_test) do |port, *_|
      { status: port == 17_890 ? 'fail' : 'pass', exit_code: port == 17_890 ? 28 : 0,
        elapsed_seconds: 3.0, detail: 'timed out' }
    end
    @adapter.define_singleton_method(:ensure_front) { @front_pid = 111 }
    2.times { @adapter.send(:supervise_front_data_path, 'a', @adapter.instance_variable_get(:@workers)['a']) }
    events = File.readlines(File.join(@dir, 'logs', 'events.jsonl')).map { |line| JSON.parse(line) }
    failures = events.select { |e| e['event'] == 'front-path-failed' }
    assert_equal [1, 2], failures.map { |e| e['consecutive_front_only_failures'] }
    assert_equal 28, failures.first.dig('front', 'exit_code')
    finish = events.find { |e| e['event'] == 'front-repair-finished' }
    assert_equal false, finish['restored']
    assert_equal failures.first['incident_id'], finish['incident_id']
    @adapter.define_singleton_method(:curl_proxy_ip_test) { |*_| { status: 'pass' } }
    @adapter.send(:supervise_front_data_path, 'a', @adapter.instance_variable_get(:@workers)['a'])
    recovery = JSON.parse(File.readlines(File.join(@dir, 'logs', 'events.jsonl')).last)
    assert_equal 'front-path-recovered', recovery['event']
    assert_equal finish['incident_id'], recovery['incident_id']
  end

  def test_failed_health_probe_persists_dns_error_evidence
    canary = @adapter.good_canary.merge(inner_dns: { status: 'fail', detail: 'DNS read timeout' })
    @adapter.send(:cache_speed_test, 'one', canary, 'active-health', 'ss')
    entry = JSON.parse(File.readlines(File.join(@dir, 'logs', 'events.jsonl')).last)
    assert_equal 'DNS read timeout', entry.dig('evidence', 'inner_dns', 'detail')
  end

  def test_new_generation_does_not_inherit_previous_recovery_cooldown
    @adapter.instance_variable_set(:@last_auto_recovery_at, Time.now)
    @adapter.instance_variable_set(:@last_recovery_generation, 5)
    refute @adapter.send(:recovery_due?, 5)
    assert @adapter.send(:recovery_due?, 6)
  end

  def test_quarantined_relays_are_excluded_and_batch_is_bounded
    @adapter.send(:quarantine_relay, 'two', 'injected')
    candidates = @adapter.send(:recovery_relay_candidates, 'one')
    refute_includes candidates, 'two'
    assert_operator candidates.length, :<=, 3
  end

  def test_endpoint_backoff_grows_and_success_clears_it
    @adapter.send(:record_ss_endpoint_outcome, 'one', '192.0.2.2', success: false)
    stats = @adapter.instance_variable_get(:@ss_endpoint_history)[:one][:endpoints][:'192.0.2.2']
    first = @adapter.send(:endpoint_retry_at, stats)
    assert @adapter.send(:endpoint_cooling_down?, stats)
    @adapter.send(:record_ss_endpoint_outcome, 'one', '192.0.2.2', success: false)
    assert_operator @adapter.send(:endpoint_retry_at, stats), :>, first
    @adapter.send(:record_ss_endpoint_outcome, 'one', '192.0.2.2', success: true)
    refute @adapter.send(:endpoint_cooling_down?, stats)
  end

  def test_endpoint_history_separates_same_ip_by_port
    @adapter.send(:record_ss_endpoint_outcome, 'one', '192.0.2.2', port: 51_900, success: false)
    @adapter.send(:record_ss_endpoint_outcome, 'one', '192.0.2.2', port: 51_901, success: true)
    endpoints = @adapter.instance_variable_get(:@ss_endpoint_history)[:one][:endpoints]

    assert_equal 1, endpoints[:'192.0.2.2:51900'][:failures]
    assert_equal 1, endpoints[:'192.0.2.2:51901'][:successes]
    refute_equal endpoints[:'192.0.2.2:51900'], endpoints[:'192.0.2.2:51901']
  end

  def test_known_port_is_preferred_for_relay_without_extra_ss_address
    @adapter.instance_variable_set(:@metadata, {
      'wireguard' => {
        'shadowsocks_port_ranges' => [[51_900, 51_902]],
        'relays' => [
          { 'hostname' => 'plain', 'active' => true, 'location' => 'us-sjc',
            'public_key' => 'public-plain', 'ipv4_addr_in' => '192.0.2.20',
            'shadowsocks_extra_addr_in' => [] }
        ]
      }
    })
    @adapter.send(:record_ss_endpoint_outcome, 'plain', '192.0.2.20', port: 51_901, success: true)

    assert_equal 51_901, @adapter.send(:ss_endpoint_candidates, @adapter.send(:find_relay, 'plain')).first[1]
  end

  def test_all_cooling_endpoints_allow_only_one_trial
    %w[192.0.2.2 192.0.2.3].each do |ip|
      @adapter.send(:record_ss_endpoint_outcome, 'one', ip, success: false)
    end
    assert_equal 1, @adapter.send(:ss_endpoint_candidates, @adapter.send(:find_relay, 'one')).length
  end

  def test_candidate_budget_stops_failed_sweep
    @adapter.seed_active
    @adapter.bad_candidate = 'two'
    clock = 0
    @adapter.define_singleton_method(:monotonic_now) { clock }
    @adapter.define_singleton_method(:run_canary) do |_slot|
      clock = 99 # The first failed probe exhausts the elapsed budget.
      { ip_data: { status: 'fail' }, inner_dns: { status: 'fail' }, https_data: { status: 'skip' } }
    end
    before = @adapter.candidate_calls
    refute @adapter.send(:activate, 'two', reason: 'select')
    assert_equal 1, @adapter.candidate_calls - before
  end

  def test_async_receipt_finishes_without_relying_on_generations
    @adapter.seed_active
    sock = StringIO.new
    @adapter.send(:accepted_async, sock, 'one', 'select', 'ss')
    receipt = JSON.parse(sock.string.split("\r\n\r\n", 2).last)
    assert receipt['id']
    Timeout.timeout(2) { sleep 0.001 while @adapter.send(:action_pending?) }
    result = @adapter.send(:operation_snapshot, receipt['id'])
    assert_equal 'succeeded', result[:state]
    assert_equal 1, @adapter.send(:snapshot)[:generation], 'same relay selection is a no-op but still completes'
  end

  def test_closed_receipt_socket_cannot_leave_action_permanently_busy
    @adapter.seed_active
    sock = Object.new
    def sock.write(*) = raise(IOError, 'closed')
    assert_raises(IOError) { @adapter.send(:accepted_async, sock, 'one', 'select', 'ss') }
    Timeout.timeout(2) { sleep 0.001 while @adapter.send(:action_pending?) }
    assert_equal 'succeeded', @adapter.send(:snapshot).dig(:operation, :state)
  end

  def test_cancelled_speedtest_cleans_candidate_and_preserves_active
    @adapter.seed_active
    id = 'cancel-test'
    @adapter.instance_variable_get(:@operations)[id] = { id: id, cancel_requested: false }
    Thread.current[:adapter_operation_id] = id
    @adapter.define_singleton_method(:run_canary) do |_slot|
      @operations['cancel-test'][:cancel_requested] = true
      { ip_data: { status: 'fail' }, inner_dns: { status: 'fail' } }
    end
    @adapter.send(:speed_test_relay, 'two')
    assert_equal ['a'], @adapter.instance_variable_get(:@workers).keys
    assert_equal 'one', @adapter.send(:snapshot)[:active_relay]
    assert_equal 2, @adapter.candidate_calls
  end

  def test_stop_and_replacement_are_serialized
    @adapter.seed_active
    stopping = Queue.new
    release = Queue.new
    @adapter.define_singleton_method(:stop_pid) { |_| stopping << true; release.pop }
    stop = Thread.new { @adapter.send(:stop_worker, 'a') }
    stopping.pop
    acquired = Queue.new
    replacement = Thread.new do
      @adapter.instance_variable_get(:@switch_mutex).synchronize { acquired << true }
    end
    Thread.pass
    assert acquired.empty?, 'a replacement cannot start during old process termination'
    release << true
    Timeout.timeout(2) { stop.join; replacement.join }
    assert_equal true, acquired.pop
  end

  def test_diagnosis_distinguishes_clash_path_from_adapter
    report = @adapter.send(:diagnosis_from_layers, {
      adapter_https: { status: 'pass' }, clash_https: { status: 'fail' }, worker: { status: 'pass' }
    })
    assert_equal 'clash_path', report[:code]
    report = @adapter.send(:diagnosis_from_layers, {
      adapter_https: { status: 'fail' }, adapter_ip: { status: 'fail' }, worker: { status: 'pass' }
    })
    assert_equal 'adapter_front', report[:code]
    report = @adapter.send(:diagnosis_from_layers, {})
    assert_equal 'unresolved', report[:code], 'multiple failed checks cannot identify a unique root cause'
  end

  def test_alternate_instance_ports_do_not_overlap_production
    adapter = MullvadAdapter.new(state_dir: @dir, worker_port_base: 18_910)
    assert_equal 18_910, adapter.instance_variable_get(:@slot_config).dig('a', :mixed)
    assert_equal 17_910, MullvadAdapter::SLOT_CONFIG.dig('a', :mixed)
  end
end
