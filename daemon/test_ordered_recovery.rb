# frozen_string_literal: true
require_relative 'test_reliability'

# Real activation/cleanup/commit code; only process I/O and clock are simulated.
class OrderedRecoveryAdapter < ReliabilityAdapter
  attr_accessor :succeed_at, :local_at, :interrupt_at, :attempt_cost
  attr_reader :paths, :waits

  def initialize(dir)
    super
    @clock = 100.0
    @paths, @waits = [], []
    @attempt_cost = 0
    @metadata['wireguard']['relays'].each { |relay| relay['shadowsocks_extra_addr_in'] << '192.0.2.4' }
  end

  def monotonic_now = @clock

  def recovery_wait(seconds)
    @waits << seconds
    @clock += seconds
    network_attempt_current?
  end

  def start_worker(slot, relay, transport_mode: 'ss', ss_candidate: nil)
    info = super
    info[:endpoint_port] = ss_candidate&.[](1) || EXTRA_SS_PORT
    info[:endpoint_kind] = ss_candidate&.[](2) || 'extra-ss-ipv4'
    @paths << [relay['hostname'], info[:endpoint], info[:endpoint_port]]
    @state[:workers][slot] = public_worker_state(info).merge(state: 'candidate')
    info
  end

  def run_canary(slot)
    @clock += attempt_cost
    interrupt_at&.call(self, @paths.length)
    raise LocalProbeTimeout, 'injected-local' if @paths.length == local_at
    return good_canary if @paths.length == succeed_at
    { ip_data: { status: 'fail' }, inner_dns: { status: 'fail' }, https_data: { status: 'skip' } }
  end

  def prepare
    worker = start_worker('a', find_relay('one'), ss_candidate: ['192.0.2.2', EXTRA_SS_PORT, 'extra-ss-ipv4'])
    commit_active('a', 'one', worker, good_canary, 'startup', old_slot: nil, transport_preference: 'auto')
    @paths.clear
  end
end

class OrderedRecoveryTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('ordered-recovery')
    @adapter = OrderedRecoveryAdapter.new(@dir)
    @adapter.prepare
  end

  def teardown
    FileUtils.rm_rf(@dir)
    %i[adapter_recovery_token adapter_recovery_inlet adapter_recovery_id adapter_network_epoch adapter_recovery_deadline].each { |key| Thread.current[key] = nil }
  end

  def run_round(**args)
    @adapter.send(:run_ordered_recovery, 'one', reason: 'health-recovery', **args)
  end

  def test_exact_original_retries_precede_two_alternates_and_four_city_nodes
    refute run_round
    assert_equal Array.new(3, ['one', '192.0.2.2', 20_484]), @adapter.paths.first(3)
    assert_equal %w[192.0.2.3 192.0.2.4], @adapter.paths[3, 2].map { |path| path[1] }
    assert_equal %w[five four three two], @adapter.paths.drop(5).map(&:first).uniq
    assert_equal [2, 2, 2, 2], @adapter.paths.drop(5).group_by(&:first).values.map(&:length)
    assert_equal [0, 1, 5], @adapter.waits.first(3)
    assert_equal 13, @adapter.paths.length
    assert_equal 'exhausted', @adapter.send(:snapshot).dig(:recovery, :phase)
    assert_equal 13, @adapter.send(:snapshot).dig(:recovery, :attempt)
    assert @adapter.instance_variable_get(:@workers).empty?
  end

  def test_second_original_attempt_restores_without_extra_entry_or_peer_overlap
    @adapter.succeed_at = 2
    assert run_round
    assert_equal 2, @adapter.paths.length
    status = @adapter.send(:snapshot)
    assert_equal 'one', status[:active_relay]
    assert_equal 'auto', status[:transport_preference]
    assert_equal 'restored', status.dig(:recovery, :phase)
    assert_equal 1, @adapter.instance_variable_get(:@workers).length
  end

  def test_original_pin_ignores_cooldown_and_never_replaces_with_another_entry
    @adapter.send(:record_ss_endpoint_outcome, 'one', '192.0.2.2', port: 20_484, success: false)
    @adapter.succeed_at = 1
    assert run_round
    assert_equal [['one', '192.0.2.2', 20_484]], @adapter.paths
  end

  def test_local_probe_failure_defers_without_other_entry_or_relay
    @adapter.local_at = 1
    refute run_round
    assert_equal 1, @adapter.paths.length
    assert_equal 'local_wait', @adapter.send(:snapshot).dig(:recovery, :phase)
    assert_empty @adapter.instance_variable_get(:@recovery_quarantine)
  end

  def test_cancellation_after_probe_cannot_commit_or_start_another_peer
    @adapter.succeed_at = 1
    @adapter.interrupt_at = ->(adapter, _) { adapter.send(:interrupt_ordered_recovery, stopped: true) }
    refute run_round
    assert_equal 1, @adapter.paths.length
    status = @adapter.send(:snapshot)
    assert_nil status[:active_slot]
    assert_equal 'stopped', status.dig(:recovery, :phase)
    assert_empty @adapter.instance_variable_get(:@workers)
    assert @adapter.send(:ordered_recovery_blocked?)
  end

  def test_round_budget_is_not_renewed_between_entries
    @adapter.attempt_cost = 160
    refute run_round
    assert_equal 2, @adapter.paths.length
    assert_operator @adapter.send(:snapshot).dig(:recovery, :elapsed_seconds), :>, 300
  end

  def test_stale_start_context_is_rejected_without_touching_live_worker
    refute run_round(expected_state: { generation: -1, active_slot: 'a', active_relay: 'one' })
    assert_empty @adapter.paths
    assert_equal 'a', @adapter.send(:snapshot)[:active_slot]
  end

  def test_manual_current_only_stays_on_original_and_can_override_cooldown
    refute run_round(current_only: true)
    @adapter.paths.clear
    @adapter.send(:interrupt_ordered_recovery, stopped: false)
    @adapter.succeed_at = 1
    assert run_round(current_only: true, manual: true)
    assert_equal ['one'], @adapter.paths.map(&:first)
  end

  def test_stop_blocks_disconnected_supervisor_and_duplicate_automatic_round
    @adapter.send(:interrupt_ordered_recovery, stopped: true)
    refute run_round
    @adapter.send(:retry_disconnected_runtime)
    assert_empty @adapter.paths
  end

  def test_original_tuple_removed_from_official_catalogue_is_not_reused
    @adapter.instance_variable_get(:@metadata)['wireguard']['relays'].first['shadowsocks_extra_addr_in'].delete('192.0.2.2')
    @adapter.succeed_at = 1
    assert run_round
    assert_equal '192.0.2.3', @adapter.paths.first[1]
  end
  def test_first_bad_observation_does_not_rebuild_the_current_tunnel
    @adapter.send(:check_active_health_once)
    assert_empty @adapter.paths
    assert_equal 1, @adapter.instance_variable_get(:@health_fail_streak)
    assert_equal 'a', @adapter.send(:snapshot)[:active_slot]
  end

  def test_dns_only_degradation_keeps_the_live_worker_across_rechecks
    @adapter.define_singleton_method(:run_canary) do |_|
      { ip_data: { status: 'pass' }, inner_dns: { status: 'fail' }, https_data: { status: 'skip' } }
    end
    3.times { @adapter.send(:check_active_health_once) }
    assert_empty @adapter.paths
    assert_equal 'a', @adapter.send(:snapshot)[:active_slot]
    assert_equal 'degraded_dns', @adapter.send(:snapshot)[:service_readiness]
  end

  def test_stop_after_manual_request_was_queued_cannot_start_that_request
    ticket = @adapter.send(:interrupt_ordered_recovery, stopped: false)
    @adapter.send(:interrupt_ordered_recovery, stopped: true)
    Thread.current[:adapter_recovery_request_epoch] = ticket
    refute run_round(manual: true)
    assert_empty @adapter.paths
  ensure
    Thread.current[:adapter_recovery_request_epoch] = nil
  end

  def test_interface_list_change_is_logged_without_restarting_or_invalidating_tunnel
    @adapter.send(:apply_local_network_observation, status: 'available', active_interfaces: ['en0'])
    epoch = @adapter.send(:network_epoch)
    @adapter.send(:apply_local_network_observation, status: 'available', active_interfaces: ['en4'])
    assert_equal epoch, @adapter.send(:network_epoch)
    assert_empty @adapter.paths
    events = File.readlines(File.join(@dir, 'logs', 'events.jsonl')).map { |line| JSON.parse(line) }
    change = events.find { |event| event['event'] == 'local-network-interface-set-changed' }
    assert_equal ['en0'], change['previous']
    assert_equal ['en4'], change['current']
  end

  def test_local_stop_permission_error_keeps_old_peer_owned_and_defers
    @adapter.define_singleton_method(:stop_pid) { |_| raise Errno::EPERM }
    refute run_round
    assert_empty @adapter.paths
    assert_equal 1, @adapter.instance_variable_get(:@workers).length
    assert_equal 'local_wait', @adapter.send(:snapshot).dig(:recovery, :phase)
    assert_empty @adapter.instance_variable_get(:@recovery_quarantine)
  end

  def test_legacy_inlet_kind_cannot_duplicate_the_original_in_alternates
    @adapter.instance_variable_get(:@workers)['a'][:endpoint_kind] = 'legacy-kind'
    refute run_round
    assert_equal %w[192.0.2.3 192.0.2.4], @adapter.paths[3, 2].map { |path| path[1] }
  end

  def test_stop_wins_over_earlier_action_admission_ticket
    request = Object.new
    def request.write(_text); end
    original = @adapter.method(:interrupt_ordered_recovery)
    @adapter.define_singleton_method(:interrupt_ordered_recovery) do |stopped:, expected_epoch: nil|
      original.call(stopped: true) if expected_epoch
      original.call(stopped: stopped, expected_epoch: expected_epoch)
    end
    @adapter.send(:accepted_async, request, 'one', 'retry-round')
    Timeout.timeout(2) { sleep 0.001 while @adapter.send(:action_pending?) }
    assert @adapter.send(:ordered_recovery_blocked?)
    assert_empty @adapter.paths
    assert_equal 'cancelled', @adapter.send(:snapshot).dig(:operation, :state)
  end

  def test_process_stop_reaps_its_own_child_before_releasing_ownership
    reader, writer = IO.pipe
    pid = Process.fork do
      reader.close
      Signal.trap('TERM') { }
      writer.puts('ready')
      writer.close
      sleep 60
      exit! 0
    end
    writer.close
    Timeout.timeout(2) { reader.gets }
    adapter = MullvadAdapter.new(state_dir: @dir)
    adapter.send(:stop_pid, pid)
    assert_raises(Errno::ECHILD) { Process.waitpid(pid, Process::WNOHANG) }
  ensure
    reader&.close
    writer&.close unless writer&.closed?
    if pid
      begin
        if Process.waitpid(pid, Process::WNOHANG).nil?
          Process.kill('KILL', pid)
          Process.waitpid(pid)
        end
      rescue Errno::ECHILD, Errno::ESRCH
      end
    end
  end

end
