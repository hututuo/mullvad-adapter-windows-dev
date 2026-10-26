# frozen_string_literal: true
require_relative 'test_ordered_recovery'

class ProbePacingTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('probe-pacing')
    @adapter = ReliabilityAdapter.new(@dir)
    @adapter.seed_active
    @clock = 100.0
    clock = -> { @clock }
    @adapter.define_singleton_method(:monotonic_now) { clock.call }
    @adapter.instance_variable_set(:@favorite_cities, ['us-sjc'])
    @adapter.instance_variable_set(:@selected_city, 'us-sjc')
  end

  def teardown
    @adapter.instance_variable_get(:@probe_event_writer)&.join(2)
    FileUtils.rm_rf(@dir)
  end

  def test_maintenance_timeout_is_unknown_and_next_candidate_is_not_starved
    called = []
    @adapter.define_singleton_method(:outer_ping_test) do |endpoint, _|
      called << endpoint
      raise MullvadAdapter::LocalProbeTimeout, 'outer-ping' if called.length == 1
      { status: 'pass' }
    end
    @adapter.send(:maintain_city_candidates_once)
    assert_equal 1, called.size
    first = @adapter.instance_variable_get(:@city_probes).dup
    assert_equal ['unknown'], first.values.map { |v| v[:status] }
    10.times { @adapter.send(:maintain_city_candidates_once) }
    assert_equal 1, called.size
    @clock += 5
    @adapter.send(:maintain_city_candidates_once)
    assert_equal 2, called.size
    probes = @adapter.instance_variable_get(:@city_probes)
    assert_equal 2, probes.size
    assert_equal 1, probes.values.count { |v| v[:status] == 'pass' }
    assert_empty @adapter.instance_variable_get(:@recovery_quarantine)
    assert_equal 'one', @adapter.send(:snapshot)[:active_relay]
  end

  def test_maintenance_does_not_send_while_disconnected_or_recovering
    @adapter.define_singleton_method(:outer_ping_test) { |*_| flunk 'must not send' }
    @adapter.instance_variable_get(:@state)[:service_readiness] = 'data_fail'
    @adapter.send(:maintain_city_candidates_once)
    @adapter.instance_variable_get(:@state)[:service_readiness] = 'ready'
    @adapter.instance_variable_get(:@ordered_recovery_mutex).synchronize do
      @adapter.send(:maintain_city_candidates_once)
    end
    assert_empty @adapter.instance_variable_get(:@city_probes)
  end

  def test_background_observers_do_not_overlap_or_queue_and_gate_releases_on_error
    entered, release = Queue.new, Queue.new
    thread = Thread.new { @adapter.send(:with_background_probe) { entered << true; release.pop } }
    Timeout.timeout(1) { entered.pop }
    @adapter.define_singleton_method(:front_service_probe) { |_| raise 'unexpected network probe' }
    worker = @adapter.instance_variable_get(:@workers)['a']
    assert_equal :retry, @adapter.send(:supervise_front_data_path, 'a', worker)
    assert_equal :retry, @adapter.send(:maintain_city_candidates_once)
    release << true
    thread.join(1)
    assert_raises(IOError) { @adapter.send(:with_background_probe) { raise IOError } }
    assert_equal :available, @adapter.send(:with_background_probe) { :available }
  ensure
    release << true if thread&.alive?
    thread&.join(1)
  end

  def test_fresh_healthy_observation_reconciles_old_failure_but_not_current_pending
    local = @adapter.instance_variable_get(:@state)[:local_network]
    local.merge!(recovery_pending: false, recovery_stage: 'failed', outcome: 'same-city-exhausted')
    @adapter.send(:check_active_health_once)
    assert_equal 'restored', @adapter.send(:snapshot).dig(:local_network, :recovery_stage)
    assert_equal 'subsequent-path-validated', local[:outcome]
    local.merge!(recovery_pending: true, recovery_stage: 'verify-original')
    @adapter.instance_variable_get(:@mutex).synchronize do
      @adapter.send(:reconcile_validated_local_recovery, { service_readiness: 'ready' }, Time.now.iso8601)
    end
    assert local[:recovery_pending]
    assert_equal 'verify-original', local[:recovery_stage]
  end

  def test_failure_evidence_is_bounded_and_does_not_emit_raw_destinations_or_credentials
    worker = @adapter.instance_variable_get(:@workers)['a']
    path = File.join(@dir, 'slots', 'a', 'core.log')
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, 'x' * 20_000 + "\nlevel=warning msg=\"dial tcp private.example:443 context deadline exceeded password=secret\"\n")
    evidence = @adapter.send(:worker_failure_log_summary, worker)
    assert_equal 'captured', evidence[:status]
    assert_operator evidence[:tail_bytes], :<=, 16_384
    assert_equal 1, evidence.dig(:categories, :inner_tcp_timeout)
    refute_match(/private.example|password|secret/, JSON.generate(evidence))
    assert_equal 'not-exposed-by-engine-controller', evidence[:handshake]
    File.unlink(path)
    File.symlink(File.join(@dir, 'missing-sensitive'), path)
    assert_equal 'not-regular-file', @adapter.send(:worker_failure_log_summary, worker)[:reason]
  end

  def test_background_metadata_failures_back_off_and_single_attempt_is_requested
    calls = []
    adapter = @adapter
    @adapter.define_singleton_method(:refresh_metadata) do |**args|
      calls << args
      @state[:metadata] = { live: false }
      raise IOError
    end
    [30, 60, 120, 240, 300, 300].each do |delay|
      assert_raises(IOError) { adapter.send(:observe_control_plane_once) }
      assert_equal({ force: true, background: true }, calls.last)
      assert_in_delta @clock + delay, adapter.instance_variable_get(:@metadata_background_retry_at), 0.001
      count = calls.size
      adapter.send(:observe_control_plane_once)
      assert_equal count, calls.size
      @clock += delay
    end
    @adapter.define_singleton_method(:refresh_metadata) do |**_|
      @state[:metadata] = { live: true }
      @metadata = { 'wireguard' => {} }
      @metadata_fetched_at = Time.now
    end
    @adapter.send(:observe_control_plane_once)
    assert_equal 0, @adapter.instance_variable_get(:@metadata_background_failures)
  end
end

class RecoveryPacingTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('recovery-pacing')
    @adapter = OrderedRecoveryAdapter.new(@dir)
    @adapter.prepare
  end

  def teardown
    @adapter.instance_variable_get(:@probe_event_writer)&.join(2)
    FileUtils.rm_rf(@dir)
    %i[adapter_recovery_token adapter_recovery_inlet adapter_recovery_id adapter_network_epoch adapter_recovery_deadline].each { |key| Thread.current[key] = nil }
  end

  def test_repeated_exhaustion_backs_off_without_reducing_the_first_round_and_resets_on_success
    [30, 60, 120, 120].each_with_index do |delay, index|
      @adapter.send(:recovery_wait, 121) if index.positive?
      refute @adapter.send(:run_ordered_recovery, 'one', reason: 'health-recovery')
      assert_equal delay, @adapter.send(:snapshot).dig(:recovery, :retry_delay_seconds)
      attempts = @adapter.paths.length
      refute @adapter.send(:run_ordered_recovery, 'one', reason: 'startup-retry')
      assert_equal attempts, @adapter.paths.length
      assert_equal 24, attempts if index.zero?
    end
    @adapter.send(:interrupt_ordered_recovery, stopped: false)
    @adapter.succeed_at = @adapter.paths.length + 1
    local = @adapter.instance_variable_get(:@state)[:local_network]
    local.merge!(recovery_pending: false, recovery_stage: 'failed', outcome: 'same-city-exhausted')
    assert @adapter.send(:run_ordered_recovery, 'one', reason: 'manual', manual: true, current_only: true)
    assert_equal 0, @adapter.instance_variable_get(:@automatic_exhausted_rounds)
    assert_equal 'restored', local[:recovery_stage]
  end
end
