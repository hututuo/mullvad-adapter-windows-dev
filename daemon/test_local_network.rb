# frozen_string_literal: true

require_relative 'test_reliability'

class MullvadLocalNetworkTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('mullvad-local-network')
    @adapter = ReliabilityAdapter.new(@dir)
    @adapter.instance_variable_get(:@options)[:local_network_settle] = 0
    @adapter.define_singleton_method(:process_alive?) { |_pid| true }
    @adapter.seed_active
    worker = @adapter.instance_variable_get(:@workers)['a']
    worker.merge!(endpoint_port: 20_484, endpoint_kind: 'extra')
    @adapter.events.clear
  end

  def teardown
    %i[adapter_network_epoch adapter_resume_path adapter_protection_profile adapter_attempt_id].each { |key| Thread.current[key] = nil }
    FileUtils.rm_rf(@dir)
  end

  def observe(status)
    @adapter.send(:apply_local_network_observation, status: status, source: 'test-hardware', detail: status)
  end

  def resume
    observe('unavailable')
    observe('available')
    @adapter.send(:check_active_health_once)
  end

  def test_hardware_attachment_ignores_tunnels_and_accepts_ethernet_or_ipv6
    hardware = "Hardware Port: Wi-Fi\nDevice: en0\nHardware Port: Ethernet\nDevice: en4\nDevice: feth4921\n"
    interfaces = "en0: flags=8863<UP,BROADCAST>\n\tstatus: inactive\nen4: flags=8863<UP,BROADCAST>\n\tinet6 2001:db8::1 prefixlen 64\n\tstatus: active\nutun7: flags=8051<UP,POINTOPOINT>\n\tinet 10.0.0.1 netmask 0xff000000\n"
    result = @adapter.send(:parse_local_network, hardware, interfaces)
    assert_equal 'available', result[:status]
    assert_equal ['en4'], result[:active_interfaces]
    result = @adapter.send(:parse_local_network, hardware, interfaces.sub('2001:db8::1', 'fe80::1%en4'))
    assert_equal 'unavailable', result[:status]
    assert_equal 'unknown', @adapter.send(:parse_local_network, hardware, interfaces.sub('status: active', 'status: unknown'))[:status]
    assert_equal 'unknown', @adapter.send(:parse_local_network, hardware, 'utun7: flags=8051<UP>')[:status]
  end

  def test_command_failure_is_unknown_instead_of_offline
    @adapter.define_singleton_method(:bounded_network_command) { |*_| raise IOError }
    @adapter.instance_variable_get(:@options)[:local_network_probe] = -> { raise IOError }
    assert_equal 'unknown', @adapter.send(:read_local_network)[:status]
    observe('unknown')
    refute @adapter.send(:snapshot).dig(:local_network, :paused)
  end

  def test_offline_pauses_all_automatic_relay_work_and_diagnostics
    observe('unavailable')
    @adapter.define_singleton_method(:run_readiness_canary) { |_| raise 'must not probe offline' }
    %i[check_active_health_once retry_disconnected_runtime supervise_worker_runtime maintain_city_candidates_once].each { |method| @adapter.send(method) }
    refute @adapter.send(:activate, 'two', reason: 'select')
    assert_empty @adapter.events
    assert_equal 'one', @adapter.send(:snapshot)[:active_relay]
    assert_equal 'waiting_network', @adapter.send(:snapshot)[:service_readiness]
    assert_equal 'local_network_unavailable', @adapter.send(:diagnose_network)[:code]
    refute @adapter.send(:repair_connection)
    @adapter.send(:quarantine_relay, 'one', 'offline')
    refute @adapter.send(:relay_quarantined?, 'one')
  end

  def test_offline_does_not_pollute_relay_or_ss_failure_history
    observe('unavailable')
    history = Marshal.dump(@adapter.instance_variable_get(:@relay_history))
    ss = Marshal.dump(@adapter.instance_variable_get(:@ss_endpoint_history))
    @adapter.send(:cache_speed_test, 'one', { ip_data: { status: 'fail' } }, 'active-health', 'ss')
    @adapter.send(:record_ss_endpoint_failure, 'one', 'ss', ['192.0.2.2', 20_484, 'extra'], RuntimeError.new('offline'))
    assert_equal history, Marshal.dump(@adapter.instance_variable_get(:@relay_history))
    assert_equal ss, Marshal.dump(@adapter.instance_variable_get(:@ss_endpoint_history))
  end

  def test_unknown_after_outage_keeps_waiting_and_settling_can_be_interrupted
    @adapter.instance_variable_get(:@options)[:local_network_settle] = 2
    observe('unavailable')
    epoch = @adapter.send(:network_epoch)
    observe('available')
    assert @adapter.send(:local_network_paused?)
    observe('unknown')
    assert @adapter.send(:local_network_paused?)
    observe('available')
    observe('unavailable')
    assert_operator @adapter.send(:network_epoch), :>, epoch
    assert_equal 'waiting', @adapter.send(:snapshot).dig(:local_network, :recovery_stage)
  end

  def test_live_original_tunnel_is_verified_without_rebuild_or_switch
    generation = @adapter.send(:snapshot)[:generation]
    resume
    assert_empty @adapter.events
    assert_equal generation, @adapter.send(:snapshot)[:generation]
    assert_equal 'ready', @adapter.send(:snapshot)[:service_readiness]
    assert_equal 'original-path-recovered', @adapter.send(:snapshot).dig(:local_network, :outcome)
  end

  def test_original_endpoint_is_rebuilt_first_and_no_alternate_is_used_on_success
    probes = 0
    @adapter.define_singleton_method(:run_readiness_canary) do |slot|
      probes += 1
      probes == 1 ? { ip_data: { status: 'fail' }, inner_dns: { status: 'fail' } } : good_canary
    end
    candidates = []
    original = @adapter.method(:start_worker)
    @adapter.define_singleton_method(:start_worker) do |slot, relay, **args|
      candidates << args[:ss_candidate]
      original.call(slot, relay, **args)
    end
    resume
    assert_equal [['192.0.2.2', 20_484, 'extra']], candidates
    assert_equal ['one'], @adapter.events.select { |e| e.first == :start }.map { |e| e[2] }
    assert_equal 'one', @adapter.send(:snapshot)[:active_relay]
    assert_equal 'ready', @adapter.send(:snapshot)[:service_readiness]
    assert_equal 'network-resume-original', @adapter.send(:snapshot)[:switch_reason]
  end

  def test_failed_original_rebuild_allows_same_city_fallback_only_afterward
    @adapter.bad_candidate = 'one'
    resume
    starts = @adapter.events.select { |e| e.first == :start }.map { |e| e[2] }
    assert_equal 'one', starts.first
    refute_equal 'one', starts.last
    assert_equal starts.last, @adapter.send(:snapshot)[:active_relay]
    assert_equal 'us-sjc', @adapter.send(:find_relay, starts.last)['location']
    assert_equal 'ready', @adapter.send(:snapshot)[:service_readiness]
    assert @adapter.send(:relay_quarantined?, 'one')
  end

  def test_crashed_worker_is_not_replaced_until_attachment_returns
    @adapter.define_singleton_method(:process_alive?) { |_pid| false }
    observe('unavailable')
    @adapter.send(:supervise_worker_runtime)
    assert_empty @adapter.events
    observe('available')
    @adapter.send(:check_active_health_once)
    assert_equal ['one'], @adapter.events.select { |e| e.first == :start }.map { |e| e[2] }
    assert_equal 'ready', @adapter.send(:snapshot)[:service_readiness]
  end

  def test_drop_during_rebuild_cleans_candidate_and_does_not_try_alternate
    probes = 0
    test = self
    @adapter.define_singleton_method(:run_readiness_canary) do |_slot|
      probes += 1
      test.observe('unavailable') if probes == 2
      { ip_data: { status: 'fail' }, inner_dns: { status: 'fail' } }
    end
    resume
    assert_equal ['one'], @adapter.events.select { |e| e.first == :start }.map { |e| e[2] }
    assert_empty @adapter.instance_variable_get(:@workers)
    assert_equal 'waiting_network', @adapter.send(:snapshot)[:service_readiness]
    refute @adapter.send(:relay_quarantined?, 'one')
  end

  def test_old_health_result_is_discarded_after_network_epoch_changes
    generation = @adapter.send(:snapshot)[:generation]
    history = Marshal.dump(@adapter.instance_variable_get(:@relay_history))
    test = self
    @adapter.define_singleton_method(:run_readiness_canary) do |_slot|
      test.observe('unavailable')
      test.observe('available')
      { ip_data: { status: 'fail' }, inner_dns: { status: 'fail' } }
    end
    @adapter.send(:check_active_health_once)
    assert_equal generation, @adapter.send(:snapshot)[:generation]
    assert_equal history, Marshal.dump(@adapter.instance_variable_get(:@relay_history))
    assert_empty @adapter.events
  end

  def test_manual_selection_wins_over_inflight_resume_verification
    original = @adapter.method(:run_readiness_canary)
    changed = false
    @adapter.define_singleton_method(:run_readiness_canary) do |slot|
      unless changed
        changed = true
        activate('two', reason: 'select')
      end
      original.call(slot)
    end
    resume
    assert_equal 'two', @adapter.send(:snapshot)[:active_relay]
    refute @adapter.send(:local_network_recovery_pending?)
    refute @adapter.send(:relay_quarantined?, 'one')
  end

  def test_paused_activation_preserves_callers_thread_context
    observe('unavailable')
    Thread.current[:adapter_attempt_id] = 'outer-attempt'
    Thread.current[:adapter_protection_profile] = { multihop: false }
    refute @adapter.send(:activate, 'one', reason: 'reconnect')
    assert_equal 'outer-attempt', Thread.current[:adapter_attempt_id]
    assert_equal({ multihop: false }, Thread.current[:adapter_protection_profile])
  end

  def test_full_speed_test_rejects_offline_and_discards_changed_network_result
    observe('unavailable')
    assert_equal 503, @adapter.send(:speed_test_relay, 'two').first
    observe('available')
    @adapter.send(:check_active_health_once)
    history = Marshal.dump(@adapter.instance_variable_get(:@relay_history))
    test = self
    @adapter.define_singleton_method(:run_canary) do |_slot|
      test.observe('unavailable')
      test.observe('available')
      { ip_data: { status: 'fail' }, inner_dns: { status: 'fail' } }
    end
    code, result = @adapter.send(:speed_test_relay, 'two')
    assert_equal 503, code
    assert_equal 'local_network_changed', result[:code]
    assert_equal history, Marshal.dump(@adapter.instance_variable_get(:@relay_history))
    assert_equal ['a'], @adapter.instance_variable_get(:@workers).keys
    assert_nil Thread.current[:adapter_network_epoch]
  end

  def test_live_original_with_dns_failure_is_preserved_for_normal_dns_policy
    generation = @adapter.send(:snapshot)[:generation]
    @adapter.define_singleton_method(:run_readiness_canary) do |_slot|
      { ip_data: { status: 'pass' }, inner_dns: { status: 'fail' }, https_data: { status: 'fail' } }
    end
    resume
    assert_empty @adapter.events
    assert_equal generation, @adapter.send(:snapshot)[:generation]
    refute @adapter.send(:local_network_recovery_pending?)
    assert_equal 'original-path-live-partial', @adapter.send(:snapshot).dig(:local_network, :outcome)
    assert_equal 'degraded_dns', @adapter.send(:snapshot)[:service_readiness]
    refute @adapter.send(:relay_quarantined?, 'one')
  end

  def test_slot_deferral_does_not_quarantine_or_switch_original_relay
    @adapter.bad_candidate = 'one'
    @adapter.define_singleton_method(:preferred_same_relay_restart_slot) { |_| 'b' }
    @adapter.define_singleton_method(:ensure_switch_slot_available) { |*_, **_| false }
    observe('unavailable')
    observe('available')
    assert_nil @adapter.send(:check_active_health_once)
    assert_equal 'one', @adapter.send(:snapshot)[:active_relay]
    assert @adapter.send(:local_network_recovery_pending?)
    refute @adapter.send(:relay_quarantined?, 'one')
    assert_empty @adapter.events
  end

  def test_local_worker_start_error_does_not_quarantine_or_try_other_nodes
    @adapter.bad_candidate = 'one'
    @adapter.fail_mode = 'ss'
    resume
    refute @adapter.send(:relay_quarantined?, 'one')
    assert_equal ['one'], @adapter.events.select { |e| e.first == :start }.map { |e| e[2] }
    assert_equal 'local-repair', @adapter.send(:snapshot).dig(:local_network, :recovery_stage)
    assert @adapter.send(:local_network_recovery_pending?)
  end

  def test_withdrawn_original_relay_can_use_same_city_without_false_quarantine
    @adapter.bad_candidate = 'one'
    @adapter.instance_variable_get(:@metadata)['wireguard']['relays'].reject! { |r| r['hostname'] == 'one' }
    resume
    refute_equal 'one', @adapter.send(:snapshot)[:active_relay]
    assert_equal 'us-sjc', @adapter.send(:find_relay, @adapter.send(:snapshot)[:active_relay])['location']
    refute @adapter.send(:relay_quarantined?, 'one')
  end

  def test_outage_events_record_transitions_and_outcome_without_polling_spam
    observe('unavailable')
    3.times { observe('unavailable') }
    observe('available')
    @adapter.send(:check_active_health_once)
    events = File.readlines(File.join(@dir, 'logs', 'events.jsonl')).map { |line| JSON.parse(line) }
      .select { |event| event['event'].start_with?('local-network-') }
    assert_equal %w[local-network-unavailable local-network-resume-requested local-network-recovery-finished], events.map { |event| event['event'] }
    assert_equal 'one', events.first['relay']
    assert_equal 'original-path-recovered', events.last['outcome']
    assert_equal true, events.last['restored']
  end

  def test_startup_without_worker_waits_then_tries_persisted_relay_first
    @adapter.send(:stop_worker, 'a')
    @adapter.instance_variable_get(:@state)[:active_slot] = nil
    @adapter.events.clear
    observe('unavailable')
    @adapter.send(:retry_disconnected_runtime)
    assert_empty @adapter.events
    observe('available')
    @adapter.send(:check_active_health_once)
    assert_equal 'one', @adapter.send(:snapshot)[:active_relay]
    assert_equal ['one'], @adapter.events.select { |e| e.first == :start }.map { |e| e[2] }
  end

  def test_resume_reuses_probe_when_lifecycle_lock_is_busy
    observe('unavailable')
    observe('available')
    calls = 0
    @adapter.define_singleton_method(:run_readiness_canary) { |_| calls += 1; good_canary }
    lock = @adapter.instance_variable_get(:@switch_mutex)
    lock.lock
    2.times { assert_equal :retry, @adapter.send(:check_active_health_once) }
    lock.unlock
    @adapter.send(:check_active_health_once)
    assert_equal 1, calls
    assert_equal 'ready', @adapter.send(:snapshot)[:service_readiness]
  ensure
    lock.unlock if lock&.owned?
  end

  def test_preoutage_automatic_round_cannot_take_over_resume
    expected = @adapter.instance_variable_get(:@state).slice(:generation, :active_slot, :active_relay)
    observe('unavailable')
    observe('available')
    refute @adapter.send(:automatic_recovery_context_valid?, expected[:generation], 'one')
    refute @adapter.send(:activate, 'two', reason: 'health-recovery', expected_state: expected)
    assert_empty @adapter.events
    assert @adapter.send(:local_network_recovery_pending?)
  end
end
