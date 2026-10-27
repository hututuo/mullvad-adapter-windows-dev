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
    @adapter&.instance_variable_get(:@probe_event_writer)&.join(2)
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

  def test_link_local_ipv6_does_not_advertise_an_internet_ipv6_source
    hardware = "Hardware Port: Wi-Fi\nDevice: en0\n"
    interfaces = "en0: flags=8863<UP,BROADCAST>\n\tinet 192.0.2.10 netmask 0xffffff00\n\tinet6 fe80::1%en0 prefixlen 64\n\tstatus: active\n"
    observed = @adapter.send(:parse_local_network, hardware, interfaces)
    assert_equal ['ipv4'], observed[:address_families]
    @adapter.send(:apply_local_network_observation, observed)
    relay = @adapter.send(:find_relay, 'one')
    assert_equal %w[ss ipv4], @adapter.send(:transport_candidates, 'auto', relay)
    assert_empty @adapter.send(:recovery_inlets, 'one', 'ipv6')
    assert_raises(RuntimeError) { @adapter.send(:transport_candidates, 'ipv6', relay) }
  end

  def test_ipv6_only_attachment_does_not_start_an_ipv4_ss_carrier
    @adapter.send(:apply_local_network_observation, status: 'available', active_interfaces: ['en0'], address_families: ['ipv6'])
    assert_equal ['ipv6'], @adapter.send(:transport_candidates, 'auto', @adapter.send(:find_relay, 'one'))
    assert_empty @adapter.send(:recovery_inlets, 'one', 'ss')
    refute @adapter.send(:snapshot).dig(:local_network, :paused)
  end

  def test_ipv6_transport_cannot_reuse_a_v4_only_default_interface
    # Use the real resolver, not ReliabilityAdapter's engine fixture.
    adapter = MullvadAdapter.new(state_dir: @dir)
    adapter.define_singleton_method(:route_interface_for) { |_, _| 'en0' }
    adapter.define_singleton_method(:network_interface_fallbacks) { ['en0'] }
    adapter.define_singleton_method(:bounded_network_command) do |*|
      "en0: flags=8863<UP,BROADCAST>\n\tinet 192.0.2.10 netmask 0xffffff00\n\tinet6 fe80::1%en0 prefixlen 64\n\tstatus: active\n"
    end
    error = assert_raises(MullvadAdapter::LocalProbeUnavailable) { adapter.send(:physical_interface, '2001:db8::1') }
    assert_equal 'physical-ipv6-route-unavailable', error.phase
    assert_equal 'en0', adapter.send(:physical_interface, '192.0.2.1')
    adapter.define_singleton_method(:bounded_network_command) do |*|
      "en0: flags=8863<UP,BROADCAST>\n\tinet6 2001:db8::2 prefixlen 64\n\tstatus: active\n"
    end
    assert_equal 'en0', adapter.send(:physical_interface, '2001:db8::1')
  end

  def test_tentative_ipv6_address_is_not_an_outer_transport_source
    adapter = MullvadAdapter.new(state_dir: @dir)
    adapter.define_singleton_method(:bounded_network_command) do |*|
      "en0: flags=8863<UP,BROADCAST>\n\tinet6 2001:db8::2 prefixlen 64 tentative\n\tstatus: active\n"
    end
    refute adapter.send(:usable_transport_interface?, 'en0', :ipv6)
  end

  def test_ipv6_fallback_requires_a_scoped_ipv6_route_even_when_an_address_exists
    adapter = MullvadAdapter.new(state_dir: @dir)
    adapter.define_singleton_method(:route_interface_for) { |_, _| 'utun7' }
    adapter.define_singleton_method(:network_interface_fallbacks) { ['en0'] }
    adapter.define_singleton_method(:bounded_network_command) do |command, *|
      raise IOError if command == '/sbin/route'
      "en0: flags=8863<UP,BROADCAST>\n\tinet6 2001:db8::2 prefixlen 64\n\tstatus: active\n"
    end
    assert_raises(MullvadAdapter::LocalProbeUnavailable) { adapter.send(:physical_interface, '2001:db8::1') }
    adapter.define_singleton_method(:bounded_network_command) do |command, *args|
      if command == '/sbin/route'
        raise 'must ask scoped IPv6 route' unless args == ['-n', 'get', '-inet6', '-ifscope', 'en0', '2001:db8::1']
        "interface: en0\n"
      else
        "en0: flags=8863<UP,BROADCAST>\n\tinet6 2001:db8::2 prefixlen 64\n\tstatus: active\n"
      end
    end
    assert_equal 'en0', adapter.send(:physical_interface, '2001:db8::1')
  end

  def test_manual_ipv6_selection_without_local_ipv6_has_a_clear_result_and_keeps_worker
    @adapter.send(:apply_local_network_observation, status: 'available', active_interfaces: ['en0'], address_families: ['ipv4'])
    response = +''
    socket = Object.new
    socket.define_singleton_method(:write) { |value| response << value }
    @adapter.send(:accepted_async, socket, 'two', 'select', 'ipv6')
    assert_includes response, '409'
    assert_includes response, 'local_ipv6_unavailable'
    assert_equal 'one', @adapter.send(:snapshot)[:active_relay]
    refute @adapter.send(:action_pending?)
    assert_empty @adapter.events
  end

  def test_inconclusive_data_observation_never_counts_as_a_tunnel_failure
    @adapter.instance_variable_get(:@options)[:health_fail_threshold] = 1
    @adapter.define_singleton_method(:run_readiness_canary) do |*|
      { at: Time.now.iso8601, ip_data: { status: 'unknown', local_failure: 'local-socket' },
        inner_dns: { status: 'fail' }, https_data: { status: 'skip' }, ping_data: { status: 'pass', delay_ms: 100 } }
    end
    @adapter.define_singleton_method(:run_ordered_recovery) { |*, **| flunk 'inconclusive observation must not initiate recovery' }
    @adapter.send(:check_active_health_once)
    assert_equal 0, @adapter.send(:snapshot).dig(:health, :consecutive_wg_failures)
    assert_equal 'one', @adapter.send(:snapshot)[:active_relay]
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

  def test_resume_probe_timeout_is_deferred_and_the_next_check_can_finish_recovery
    calls = 0
    @adapter.define_singleton_method(:run_readiness_canary) do |_slot|
      calls += 1
      raise MullvadAdapter::LocalProbeTimeout, 'ip-data' if calls == 1
      good_canary
    end
    resume
    assert @adapter.send(:local_network_recovery_pending?)
    assert_equal 'local-repair', @adapter.send(:snapshot).dig(:local_network, :recovery_stage)
    assert_empty @adapter.events
    refute @adapter.send(:relay_quarantined?, 'one')
    @adapter.instance_variable_set(:@network_recovery_retry_at, nil)
    @adapter.send(:check_active_health_once)
    refute @adapter.send(:local_network_recovery_pending?)
    assert_equal 'original-path-recovered', @adapter.send(:snapshot).dig(:local_network, :outcome)
  end

  def test_manual_retry_round_can_rebuild_the_original_while_resume_is_pending
    observe('unavailable')
    observe('available')
    assert @adapter.send(:local_network_recovery_pending?)
    assert @adapter.send(:run_ordered_recovery, 'one', reason: 'retry-round', manual: true)
    assert_equal 'restored', @adapter.send(:snapshot).dig(:recovery, :phase)
    refute @adapter.send(:local_network_recovery_pending?)
    assert_equal ['one'], @adapter.events.select { |event| event.first == :start }.map { |event| event[2] }
  end

  def test_health_monitor_continues_after_an_unexpected_iteration_error
    checks = 0
    @adapter.define_singleton_method(:wait_for_health_check) { |_| sleep 0.005 }
    @adapter.define_singleton_method(:check_active_health_once) do
      checks += 1
      raise IOError, 'fixture-sensitive-message' if checks == 1
      @stop_requested = true
      nil
    end
    monitor = @adapter.send(:start_active_health_monitor)
    monitor.report_on_exception = false
    assert monitor.join(1), 'one observation error must not terminate or wedge the health owner'
    assert_equal 2, checks
    @adapter.instance_variable_get(:@probe_event_writer)&.join(1)
    records = File.readlines(File.join(@dir, 'logs', 'events.jsonl')).map { |line| JSON.parse(line) }
    error = records.find { |entry| entry['event'] == 'health-monitor-error' }
    assert_equal 'IOError', error.fetch('error_class')
    refute_includes JSON.generate(records), 'fixture-sensitive-message'
  ensure
    @adapter.instance_variable_set(:@stop_requested, true)
    monitor&.kill if monitor&.alive?
    begin
      monitor&.join(1)
    rescue IOError
      nil
    end
  end

  def test_failed_manual_selection_during_resume_cannot_claim_the_old_path_was_restored
    observe('unavailable')
    observe('available')
    @adapter.define_singleton_method(:activate) { |*_, **_| false }
    request = Object.new
    def request.write(_text); end
    @adapter.send(:accepted_async, request, 'two', 'select')
    Timeout.timeout(1) { sleep 0.001 while @adapter.send(:action_pending?) }
    assert_equal 'failed', @adapter.send(:snapshot).dig(:operation, :state)
    assert @adapter.send(:local_network_recovery_pending?)
    assert_equal 'one', @adapter.send(:snapshot)[:active_relay]
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
