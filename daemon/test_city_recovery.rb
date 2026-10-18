# frozen_string_literal: true

# Loading the reliability fixture also runs its existing deterministic tests.
require_relative 'test_reliability'

class MullvadCityRecoveryTest < Minitest::Test
  class TestSocket
    attr_reader :response
    def initialize(request)
      @request = StringIO.new(request)
      @response = +''
    end
    def gets(limit) = @request.gets(limit)
    def read(length) = @request.read(length)
    def write(value) = @response << value
    def close; end
  end
  CITIES = {
    'one' => 'us-sjc', 'two' => 'us-sjc',
    'three' => 'us-nyc', 'four' => 'us-nyc',
    'five' => 'us-sea', 'six' => 'us-lax'
  }.freeze

  def setup
    @dir = Dir.mktmpdir('mullvad-city-recovery')
    @adapter = ReliabilityAdapter.new(@dir)
    install_city_metadata
  end

  def teardown
    Thread.current[:adapter_operation_id] = nil
    FileUtils.rm_rf(@dir)
  end

  def test_health_canary_runs_while_another_thread_acquires_switch_mutex
    @adapter.seed_active
    probe_entered = Queue.new
    release_probe = Queue.new
    mutex_acquired = Queue.new
    checker = contender = nil
    released = false

    @adapter.define_singleton_method(:run_readiness_canary) do |_slot|
      probe_entered << true
      release_probe.pop
      good_canary
    end

    checker = Thread.new { @adapter.send(:check_active_health_once) }
    Timeout.timeout(2) { probe_entered.pop }
    contender = Thread.new do
      @adapter.instance_variable_get(:@switch_mutex).synchronize { mutex_acquired << true }
    end

    Timeout.timeout(2) { mutex_acquired.pop }
    release_probe << true
    released = true
    Timeout.timeout(2) do
      checker.value
      contender.value
    end
  ensure
    unless released
      release_probe << true
    end
    [checker, contender].compact.each { |thread| thread.join(2) }
  end

  def test_health_result_from_old_generation_does_not_change_state_or_history
    assert_stale_health_result_is_discarded do
      mutex = @adapter.instance_variable_get(:@mutex)
      mutex.synchronize { @adapter.instance_variable_get(:@state)[:generation] += 1 }
    end
  end

  def test_health_result_from_replaced_worker_token_does_not_change_state_or_history
    assert_stale_health_result_is_discarded do
      mutex = @adapter.instance_variable_get(:@mutex)
      mutex.synchronize do
        @adapter.instance_variable_get(:@workers).fetch('a')[:instance_token] = 'replacement-token'
      end
    end
  end

  def test_busy_commit_lock_retries_and_reuses_completed_health_observation
    @adapter.seed_active
    mutex_acquired = Queue.new
    release_mutex = Queue.new
    canaries = []
    probe_saw_busy_mutex = Queue.new
    lock_holder = Thread.new do
      @adapter.instance_variable_get(:@switch_mutex).synchronize do
        mutex_acquired << true
        release_mutex.pop
      end
    end
    Timeout.timeout(2) { mutex_acquired.pop }
    @adapter.define_singleton_method(:run_readiness_canary) do |_slot|
      probe_saw_busy_mutex << @switch_mutex.locked?
      canary = good_canary.merge(at: 'single-health-observation')
      canaries << canary
      canary
    end

    assert_equal :retry, @adapter.send(:check_active_health_once)
    assert_equal true, probe_saw_busy_mutex.pop
    assert_equal 1, canaries.length
    refute_nil @adapter.instance_variable_get(:@pending_health_observation)

    release_mutex << true
    lock_holder.value
    @adapter.send(:check_active_health_once)

    assert_equal 1, canaries.length, 'the next check must reuse the completed observation'
    assert_nil @adapter.instance_variable_get(:@pending_health_observation)
    assert_equal canaries.first, @adapter.send(:snapshot)[:last_canary]
    assert_equal 1, @adapter.instance_variable_get(:@metrics)[:health_checks]
  ensure
    release_mutex << true if lock_holder&.alive?
    lock_holder&.join(2)
  end

  def test_health_wake_interrupts_condition_wait
    entered_wait = Queue.new
    returned = Queue.new
    waiter = nil
    @adapter.define_singleton_method(:health_wait_seconds) do
      entered_wait << true
      60
    end

    waiter = Thread.new do
      @adapter.send(:wait_for_health_check)
      returned << true
    end
    Timeout.timeout(2) { entered_wait.pop }
    @adapter.send(:wake_health_monitor, 'test-wake')
    Timeout.timeout(2) { returned.pop }
    waiter.value
    refute @adapter.instance_variable_get(:@health_wake_pending)
  ensure
    @adapter.send(:wake_health_monitor, 'test-cleanup') if waiter&.alive?
    waiter&.join(2)
  end

  def test_repeated_health_wakes_coalesce_until_the_waiter_consumes_them
    @adapter.define_singleton_method(:health_wait_seconds) { raise 'pending wake should skip timed wait' }

    @adapter.send(:wake_health_monitor, 'first')
    @adapter.send(:wake_health_monitor, 'second')
    assert @adapter.instance_variable_get(:@health_wake_pending)
    @adapter.send(:wait_for_health_check)
    refute @adapter.instance_variable_get(:@health_wake_pending)

    events = event_log
    assert_equal 1, events.count { |event| event['event'] == 'health-check-requested' }
  end

  def test_front_external_probe_runs_without_switch_mutex
    @adapter.seed_active
    @adapter.instance_variable_get(:@options)[:front_data_probe_interval] = 0
    @adapter.instance_variable_set(:@front_pid, 71_111)
    worker = @adapter.instance_variable_get(:@workers).fetch('a').dup
    probe_entered = Queue.new
    release_probe = Queue.new
    mutex_acquired = Queue.new
    probe = contender = nil
    released = false
    @adapter.define_singleton_method(:curl_proxy_ip_test) do |port, *_args|
      if port == @options[:front_mixed]
        probe_entered << true
        release_probe.pop
      end
      { status: 'pass', detail: 'injected' }
    end

    probe = Thread.new { @adapter.send(:supervise_front_data_path, 'a', worker) }
    Timeout.timeout(2) { probe_entered.pop }
    contender = Thread.new do
      @adapter.instance_variable_get(:@switch_mutex).synchronize { mutex_acquired << true }
    end
    Timeout.timeout(2) { mutex_acquired.pop }
    release_probe << true
    released = true
    Timeout.timeout(2) do
      probe.value
      contender.value
    end
  ensure
    release_probe << true unless released
    [probe, contender].compact.each { |thread| thread.join(2) }
  end

  def test_front_probe_result_from_stale_context_cannot_restart_front
    @adapter.seed_active
    @adapter.instance_variable_get(:@options)[:front_data_probe_interval] = 0
    @adapter.instance_variable_set(:@front_pid, 71_111)
    worker = @adapter.instance_variable_get(:@workers).fetch('a').dup
    probe_entered = Queue.new
    release_probe = Queue.new
    stopped = []
    restarted = []
    probe = nil
    released = false
    @adapter.define_singleton_method(:curl_proxy_ip_test) do |port, *_args|
      if port == @options[:front_mixed]
        probe_entered << true
        release_probe.pop
        { status: 'fail', detail: 'injected front failure' }
      else
        { status: 'pass', detail: 'injected worker pass' }
      end
    end
    @adapter.define_singleton_method(:stop_pid) { |pid| stopped << pid }
    @adapter.define_singleton_method(:ensure_front) { restarted << :ensure_front }

    probe = Thread.new { @adapter.send(:supervise_front_data_path, 'a', worker) }
    Timeout.timeout(2) { probe_entered.pop }
    @adapter.instance_variable_get(:@mutex).synchronize { @adapter.instance_variable_set(:@front_pid, 71_112) }
    release_probe << true
    released = true
    Timeout.timeout(2) { probe.value }

    assert_empty stopped
    assert_empty restarted
    assert_equal 0, @adapter.instance_variable_get(:@front_data_probe_failures)
    assert_nil @adapter.instance_variable_get(:@front_incident_id)
    discarded = event_log.find { |event| event['event'] == 'front-result-discarded' }
    refute_nil discarded
    assert_equal 'active-context-changed', discarded['reason']
  ensure
    release_probe << true unless released
    probe&.join(2)
  end

  def test_readiness_canary_skips_controller_delay_but_keeps_dns_and_https_checks
    @adapter.seed_active
    observations = Queue.new
    dns_status = 'pass'
    https_status = 'pass'
    delay_calls = Queue.new
    @adapter.define_singleton_method(:run_canary) do |slot|
      MullvadAdapter.instance_method(:run_canary).bind(self).call(slot)
    end
    @adapter.define_singleton_method(:outer_ping_test) do |endpoint, _timeout|
      observations << [:outer, endpoint]
      { status: 'pass', target: endpoint }
    end
    @adapter.define_singleton_method(:curl_proxy_ip_test) do |port, *_args|
      observations << [:ip, port]
      { status: 'pass' }
    end
    @adapter.define_singleton_method(:inner_dns_tcp_test) do |port, *_args|
      observations << [:dns, port]
      { status: dns_status }
    end
    @adapter.define_singleton_method(:curl_proxy_test) do |port, *_args|
      observations << [:https, port]
      { status: https_status }
    end
    @adapter.define_singleton_method(:delay_test) do |*_args|
      delay_calls << true
      { status: 'pass' }
    end

    ready = @adapter.send(:run_readiness_canary, 'a')
    assert_equal 'skip', ready.dig(:controller_probe, :status)
    assert_equal 'pass', ready.dig(:inner_dns, :status)
    assert_equal 'pass', ready.dig(:https_data, :status)
    assert_equal 'ready', @adapter.send(:classify_canary, ready)[:service_readiness]

    https_status = 'fail'
    degraded_service = @adapter.send(:run_readiness_canary, 'a')
    assert_equal 'degraded_service', @adapter.send(:classify_canary, degraded_service)[:service_readiness]

    dns_status = 'fail'
    degraded_dns = @adapter.send(:run_readiness_canary, 'a')
    assert_equal 'fail', degraded_dns.dig(:inner_dns, :status)
    assert_equal 'skip', degraded_dns.dig(:https_data, :status)
    assert_equal 'degraded_dns', @adapter.send(:classify_canary, degraded_dns)[:service_readiness]

    seen = []
    seen << observations.pop until observations.empty?
    assert seen.any? { |kind, _port| kind == :dns }
    assert_equal 2, seen.count { |kind, _port| kind == :https }, 'HTTPS runs when DNS passes, then respects its failure result'
    assert_empty delay_calls
  end

  def test_recovery_candidates_and_missing_startup_preference_stay_in_selected_city
    set_city_policy(%w[us-sjc us-nyc], 'us-nyc')

    recovery = @adapter.send(:recovery_relay_candidates, 'one')
    refute_empty recovery
    assert recovery.all? { |name| CITIES.fetch(name) == 'us-nyc' }

    attempted = []
    @adapter.define_singleton_method(:activate) do |name, **_options|
      attempted << name
      false
    end
    refute @adapter.send(:activate_startup_with_fallback, 'missing-preferred-relay', 'ss', reason: 'startup')
    refute_empty attempted
    assert attempted.all? { |name| CITIES.fetch(name) == 'us-nyc' }
  end

  def test_favorites_are_limited_to_three_and_cannot_remove_selected_city
    favorites = %w[us-sjc us-nyc us-sea]
    set_city_policy(favorites, 'us-sjc')

    assert_raises(ArgumentError) do
      @adapter.send(:update_favorite_cities, %w[us-sjc us-nyc us-sea us-lax])
    end
    assert_raises(ArgumentError) do
      @adapter.send(:update_favorite_cities, %w[us-nyc us-sea])
    end
    assert_equal [favorites, 'us-sjc'], city_policy
  end

  def test_startup_stops_new_candidates_when_round_budget_expires_and_restores_trace
    set_city_policy(%w[us-sjc us-nyc], 'us-nyc')
    clock = 0
    attempted = []
    @adapter.define_singleton_method(:monotonic_now) { clock }
    @adapter.define_singleton_method(:activate) do |name, **_options|
      attempted << name
      clock = 100
      false
    end
    refute @adapter.send(:activate_startup_with_fallback, 'missing', 'auto', reason: 'startup')
    assert_equal 1, attempted.length
    assert_nil Thread.current[:adapter_recovery_deadline]
    assert_nil Thread.current[:adapter_recovery_id]
    events = event_log.select { |e| e['event'].start_with?('recovery-round-') }
    assert_equal 2, events.length
    assert_equal events.first['recovery_id'], events.last['recovery_id']
  end

  def test_city_success_early_return_restores_callers_deadline_and_trace
    set_city_policy(%w[us-sjc], 'us-sjc')
    @adapter.define_singleton_method(:monotonic_now) { 0 }
    @adapter.define_singleton_method(:activate) { |_name, **_options| true }
    Thread.current[:adapter_recovery_id] = 'caller-trace'
    Thread.current[:adapter_recovery_deadline] = 10
    assert @adapter.send(:activate_city, 'us-sjc', 'auto')
    assert_equal 'caller-trace', Thread.current[:adapter_recovery_id]
    assert_equal 10, Thread.current[:adapter_recovery_deadline]
    assert_equal 'recovery-round-finished', event_log.last['event']
  ensure
    Thread.current[:adapter_recovery_id] = nil
    Thread.current[:adapter_recovery_deadline] = nil
  end

  def test_crash_rebuild_budget_prevents_another_node_attempt_after_expiry
    @adapter.seed_active
    clock = 0
    attempted = []
    @adapter.define_singleton_method(:monotonic_now) { clock }
    @adapter.define_singleton_method(:process_alive?) { |_pid| false }
    @adapter.define_singleton_method(:activate) do |name, **_options|
      attempted << name
      clock = 100
      false
    end
    @adapter.send(:supervise_worker_runtime)
    assert_equal ['one'], attempted
    assert_nil Thread.current[:adapter_recovery_deadline]
    assert_equal 'data_fail', @adapter.send(:snapshot)[:service_readiness]
    assert_equal 'recovery-round-finished', event_log.last['event']
  end

  def test_health_round_does_not_expand_to_three_backup_nodes_when_candidates_fail
    @adapter.seed_active
    metadata = @adapter.instance_variable_get(:@metadata)
    %w[seven eight].each do |name|
      metadata['wireguard']['relays'] << metadata['wireguard']['relays'].first.merge('hostname' => name)
    end
    @adapter.instance_variable_get(:@workers)['a'][:transport_mode] = 'ipv6'
    @adapter.instance_variable_set(:@health_fail_streak, 1)
    @adapter.define_singleton_method(:run_readiness_canary) do |_slot|
      { ip_data: { status: 'fail' }, inner_dns: { status: 'fail' }, https_data: { status: 'fail' } }
    end
    attempted = []
    @adapter.define_singleton_method(:activate) do |name, **_options|
      attempted << name
      false
    end
    @adapter.send(:check_active_health_once)
    assert_equal 2, attempted.uniq.length
    refute_includes attempted, 'one'
  end

  def test_failed_favorites_persist_leaves_in_memory_policy_unchanged
    favorites = %w[us-sjc us-nyc]
    set_city_policy(favorites, 'us-sjc')
    @adapter.define_singleton_method(:persist_city_workspace) { |_favorites, _selected| raise IOError, 'injected disk failure' }

    assert_raises(IOError) { @adapter.send(:update_favorite_cities, %w[us-sjc us-sea]) }
    assert_equal [favorites, 'us-sjc'], city_policy
  end

  def test_city_backup_maintenance_only_probes_and_preserves_active_worker
    @adapter.seed_active
    @adapter.send(:update_favorite_cities, %w[us-sjc us-nyc])
    before_state = @adapter.send(:snapshot)
    before_workers = Marshal.load(Marshal.dump(@adapter.instance_variable_get(:@workers)))
    starts_before = @adapter.events.count { |event| event.first == :start }
    pings = []
    @adapter.define_singleton_method(:outer_ping_test) do |endpoint, timeout_ms|
      pings << [endpoint, timeout_ms]
      { status: 'pass', target: endpoint }
    end

    @adapter.send(:maintain_city_candidates_once)

    assert_operator pings.length, :>, 0
    assert_equal starts_before, @adapter.events.count { |event| event.first == :start }
    assert_equal before_workers, @adapter.instance_variable_get(:@workers)
    after_state = @adapter.send(:snapshot)
    assert_equal before_state[:active_relay], after_state[:active_relay]
    assert_equal before_state[:active_slot], after_state[:active_slot]
    assert_equal before_state[:generation], after_state[:generation]
  end

  def test_expired_success_history_is_not_reported_as_recent_ready
    old = @adapter.good_canary.merge(
      relay: 'three', transport_mode: 'ss', tested_at: (Time.now - 601).iso8601,
      source: 'fixture', relay_liveness: 'pass', service_readiness: 'ready'
    )
    @adapter.send(:record_relay_history, old)

    evidence = @adapter.send(:city_node_evidence, 'three')
    assert_equal 'expired_or_failed', evidence[:evidence]
    assert_operator evidence[:age_seconds], :>=, 600
  end

  def test_city_api_saves_favorites_and_selects_a_city_through_a_receipt
    @adapter.seed_active
    response = api_request('POST', '/cities', favorite_cities: %w[us-sjc us-nyc])
    assert_equal 200, response[:code]
    assert_equal %w[us-sjc us-nyc], response[:body]['favorite_cities']
    receipt = api_request('POST', '/cities/select', city: 'us-nyc', transport: 'auto')
    assert_equal 202, receipt[:code]
    id = receipt[:body].fetch('id')
    Timeout.timeout(2) { sleep 0.001 while @adapter.send(:action_pending?) }
    assert_equal 'succeeded', @adapter.send(:operation_snapshot, id)[:state]
    current = api_request('GET', '/cities')[:body]
    assert_equal 'us-nyc', current['selected_city']
    assert_equal 2, current['generation']
    primary = current['cities'].find { |city| city['id'] == 'us-nyc' }.dig('primary', 'relay')
    assert_equal 'us-nyc', CITIES.fetch(primary)
    refute current['auto_cross_city']
  end

  def test_failed_city_selection_preserves_original_connection_and_city
    @adapter.seed_active
    @adapter.send(:update_favorite_cities, %w[us-sjc us-nyc])
    @adapter.define_singleton_method(:run_canary) do |slot|
      @workers[slot][:relay] == 'one' ? good_canary : { ip_data: { status: 'fail' }, inner_dns: { status: 'fail' }, https_data: { status: 'skip' } }
    end
    receipt = api_request('POST', '/cities/select', city: 'us-nyc')
    assert_equal 202, receipt[:code]
    Timeout.timeout(2) { sleep 0.001 while @adapter.send(:action_pending?) }
    assert_equal 'preserved', @adapter.send(:operation_snapshot, receipt[:body]['id'])[:state]
    assert_equal 'one', @adapter.send(:snapshot)[:active_relay]
    assert_equal 'us-sjc', @adapter.send(:city_workspace_snapshot)[:selected_city]
    assert_equal 1, @adapter.send(:snapshot)[:generation]
    assert_equal ['a'], @adapter.instance_variable_get(:@workers).keys
  end

  def test_city_file_round_trip_and_browser_origin_mutation_rejection
    @adapter.seed_active
    @adapter.send(:update_favorite_cities, %w[us-sjc us-nyc us-sea])
    assert_equal 0o600, File.stat(@adapter.send(:city_workspace_path)).mode & 0o777
    restored = ReliabilityAdapter.new(@dir)
    restored.send(:load_city_workspace)
    assert_equal 'us-sjc', restored.send(:city_workspace_snapshot)[:selected_city]
    assert_equal %w[us-sjc us-nyc us-sea], restored.send(:city_workspace_snapshot)[:favorite_cities]
    socket = TestSocket.new("POST /cities HTTP/1.1\r\nOrigin: http://untrusted.invalid\r\nContent-Length: 2\r\n\r\n{}")
    @adapter.send(:handle_http, socket)
    assert_match(/HTTP\/1.1 403/, socket.response)
  end

  def test_unhealthy_current_city_node_is_rebuilt_instead_of_reporting_noop_success
    @adapter.seed_active
    @adapter.instance_variable_get(:@state).merge!(status: 'data_fail', relay_liveness: 'fail', service_readiness: 'data_fail')
    assert @adapter.send(:activate, 'one', reason: 'city-select', transport_preference: 'auto')
    assert_equal 2, @adapter.send(:snapshot)[:generation]
    assert_equal 'ready', @adapter.send(:snapshot)[:service_readiness]
    assert_equal 1, @adapter.instance_variable_get(:@workers).length
    assert_equal 0, @adapter.send(:snapshot)[:health][:consecutive_wg_failures]
  end

  def test_recent_ipv6_success_survives_newer_ss_failure_but_explicit_ss_stays_exact
    ready = @adapter.good_canary.merge(relay: 'two', transport_mode: 'ipv6', tested_at: (Time.now - 5).iso8601,
      relay_liveness: 'pass', service_readiness: 'ready')
    failed = { relay: 'two', transport_mode: 'ss', tested_at: Time.now.iso8601,
      relay_liveness: 'fail', service_readiness: 'data_fail', ip_data: { status: 'fail' }, inner_dns: { status: 'fail' } }
    @adapter.send(:record_relay_history, ready)
    @adapter.send(:record_relay_history, failed)
    relay = @adapter.send(:find_relay, 'two')
    assert_equal 'ipv6', @adapter.send(:transport_candidates, 'auto', relay).first
    assert_equal ['ss'], @adapter.send(:transport_candidates, 'ss', relay)
    assert_equal 'recent_ready', @adapter.send(:city_node_evidence, 'two')[:evidence]
    @adapter.send(:quarantine_relay, 'two', 'fixture')
    assert @adapter.send(:activate, 'two', reason: 'select', transport_preference: 'auto')
    refute @adapter.send(:relay_quarantined?, 'two')
  end

  private

  def api_request(method, path, payload = {})
    body = method == 'POST' ? JSON.generate(payload) : ''
    @adapter.send(:load_account_manager) unless @adapter.instance_variable_get(:@account_capability)
    capability = @adapter.instance_variable_get(:@account_capability)
    socket = TestSocket.new("#{method} #{path} HTTP/1.1\r\nAuthorization: Bearer #{capability}\r\nContent-Length: #{body.bytesize}\r\n\r\n#{body}")
    @adapter.send(:handle_http, socket)
    header, response = socket.response.split("\r\n\r\n", 2)
    { code: header.split[1].to_i, body: JSON.parse(response) }
  end

  def install_city_metadata
    metadata = @adapter.instance_variable_get(:@metadata)
    relays = metadata.dig('wireguard', 'relays')
    CITIES.each do |name, city|
      relay = relays.find { |candidate| candidate['hostname'] == name }
      unless relay
        relay = relays.find { |candidate| candidate['hostname'] == 'five' }.dup
        relay['hostname'] = name
        relay['public_key'] = "public-#{name}"
        relays << relay
      end
      relay['location'] = city
    end
    metadata['locations'] = CITIES.values.uniq.to_h do |city|
      country, short_city = city.split('-', 2)
      [city, { 'country' => country, 'city' => short_city }]
    end
  end

  def set_city_policy(favorites, selected)
    @adapter.instance_variable_get(:@city_mutex).synchronize do
      @adapter.instance_variable_set(:@favorite_cities, favorites.dup)
      @adapter.instance_variable_set(:@selected_city, selected)
    end
  end

  def city_policy
    @adapter.instance_variable_get(:@city_mutex).synchronize do
      [@adapter.instance_variable_get(:@favorite_cities).dup,
       @adapter.instance_variable_get(:@selected_city)]
    end
  end

  def assert_stale_health_result_is_discarded
    @adapter.seed_active
    baseline = @adapter.send(:snapshot)
    baseline_canary = baseline[:last_canary]
    baseline_health_checks = @adapter.instance_variable_get(:@metrics)[:health_checks]
    old_history = @adapter.good_canary.merge(
      relay: 'one', transport_mode: 'ss', tested_at: (Time.now - 900).iso8601,
      source: 'fixture', relay_liveness: 'pass', service_readiness: 'ready'
    )
    @adapter.send(:record_relay_history, old_history)
    history_before = Marshal.load(Marshal.dump(@adapter.instance_variable_get(:@relay_history)))
    stale_canary = {
      at: 'stale-health-result', duration_ms: 99,
      ip_data: { status: 'fail' }, inner_dns: { status: 'fail' }, https_data: { status: 'skip' }
    }
    adapter = @adapter
    adapter.define_singleton_method(:run_readiness_canary) do |_slot|
      yield
      stale_canary
    end

    adapter.send(:check_active_health_once)

    assert_equal baseline_canary, adapter.send(:snapshot)[:last_canary]
    assert_equal baseline_health_checks, adapter.instance_variable_get(:@metrics)[:health_checks]
    assert_equal history_before, adapter.instance_variable_get(:@relay_history)
    assert_empty adapter.instance_variable_get(:@speed_tests)
  end

  def event_log
    path = File.join(@dir, 'logs', 'events.jsonl')
    return [] unless File.file?(path)

    File.readlines(path).map { |line| JSON.parse(line) }
  end
end
