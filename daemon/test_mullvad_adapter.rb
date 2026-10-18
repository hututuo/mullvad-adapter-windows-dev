# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require_relative 'mullvad_adapter'

class MullvadAdapterPolicyTest < Minitest::Test
  def build_adapter
    dir = Dir.mktmpdir('mullvad-adapter-test')
    @tmpdirs ||= []
    @tmpdirs << dir
    MullvadAdapter.new(state_dir: dir, recovery_quarantine: 900)
  end

  def teardown
    Array(@tmpdirs).each { |dir| FileUtils.rm_rf(dir) }
  end

  def test_stale_recovery_is_suppressed_before_network_work
    adapter = build_adapter
    state = adapter.instance_variable_get(:@state)
    state[:generation] = 7
    state[:active_slot] = 'a'
    state[:active_relay] = 'relay-a'

    result = adapter.send(
      :activate,
      'relay-b',
      reason: 'health-recovery',
      transport_preference: 'ss',
      expected_state: { generation: 6, active_slot: 'a', active_relay: 'relay-a' }
    )

    refute result
    assert_equal 'relay-a', state[:active_relay]
    assert_equal 'stale-recovery-suppressed', state.dig(:routing_policy, :last_event)
  end

  def test_recovery_prefers_non_quarantined_same_location_with_history
    adapter = build_adapter
    adapter.instance_variable_set(:@metadata, {
      'wireguard' => {
        'shadowsocks_port_ranges' => [[20_000, 20_100]],
        'relays' => [
          relay('us-sjc-wg-001', 'us-sjc'),
          relay('us-sjc-wg-002', 'us-sjc'),
          relay('us-sjc-wg-003', 'us-sjc')
        ]
      }
    })
    history = adapter.instance_variable_get(:@relay_history)
    history['us-sjc-wg-002|ss'] = history_entry('us-sjc-wg-002', samples: 20, ready: 20, ping: 120)
    history['us-sjc-wg-003|ss'] = history_entry('us-sjc-wg-003', samples: 8, ready: 8, ping: 90)

    assert_equal 'us-sjc-wg-002', adapter.send(:select_recovery_relay, 'us-sjc-wg-001')

    adapter.send(:quarantine_relay, 'us-sjc-wg-002', 'test')
    assert_equal 'us-sjc-wg-003', adapter.send(:select_recovery_relay, 'us-sjc-wg-001')
  end

  def test_repeat_switch_preempts_only_draining_standby
    adapter = build_adapter
    workers = adapter.instance_variable_get(:@workers)
    state = adapter.instance_variable_get(:@state)
    workers['b'] = { relay: 'old-relay', instance_token: 'token', pid: 99_999 }
    state[:workers]['b'] = { relay: 'old-relay', state: 'draining', front_connection_count: 7 }

    adapter.define_singleton_method(:front_connections_for) { |_slot| 7 }
    adapter.define_singleton_method(:stop_worker) do |slot, expected_token: nil|
      @mutex.synchronize do
        @workers.delete(slot)
        @state[:workers][slot][:state] = 'stopped'
        @state[:workers][slot][:front_connection_count] = 0
      end
      true
    end

    assert adapter.send(:ensure_switch_slot_available, 'b', 'select')
    assert_equal 1, adapter.instance_variable_get(:@metrics)[:drain_preemptions]
    assert_equal 1, adapter.instance_variable_get(:@metrics)[:drain_forced]
    assert_equal 7, state.dig(:routing_policy, :last_preempted_connections)
  end

  def test_free_slot_is_reused_before_preempting_existing_drain
    adapter = build_adapter
    workers = adapter.instance_variable_get(:@workers)
    state = adapter.instance_variable_get(:@state)
    workers['a'] = { relay: 'older-relay', instance_token: 'older', pid: 99_998 }
    state[:workers]['a'] = { relay: 'older-relay', state: 'draining', front_connection_count: 5 }

    assert_equal 'b', adapter.send(:preferred_switch_slot, nil)
    assert_equal 'b', adapter.send(:preferred_same_relay_restart_slot, 'b')
  end

  def test_controller_failure_does_not_mark_live_socks_data_as_relay_failure
    adapter = build_adapter
    adapter.instance_variable_get(:@workers)['a'] = { endpoint: '10.0.0.2' }
    adapter.define_singleton_method(:outer_ping_test) { |_endpoint, _timeout| { status: 'pass', delay_ms: 10 } }
    adapter.define_singleton_method(:delay_test) { |_controller, _proxy, _url, _timeout| { status: 'fail', detail: 'controller unavailable' } }
    adapter.define_singleton_method(:curl_proxy_ip_test) { |_port, _url, _timeout| { status: 'pass', http_code: 200 } }
    adapter.define_singleton_method(:inner_dns_tcp_test) { |_port, _qname, _timeout| { status: 'pass', delay_ms: 10 } }
    adapter.define_singleton_method(:curl_proxy_test) { |_port, _url, _timeout| { status: 'pass', http_code: 204 } }

    canary = adapter.send(:run_canary, 'a')
    classification = adapter.send(:classify_canary, canary)

    assert_equal 'fail', canary.dig(:controller_probe, :status)
    assert_equal 'pass', classification[:relay_liveness]
    assert_equal 'ready', classification[:service_readiness]
  end

  def test_client_disconnect_during_response_is_ignored
    adapter = build_adapter
    socket = Object.new
    socket.define_singleton_method(:write) { |_payload| raise Errno::EPIPE }

    assert_equal false, adapter.send(:respond, socket, 200, { ok: true })
  end

  def test_metadata_validation_filters_bad_relay_and_keeps_valid_snapshot
    adapter = build_adapter
    valid = relay('valid-relay', 'us-sjc').merge('shadowsocks_extra_addr_in' => ['2001:db8::2'])
    invalid = relay('bad-relay', 'us-sjc').merge('ipv4_addr_in' => 'not-an-ip')
    payload = {
      'wireguard' => {
        'port_ranges' => [[1, 65_535]],
        'shadowsocks_port_ranges' => [[20_000, 20_100]],
        'relays' => [valid, invalid]
      }
    }

    result = adapter.send(:validate_metadata_payload, payload)

    assert_equal ['valid-relay'], result.dig('wireguard', 'relays').map { |item| item['hostname'] }
    assert_equal 1, adapter.instance_variable_get(:@last_metadata_validation_warnings).length
  end

  def test_quick_ping_targets_are_derived_from_validated_relay_metadata
    adapter = build_adapter
    targets = adapter.send(:quick_ping_targets, relay('relay-a', 'us-sjc'))

    assert_equal '10.0.0.2', targets.dig('ss', :target)
    assert_equal 'shadowsocks-extra-ipv4', targets.dig('ss', :kind)
    assert_equal '10.0.0.1', targets.dig('ipv4', :target)
  end

  def test_persistence_failure_is_observable_but_nonfatal
    adapter = build_adapter
    blocking = File.join(adapter.instance_variable_get(:@state_dir), 'blocking')
    FileUtils.mkdir_p(blocking)
    adapter.define_singleton_method(:persisted_relay_path) { blocking }

    refute adapter.send(:persist_relay, 'relay-a')
    assert_equal 1, adapter.instance_variable_get(:@metrics)[:persistence_failures]
    assert_equal 'degraded', adapter.instance_variable_get(:@state).dig(:persistence, :status)
  end

  def test_startup_falls_back_when_persisted_relay_is_retired
    adapter = build_adapter
    adapter.instance_variable_set(:@selected_city, 'us-sjc')
    adapter.instance_variable_set(:@metadata, {
      'wireguard' => {
        'shadowsocks_port_ranges' => [[20_000, 20_100]],
        'relays' => [
          relay('us-sjc-wg-002', 'us-sjc'),
          relay('us-lax-wg-001', 'us-lax')
        ]
      }
    })
    chosen = []
    adapter.define_singleton_method(:activate) do |relay_name, reason:, transport_preference:, expected_state: nil|
      chosen << relay_name
      true
    end

    assert adapter.send(:activate_startup_with_fallback, 'us-sjc-wg-999', 'ss', reason: 'startup')
    assert_equal ['us-sjc-wg-002'], chosen
  end

  def test_front_controller_failure_keeps_front_when_data_path_is_alive
    adapter = build_adapter
    adapter.instance_variable_set(:@front_pid, 111)
    adapter.instance_variable_set(:@front_probe_failures, 2)
    state = adapter.instance_variable_get(:@state)
    state[:active_slot] = 'a'
    adapter.instance_variable_get(:@workers)['a'] = { pid: 222, relay: 'relay-a' }
    stopped = []
    adapter.define_singleton_method(:process_alive?) { |_pid| true }
    adapter.define_singleton_method(:http_json) do |_port, path, **_kwargs|
      case path
      when '/version'
        raise 'controller timeout'
      when '/proxies/ACTIVE'
        { 'now' => 'worker-a' }
      end
    end
    adapter.define_singleton_method(:curl_proxy_ip_test) do |_port, _url, _timeout|
      { status: 'pass', detail: 'data alive' }
    end
    adapter.define_singleton_method(:stop_pid) { |pid| stopped << pid }

    adapter.send(:supervise_front_runtime)

    assert_empty stopped
    assert_equal true, state.dig(:front, :controller_degraded)
    assert_equal 'front-controller-degraded-kept', state.dig(:routing_policy, :last_event)
  end

  def test_front_only_data_failure_restarts_front_not_worker
    adapter = build_adapter
    adapter.instance_variable_get(:@options)[:front_data_probe_interval] = 0
    adapter.instance_variable_set(:@front_pid, 111)
    restarts = []
    adapter.define_singleton_method(:curl_proxy_ip_test) do |port, _url, _timeout|
      port == 17_890 ? { status: 'fail', detail: 'front broken' } : { status: 'pass', detail: 'worker ok' }
    end
    adapter.define_singleton_method(:stop_pid) { |pid| restarts << [:stop, pid] }
    adapter.define_singleton_method(:ensure_front) { @front_pid = 222 }
    adapter.define_singleton_method(:select_front) { |slot| restarts << [:select, slot]; true }

    worker = { relay: 'relay-a', mixed_port: 17_910, pid: 333, instance_token: 'active-worker' }
    adapter.instance_variable_get(:@workers)['a'] = worker
    adapter.instance_variable_get(:@state).merge!(active_slot: 'a', active_relay: 'relay-a', status: 'ready')
    adapter.send(:supervise_front_data_path, 'a', worker)
    assert_empty restarts

    adapter.send(:supervise_front_data_path, 'a', worker)
    assert_includes restarts, [:stop, 111]
    assert_includes restarts, [:select, 'a']
    assert_equal 'front-data-path-restarted', adapter.instance_variable_get(:@state).dig(:routing_policy, :last_event)
  end

  def test_relay_without_extra_ss_gets_multiple_port_candidates_across_ranges
    adapter = build_adapter
    adapter.instance_variable_set(:@metadata, {
      'wireguard' => {
        'shadowsocks_port_ranges' => [[10_000, 10_000], [20_000, 20_000], [30_000, 30_000]]
      }
    })
    relay = {
      'hostname' => 'relay-no-extra',
      'ipv4_addr_in' => '10.10.10.10',
      'shadowsocks_extra_addr_in' => []
    }

    candidates = adapter.send(:ss_endpoint_candidates, relay)
    assert_equal 3, candidates.length
    assert_equal [10_000, 20_000, 30_000], candidates.map { |candidate| candidate[1] }.sort
  end

  def test_common_inner_dns_breaker_requires_two_distinct_relays
    adapter = build_adapter
    canary = {
      ip_data: { status: 'pass' },
      inner_dns: { status: 'fail' },
      https_data: { status: 'fail' }
    }

    adapter.send(:observe_inner_dns_result, 'relay-a', canary)
    adapter.send(:observe_inner_dns_result, 'relay-a', canary)
    assert_equal 'closed', adapter.instance_variable_get(:@state).dig(:dns, :inner_breaker, :status)

    adapter.send(:observe_inner_dns_result, 'relay-b', canary)
    assert_equal 'open', adapter.instance_variable_get(:@state).dig(:dns, :inner_breaker, :status)
  end

  def test_successful_https_keeps_relay_live_when_literal_ip_canary_fails
    adapter = build_adapter
    canary = {
      ip_data: { status: 'fail' },
      inner_dns: { status: 'pass' },
      https_data: { status: 'pass' }
    }

    classification = adapter.send(:classify_canary, canary)
    assert_equal 'pass', classification[:relay_liveness]
    assert_equal 'ready', classification[:service_readiness]
  end

  def test_manual_repeat_switch_defers_if_drain_connection_count_is_unknown
    adapter = build_adapter
    workers = adapter.instance_variable_get(:@workers)
    state = adapter.instance_variable_get(:@state)
    workers['b'] = { relay: 'old-relay', instance_token: 'token', pid: 99_999 }
    state[:workers]['b'] = { relay: 'old-relay', state: 'draining', front_connection_count: 7 }
    adapter.define_singleton_method(:front_connections_for) { |_slot| nil }

    refute adapter.send(:ensure_switch_slot_available, 'b', 'select')
    assert workers['b']
    assert_equal 'drain-preemption-deferred', state.dig(:routing_policy, :last_event)
    assert_equal 0, adapter.instance_variable_get(:@metrics)[:drain_preemptions]
  end

  def test_wait_controller_is_bound_to_spawned_pid_lifetime
    adapter = build_adapter
    alive_calls = 0
    adapter.define_singleton_method(:process_alive?) do |_pid|
      alive_calls += 1
      alive_calls < 3
    end
    adapter.define_singleton_method(:http_json) do |_port, _path, **_kwargs|
      { 'version' => 'stale-controller' }
    end

    refute adapter.send(:wait_controller, 17_911, 1, pid: 123_456)
  end

  def test_switch_uses_stale_validated_metadata_without_live_refresh
    adapter = build_adapter
    adapter.instance_variable_set(:@metadata, {
      'wireguard' => {
        'shadowsocks_port_ranges' => [[20_000, 20_100]],
        'relays' => [relay('us-sjc-wg-001', 'us-sjc')]
      }
    })
    state = adapter.instance_variable_get(:@state)
    state[:active_slot] = 'a'
    state[:active_relay] = 'us-sjc-wg-001'
    state[:active_transport_mode] = 'ss'
    state[:transport_preference] = 'ss'
    state[:relay_liveness] = 'pass'
    state[:service_readiness] = 'ready'
    adapter.instance_variable_get(:@workers)['a'] = { transport_mode: 'ss' }
    adapter.define_singleton_method(:refresh_metadata) { raise 'live bootstrap must not run during switch' }

    assert adapter.send(:activate, 'us-sjc-wg-001', reason: 'select', transport_preference: 'ss')
  end

  def test_transient_selector_error_does_not_restart_front_if_readback_already_matches
    adapter = build_adapter
    adapter.instance_variable_set(:@front_pid, 111)
    puts_seen = 0
    stopped = []
    adapter.define_singleton_method(:http_json) do |_port, _path, method: :get, **_kwargs|
      if method == :put
        puts_seen += 1
        raise 'transient selector timeout' if puts_seen == 1
        {}
      else
        { 'now' => 'worker-a' }
      end
    end
    adapter.define_singleton_method(:stop_pid) { |pid| stopped << pid }
    adapter.define_singleton_method(:ensure_front) { raise 'front must not restart' }

    assert adapter.send(:select_front, 'a')
    assert_empty stopped
  end

  def test_shutdown_flag_blocks_new_worker_spawn_before_side_effects
    adapter = build_adapter
    adapter.instance_variable_set(:@stop_requested, true)
    error = assert_raises(RuntimeError) do
      adapter.send(:start_worker, 'a', relay('relay-a', 'us-sjc'), transport_mode: 'ss')
    end
    assert_equal 'shutdown requested', error.message
    assert_empty adapter.instance_variable_get(:@workers)
  end

  # 回归：2026-09-19 晚上 us-lax-wg-001 的入口试序是
  # .11 -> .6 -> .7 -> .8 -> .9 -> .5 -> .10，
  # 四个从未成功过的入口被排在成功率 90% 的 .5 前面，每个白等约 29 秒。
  def test_never_succeeded_ss_endpoint_ranks_behind_proven_one
    adapter = build_adapter
    candidate_relay = {
      'hostname' => 'us-lax-wg-001',
      'ipv4_addr_in' => '10.0.0.1',
      'shadowsocks_extra_addr_in' => %w[23.234.72.6 23.234.72.7 23.234.72.5 23.234.72.11]
    }
    adapter.instance_variable_get(:@ss_endpoint_history)['us-lax-wg-001'] = {
      last_good: nil,
      endpoints: {
        '23.234.72.5' => { successes: 18, failures: 2, consecutive_failures: 2 },
        '23.234.72.6' => { successes: 0, failures: 1, consecutive_failures: 1 },
        '23.234.72.7' => { successes: 0, failures: 1, consecutive_failures: 1 }
      }
    }

    order = adapter.send(:ss_endpoint_candidates, candidate_relay).map { |candidate| candidate[0] }

    assert_equal %w[23.234.72.6 23.234.72.7], order.last(2).sort,
                 'never-succeeded inlets must be tried last'
    assert_operator order.index('23.234.72.11'), :<, order.index('23.234.72.5'),
                    'an untried inlet outranks a proven one that is currently failing'
  end

  def test_last_good_ss_endpoint_still_ranks_first
    adapter = build_adapter
    candidate_relay = {
      'hostname' => 'us-lax-wg-001',
      'ipv4_addr_in' => '10.0.0.1',
      'shadowsocks_extra_addr_in' => %w[23.234.72.5 23.234.72.11]
    }
    adapter.instance_variable_get(:@ss_endpoint_history)['us-lax-wg-001'] = {
      last_good: '23.234.72.11',
      endpoints: {
        '23.234.72.5' => { successes: 18, failures: 0, consecutive_failures: 0 },
        '23.234.72.11' => { successes: 2, failures: 1, consecutive_failures: 1 }
      }
    }

    order = adapter.send(:ss_endpoint_candidates, candidate_relay).map { |candidate| candidate[0] }
    assert_equal '23.234.72.11', order.first
  end

  # 死隧道原本要白等 29 秒（controller 8 + ip 8 + dns 8 + https 12，
  # 实测 us-dal-wg-001 一次 27469 ms）。内层 DNS 一挂，
  # domain_ok 必然为 false，https 和 controller 都不可能改变结论。
  def test_canary_skips_domain_and_controller_probe_when_data_path_is_down
    adapter = build_adapter
    adapter.instance_variable_get(:@workers)['a'] = { endpoint: '10.0.0.2' }
    calls = []
    adapter.define_singleton_method(:outer_ping_test) { |_endpoint, _timeout| { status: 'fail', detail: 'no icmp' } }
    adapter.define_singleton_method(:curl_proxy_ip_test) do |_port, _url, _timeout|
      calls << :ip
      { status: 'fail', http_code: 0, detail: 'ssl error' }
    end
    adapter.define_singleton_method(:inner_dns_tcp_test) do |_port, _qname, _timeout|
      calls << :dns
      { status: 'fail', detail: 'eof' }
    end
    adapter.define_singleton_method(:curl_proxy_test) do |_port, _url, _timeout|
      calls << :https
      { status: 'fail', http_code: 0 }
    end
    adapter.define_singleton_method(:delay_test) do |_controller, _proxy, _url, _timeout|
      calls << :controller
      { status: 'fail' }
    end

    canary = adapter.send(:run_canary, 'a')
    classification = adapter.send(:classify_canary, canary)

    refute_includes calls, :https, 'domain check must be skipped once inner DNS failed'
    refute_includes calls, :controller, 'controller probe must be skipped once the data path is down'
    assert_equal 'skip', canary.dig(:https_data, :status)
    assert_equal 'skip', canary.dig(:controller_probe, :status)
    assert_equal 'fail', classification[:relay_liveness]
    assert_equal 'data_fail', classification[:service_readiness]
  end

  # 跳过 https 必须和"跑了然后失败"得出完全一样的结论，否则就是引入回归。
  def test_skipped_domain_check_classifies_same_as_failed_one
    adapter = build_adapter
    [%w[pass fail], %w[fail fail]].each do |ip_status, dns_status|
      expected = ip_status == 'pass' ? 'degraded_dns' : 'data_fail'
      %w[skip fail].each do |https_status|
        canary = {
          ip_data: { status: ip_status },
          inner_dns: { status: dns_status },
          https_data: { status: https_status }
        }
        classification = adapter.send(:classify_canary, canary)
        assert_equal expected, classification[:service_readiness],
                     "ip=#{ip_status} dns=#{dns_status} https=#{https_status}"
      end
    end
  end

  def test_canary_still_runs_every_probe_when_data_path_is_alive
    adapter = build_adapter
    adapter.instance_variable_get(:@workers)['a'] = { endpoint: '10.0.0.2' }
    calls = []
    adapter.define_singleton_method(:outer_ping_test) { |_endpoint, _timeout| { status: 'pass', delay_ms: 160 } }
    adapter.define_singleton_method(:curl_proxy_ip_test) do |_port, _url, _timeout|
      calls << :ip
      { status: 'pass', http_code: 200 }
    end
    adapter.define_singleton_method(:inner_dns_tcp_test) do |_port, _qname, _timeout|
      calls << :dns
      { status: 'pass', delay_ms: 330 }
    end
    adapter.define_singleton_method(:curl_proxy_test) do |_port, _url, _timeout|
      calls << :https
      { status: 'pass', http_code: 204 }
    end
    adapter.define_singleton_method(:delay_test) do |_controller, _proxy, _url, _timeout|
      calls << :controller
      { status: 'pass', delay_ms: 1_190 }
    end

    canary = adapter.send(:run_canary, 'a')

    # 探针现在并发跑，ip/dns 的先后顺序本身没有意义，只断言"四个都跑了"。
    assert_equal %i[controller dns https ip], calls.sort,
                 'every probe must still run when the data path is alive'
    assert_equal 'ready', adapter.send(:classify_canary, canary)[:service_readiness]
  end

  # Barriers prove overlap without depending on hosted-runner scheduling speed.
  def test_canary_overlaps_only_the_probes_that_do_not_depend_on_each_other
    adapter = build_adapter
    adapter.instance_variable_get(:@workers)['a'] = { endpoint: '10.0.0.2' }
    spans = {}
    gates = { ip: Queue.new, dns: Queue.new, https: Queue.new, controller: Queue.new }
    peers = { ip: :dns, dns: :ip, https: :controller, controller: :https }
    span = lambda do |name, result|
      lambda do |*_args|
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        if peers[name]
          gates[name] << true
          Timeout.timeout(5) { gates[peers[name]].pop }
        end
        spans[name] = [started, Process.clock_gettime(Process::CLOCK_MONOTONIC)]
        result
      end
    end
    adapter.define_singleton_method(:outer_ping_test, &span.call(:ping, { status: 'pass', delay_ms: 50 }))
    adapter.define_singleton_method(:curl_proxy_ip_test, &span.call(:ip, { status: 'pass', http_code: 200 }))
    adapter.define_singleton_method(:inner_dns_tcp_test, &span.call(:dns, { status: 'pass', delay_ms: 10 }))
    adapter.define_singleton_method(:curl_proxy_test, &span.call(:https, { status: 'pass', http_code: 204 }))
    adapter.define_singleton_method(:delay_test, &span.call(:controller, { status: 'pass', delay_ms: 300 }))

    canary = adapter.send(:run_canary, 'a')

    assert_equal 5, spans.size, 'all five probes must complete their bounded barriers'
    assert_operator spans[:ip][0], :<, spans[:dns][1], 'ip and dns must overlap'
    assert_operator spans[:dns][0], :<, spans[:ip][1], 'ip and dns must overlap'
    assert_operator spans[:controller][0], :<, spans[:https][1],
                    'controller probe must overlap the domain check'
    assert_operator spans[:https][0], :<, spans[:controller][1],
                    'domain check must overlap the controller probe'
    assert_operator spans[:dns][1], :<=, spans[:https][0], 'https must wait for DNS'
    assert_operator spans[:ip][1], :<=, spans[:controller][0], 'controller must wait for data'
    assert_equal 'ready', adapter.send(:classify_canary, canary)[:service_readiness]
  end

  # 一个探针自己炸了，只能算"这一项没过"，不能把整轮金丝雀掀翻 ——
  # 并发跑的时候那样会连累另外两个还没读完的结果。
  def test_canary_probe_crash_is_reported_as_a_failed_probe
    adapter = build_adapter
    adapter.instance_variable_get(:@workers)['a'] = { endpoint: '10.0.0.2' }
    adapter.define_singleton_method(:outer_ping_test) { |_endpoint, _timeout| raise 'icmp tool missing' }
    adapter.define_singleton_method(:curl_proxy_ip_test) { |_p, _u, _t| { status: 'pass', http_code: 200 } }
    adapter.define_singleton_method(:inner_dns_tcp_test) { |_p, _q, _t| { status: 'pass', delay_ms: 5 } }
    adapter.define_singleton_method(:curl_proxy_test) { |_p, _u, _t| { status: 'pass', http_code: 204 } }
    adapter.define_singleton_method(:delay_test) { |_c, _pr, _u, _t| { status: 'pass', delay_ms: 10 } }

    canary = adapter.send(:run_canary, 'a')

    assert_equal 'fail', canary.dig(:ping_data, :status)
    assert_match(/icmp tool missing/, canary.dig(:ping_data, :detail).to_s)
    assert_equal 'ready', adapter.send(:classify_canary, canary)[:service_readiness],
                 'a broken probe must not sink the whole canary'
  end

  # 用户按"测速其他节点"时，对侧槽位常常还在收尾上一条隧道。
  # 以前这里直接回 409，用户当场被拒，而槽位还要再等十几分钟。
  def test_speed_test_frees_the_draining_standby_slot_instead_of_refusing
    adapter = build_adapter
    workers = adapter.instance_variable_get(:@workers)
    state = adapter.instance_variable_get(:@state)
    state[:active_slot] = 'b'
    state[:active_relay] = 'active-relay'
    workers['a'] = { relay: 'old-relay', instance_token: 'token', pid: 99_993 }
    state[:workers]['a'] = {
      relay: 'old-relay', state: 'draining', front_connection_count: 8, drain_remaining_seconds: 795
    }

    adapter.define_singleton_method(:refresh_metadata) { nil }
    adapter.define_singleton_method(:front_connections_for) { |_slot| 8 }
    adapter.define_singleton_method(:stop_worker) do |slot, expected_token: nil|
      @mutex.synchronize do
        @workers.delete(slot)
        @state[:workers][slot][:state] = 'stopped'
        @state[:workers][slot][:front_connection_count] = 0
      end
      true
    end
    adapter.define_singleton_method(:find_relay) do |_name|
      { 'hostname' => 'new-relay', 'public_key' => 'pk', 'active' => true }
    end
    adapter.define_singleton_method(:transport_candidates) { |_pref, _relay| ['ss'] }
    adapter.define_singleton_method(:endpoint_candidates_for_transport) do |_relay, _mode|
      [['203.0.113.1', 20_484, 'extra-ss-ipv4']]
    end
    adapter.define_singleton_method(:start_worker) do |slot, relay, transport_mode: 'ss', ss_candidate: nil|
      @mutex.synchronize { @workers[slot] = { relay: relay['hostname'], instance_token: "t-#{slot}", pid: 99_992 } }
      { relay: relay['hostname'], endpoint: '203.0.113.1', endpoint_port: 20_484, transport_mode: transport_mode }
    end
    # 注意：define_singleton_method 的块里 self 是 adapter，不能直接调测试类的辅助方法，
    # 所以先抓成局部变量再闭包进去。
    healthy_canary = ready_canary
    adapter.define_singleton_method(:run_canary) { |_slot| healthy_canary }
    adapter.define_singleton_method(:cache_speed_test) do |relay_name, canary, source, mode|
      {
        relay: relay_name, transport_mode: mode, source: source, duration_ms: canary[:duration_ms],
        relay_liveness: 'pass', service_readiness: 'ready'
      }
    end
    adapter.define_singleton_method(:record_ss_endpoint_canary) { |*_args| nil }

    code, body = adapter.send(:speed_test_relay, 'new-relay')

    assert_equal 200, code, "speed test must not be refused while a drain is counting down: #{body.inspect}"
    assert body[:ok]
    assert_equal 1, adapter.instance_variable_get(:@metrics)[:drain_preemptions]
    assert_equal 'speedtest-slot-freed', state.dig(:routing_policy, :last_event)
    assert_equal 8, state.dig(:routing_policy, :last_preempted_connections)
  end

  # 宽松档只放宽"对侧槽位"，绝不能碰正在承载流量的那个。
  def test_speed_test_preemption_never_touches_the_active_slot
    adapter = build_adapter
    workers = adapter.instance_variable_get(:@workers)
    state = adapter.instance_variable_get(:@state)
    state[:active_slot] = 'a'
    workers['a'] = { relay: 'live-relay', instance_token: 'token', pid: 99_991 }
    state[:workers]['a'] = { relay: 'live-relay', state: 'active', front_connection_count: 25 }

    refute adapter.send(:ensure_switch_slot_available, 'a', 'speed-test', any_non_active: true)
    assert workers.key?('a'), 'the worker carrying traffic must survive a speed-test preemption'
    assert_equal 0, adapter.instance_variable_get(:@metrics)[:drain_preemptions]
  end

  # 切换走保守档：只抢 draining，遇到半成品状态仍然拒绝，行为与以前一致。
  def test_switch_path_still_refuses_a_standby_slot_that_is_not_draining
    adapter = build_adapter
    workers = adapter.instance_variable_get(:@workers)
    state = adapter.instance_variable_get(:@state)
    state[:active_slot] = 'a'
    workers['b'] = { relay: 'standby-relay', instance_token: 'token', pid: 99_990 }
    state[:workers]['b'] = { relay: 'standby-relay', state: 'candidate', front_connection_count: 0 }

    refute adapter.send(:ensure_switch_slot_available, 'b', 'select')
    assert workers.key?('b'), 'conservative switch path must not preempt a non-draining worker'
  end

  # 同一状态在测速下应当被放开 —— 用户点了就要拿到结果，不能被半成品状态挡住。
  def test_speed_test_frees_a_leftover_standby_worker_too
    adapter = build_adapter
    workers = adapter.instance_variable_get(:@workers)
    state = adapter.instance_variable_get(:@state)
    state[:active_slot] = 'a'
    workers['b'] = { relay: 'standby-relay', instance_token: 'token', pid: 99_989 }
    state[:workers]['b'] = { relay: 'standby-relay', state: 'candidate', front_connection_count: 0 }

    adapter.define_singleton_method(:front_connections_for) { |_slot| 0 }
    adapter.define_singleton_method(:stop_worker) do |slot, expected_token: nil|
      @mutex.synchronize do
        @workers.delete(slot)
        @state[:workers][slot][:state] = 'stopped'
        @state[:workers][slot][:front_connection_count] = 0
      end
      true
    end

    assert adapter.send(:ensure_switch_slot_available, 'b', 'speed-test', any_non_active: true)
    assert_equal 'speedtest-slot-freed', state.dig(:routing_policy, :last_event)
    assert_equal 0, state.dig(:routing_policy, :last_preempted_connections)
    assert_equal 0, adapter.instance_variable_get(:@metrics)[:drain_forced],
                 'freeing a slot with no live connections is not a forced preemption'
  end

  # 前端控制面读不到连接数时，切换会暂缓（怕打断看不见的连接），
  # 但测速不能也这样 —— 那样前端一挂，按钮就永久卡死了。用户点了就得给结果。
  def test_speed_test_preempts_even_when_the_connection_count_is_unknown
    adapter = build_adapter
    workers = adapter.instance_variable_get(:@workers)
    state = adapter.instance_variable_get(:@state)
    state[:active_slot] = 'a'
    workers['b'] = { relay: 'standby-relay', instance_token: 'token', pid: 99_988 }
    state[:workers]['b'] = { relay: 'standby-relay', state: 'draining', front_connection_count: 3 }

    adapter.define_singleton_method(:front_connections_for) { |_slot| nil }
    adapter.define_singleton_method(:stop_worker) do |slot, expected_token: nil|
      @mutex.synchronize do
        @workers.delete(slot)
        @state[:workers][slot][:state] = 'stopped'
        @state[:workers][slot][:front_connection_count] = 0
      end
      true
    end

    assert adapter.send(:ensure_switch_slot_available, 'b', 'speed-test', any_non_active: true)
    assert_equal 'speedtest-slot-freed', state.dig(:routing_policy, :last_event)

    # 对照：同一种"读不到连接数"的情形，切换路径仍然保守地暂缓。
    workers['b'] = { relay: 'standby-relay', instance_token: 'token2', pid: 99_987 }
    state[:workers]['b'] = { relay: 'standby-relay', state: 'draining', front_connection_count: 3 }
    refute adapter.send(:ensure_switch_slot_available, 'b', 'select')
    assert_equal 'drain-preemption-deferred', state.dig(:routing_policy, :last_event)
  end

  def test_health_wait_shortens_after_first_failure
    adapter = build_adapter

    assert_equal 30, adapter.send(:health_wait_seconds), 'steady state keeps the full interval'

    adapter.instance_variable_set(:@health_fail_streak, 1)
    assert_equal 2, adapter.send(:health_wait_seconds), 'one failure should trigger a fast recheck'

    adapter.instance_variable_set(:@health_fail_streak, 2)
    assert_equal 30, adapter.send(:health_wait_seconds),
                 'once the threshold is met, recovery is already running; do not poll faster'

    adapter.instance_variable_set(:@health_fail_streak, 0)
    adapter.instance_variable_set(:@dns_fail_streak, 1)
    assert_equal 2, adapter.send(:health_wait_seconds), 'DNS failures get the same fast recheck'
  end

  private

  def ready_canary
    {
      at: Time.now.iso8601,
      duration_ms: 900,
      ping_data: { status: 'pass', delay_ms: 12 },
      controller_probe: { status: 'pass', delay_ms: 15 },
      ip_data: { status: 'pass', http_code: 200 },
      inner_dns: { status: 'pass', delay_ms: 5 },
      https_data: { status: 'pass', http_code: 204 }
    }
  end

  def relay(hostname, location)
    {
      'hostname' => hostname,
      'location' => location,
      'active' => true,
      'public_key' => 'test-public-key',
      'ipv4_addr_in' => '10.0.0.1',
      'shadowsocks_extra_addr_in' => ['10.0.0.2']
    }
  end

  def history_entry(relay_name, samples:, ready:, ping:)
    {
      relay: relay_name,
      transport_mode: 'ss',
      samples: samples,
      ready_samples: ready,
      consecutive_failures: 0,
      latency_ewma_ms: ping
    }
  end
end
