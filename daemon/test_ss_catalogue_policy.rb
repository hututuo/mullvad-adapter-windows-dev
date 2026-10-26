# frozen_string_literal: true

require_relative 'minitest_dependencies'
require 'tmpdir'
require_relative 'mullvad_adapter'

class SsCataloguePolicyTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('ss-catalogue-policy')
    @adapter = MullvadAdapter.new({ state_dir: @dir })
    @relay = {
      'hostname' => 'relay-one',
      'active' => true,
      'location' => 'us-sjc',
      'public_key' => 'public-relay-one',
      'ipv4_addr_in' => '192.0.2.1',
      'ipv6_addr_in' => '2001:db8::1',
      # Include a duplicate and the primary address to exercise tuple dedupe.
      'shadowsocks_extra_addr_in' => %w[192.0.2.2 192.0.2.3 192.0.2.2 192.0.2.1]
    }
    @metadata = {
      'wireguard' => {
        'port_ranges' => [[33_431, 51_820]],
        # Overlap at 20486 is deliberate; the catalogue must still be unique.
        'shadowsocks_port_ranges' => [[20_484, 20_486], [20_486, 20_490]],
        'relays' => [@relay]
      }
    }
    @adapter.instance_variable_set(:@metadata, @metadata)
  end

  def teardown
    @adapter&.instance_variable_get(:@probe_event_writer)&.join(2)
    FileUtils.rm_rf(@dir) if @dir
  end

  def test_catalogue_combines_dedicated_addresses_and_primary_address_ports_once
    candidates = @adapter.send(:ss_catalogue_candidates, @relay)
    keys = candidates.map { |ip, port, _kind| [ip, port] }

    assert_equal keys.uniq, keys
    assert_equal 9, candidates.length
    assert_includes keys, ['192.0.2.2', MullvadAdapter::EXTRA_SS_PORT]
    assert_includes keys, ['192.0.2.3', MullvadAdapter::EXTRA_SS_PORT]
    assert_includes keys, ['192.0.2.1', MullvadAdapter::EXTRA_SS_PORT]
    (20_484..20_490).each { |port| assert_includes keys, ['192.0.2.1', port] }

    # When both official forms describe the same tuple, retain one candidate.
    primary_extra = candidates.find { |ip, port, _kind| ip == '192.0.2.1' && port == MullvadAdapter::EXTRA_SS_PORT }
    assert_equal 'extra-ss-ipv4', primary_extra.last
  end

  def test_endpoint_selector_defaults_to_six_and_recovery_can_read_full_pool
    assert_equal 6, @adapter.send(:ss_endpoint_candidates, @relay).length
    full_pool = @adapter.send(:ss_endpoint_candidates, @relay, include_cooling: true)
    assert_equal 9, full_pool.length
    assert_equal full_pool.map { |ip, port, _kind| [ip, port] }.uniq,
                 full_pool.map { |ip, port, _kind| [ip, port] }
  end

  def test_authorization_accepts_both_catalogue_paths_and_rejects_near_misses
    assert @adapter.send(:ss_candidate_authorized?, @relay, ['192.0.2.2', MullvadAdapter::EXTRA_SS_PORT])
    assert @adapter.send(:ss_candidate_authorized?, @relay, ['192.0.2.1', 20_487])
    assert @adapter.send(:ss_candidate_authorized?, @relay, ['192.0.2.1', MullvadAdapter::EXTRA_SS_PORT])

    refute @adapter.send(:ss_candidate_authorized?, @relay, ['192.0.2.2', 20_485])
    refute @adapter.send(:ss_candidate_authorized?, @relay, ['192.0.2.9', 20_485])
    refute @adapter.send(:ss_candidate_authorized?, @relay, ['192.0.2.1', 20_483])
    refute @adapter.send(:ss_candidate_authorized?, @relay, ['2001:db8::1', 20_485])
  end

  def test_fallback_rotation_returns_three_unseen_candidates_after_first_three_attempts
    pool = @adapter.send(:ss_endpoint_candidates, @relay, include_cooling: true)
    original = pool.first
    excluded_key = @adapter.send(:recovery_inlet_key, original)

    first_window = @adapter.send(:rotating_ss_recovery_inlets, 'relay-one', pool, excluding: [excluded_key]).first(3)
    assert_equal 3, first_window.length
    refute_includes first_window.map { |item| @adapter.send(:recovery_inlet_key, item) }, excluded_key
    first_window.each { |inlet| @adapter.send(:record_ss_recovery_attempt, 'relay-one', inlet) }

    second_window = @adapter.send(:rotating_ss_recovery_inlets, 'relay-one', pool, excluding: [excluded_key]).first(3)
    assert_equal 3, second_window.length
    first_keys = first_window.map { |item| @adapter.send(:recovery_inlet_key, item) }
    second_keys = second_window.map { |item| @adapter.send(:recovery_inlet_key, item) }
    assert_empty first_keys & second_keys
    refute_includes second_keys, excluded_key
  end

  def test_planning_does_not_consume_unstarted_candidates
    pool = @adapter.send(:ss_endpoint_candidates, @relay, include_cooling: true)

    planned = @adapter.send(:rotating_ss_recovery_inlets, 'relay-one', pool).first(3)
    repeated_plan = @adapter.send(:rotating_ss_recovery_inlets, 'relay-one', pool).first(3)
    assert_equal planned, repeated_plan

    @adapter.send(:record_ss_recovery_attempt, 'relay-one', planned.first)
    next_plan = @adapter.send(:rotating_ss_recovery_inlets, 'relay-one', pool).first(3)
    refute_includes next_plan.map { |item| @adapter.send(:recovery_inlet_key, item) },
                    @adapter.send(:recovery_inlet_key, planned.first)
    assert_equal planned.drop(1), next_plan.first(2)
  end

  def test_metadata_candidate_change_resets_the_rotation_window
    pool = @adapter.send(:ss_endpoint_candidates, @relay, include_cooling: true)
    seen = @adapter.send(:rotating_ss_recovery_inlets, 'relay-one', pool).first(3)
    seen.each { |inlet| @adapter.send(:record_ss_recovery_attempt, 'relay-one', inlet) }

    @relay['shadowsocks_extra_addr_in'] << '192.0.2.4'
    refreshed_pool = @adapter.send(:ss_endpoint_candidates, @relay, include_cooling: true)
    refreshed = @adapter.send(:rotating_ss_recovery_inlets, 'relay-one', refreshed_pool)
    refreshed_keys = refreshed.map { |item| @adapter.send(:recovery_inlet_key, item) }

    assert_equal 10, refreshed_pool.length
    seen.each do |inlet|
      assert_includes refreshed_keys, @adapter.send(:recovery_inlet_key, inlet)
    end
  end

  def test_exhausted_window_reopens_only_after_every_eligible_tuple_was_attempted
    pool = @adapter.send(:ss_endpoint_candidates, @relay, include_cooling: true)
    first_cycle = @adapter.send(:rotating_ss_recovery_inlets, 'relay-one', pool)
    first_cycle.each { |inlet| @adapter.send(:record_ss_recovery_attempt, 'relay-one', inlet) }

    reopened = @adapter.send(:rotating_ss_recovery_inlets, 'relay-one', pool)
    assert_equal first_cycle.map { |item| @adapter.send(:recovery_inlet_key, item) }.sort_by(&:to_s),
                 reopened.map { |item| @adapter.send(:recovery_inlet_key, item) }.sort_by(&:to_s)
  end

  def test_auto_transport_order_stays_ss_first_despite_recent_ipv6_history
    ready = {
      ip_data: { status: 'pass' }, inner_dns: { status: 'pass' }, https_data: { status: 'pass' }
    }
    @adapter.instance_variable_get(:@relay_history)['relay-one|ipv6'] = {
      relay: 'relay-one', transport_mode: 'ipv6', last_tested_at: Time.now.iso8601, last_result: ready
    }
    @adapter.instance_variable_get(:@relay_history)['relay-one|ss'] = {
      relay: 'relay-one', transport_mode: 'ss', last_tested_at: Time.now.iso8601, last_result: { ip_data: { status: 'fail' } }
    }

    assert_equal %w[ss ipv6 ipv4], @adapter.send(:transport_candidates, 'auto', @relay)
    assert_equal ['ipv6'], @adapter.send(:transport_candidates, 'ipv6', @relay)
    assert_equal ['ipv4'], @adapter.send(:transport_candidates, 'ipv4', @relay)
  end
end
