# frozen_string_literal: true
require_relative 'test_ordered_recovery'

class StartupTransportPreservationTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('startup-preservation')
    @adapter = OrderedRecoveryAdapter.new(@dir)
    @adapter.instance_variable_get(:@relay_history)['one|ipv6'] = {
      last_tested_at: Time.now.iso8601, last_result: @adapter.good_canary
    }
    @calls = []
    calls = @calls
    @adapter.define_singleton_method(:activate) do |relay, **_|
      calls << [:verify, relay, Thread.current[:adapter_recovery_inlet]&.dig(:mode)]
      true
    end
    @adapter.define_singleton_method(:run_ordered_recovery) do |relay, **_|
      calls << [:ladder, relay]
      true
    end
  end

  def teardown
    @adapter.instance_variable_get(:@probe_event_writer)&.join(2)
    Thread.current[:adapter_recovery_inlet] = nil
    FileUtils.rm_rf(@dir)
  end

  def test_recent_validated_path_is_verified_once_without_ss_preemption
    assert @adapter.send(:activate_startup_with_fallback, 'one', 'auto', reason: 'startup')
    assert_equal [[:verify, 'one', 'ipv6']], @calls
    assert_nil Thread.current[:adapter_recovery_inlet]
  end

  def test_stale_evidence_starts_the_ss_first_ladder
    @adapter.instance_variable_get(:@relay_history)['one|ipv6'][:last_tested_at] = (Time.now - 120).iso8601
    assert @adapter.send(:activate_startup_with_fallback, 'one', 'auto', reason: 'startup')
    assert_equal [[:ladder, 'one']], @calls
  end

  def test_failed_recent_path_returns_to_the_normal_ladder_and_restores_pin
    calls = @calls
    @adapter.define_singleton_method(:activate) { |_relay, **_| calls << [:failed_verification]; false }
    assert @adapter.send(:activate_startup_with_fallback, 'one', 'auto', reason: 'startup')
    assert_equal [[:failed_verification], [:ladder, 'one']], @calls
    assert_nil Thread.current[:adapter_recovery_inlet]
  end
end
