# frozen_string_literal: true
require_relative 'test_protection'

class MullvadPQTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('mullvad-pq')
    @helper = File.join(@dir, 'helper')
    File.write(@helper, "#!/bin/sh\nexit 0\n", mode: 'w', perm: 0o755)
    @adapter = MullvadAdapter.new(state_dir: @dir, pq_helper: @helper)
    @adapter.send(:prepare_state_dir)
    # Public RFC vector, never a user identity.
    @private = Base64.strict_encode64([MullvadAccountTest::PRIVATE].pack('H*'))
    @template = { 'ip' => '10.0.0.2', 'private-key' => @private }
    @adapter.instance_variable_set(:@template, @template)
    @adapter.instance_variable_set(:@metadata, ReliabilityAdapter.new(@dir).instance_variable_get(:@metadata))
    @adapter.define_singleton_method(:physical_interface) { |_endpoint| 'en0' }
    # Use bytes, not a private credential.
    @fresh = Base64.strict_encode64(Array.new(32, 3).pack('C*'))
    @result = { 'schema' => 1, 'ephemeral_private_key' => @fresh,
      'ephemeral_public_key' => @adapter.send(:template_public_key, @fresh),
      'preshared_keys' => [Base64.strict_encode64(Array.new(32, 4).pack('C*'))] }
    @stopped, @configs = [], []
    stopped, configs = @stopped, @configs
    @adapter.define_singleton_method(:stop_pid) { |pid| stopped << pid }
    @adapter.define_singleton_method(:spawn_worker_core) do |_dir, path, _spec|
      configs << JSON.parse(File.read(path))
      100 + configs.length
    end
  end

  def teardown
    Thread.current[:adapter_protection_profile] = nil
    FileUtils.remove_entry(@dir)
  end

  def profile(multihop: false)
    { multihop: multihop, entry_city: multihop ? 'us-sjc' : nil, post_quantum: true }.freeze
  end

  def test_missing_helper_rejects_change_before_old_peer_is_stopped
    @adapter.instance_variable_get(:@options)[:pq_helper] = File.join(@dir, 'missing')
    assert_raises(RuntimeError) { @adapter.send(:ensure_pq_available!, profile) }
    assert_empty @stopped
    assert_empty @configs
  end

  def test_response_rejects_parent_identity_wrong_public_key_and_wrong_hop_count
    assert_equal @result, @adapter.send(:validate_pq_result, @result)
    [@result.merge('ephemeral_public_key' => @adapter.send(:template_public_key)),
     @result.merge('preshared_keys' => []), @result.merge('schema' => 2),
     @result.merge('ephemeral_private_key' => 'invalid')].each do |bad|
      assert_raises(StandardError) { @adapter.send(:validate_pq_result, bad) }
    end
  end

  def test_final_single_hop_has_psk_without_persisting_new_identity
    original = Marshal.dump(@template)
    result = @result
    @adapter.define_singleton_method(:negotiate_pq) { |_port, **_kwargs| result }
    Thread.current[:adapter_protection_profile] = profile
    worker = @adapter.send(:start_worker, 'a', @adapter.send(:find_relay, 'one'))
    assert worker[:post_quantum]
    assert @adapter.send(:public_worker_state, worker)[:post_quantum]
    assert_equal [101], @stopped
    assert_equal @private, @configs.first['proxies'].last['private-key']
    assert_equal @fresh, @configs.last['proxies'].last['private-key']
    assert_equal @result['preshared_keys'].first, @configs.last['proxies'].last['pre-shared-key']
    refute File.exist?(File.join(@dir, 'slots', 'a', 'config.json'))
    assert_equal original, Marshal.dump(@template)
  end

  def test_negotiation_failure_stops_bootstrap_and_never_publishes_worker
    @adapter.define_singleton_method(:negotiate_pq) { |_port, **_kwargs| raise 'injected failure' }
    Thread.current[:adapter_protection_profile] = profile
    assert_raises(RuntimeError) { @adapter.send(:start_worker, 'a', @adapter.send(:find_relay, 'one')) }
    assert_includes @stopped, 101
    assert_empty @adapter.instance_variable_get(:@workers)
    refute File.exist?(File.join(@dir, 'slots', 'a', 'config.json'))
  end

  def test_bootstrap_configuration_failure_leaves_no_runtime_key_file
    @adapter.instance_variable_get(:@options)[:validate_configs] = true
    @adapter.define_singleton_method(:validate_runtime_config) { |_path, _dir| raise 'injected parse failure' }
    Thread.current[:adapter_protection_profile] = profile
    assert_raises(RuntimeError) { @adapter.send(:start_worker, 'a', @adapter.send(:find_relay, 'one')) }
    assert_empty @configs
    refute File.exist?(File.join(@dir, 'slots', 'a', 'config.json'))
  end

  def test_protected_backup_cannot_reuse_plain_tunnel_history
    adapter = ReliabilityAdapter.new(@dir)
    adapter.send(:cache_speed_test, 'one', adapter.good_canary, 'test', 'ss')
    assert_equal 'recent_ready', adapter.send(:city_node_evidence, 'one')[:evidence]
    Thread.current[:adapter_protection_profile] = profile
    assert_equal 'unverified', adapter.send(:city_node_evidence, 'one')[:evidence]
  end

  def test_unverified_combination_is_rejected_before_bootstrap
    assert_raises(ArgumentError) { @adapter.send(:normalize_protection_profile, profile(multihop: true)) }
    assert_raises(RuntimeError) { @adapter.send(:ensure_pq_available!, profile(multihop: true)) }
    assert_empty @configs
    assert_empty @stopped
  end
end
