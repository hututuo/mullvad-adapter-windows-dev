# frozen_string_literal: true
require_relative 'test_reliability'
require_relative 'test_account'

class MullvadProtectionTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('mullvad-protection')
    @adapter = ReliabilityAdapter.new(@dir)
    @adapter.instance_variable_set(:@template, { 'ip' => '10.0.0.2', 'private-key' => 'public-test-vector-only' })
    relays = @adapter.instance_variable_get(:@metadata)['wireguard']['relays']
    relays.last(3).each { |r| r['location'] = 'jp-tyo' }
    @profile = { multihop: true, entry_city: 'jp-tyo', post_quantum: false }.freeze
  end

  def teardown
    @adapter&.instance_variable_get(:@probe_event_writer)&.join(2)
    Thread.current[:adapter_protection_profile] = nil
    Thread.current[:adapter_operation_id] = nil
    FileUtils.remove_entry(@dir)
  end

  def test_legacy_install_defaults_to_single_hop_without_writing_settings
    @adapter.send(:load_protection_profile)
    assert_equal({ multihop: false, entry_city: nil, post_quantum: false }, @adapter.send(:protection_profile))
    refute File.exist?(File.join(@dir, 'protection.json'))
  end

  def test_corrupt_saved_policy_blocks_activation_instead_of_silent_downgrade
    File.write(File.join(@dir, 'protection.json'), '{broken')
    @adapter.send(:load_protection_profile)
    capture_io { refute @adapter.send(:activate, 'one', reason: 'startup') }
    assert_empty @adapter.instance_variable_get(:@workers)
    assert @adapter.send(:protection_snapshot)[:config_error]
  end

  def test_unsupported_security_flags_and_invalid_entry_are_rejected
    [{ multihop: true, entry_city: '' }, { multihop: 'true', entry_city: 'jp-tyo' },
     { multihop: false, post_quantum: 'true' }, { multihop: false, daita: false }].each do |value|
      assert_raises(ArgumentError) { @adapter.send(:normalize_protection_profile, value) }
    end
    assert_equal @profile, @adapter.send(:normalize_protection_profile, { 'multihop' => true, 'entry_city' => 'jp-tyo' })
  end

  def test_multihop_graph_only_sends_exit_packets_through_entry
    Thread.current[:adapter_protection_profile] = @profile
    @adapter.define_singleton_method(:physical_interface) { |_ip| 'test-physical-interface' }
    relay = @adapter.send(:find_relay, 'one')
    descriptor = @adapter.send(:endpoint_candidates_for_transport, relay, 'ss').first
    config, info = @adapter.send(:worker_tunnel_config, { mixed: 18000, controller: 18001 }, relay, 'ss', descriptor)
    assert_equal @adapter.send(:controller_secret, 18001), config.fetch('secret')
    refute_includes JSON.generate(info), config.fetch('secret')
    ss, entry, exit_node = config['proxies']
    assert_operator entry.fetch('mtu'), :>=, 1280
    assert_operator exit_node.fetch('mtu'), :>=, 1280
    assert_equal 'SS-INLET', ss['name']
    assert_equal 'SS-INLET', entry['dialer-proxy']
    assert_equal ['192.0.2.1/32'], entry['allowed-ips']
    assert_equal false, entry['remote-dns-resolve']
    assert_equal 'WG-ENTRY', exit_node['dialer-proxy']
    assert_equal '192.0.2.1', exit_node['server']
    assert_equal 51_820, exit_node['port']
    assert_equal ['0.0.0.0/0', '::/0'], exit_node['allowed-ips']
    refute exit_node.key?('interface-name')
    refute config['tun']['enable']
    refute config['dns']['enable']
    assert_equal 2, info[:peer_keys].uniq.length
    assert_equal 'jp-tyo', info[:entry_city]
    refute_equal relay['hostname'], info[:entry_relay]
  end

  def test_direct_outer_multihop_is_still_nested_and_template_is_preserved
    Thread.current[:adapter_protection_profile] = @profile
    @adapter.define_singleton_method(:physical_interface) { |_ip| 'en0' }
    template = Marshal.dump(@adapter.instance_variable_get(:@template))
    %w[ipv4 ipv6].each do |mode|
      relay = @adapter.send(:find_relay, 'one')
      candidate = @adapter.send(:endpoint_candidates_for_transport, relay, mode).first
      config, = @adapter.send(:worker_tunnel_config, { mixed: 18000, controller: 18001 }, relay, mode, candidate)
      assert_equal @adapter.send(:controller_secret, 18001), config.fetch('secret')
      entry, exit_node = config['proxies']
      assert_operator entry.fetch('mtu'), :>=, 1280
      assert_operator exit_node.fetch('mtu'), :>=, 1280
      assert_equal 'en0', entry['interface-name']
      assert_equal 'WG-ENTRY', exit_node['dialer-proxy']
      assert_equal 51_820, exit_node['port']
    end
    assert_equal template, Marshal.dump(@adapter.instance_variable_get(:@template))
  end

  def test_single_hop_dual_stack_mtu_is_valid_without_rewriting_saved_identity
    @adapter.define_singleton_method(:physical_interface) { |_ip| 'en0' }
    @adapter.instance_variable_get(:@template).merge!('ipv6' => '2001:db8::2', 'mtu' => 1200)
    template = Marshal.dump(@adapter.instance_variable_get(:@template))
    relay = @adapter.send(:find_relay, 'one')
    %w[ss ipv4 ipv6].each do |mode|
      candidate = @adapter.send(:endpoint_candidates_for_transport, relay, mode).first
      config, = @adapter.send(:worker_tunnel_config, { mixed: 18000, controller: 18001 }, relay, mode, candidate)
      wg = config['proxies'].find { |node| node['type'] == 'wireguard' }
      assert_equal '2001:db8::2', wg['ipv6']
      assert_operator wg.fetch('mtu'), :>=, 1280
      assert_equal ['MATCH,OUT'], config['rules']
      assert_equal @adapter.send(:https_destination_recovery_config), config['sniffer']
      assert_equal true, wg['remote-dns-resolve']
      assert_equal ['tcp://10.64.0.1'], wg['dns']
      refute config['dns']['enable'], 'hostname recovery must not enable a system DNS listener'
    end
    assert_equal template, Marshal.dump(@adapter.instance_variable_get(:@template))
  end

  def test_shared_ss_gateway_forwards_to_selected_relay_not_gateway_loopback
    @adapter.define_singleton_method(:physical_interface) { |_ip| 'en0' }
    relay = @adapter.send(:find_relay, 'one')
    config, = @adapter.send(:worker_tunnel_config, { mixed: 18000, controller: 18001 }, relay, 'ss', ['192.0.2.2', 20_484, 'extra-ss-ipv4'])
    inlet = config['proxies'].find { |item| item['name'] == 'SS-INLET' }
    wg = config['proxies'].find { |item| item['name'] == 'MULLVAD' }
    assert_equal '192.0.2.2', inlet['server']
    assert_equal relay['ipv4_addr_in'], wg['server']
    refute_equal '127.0.0.1', wg['server']
    assert_equal 51_820, wg['port']
    assert_equal 'SS-INLET', wg['dialer-proxy']
    assert_equal ['MATCH,OUT'], config['rules']
  end

  def test_entries_exclude_all_live_entry_and_exit_peer_keys
    Thread.current[:adapter_protection_profile] = @profile
    @adapter.instance_variable_set(:@workers, { 'a' => { peer_keys: %w[public-three public-five] } })
    assert_equal ['four'], @adapter.send(:multihop_entries, @adapter.send(:find_relay, 'one'), 'ss').map { |r| r['hostname'] }
    @adapter.instance_variable_get(:@workers)['a'][:peer_keys] << 'public-four'
    assert_empty @adapter.send(:endpoint_candidates_for_transport, @adapter.send(:find_relay, 'one'), 'ss')
  end

  def test_empty_entry_city_does_not_produce_a_single_hop_candidate
    Thread.current[:adapter_protection_profile] = { multihop: true, entry_city: 'de-ber' }
    assert_empty @adapter.send(:endpoint_candidates_for_transport, @adapter.send(:find_relay, 'one'), 'ss')
  end

  def install_profile_worker_fixture
    @adapter.define_singleton_method(:start_worker) do |slot, relay, transport_mode: 'ss', ss_candidate: nil|
      profile = protection_profile
      raise 'injected protection failure' if profile[:multihop] && @reject_multihop
      raise 'same exit peer overlap' if @workers.values.any? { |w| w[:relay] == relay['hostname'] }
      worker = { pid: 99999, slot: slot, relay: relay['hostname'], instance_token: SecureRandom.uuid,
        transport_mode: transport_mode, protection_profile: profile, location: relay['location'],
        entry_relay: profile[:multihop] ? 'three' : nil }
      @workers[slot] = worker
      @worker_state_tokens[slot] = worker[:instance_token]
      @state[:workers][slot] = public_worker_state(worker).merge(state: 'candidate')
      worker
    end
  end

  def test_failed_policy_change_rebuilds_original_policy_without_saving_new_one
    install_profile_worker_fixture
    @adapter.seed_active
    @adapter.instance_variable_set(:@reject_multihop, true)
    refute @adapter.send(:activate, 'one', reason: 'protection-change', protection_profile: @profile)
    assert_equal false, @adapter.send(:protection_profile)[:multihop]
    assert_equal false, @adapter.send(:protection_snapshot).dig(:effective, :multihop)
    assert_equal 'reconnect-rollback', @adapter.send(:snapshot)[:switch_reason]
    refute File.exist?(File.join(@dir, 'protection.json'))
    assert_nil Thread.current[:adapter_protection_profile]
  end

  def test_successful_policy_change_persists_only_after_canary_and_can_be_disabled
    install_profile_worker_fixture
    @adapter.seed_active
    assert @adapter.send(:activate, 'one', reason: 'protection-change', protection_profile: @profile)
    assert_equal @profile, @adapter.send(:protection_profile)
    assert_equal true, @adapter.send(:protection_snapshot).dig(:effective, :multihop)
    assert_equal 0o600, File.stat(File.join(@dir, 'protection.json')).mode & 0o777
    another = MullvadAdapter.new(state_dir: @dir)
    another.send(:load_protection_profile)
    assert_equal @profile, another.send(:protection_profile)
    assert @adapter.send(:activate, 'one', reason: 'protection-change', protection_profile: { multihop: false, entry_city: nil, post_quantum: false })
    refute @adapter.send(:protection_snapshot).dig(:effective, :multihop)
  end

  def test_protection_change_requires_full_readiness_and_reaches_rollback
    install_profile_worker_fixture
    @adapter.seed_active
    @adapter.define_singleton_method(:run_readiness_canary) do |slot|
      canary = good_canary
      canary[:inner_dns] = { status: 'fail' } if @workers[slot][:protection_profile][:multihop]
      canary
    end
    refute @adapter.send(:activate, 'one', reason: 'protection-change', protection_profile: @profile)
    assert_equal false, @adapter.send(:protection_profile)[:multihop]
    assert_equal 'ready', @adapter.send(:snapshot)[:status]
  end

  def test_disk_failure_reaches_old_policy_rollback
    install_profile_worker_fixture
    @adapter.seed_active
    @adapter.define_singleton_method(:atomic_account_file) { |*_args| raise IOError, 'injected' }
    refute @adapter.send(:activate, 'one', reason: 'protection-change', protection_profile: @profile)
    assert_equal false, @adapter.send(:protection_profile)[:multihop]
    assert_equal 'ready', @adapter.send(:snapshot)[:status]
  end

  def test_multihop_evidence_does_not_contaminate_single_hop_history
    @adapter.instance_variable_get(:@workers)['a'] = { relay: 'one', entry_relay: 'three' }
    result = @adapter.send(:cache_speed_test, 'one', @adapter.good_canary, 'test', 'ss')
    assert_equal true, result[:multihop]
    assert_empty @adapter.send(:relay_history_snapshot)
    assert_empty @adapter.send(:speed_test_snapshot)
  end

  def test_protection_post_requires_capability_and_browser_origin_is_rejected
    @adapter.send(:load_account_manager)
    [nil, 'Origin: https://malicious.invalid\r\n'].each do |header|
      request = "POST /protection HTTP/1.1\r\n#{header}\r\n"
      sock = MullvadAccountTest::Socket.new(request)
      @adapter.send(:handle_http, sock)
      assert_equal '403', sock.response.split[1]
    end
  end
end
