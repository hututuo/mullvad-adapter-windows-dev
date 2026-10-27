# frozen_string_literal: true
require_relative 'minitest_dependencies'
require_relative 'mullvad_adapter'
require 'tmpdir'
require 'rbconfig'

class QuicCarrierTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('quic-fixture')
    @helper = File.join(@dir, 'carrier')
    @request = { 'schema' => 1, 'remote_endpoint' => '192.0.2.99:443', 'server_hostname' => 'fixture.invalid',
      'auth_token' => 'fixture-secret-token', 'target_endpoint' => '127.0.0.1:51820',
      'interface_index' => 999, 'interface_name' => 'fixture-interface', 'source_address' => '192.0.2.10', 'mtu' => 1280 }
    @adapter = MullvadAdapter.new(state_dir: @dir, quic_helper: @helper)
    @adapter.instance_variable_set(:@template, { 'private-key' => Base64.strict_encode64('x' * 32), 'ip' => '10.0.0.2', 'ipv6' => 'fd00::2', 'allowed-ips' => ['0.0.0.0/0', '::/0'] })
    @relay = { 'hostname' => 'fixture-one', 'active' => true, 'location' => 'us-sjc',
      'public_key' => 'fixture-public', 'ipv4_addr_in' => '192.0.2.1',
      'features' => { 'quic' => { 'addr_in' => ['192.0.2.99'], 'domain' => 'fixture.invalid', 'token' => 'fixture-secret-token' } } }
    @metadata = { 'wireguard' => { 'relays' => [@relay], 'port_ranges' => [[51_820, 51_820]], 'shadowsocks_port_ranges' => [[51_900, 51_949]] } }
    @adapter.instance_variable_set(:@metadata, @metadata)
    @adapter.define_singleton_method(:physical_interface) { |_ip = nil| 'fixture-interface' }
  end

  def teardown
    @carrier&.stop
    @adapter.instance_variable_get(:@probe_event_writer)&.join(2)
    FileUtils.rm_rf(@dir)
  end

  def helper(local: '127.0.0.1:12345', fail_remote: false)
    File.write(@helper, <<~RUBY)
      #!#{RbConfig.ruby}
      require 'json'
      r = JSON.parse(STDIN.gets)
      if #{fail_remote}
        puts JSON.generate(schema: 1, event: 'error', code: 'quic_connect_failed')
        exit 1
      end
      puts JSON.generate(schema: 1, event: 'ready', transport: 'quic', upstream_sha: '#{MullvadAdapter::QuicCarrier::UPSTREAM_SHA}',
        local_endpoint: '#{local}', carrier_authenticated: true,
        binding: r.slice('interface_index', 'interface_name', 'source_address', 'remote_endpoint'))
      STDOUT.flush
      n = 0
      while (line = STDIN.gets)
        action = JSON.parse(line)['action']
        break if action == 'stop'
        next unless action == 'stats'
        n += 1
        puts JSON.generate(schema: 1, event: 'stats', tx_packets: n, rx_packets: 0, tx_bytes: 148, rx_bytes: 0,
          wg_initiations: 1, wg_response_packets: 0, wg_cookie_packets: 0)
        STDOUT.flush
      end
    RUBY
    File.chmod(0o700, @helper)
  end

  def test_cached_packet_observations_and_parent_eof_cleanup
    helper
    @carrier = MullvadAdapter::QuicCarrier.new(@helper, @request)
    pid = @carrier.pid
    assert_equal ['127.0.0.1', 12345], @carrier.local_endpoint
    @carrier.request_stats
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
    sleep 0.01 until @carrier.stats['tx_packets'] || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
    20.times { assert_equal 1, @carrier.stats['tx_packets'] }
    refute @carrier.stats.key?('authenticated')
    refute_includes JSON.generate(@carrier.stats), @request['auth_token']
    @carrier.stop
    refute @carrier.alive?
    assert_raises(Errno::ESRCH) { Process.kill(0, pid) }
  end

  def test_thread_cancellation_during_startup_reaps_helper_and_releases_owner
    pid_file = File.join(@dir, 'fixture-pid')
    File.write(@helper, "#!#{RbConfig.ruby}\nFile.write(#{pid_file.inspect}, Process.pid.to_s)\nSTDIN.gets\nsleep 60\n")
    File.chmod(0o700, @helper)
    @adapter.instance_variable_set(:@account_only_mode, false)
    FileUtils.mkdir_p(@adapter.send(:slot_dir, 'a'))
    address = Struct.new(:name, :ifindex, :addr).new('fixture-interface', 999, Addrinfo.ip('192.0.2.10'))
    thread = nil
    Socket.stub(:getifaddrs, [address]) do
      thread = Thread.new { @adapter.send(:start_worker, 'a', @relay, transport_mode: 'quic') }
      thread.report_on_exception = false
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
      sleep 0.01 until File.file?(pid_file) || !thread.alive? || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
      assert File.file?(pid_file), 'owned fixture did not start'
      owner = @adapter.instance_variable_get(:@workers).dig('a', :quic_carrier)
      assert owner
      pid = Integer(File.read(pid_file))
      thread.kill
      assert thread.join(9), 'cancelled start did not clean up within its stop bound'
      assert_empty @adapter.instance_variable_get(:@workers)
      refute owner.alive?
      assert_raises(Errno::ESRCH) { Process.kill(0, pid) }
      refute owner.instance_variable_get(:@reader)&.alive?
      refute owner.instance_variable_get(:@drain)&.alive?
    end
  ensure
    thread&.kill
    thread&.join(9)
  end

  def test_untrusted_non_loopback_ready_is_rejected_and_owned_child_stops
    helper(local: '0.0.0.0:12345')
    owned = nil
    assert_raises(MullvadAdapter::LocalProbeUnavailable) do
      MullvadAdapter::QuicCarrier.new(@helper, @request) { |value| owned = value }
    end
    refute owned.alive?
  end

  def test_remote_connect_failure_is_distinct_from_local_helper_failure
    helper(fail_remote: true)
    error = assert_raises(MullvadAdapter::QuicRemoteFailure) { MullvadAdapter::QuicCarrier.new(@helper, @request) }
    refute_includes error.message, @request['auth_token']
  end

  def test_directory_authorization_and_generated_config_contain_no_connect_token
    helper
    assert @adapter.send(:transport_supported?, @relay, 'quic')
    tuple = ['192.0.2.99', 443, 'relay-quic']
    config, info = @adapter.send(:worker_tunnel_config, { mixed: 17910, controller: 17911 }, @relay, 'quic', tuple, quic_local: ['127.0.0.1', 12345])
    assert_equal 1, config['proxies'].length
    assert_equal '127.0.0.1', config['proxies'].first['server']
    assert_equal 12345, config['proxies'].first['port']
    assert_equal 'wireguard-over-quic', info[:transport]
    refute_includes JSON.generate(config), 'fixture-secret-token'
    @relay['features']['quic']['addr_in'] = ['192.0.2.98']
    refute @adapter.send(:quic_candidate_authorized?, @relay, tuple)
  end

  def test_bad_quic_metadata_or_missing_helper_does_not_remove_ss_capability
    helper
    @relay['features']['quic']['token'] = "bad\ntoken"
    refute @adapter.send(:transport_supported?, @relay, 'quic')
    assert @adapter.send(:transport_supported?, @relay, 'ss')
    @relay['features']['quic']['token'] = 'fixture-secret-token'
    File.unlink(@helper)
    refute @adapter.send(:transport_supported?, @relay, 'quic')
    assert @adapter.send(:transport_supported?, @relay, 'ss')
  end

  def test_feature_change_summary_hides_connect_token
    feature = @relay['features']
    field = @adapter.send(:catalogue_field_change, 'features', 'QUIC参数', feature, feature.merge('quic' => feature['quic'].merge('token' => 'new-secret-token')))
    text = JSON.generate(field)
    refute_includes text, 'fixture-secret-token'
    refute_includes text, 'new-secret-token'
    previous = Marshal.load(Marshal.dump(@metadata))
    @relay['features']['quic']['token'] = 'new-secret-token'
    result = @adapter.send(:catalogue_change_summary, previous, @metadata, current_relay: 'fixture-one')
    assert_equal 'changed', result.dig(:current_relay, :state)
    refute_includes JSON.generate(result), 'new-secret-token'
    refute_includes JSON.generate(result), 'fixture-secret-token'
  end

  def test_quic_rotation_is_separate_from_ss_and_survives_restart_and_catalogue_edits
    helper
    @relay['features']['quic']['addr_in'] = %w[192.0.2.99 192.0.2.98 192.0.2.97 2001:db8::99]
    pool = @adapter.send(:quic_endpoint_candidates, @relay)
    first = @adapter.send(:rotating_ss_recovery_inlets, 'fixture-one', pool, mode: 'quic')
    attempted = [first[0], first[1], first.last]
    attempted.each { |tuple| @adapter.send(:record_ss_recovery_attempt, 'fixture-one', tuple, mode: 'quic') }
    # The same socket tuple under SS must have a separate coverage namespace.
    assert_equal pool, @adapter.send(:rotating_ss_recovery_inlets, 'fixture-one', pool, mode: 'ss')
    restarted = MullvadAdapter.new(state_dir: @dir, quic_helper: @helper)
    restarted.instance_variable_set(:@metadata, @metadata)
    restarted.send(:load_ss_recovery_windows)
    remaining = restarted.send(:rotating_ss_recovery_inlets, 'fixture-one', pool, mode: 'quic')
    assert_equal [first[2]], remaining
    @relay['features']['quic']['addr_in'] << '192.0.2.96'
    expanded = restarted.send(:quic_endpoint_candidates, @relay)
    choices = restarted.send(:rotating_ss_recovery_inlets, 'fixture-one', expanded, mode: 'quic')
    assert_equal [first[2], ['192.0.2.96', 443, 'relay-quic']], choices
    @relay['public_key'] = 'new-peer-key'
    assert_equal expanded, restarted.send(:rotating_ss_recovery_inlets, 'fixture-one', expanded, mode: 'quic')
  ensure
    restarted&.instance_variable_get(:@probe_event_writer)&.join(2)
  end
end
