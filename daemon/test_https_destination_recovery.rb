# frozen_string_literal: true
require_relative 'minitest_dependencies'
require_relative 'mullvad_adapter'

class MullvadHttpsDestinationRecoveryTest < Minitest::Test
  def setup
    @adapter = MullvadAdapter.allocate
  end

  def test_recovery_is_limited_to_missing_tls_names_and_never_enables_dns_or_direct
    config = @adapter.send(:https_destination_recovery_config)
    assert config['enable']
    assert config['parse-pure-ip']
    assert config['override-destination']
    refute config['force-dns-mapping'], 'an explicit hostname must retain its original destination'
    assert_equal({ 'TLS' => { 'ports' => [443, 8443] } }, config['sniff'])
    assert_includes config['skip-dst-address'], '127.0.0.0/8'
    assert_includes config['skip-dst-address'], 'fc00::/7'
    refute_includes JSON.generate(config), 'DIRECT'
    refute config.key?('dns')
  end

  def test_config_is_fresh_for_each_worker
    first = @adapter.send(:https_destination_recovery_config)
    first['sniff']['TLS']['ports'] << 1234
    refute_includes @adapter.send(:https_destination_recovery_config)['sniff']['TLS']['ports'], 1234
  end

  def test_ipv6_echo_does_not_treat_ipv4_timeout_as_a_node_information_target
    calls = []
    status = Struct.new(:success?).new(true)
    @adapter.define_singleton_method(:capture_probe_command) do |*args, **options|
      calls << [args, options]
      ["64 bytes time=12.3 ms\n", '', status]
    end
    assert_equal 'pass', @adapter.send(:outer_ping_test, '2001:db8::1', 1500)[:status]
    assert_equal ['/sbin/ping6', '-n', '-c', '1', '2001:db8::1'], calls.first.first
    assert_equal 2.5, calls.first.last[:timeout_seconds], 'the subprocess deadline still bounds IPv6 echo'
    @adapter.send(:outer_ping_test, '192.0.2.1', 1500)
    assert_equal ['/sbin/ping', '-n', '-c', '1', '-W', '1500', '192.0.2.1'], calls.last.first
  end
end
