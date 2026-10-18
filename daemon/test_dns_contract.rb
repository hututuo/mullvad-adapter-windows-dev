# frozen_string_literal: true
require 'minitest/autorun'
require 'json'
require 'socket'
require_relative 'mullvad_adapter'

class DnsSharedContractTest < Minitest::Test
  CASES = JSON.parse(File.read(File.expand_path('../core/crates/probe/fixtures/dns-canary.json', __dir__)))

  def test_shared_wire_contract_against_ruby_decoder
    adapter = MullvadAdapter.allocate
    CASES.each do |item|
      count = adapter.send(:validated_dns_answer_count, [item.fetch('hex')].pack('H*'),
                           item.fetch('query_id'), item.fetch('question'))
      assert_equal item.fetch('answers'), count, item.fetch('name')
    end
  end

  def test_shared_wire_contract_over_actual_framed_socket
    CASES.each do |item|
      client, server = Socket.pair(:UNIX, :STREAM, 0)
      adapter = MullvadAdapter.allocate
      adapter.define_singleton_method(:socks5_connect) { |*_args| client }
      worker = Thread.new do
        length = server.read(2).unpack1('n')
        query_id = server.read(length).unpack1('n')
        packet = [item.fetch('hex')].pack('H*')
        if packet.bytesize >= 2
          # Preserve intentional wrong-ID cases while adapting to the real query.
          delta = packet.unpack1('n') - item.fetch('query_id')
          packet[0, 2] = [(query_id + delta) & 0xffff].pack('n')
        end
        server.write([packet.bytesize].pack('n') + packet)
      ensure
        server.close
      end
      result = adapter.send(:inner_dns_tcp_test, 17_910, item.fetch('question'), 2)
      assert_equal(item.fetch('answers').positive? ? 'pass' : 'fail', result[:status], item.fetch('name'))
    ensure
      client&.close unless client&.closed?
      unless worker&.join(2)
        server&.close unless server&.closed?
        worker&.kill&.join
      end
      server&.close unless server&.closed?
      worker&.value
    end
  end
  def test_svcb_https_unknown_parameters_do_not_grow_global_classes_or_constants
    before = [Resolv::DNS::SvcParam::ClassHash.size, Resolv::DNS::SvcParam::Generic.constants.size,
              Resolv::DNS::Resource::ClassHash.size]
    [64, 65].each do |type|
      100.times do |i|
        packet = [CASES.first.fetch('hex')].pack('H*')
        packet[10, 2] = [1].pack('n')
        data = [1].pack('n') + "\0" + [40_000 + i, 0].pack('nn')
        packet << "\0" << [type, 1, 30, data.bytesize].pack('nnNn') << data
        assert_equal 1, MullvadAdapter.allocate.send(:validated_dns_answer_count, packet, 123, 'www.gstatic.com')
        assert_equal 0, MullvadAdapter.allocate.send(:validated_dns_answer_count, packet + 'junk', 123, 'www.gstatic.com')
      end
    end
    assert_equal before, [Resolv::DNS::SvcParam::ClassHash.size, Resolv::DNS::SvcParam::Generic.constants.size,
                         Resolv::DNS::Resource::ClassHash.size]
  end

end
