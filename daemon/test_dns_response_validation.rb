# frozen_string_literal: true
require 'minitest/autorun'
require 'resolv'
require 'socket'
require_relative 'mullvad_adapter'

class DnsResponseValidationTest < Minitest::Test
  QUERY = 'www.gstatic.com'
  A = Resolv::DNS::Resource::IN::A
  CNAME = Resolv::DNS::Resource::IN::CNAME

  def cname(name)
    CNAME.new(Resolv::DNS::Name.create(name))
  end

  def valid_message(id, question: QUERY, type: A)
    message = Resolv::DNS::Message.new(id)
    message.qr = 1
    message.rd = 1
    message.ra = 1
    message.add_question(question, type)
    message.add_answer(question, 30, A.new('192.0.2.10'))
    message
  end

  def probe(&reply)
    client, server = Socket.pair(:UNIX, :STREAM, 0)
    adapter = MullvadAdapter.allocate
    adapter.define_singleton_method(:socks5_connect) { |*_args| client }
    worker = Thread.new do
      size = server.read(2).unpack1('n')
      query = server.read(size)
      packet = reply.call(query.unpack1('n'))
      server.write([packet.bytesize].pack('n') + packet)
    ensure
      server.close
    end
    adapter.send(:inner_dns_tcp_test, 17_910, QUERY, 2)
  ensure
    client&.close unless client&.closed?
    unless worker&.join(2)
      server&.close unless server&.closed?
      worker&.kill&.join
    end
    server&.close unless server&.closed?
    worker&.value
  end

  def test_valid_compressed_a_and_cname_chain_are_real_socket_successes
    result = probe { |id| valid_message(id).encode }
    assert_equal 'pass', result[:status]
    assert_equal 1, result[:answers]
    result = probe do |id|
      message = Resolv::DNS::Message.new(id)
      message.qr = 1
      message.add_question(QUERY.upcase, A)
      message.add_answer(QUERY, 30, cname('edge.example.'))
      message.add_answer('edge.example.', 30, A.new('192.0.2.20'))
      message.encode
    end
    assert_equal 'pass', result[:status]
    assert_equal 1, result[:answers]
  end

  def test_header_claim_and_wrong_response_flags_are_not_dns_success
    builders = [
      ->(id) { [id, 0, 1, 1, 0, 0].pack('n6') },
      ->(id) { [id, 0x8000, 1, 1, 0, 0].pack('n6') },
      ->(id) { valid_message(id).tap { |m| m.qr = 0 }.encode },
      ->(id) { valid_message(id).tap { |m| m.tc = 1 }.encode },
      ->(id) { valid_message(id).tap { |m| m.opcode = 2 }.encode },
      ->(id) { valid_message(id).tap { |m| m.rcode = 3 }.encode },
      ->(id) { valid_message(id).encode.tap { |p| p.setbyte(3, p.getbyte(3) | 0x40) } },
      ->(id) { valid_message(id ^ 1).encode },
      ->(id) { valid_message(id, question: 'unrelated.example').encode },
      ->(id) { valid_message(id, type: Resolv::DNS::Resource::IN::AAAA).encode }
    ]
    builders.each_with_index { |builder, i| assert_equal 'fail', probe(&builder)[:status], "invalid response #{i}" }
  end

  def test_declared_count_truncation_trailing_data_and_compression_bounds_fail
    builders = [
      ->(id) { valid_message(id).encode.tap { |p| p[6, 2] = [2].pack('n') } },
      ->(id) { valid_message(id).encode[0...-1] },
      ->(id) { valid_message(id).encode + 'junk' },
      ->(id) { valid_message(id).encode.tap { |p| offset = p.index("\xc0\x0c".b); p[offset, 2] = [0xc000 | offset].pack('n') } },
      ->(id) { valid_message(id).encode.tap { |p| offset = p.index("\xc0\x0c".b); p[offset, 2] = "\xff\xff".b } },
      ->(id) { valid_message(id).encode.tap { |p| offset = p.index("\xc0\x0c".b); p[offset, 2] = [0xc000 | (offset + 2)].pack('n') } },
      ->(id) { valid_message(id).encode.tap { |p| p[-6, 2] = [3].pack('n') } }
    ]
    builders.each_with_index { |builder, i| assert_equal 'fail', probe(&builder)[:status], "wire boundary #{i}" }
  end

  def test_only_related_in_a_answers_or_valid_cname_chains_pass
    builders = [
      ->(m) { m.add_answer(QUERY, 30, Resolv::DNS::Resource::IN::AAAA.new('2001:db8::1')) },
      ->(m) { m.add_answer('other.example.', 30, A.new('192.0.2.1')) },
      ->(m) { m.add_answer(QUERY, 30, cname('edge.example.')) },
      ->(m) { m.add_answer(QUERY, 30, cname('edge.example.')); m.add_answer('edge.example.', 30, cname(QUERY + '.')) },
      ->(m) { m.add_answer(QUERY, 30, cname('edge.example.')); m.add_answer(QUERY, 30, cname('other.example.')); m.add_answer('edge.example.', 30, A.new('192.0.2.1')) },
      ->(m) { m.add_answer(QUERY, 30, cname('edge.example.')); m.add_answer(QUERY, 30, A.new('192.0.2.1')) }
    ]
    builders.each_with_index do |builder, i|
      result = probe do |id|
        m = Resolv::DNS::Message.new(id); m.qr = 1; m.add_question(QUERY, A)
        builder.call(m); m.encode
      end
      assert_equal 'fail', result[:status], "answer relationship #{i}"
    end
  end

  def test_all_truncation_offsets_and_oversize_labels_fail_without_network
    adapter = MullvadAdapter.allocate
    packet = valid_message(123).encode
    (0...packet.bytesize).each do |size|
      assert_equal 0, adapter.send(:validated_dns_answer_count, packet.byteslice(0, size), 123, QUERY), "prefix #{size}"
    end
    name = Resolv::DNS::Name.create(('a' * 64) + '.example.')
    refute adapter.send(:valid_dns_wire_name?, name)
    long_name = Resolv::DNS::Name.create(([('a' * 63)] * 4).join('.') + '.')
    refute adapter.send(:valid_dns_wire_name?, long_name)
  end
  def test_cname_hop_and_record_count_limits
    adapter = MullvadAdapter.allocate
    [16, 17].each do |hops|
      message = Resolv::DNS::Message.new(123); message.qr = 1; message.add_question(QUERY, A)
      name = QUERY + '.'
      hops.times do |n|
        target = "edge#{n}.example."
        message.add_answer(name, 30, cname(target)); name = target
      end
      message.add_answer(name, 30, A.new('192.0.2.1'))
      assert_equal(hops == 16 ? 1 : 0, adapter.send(:validated_dns_answer_count, message.encode, 123, QUERY))
    end
    assert_equal 0, adapter.send(:validated_dns_answer_count, [123, 0x8000, 1, 4097, 0, 0].pack('n6'), 123, QUERY)
  end

  def test_nested_authority_and_additional_names_obey_wire_label_limits
    [2, 5, 12, 15, 6, 33].product([:long_label, :long_name]).each do |type, malformed|
      result = probe do |id|
        packet = valid_message(id).encode
        packet[8, 2] = [1].pack('n') # One authority record.
        bad_name = if malformed == :long_label
                     [64].pack('C') + ('x' * 64) + "\0"
                   else
                     ([63].pack('C') + ('x' * 63)) * 4 + "\0"
                   end
        data = case type
               when 15 then [10].pack('n') + bad_name
               when 6 then bad_name + "\0" + [1, 1, 1, 1, 1].pack('N5')
               when 33 then [0, 0, 443].pack('n3') + bad_name
               else bad_name
               end
        packet + "\xc0\x0c".b + [type, 1, 30, data.bytesize].pack('nnNn') + data
      end
      assert_equal 'fail', result[:status], "embedded #{malformed} type #{type}"
    end
  end

  def test_unknown_resource_types_are_bounded_opaque_data_without_global_class_growth
    before = Resolv::DNS::Resource::ClassHash.size
    16.times do |n|
      result = probe do |id|
        packet = valid_message(id).encode
        packet[10, 2] = [1].pack('n')
        packet + "\xc0\x0c".b + [60_000 + n, 60_000 + n, 0, 3].pack('nnNn') + 'abc'
      end
      assert_equal 'pass', result[:status]
    end
    assert_equal before, Resolv::DNS::Resource::ClassHash.size
    result = probe { |id| valid_message(id).encode.tap { |p| p[29, 4] = [60_100, 60_100].pack('nn') } }
    assert_equal 'fail', result[:status]
    assert_equal before, Resolv::DNS::Resource::ClassHash.size
  end

  def test_valid_ad_cd_opt_and_nested_ns_authority_remain_accepted
    before = Resolv::DNS::Resource::ClassHash.size
    result = probe do |id|
      message = valid_message(id)
      message.add_authority('gstatic.com.', 30,
        Resolv::DNS::Resource::IN::NS.new(Resolv::DNS::Name.create('ns.example.')))
      packet = message.encode
      packet.setbyte(3, packet.getbyte(3) | 0x30) # Valid AD/CD bits, not reserved Z.
      packet[10, 2] = [1].pack('n')
      packet + "\0" + [41, 1232, 0x8000, 0].pack('nnNn') # Empty valid OPT, DO bit.
    end
    assert_equal 'pass', result[:status]
    assert_equal 1, result[:answers]
    assert_equal before, Resolv::DNS::Resource::ClassHash.size
  end

end
