# frozen_string_literal: true

require 'openssl'
require 'stringio'
require 'tmpdir'
require_relative '../scripts/diagnostics/ss_wg_observer'
require_relative '../scripts/diagnostics/observe_ss_wg'
require_relative 'minitest_dependencies'

class SSObservationsTest < Minitest::Test
  ENDPOINT_IP = '198.51.100.7'
  ENDPOINT_PORT = 443
  PASSWORD = 'mullvad'

  # Independent fixture: the EVP_BytesToKey master and HKDF subkey were
  # calculated with Python hashlib/hmac, then this authenticated UDP datagram
  # was sealed with AES-256-GCM. The decoder must derive the same key from the
  # password and salt to accept it.
  KNOWN_SS_UDP_HEX = <<~HEX.delete("\n \t").freeze
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    956c0ce6866db791b6fd6e2bd0a4e7156936fc0ac80ae4fe795e994f19f96b5dd29bcad5f49a0a4391444bc5fdcd94454a46236e13808bfc6e53b42abd9ee1474640fd4388034a4be9684e4afa41f4993531867f8e622286cbed5418f03b9ee5b927aee5ee23063fec7a5dc68093c479ad4deac280336aae918728219e2c7c44a7c807ff79aa6d00fca2d9402e0831b418a370012fe197047295b0c4b1d44574ce435a1bcb18dc6b4ae347
  HEX

  # Fixed test-only key from the independent derivation above. This helper is
  # used to create authenticated protocol-shape cases; it is never production
  # code and its payloads stay in StringIO fixtures.
  TEST_ONLY_SUBKEY = ['6f46a35963e2b96821f05429b99fc072994350665a19bdf2ab693afdc1c627e9'].pack('H*').freeze
  TEST_ONLY_SALT = (0..31).to_a.pack('C*').freeze

  def test_independent_known_fixture_derives_key_and_counts_tx_init
    summary = observe([udp_frame(payload: known_payload, destination_ip: ENDPOINT_IP,
                                 destination_port: ENDPOINT_PORT)])

    assert_equal 1, summary['pcap_records']
    assert_equal 1, summary['endpoint_packets']
    assert_equal 1, summary['tx_packets']
    assert_equal 1, summary['tx_ss_authenticated']
    assert_equal 1, summary['tx_wg_type1']
    assert_equal 0, summary['tx_ss_auth_failed']
    assert_equal 0, summary['tx_wg_invalid']
  end

  def test_wireguard_type_counts_and_rx_direction_across_classic_pcap_variants
    records = [
      udp_frame(payload: seal_for_test(socks_payload(wg_packet(1, 148))),
                source_ip: ENDPOINT_IP, source_port: ENDPOINT_PORT,
                destination_ip: '192.0.2.20', destination_port: 52_000),
      udp_frame(payload: seal_for_test(socks_payload(wg_packet(2, 92))),
                source_ip: ENDPOINT_IP, source_port: ENDPOINT_PORT,
                destination_ip: '192.0.2.20', destination_port: 52_000),
      udp_frame(payload: seal_for_test(socks_payload(wg_packet(3, 64))),
                source_ip: ENDPOINT_IP, source_port: ENDPOINT_PORT,
                destination_ip: '192.0.2.20', destination_port: 52_000),
      udp_frame(payload: seal_for_test(socks_payload(wg_packet(4, 44))),
                source_ip: ENDPOINT_IP, source_port: ENDPOINT_PORT,
                destination_ip: '192.0.2.20', destination_port: 52_000)
    ]
    observer = new_observer

    [[:little, :micro], [:big, :micro], [:little, :nano], [:big, :nano]].each_with_index do |format, index|
      observer.consume_pcap(StringIO.new(pcap([records[index]], byte_order: format[0], precision: format[1])))
    end
    summary = observer.summary

    assert_equal 4, summary['rx_packets']
    assert_equal 1, summary['rx_wg_type1']
    assert_equal 1, summary['rx_wg_type2']
    assert_equal 1, summary['rx_wg_type3']
    assert_equal 1, summary['rx_wg_type4']
    assert_equal 4, summary['rx_ss_authenticated']
  ensure
    observer&.close
  end

  def test_tampered_shadowsocks_tag_is_rejected
    payload = known_payload.dup
    payload.setbyte(payload.bytesize - 1, payload.getbyte(payload.bytesize - 1) ^ 1)
    summary = observe([udp_frame(payload: payload, destination_ip: ENDPOINT_IP,
                                 destination_port: ENDPOINT_PORT)])

    assert_equal 1, summary['tx_ss_auth_failed']
    assert_equal 0, summary['tx_ss_authenticated']
    assert_equal 0, summary['tx_wg_type1']
  end

  def test_authenticated_but_invalid_wireguard_header_or_length_is_not_counted
    bad_reserved = wg_packet(1, 148)
    bad_reserved.setbyte(1, 1)
    bad_length = wg_packet(1, 147)
    frames = [bad_reserved, bad_length].map do |wireguard|
      udp_frame(payload: seal_for_test(socks_payload(wireguard)), destination_ip: ENDPOINT_IP,
                destination_port: ENDPOINT_PORT)
    end
    summary = observe(frames)

    assert_equal 2, summary['tx_ss_authenticated']
    assert_equal 2, summary['tx_wg_invalid']
    assert_equal 0, summary['tx_wg_type1']
  end

  def test_truncated_record_body_is_counted_without_parsing_partial_frame
    frame = udp_frame(payload: known_payload, destination_ip: ENDPOINT_IP,
                      destination_port: ENDPOINT_PORT)
    header = pcap_header
    record_header = [1, 0, frame.bytesize, frame.bytesize].pack('V4')
    summary = observe_capture(header + record_header + frame.byteslice(0, 10))

    assert_equal 1, summary['pcap_truncated']
    assert_equal 0, summary['pcap_records']
    assert_equal 0, summary['endpoint_packets']
  end

  def test_record_length_over_limit_is_rejected_without_reading_its_body
    capture = pcap_header + [1, 0, 65_536, 65_536].pack('V4')
    summary = observe_capture(capture)

    assert_equal 1, summary['pcap_invalid_records']
    assert_equal 0, summary['pcap_records']
    assert_equal 0, summary['endpoint_packets']
  end

  def test_missing_record_body_and_empty_authenticated_payload_do_not_crash
    summary = observe_capture(pcap_header + [1, 0, 10, 10].pack('V4'))
    assert_equal 1, summary['pcap_truncated']
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.encrypt
    cipher.key = TEST_ONLY_SUBKEY
    cipher.iv = "\0" * 12
    payload = TEST_ONLY_SALT + cipher.final + cipher.auth_tag
    summary = observe([udp_frame(payload: payload, destination_ip: ENDPOINT_IP,
                                destination_port: ENDPOINT_PORT)])
    assert_equal 1, summary['tx_ss_authenticated']
    assert_equal 1, summary['tx_wg_invalid']
  end

  def test_fragmented_ipv4_packet_is_rejected_before_endpoint_decode
    frame = udp_frame(payload: known_payload, destination_ip: ENDPOINT_IP,
                      destination_port: ENDPOINT_PORT, fragment_bits: 0x2000)
    summary = observe([frame])

    assert_equal 1, summary['fragmented_ipv4_packets']
    assert_equal 0, summary['endpoint_packets']
    assert_equal 0, summary['tx_ss_authenticated']
  end

  def test_nonmatching_endpoint_is_ignored
    frame = udp_frame(payload: known_payload, destination_ip: '198.51.100.8',
                      destination_port: ENDPOINT_PORT)
    summary = observe([frame])

    assert_equal 1, summary['ipv4_udp_packets']
    assert_equal 1, summary['non_endpoint_udp_packets']
    assert_equal 0, summary['endpoint_packets']
    assert_equal 0, summary['tx_ss_authenticated']
  end

  def test_results_and_object_logging_are_redacted_allowlisted_counts
    observer = new_observer
    summary = observer.consume_pcap(StringIO.new(pcap([
      udp_frame(payload: known_payload, destination_ip: ENDPOINT_IP,
                destination_port: ENDPOINT_PORT)
    ])))

    assert_equal SSObservations::COUNT_KEYS.sort, summary.keys.sort
    assert summary.values.all? { |value| value.is_a?(Integer) }
    refute_includes summary.to_s, PASSWORD
    refute_includes summary.to_s, '127.0.0.1'
    refute_includes summary.to_s, TEST_ONLY_SALT.unpack1('H*')
    refute_includes observer.inspect, PASSWORD
    refute_includes observer.inspect, 'master_key'
    assert summary.frozen?
  ensure
    observer&.close
  end

  def test_oversized_snaplen_and_non_ethernet_linktype_are_rejected
    observer = new_observer
    assert_raises(ArgumentError) do
      observer.consume_pcap(StringIO.new(pcap_header(snaplen: 65_536)))
    end
    assert_raises(ArgumentError) do
      observer.consume_pcap(StringIO.new(pcap_header(linktype: 101)))
    end
  ensure
    observer&.close
  end

  def test_cli_offline_decodes_without_reporting_configuration_or_contents
    Dir.mktmpdir('passive-observer') do |dir|
      config = File.join(dir, 'config.json')
      capture = File.join(dir, 'capture.pcap')
      File.write(config, JSON.generate('proxies' => [{ 'name' => 'SS-INLET', 'type' => 'ss',
        'cipher' => 'aes-256-gcm', 'server' => ENDPOINT_IP, 'port' => ENDPOINT_PORT, 'password' => PASSWORD }]))
      File.binwrite(capture, pcap([udp_frame(payload: known_payload, destination_ip: ENDPOINT_IP,
                                           destination_port: ENDPOINT_PORT)]))
      result = PassiveSSCapture.run(['--config', config, '--pcap', capture])
      assert_equal 'completed', result[:status]
      assert_equal 1, result.dig(:counters, 'tx_wg_type1')
      refute_includes JSON.generate(result), PASSWORD
      refute_includes JSON.generate(result), ENDPOINT_IP
      assert_equal 'unavailable', PassiveSSCapture.run(['--config', config, '--interface', 'en0;bad'])[:status]
    end
  end

  private

  def new_observer
    SSObservations.new(password: PASSWORD, endpoint_ip: ENDPOINT_IP,
                       endpoint_port: ENDPOINT_PORT)
  end

  def observe(frames)
    observer = new_observer
    observer.consume_pcap(StringIO.new(pcap(frames)))
  ensure
    observer&.close
  end

  def observe_capture(capture)
    observer = new_observer
    observer.consume_pcap(StringIO.new(capture))
  ensure
    observer&.close
  end

  def known_payload
    [KNOWN_SS_UDP_HEX].pack('H*')
  end

  def socks_payload(wireguard)
    # SOCKS5 IPv4 destination 127.0.0.1:51820 followed by opaque WG bytes.
    [1, 127, 0, 0, 1, 0xca, 0x6c].pack('C7') + wireguard
  end

  def wg_packet(type, length)
    [type].pack('V') + ("\0" * (length - 4)).b
  end

  def seal_for_test(plaintext)
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.encrypt
    cipher.key = TEST_ONLY_SUBKEY
    cipher.iv = "\0" * 12
    encrypted = cipher.update(plaintext) + cipher.final
    TEST_ONLY_SALT + encrypted + cipher.auth_tag
  end

  def udp_frame(payload:, source_ip: '192.0.2.20', destination_ip:, source_port: 52_000,
                destination_port:, fragment_bits: 0)
    udp_length = 8 + payload.bytesize
    ip_length = 20 + udp_length
    udp = [source_port, destination_port, udp_length, 0].pack('n4') + payload
    ip = [0x45, 0, ip_length, 1, fragment_bits, 64, 17, 0].pack('CCnnnCCn') +
         ipv4_bytes(source_ip) + ipv4_bytes(destination_ip)
    ("\0" * 12).b + "\x08\x00".b + ip + udp
  end

  def ipv4_bytes(address)
    address.split('.').map(&:to_i).pack('C4')
  end

  def pcap(frames, byte_order: :little, precision: :micro)
    header = pcap_header(byte_order: byte_order, precision: precision)
    records = frames.map do |frame|
      fields = [1, 0, frame.bytesize, frame.bytesize]
      record_header = fields.pack(byte_order == :little ? 'V4' : 'N4')
      record_header + frame
    end
    header + records.join
  end

  def pcap_header(byte_order: :little, precision: :micro, snaplen: 65_535, linktype: 1)
    magic = {
      [:little, :micro] => "\xd4\xc3\xb2\xa1".b,
      [:big, :micro] => "\xa1\xb2\xc3\xd4".b,
      [:little, :nano] => "\x4d\x3c\xb2\xa1".b,
      [:big, :nano] => "\xa1\xb2\x3c\x4d".b
    }.fetch([byte_order, precision])
    fields = [2, 4, 0, 0, snaplen, linktype]
    magic + fields.pack(byte_order == :little ? 'v2V4' : 'n2N4')
  end
end
