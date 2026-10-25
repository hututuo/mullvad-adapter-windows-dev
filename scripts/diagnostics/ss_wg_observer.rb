# frozen_string_literal: true

require 'ipaddr'
require 'openssl'

# Passively counts syntactically valid WireGuard packets carried by Shadowsocks
# AEAD UDP packets addressed to one explicitly configured IPv4 endpoint.
# This class never returns packet bytes, decrypted content, or endpoint details.
class SSObservations
  MAX_PACKET_SIZE = 65_535
  SS_SALT_BYTES = 32
  SS_TAG_BYTES = 16
  SS_KEY_BYTES = 32
  SS_NONCE = ("\0" * 12).b.freeze
  SS_INFO = 'ss-subkey'.b.freeze

  COUNT_KEYS = %w[
    pcap_records pcap_truncated pcap_invalid_records
    packets_malformed non_ipv4_ethernet non_udp_ipv4 fragmented_ipv4_packets
    ipv4_udp_packets non_endpoint_udp_packets ambiguous_endpoint_packets endpoint_packets
    tx_packets rx_packets
    tx_ss_authenticated rx_ss_authenticated tx_ss_auth_failed rx_ss_auth_failed
    tx_ss_malformed rx_ss_malformed tx_wg_invalid rx_wg_invalid
    tx_wg_type1 rx_wg_type1 tx_wg_type2 rx_wg_type2
    tx_wg_type3 rx_wg_type3 tx_wg_type4 rx_wg_type4
  ].freeze

  PCAP_MAGICS = {
    "\xd4\xc3\xb2\xa1".b => [:little, :micro],
    "\xa1\xb2\xc3\xd4".b => [:big, :micro],
    "\x4d\x3c\xb2\xa1".b => [:little, :nano],
    "\xa1\xb2\x3c\x4d".b => [:big, :nano]
  }.freeze

  def initialize(password:, endpoint_ip:, endpoint_port:)
    unless password.is_a?(String) && !password.empty?
      raise ArgumentError, 'password must be a non-empty string'
    end

    ip = begin
      IPAddr.new(endpoint_ip)
    rescue IPAddr::InvalidAddressError, TypeError
      nil
    end
    unless ip&.ipv4? && endpoint_ip.to_s.match?(/\A(?:\d{1,3}\.){3}\d{1,3}\z/)
      raise ArgumentError, 'endpoint must be an IPv4 address'
    end
    unless endpoint_port.is_a?(Integer) && endpoint_port.between?(1, 65_535)
      raise ArgumentError, 'endpoint port must be between 1 and 65535'
    end

    password_bytes = password.b
    @master_key = evp_bytes_to_key(password_bytes)
    @endpoint_ip = ip.hton.freeze
    @endpoint_port = endpoint_port
    @counts = COUNT_KEYS.to_h { |key| [key, 0] }
    @closed = false
  ensure
    password_bytes&.replace("\0" * password_bytes.bytesize)
  end

  # Read one classic PCAP stream incrementally. At most one bounded record is
  # held at a time; EOF inside a header or record is counted and ends the read.
  # The return value is always a fresh, frozen hash of fixed numeric counters.
  def consume_pcap(io)
    raise ArgumentError, 'input must respond to read' unless io.respond_to?(:read)
    raise IOError, 'observer is closed' if @closed

    magic = read_exact(io, 4)
    if magic.nil?
      bump('pcap_truncated')
      return summary
    end
    unless magic.bytesize == 4
      bump('pcap_truncated')
      return summary
    end
    format = PCAP_MAGICS[magic]
    raise ArgumentError, 'unsupported classic PCAP format' unless format

    byte_order, timestamp_precision = format
    global_rest = read_exact(io, 20)
    unless global_rest&.bytesize == 20
      bump('pcap_truncated')
      return summary
    end

    fields = unpack_words(global_rest, byte_order)
    major, minor, _zone, _sigfigs, snaplen, network = fields
    unless major == 2 && minor == 4 && snaplen.positive? && snaplen <= MAX_PACKET_SIZE && network == 1
      raise ArgumentError, 'unsupported classic PCAP header'
    end

    loop do
      record_header = read_exact(io, 16)
      break if record_header.nil?
      unless record_header.bytesize == 16
        bump('pcap_truncated')
        break
      end

      _seconds, fraction, included_length, original_length = unpack_record_words(record_header, byte_order)
      fraction_limit = timestamp_precision == :nano ? 1_000_000_000 : 1_000_000
      record_invalid = included_length > MAX_PACKET_SIZE ||
                       original_length > MAX_PACKET_SIZE ||
                       included_length > snaplen ||
                       original_length < included_length ||
                       fraction >= fraction_limit
      if included_length > MAX_PACKET_SIZE
        bump('pcap_invalid_records')
        break
      end

      frame = read_exact(io, included_length)
      unless frame&.bytesize == included_length
        bump('pcap_truncated')
        break
      end

      bump('pcap_records')
      if record_invalid
        bump('pcap_invalid_records')
        next
      end

      observe_ethernet(frame)
    end

    summary
  end

  def summary
    COUNT_KEYS.to_h { |key| [key, @counts.fetch(key)] }.freeze
  end

  # Wipe the retained password-derived master key when the caller is done.
  def close
    return if @closed

    @master_key&.replace("\0" * @master_key.bytesize)
    @master_key = nil
    @closed = true
    nil
  end

  # Object logging must not expose instance variables, including endpoint/key.
  def inspect
    '#<SSObservations>'
  end

  alias to_s inspect

  private

  def evp_bytes_to_key(password)
    output = ''.b
    previous = ''.b
    while output.bytesize < SS_KEY_BYTES
      digest = OpenSSL::Digest::MD5.digest(previous + password)
      previous.replace("\0" * previous.bytesize)
      previous = digest
      output << digest
    end
    output.byteslice(0, SS_KEY_BYTES)
  ensure
    output&.replace("\0" * output.bytesize)
    previous&.replace("\0" * previous.bytesize)
  end

  def hkdf_subkey(salt)
    prk = OpenSSL::HMAC.digest('SHA1', salt, @master_key)
    output = ''.b
    previous = ''.b
    counter = 1
    while output.bytesize < SS_KEY_BYTES
      next_block = OpenSSL::HMAC.digest('SHA1', prk, previous + SS_INFO + [counter].pack('C'))
      previous.replace("\0" * previous.bytesize)
      previous = next_block
      output << next_block
      counter += 1
    end
    output.byteslice(0, SS_KEY_BYTES)
  ensure
    prk&.replace("\0" * prk.bytesize)
    output&.replace("\0" * output.bytesize)
    previous&.replace("\0" * previous.bytesize)
  end

  def read_exact(io, length)
    return ''.b if length.zero?

    buffer = ''.b
    while buffer.bytesize < length
      chunk = io.read(length - buffer.bytesize)
      return buffer.empty? ? nil : buffer if chunk.nil? || chunk.empty?

      buffer << chunk.b
    end
    buffer
  end

  def unpack_words(bytes, byte_order)
    bytes.unpack(byte_order == :little ? 'v2V4' : 'n2N4')
  end

  def unpack_record_words(bytes, byte_order)
    bytes.unpack(byte_order == :little ? 'V4' : 'N4')
  end

  def observe_ethernet(frame)
    if frame.bytesize < 14
      bump('packets_malformed')
      return
    end
    unless frame.byteslice(12, 2).unpack1('n') == 0x0800
      bump('non_ipv4_ethernet')
      return
    end
    if frame.bytesize < 34
      bump('packets_malformed')
      return
    end

    ip_offset = 14
    version_ihl = frame.getbyte(ip_offset)
    version = version_ihl >> 4
    header_length = (version_ihl & 0x0f) * 4
    if version != 4 || header_length < 20 || frame.bytesize < ip_offset + header_length
      bump('packets_malformed')
      return
    end

    total_length = frame.byteslice(ip_offset + 2, 2).unpack1('n')
    if total_length < header_length + 8 || frame.bytesize < ip_offset + total_length
      bump('packets_malformed')
      return
    end
    unless frame.getbyte(ip_offset + 9) == 17
      bump('non_udp_ipv4')
      return
    end

    fragment_bits = frame.byteslice(ip_offset + 6, 2).unpack1('n')
    if (fragment_bits & 0x3fff) != 0
      bump('fragmented_ipv4_packets')
      return
    end

    udp_offset = ip_offset + header_length
    source_port, destination_port, udp_length = frame.byteslice(udp_offset, 6).unpack('n3')
    unless udp_length >= 8 && udp_length == total_length - header_length
      bump('packets_malformed')
      return
    end

    bump('ipv4_udp_packets')
    source_ip = frame.byteslice(ip_offset + 12, 4)
    destination_ip = frame.byteslice(ip_offset + 16, 4)
    source_matches = source_ip == @endpoint_ip && source_port == @endpoint_port
    destination_matches = destination_ip == @endpoint_ip && destination_port == @endpoint_port
    if source_matches && destination_matches
      bump('ambiguous_endpoint_packets')
      return
    elsif source_matches
      direction = 'rx'
    elsif destination_matches
      direction = 'tx'
    else
      bump('non_endpoint_udp_packets')
      return
    end

    bump('endpoint_packets')
    bump("#{direction}_packets")
    payload_offset = udp_offset + 8
    payload = frame.byteslice(payload_offset, udp_length - 8) || ''.b
    observe_shadowsocks(direction, payload)
  end

  def observe_shadowsocks(direction, payload)
    if payload.bytesize < SS_SALT_BYTES + SS_TAG_BYTES
      bump("#{direction}_ss_malformed")
      return
    end

    salt = payload.byteslice(0, SS_SALT_BYTES)
    ciphertext_length = payload.bytesize - SS_SALT_BYTES - SS_TAG_BYTES
    ciphertext = payload.byteslice(SS_SALT_BYTES, ciphertext_length)
    tag = payload.byteslice(-SS_TAG_BYTES, SS_TAG_BYTES)
    subkey = hkdf_subkey(salt)
    candidate = ''.b
    plaintext = nil

    begin
      cipher = OpenSSL::Cipher.new('aes-256-gcm')
      cipher.decrypt
      cipher.key = subkey
      cipher.iv = SS_NONCE
      cipher.auth_tag = tag
      candidate = ciphertext.empty? ? ''.b : cipher.update(ciphertext)
      candidate << cipher.final
      plaintext = candidate
      candidate = ''.b
    rescue OpenSSL::Cipher::CipherError
      bump("#{direction}_ss_auth_failed")
      return
    ensure
      subkey&.replace("\0" * subkey.bytesize)
      candidate&.replace("\0" * candidate.bytesize)
    end

    bump("#{direction}_ss_authenticated")
    begin
      wireguard_type = wireguard_type_from_socks_payload(plaintext)
      if wireguard_type
        bump("#{direction}_wg_type#{wireguard_type}")
      else
        bump("#{direction}_wg_invalid")
      end
    ensure
      plaintext&.replace("\0" * plaintext.bytesize)
    end
  end

  def wireguard_type_from_socks_payload(plaintext)
    return nil if plaintext.nil? || plaintext.empty?

    socks_type = plaintext.getbyte(0)
    payload_offset = case socks_type
                     when 1
                       1 + 4 + 2
                     when 3
                       return nil if plaintext.bytesize < 2

                       domain_length = plaintext.getbyte(1)
                       return nil if domain_length.zero?

                       1 + 1 + domain_length + 2
                     when 4
                       1 + 16 + 2
                     else
                       return nil
                     end
    return nil if plaintext.bytesize < payload_offset + 4

    wg_length = plaintext.bytesize - payload_offset
    message_type = plaintext.byteslice(payload_offset, 4).unpack1('V')
    # The upper three bytes of the little-endian type word are reserved zeroes.
    return nil unless plaintext.getbyte(payload_offset + 1).zero? &&
                      plaintext.getbyte(payload_offset + 2).zero? &&
                      plaintext.getbyte(payload_offset + 3).zero?

    case message_type
    when 1
      wg_length == 148 ? 1 : nil
    when 2
      wg_length == 92 ? 2 : nil
    when 3
      wg_length == 64 ? 3 : nil
    when 4
      # Do not require 16-byte padding: implementations can cap padding at MTU.
      wg_length >= 32 ? 4 : nil
    else
      nil
    end
  end

  def bump(key)
    @counts.fetch(key) { raise 'internal counter is not allowlisted' }
    @counts[key] += 1
  end
end
