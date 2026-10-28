# frozen_string_literal: true

require 'ipaddr'
require 'json'
require 'open3'
require 'securerandom'
require 'uri'

# Selects a credential-free route to Mullvad's official API before account
# requests are made. The selected route is returned to the caller; this class
# never sends account credentials or retries an account/device operation.
class AccountApiRoutes
  API_HOST = 'api.mullvad.net'
  API_ADDRESSES_URL = "https://#{API_HOST}/app/v1/api-addrs".freeze
  # Official versioned seed mirrored by core/crates/mullvad-api/src/bootstrap.rs.
  OFFICIAL_SEED = '45.83.223.196:443'.freeze
  API_PORT = 443
  MAX_ADDRESSES = 16
  MAX_CACHE_BYTES = 16 * 1024
  MAX_DIRECT_CANDIDATES = 4
  MAX_TOTAL_SECONDS = 12.0
  MAX_ATTEMPT_SECONDS = 3.0

  class Error < StandardError
    attr_reader :code

    def initialize(code = 'route_unavailable')
      @code = code
      super('Mullvad account API route unavailable')
    end
  end

  def initialize(proxy:, cache_path:, excluded_proxy_ports: [], runner: nil, clock: nil)
    @proxy = proxy
    @cache_path = File.expand_path(cache_path.to_s)
    @excluded_proxy_ports = Array(excluded_proxy_ports).filter_map do |port|
      value = Integer(port)
      value if value.between?(1, 65_535)
    rescue ArgumentError, TypeError
      nil
    end.uniq.freeze
    @runner = runner || method(:run_curl)
    @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
  end

  # Returns curl route arguments, the route kind, and only addresses accepted
  # from a successful TLS-verified official api-addrs response.
  def select
    cache, cache_writable = read_cache
    started_at = @clock.call
    routes = []
    last_success = cache[:last_success]
    routes << direct_route(last_success) if last_success
    proxy_route = configured_proxy_route
    routes << proxy_route if proxy_route
    direct_candidates_for(cache, excluding: last_success).each { |address| routes << direct_route(address) }
    routes << system_route

    direct_count = 0
    routes.each do |route|
      if route[:address]
        break if direct_count >= MAX_DIRECT_CANDIDATES

        direct_count += 1
      end
      remaining = MAX_TOTAL_SECONDS - (@clock.call - started_at)
      break unless remaining.positive?

      timeout = [MAX_ATTEMPT_SECONDS, remaining].min
      begin
        body = request_addresses(route[:args], timeout)
        raise Error if @clock.call - started_at > MAX_TOTAL_SECONDS

        addresses = parse_addresses(body)
        persist_cache(cache, addresses, route[:address], cache_writable)
        return { args: route[:args].dup, kind: route[:kind], addresses: addresses.dup }
      rescue StandardError
        # A failed route or invalid reply is safe to discard. Do not expose curl,
        # proxy, or response details through this selector's errors.
      end
    end

    raise Error
  end

  private

  def direct_candidates_for(cache, excluding: nil)
    ordered = [OFFICIAL_SEED] + cache[:addresses]
    ordered = ordered.compact.uniq.reject { |address| address == excluding }
    slots = MAX_DIRECT_CANDIDATES - (excluding ? 1 : 0)
    ordered.first([slots, 0].max)
  end

  def configured_proxy_route
    raw = @proxy.to_s
    return if raw.empty?

    uri = URI.parse(raw)
    return unless uri.is_a?(URI::HTTP) && uri.scheme == 'http' && uri.userinfo.nil? &&
                  uri.query.nil? && uri.fragment.nil? && ['', '/'].include?(uri.path.to_s)
    return if @excluded_proxy_ports.include?(uri.port)

    address = IPAddr.new(uri.host.to_s)
    return unless loopback_address?(address)

    { kind: 'configured_proxy', args: ['--proxy', raw, '--noproxy', ''] }
  rescue URI::InvalidURIError, IPAddr::InvalidAddressError
    nil
  end

  def direct_route(address)
    ip = if address.start_with?('[')
           address[/\A\[([^\]]+)\]:443\z/, 1]
         else
           address.sub(/:443\z/, '')
         end
    raise Error unless ip

    curl_address = ip.include?(':') ? "[#{ip}]" : ip
    { kind: address == OFFICIAL_SEED ? 'direct_seed' : 'direct_cached', address: address,
      args: ['--resolve', "#{API_HOST}:#{API_PORT}:#{curl_address}", '--proxy', '', '--noproxy', '*'] }
  end

  def system_route
    { kind: 'system_https', args: ['--proxy', '', '--noproxy', '*'] }
  end

  def request_addresses(route_args, timeout)
    argv = ['/usr/bin/curl', '-q', '--silent', '--show-error', '--request', 'GET',
            '--max-time', format('%.3f', timeout),
            '--connect-timeout', format('%.3f', [timeout, 2.0].min),
            '--max-filesize', MAX_CACHE_BYTES.to_s,
            *route_args, '--write-out', "\n%{http_code}", API_ADDRESSES_URL]
    stdout, _stderr, status = @runner.call(argv, timeout: timeout)
    raise Error unless command_succeeded?(status)

    body, separator, code = stdout.to_s.rpartition("\n")
    raise Error unless separator == "\n" && code == '200' && body.bytesize <= MAX_CACHE_BYTES

    body
  end

  def run_curl(argv, timeout:)
    # curl's own request deadline bounds the subprocess; Timeout around
    # capture3 would leave a child process running after the Ruby timeout.
    raise Error unless timeout.positive? && timeout <= MAX_ATTEMPT_SECONDS

    Open3.capture3(*argv)
  end

  def command_succeeded?(status)
    status.respond_to?(:success?) ? status.success? : status.to_i.zero?
  rescue StandardError
    false
  end

  def parse_addresses(body)
    raise Error if body.bytesize > MAX_CACHE_BYTES

    values = JSON.parse(body)
    raise Error unless values.is_a?(Array) && values.length.between?(1, MAX_ADDRESSES)

    addresses = values.map { |value| parse_socket_address(value) }.uniq
    raise Error if addresses.empty?

    addresses
  rescue JSON::ParserError, ArgumentError, TypeError
    raise Error
  end

  def parse_socket_address(value)
    raise Error unless value.is_a?(String) && value.bytesize <= 128

    match = if value.start_with?('[')
              value.match(/\A\[([0-9A-Fa-f:]+)\]:(\d{1,5})\z/)
            else
              value.match(/\A((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\z/)
            end
    raise Error unless match && Integer(match[2], 10) == API_PORT

    literal = match[1]
    address = IPAddr.new(literal)
    raise Error unless public_address?(address)
    raise Error if address.ipv4? && address.to_s != literal

    address_string(address)
  rescue IPAddr::InvalidAddressError, ArgumentError
    raise Error
  end

  def public_address?(address)
    if address.ipv4?
      denied = %w[
        0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8
        169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24
        192.88.99.0/24 192.168.0.0/16 198.18.0.0/15
        198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4
      ]
      denied.none? { |range| IPAddr.new(range).include?(address) }
    else
      IPAddr.new('2000::/3').include?(address) &&
        !IPAddr.new('2001:db8::/32').include?(address)
    end
  end

  def loopback_address?(address)
    address.ipv4? ? IPAddr.new('127.0.0.0/8').include?(address) : address == IPAddr.new('::1')
  end

  def address_string(address)
    address.ipv6? ? "[#{address}]:#{API_PORT}" : "#{address}:#{API_PORT}"
  end

  def read_cache
    parent_state = safe_cache_parent?
    return [empty_cache, false] unless parent_state

    state = cache_file_state
    return [empty_cache, true] if state == :missing
    return [empty_cache, false] unless state.is_a?(File::Stat)

    bytes = nil
    flags = File::RDONLY | File::NOFOLLOW
    File.open(@cache_path, flags) do |file|
      opened = file.stat
      return [empty_cache, false] unless same_file?(state, opened) && safe_cache_stat?(opened)

      bytes = file.read(MAX_CACHE_BYTES + 1)
    end
    return [empty_cache, false] if bytes.nil? || bytes.bytesize > MAX_CACHE_BYTES

    value = JSON.parse(bytes)
    return [empty_cache, false] unless value.is_a?(Hash) && (value.keys - %w[addresses last_success]).empty?
    return [empty_cache, false] unless value['addresses'].is_a?(Array) && value['addresses'].length <= MAX_ADDRESSES

    addresses = value['addresses'].map { |item| parse_socket_address(item) }.uniq
    last_success = value['last_success'] && parse_socket_address(value['last_success'])
    [{ addresses: addresses, last_success: last_success }, true]
  rescue StandardError
    # An unsafe or malformed cache is neither used nor overwritten. Discovery
    # can still proceed through the independent configured/direct routes.
    [empty_cache, false]
  end

  def empty_cache
    { addresses: [], last_success: nil }
  end

  def persist_cache(previous, addresses, direct_address, writable)
    return unless writable && safe_cache_parent?

    parsed = addresses.map { |address| parse_socket_address(address) }
    previous_success = previous[:last_success]
    last_success = direct_address || (parsed.include?(previous_success) ? previous_success : nil)
    bytes = JSON.generate(addresses: parsed, last_success: last_success)
    return if bytes.bytesize > MAX_CACHE_BYTES

    existing = cache_file_state
    return unless existing == :missing || (existing.is_a?(File::Stat) && safe_cache_stat?(existing))

    temporary = "#{@cache_path}.pending-#{Process.pid}-#{SecureRandom.hex(8)}"
    File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
      file.write(bytes)
      file.flush
      file.fsync
    end
    current = cache_file_state
    return unless current == :missing || (current.is_a?(File::Stat) && safe_cache_stat?(current))

    File.rename(temporary, @cache_path)
    begin
      File.open(File.dirname(@cache_path), File::RDONLY) { |directory| directory.fsync }
    rescue SystemCallError, IOError
      # The atomic cache rename succeeded. Directory fsync support varies.
    end
  rescue StandardError
    # Discovery success must not depend on this optional cache write.
    nil
  ensure
    File.unlink(temporary) if defined?(temporary) && temporary && File.exist?(temporary)
  end

  def cache_file_state
    stat = File.lstat(@cache_path)
    return nil unless safe_cache_stat?(stat)

    stat
  rescue Errno::ENOENT
    :missing
  rescue SystemCallError
    nil
  end

  def safe_cache_stat?(stat)
    stat.file? && !stat.symlink? && stat.uid == Process.uid && stat.nlink == 1 &&
      (stat.mode & 0o077).zero? && (stat.mode & 0o400).positive? && stat.size <= MAX_CACHE_BYTES
  end

  def same_file?(left, right)
    left.dev == right.dev && left.ino == right.ino && left.uid == right.uid && left.nlink == right.nlink
  end

  def safe_cache_parent?
    directory = File.dirname(@cache_path)
    stat = File.lstat(directory)
    stat.directory? && !stat.symlink? && stat.uid == Process.uid && (stat.mode & 0o022).zero?
  rescue SystemCallError
    false
  end
end
