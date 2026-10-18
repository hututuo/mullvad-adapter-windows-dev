#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'yaml'
require 'socket'
require 'net/http'
require 'uri'
require 'open3'
require 'fileutils'
require 'optparse'
require 'time'
require 'date'
require 'ipaddr'
require 'securerandom'
require 'timeout'
require 'digest'
require 'base64'
require 'resolv'

Encoding.default_external = Encoding::UTF_8
Encoding.default_internal = Encoding::UTF_8

class MullvadAdapter
  class LocalNetworkInterrupted < StandardError; end
  # Local decoder only: never monkey-patch Resolv or allocate globally cached
  # resource classes from response-controlled type/class numbers.
  class DnsCanaryDecoder < Resolv::DNS::Message::MessageDecoder
    def get_label
      label = super
      raise Resolv::DNS::DecodeError, 'invalid DNS label length' unless label.to_s.bytesize.between?(1, 63)
      label
    end

    def get_name
      name = super
      sizes = name.to_a.map { |label| label.to_s.bytesize }
      raise Resolv::DNS::DecodeError, 'DNS name too long' if sizes.sum + sizes.length + 1 > 255
      name
    end

    def get_bytes(length = @limit - @index)
      raise Resolv::DNS::DecodeError, 'invalid DNS byte length' if length.negative?
      bytes = super(length)
      raise Resolv::DNS::DecodeError, 'truncated DNS bytes' unless bytes && bytes.bytesize == length
      bytes
    end

    def get_rr
      owner = get_name
      type, klass, ttl = get_unpack('nnN')
      typeclass = Resolv::DNS::Resource::ClassHash[[type, klass]]
      resource = get_length16 do |length|
        if type == 41
          # OPT options have a bounded code/length/value framing (RFC6891).
          remaining = length
          while remaining.positive?
            raise Resolv::DNS::DecodeError, 'truncated OPT option' if remaining < 4
            _code, size = get_unpack('nn')
            remaining -= 4
            raise Resolv::DNS::DecodeError, 'truncated OPT option data' if size > remaining
            get_bytes(size)
            remaining -= size
          end
          nil
        elsif klass == 1 && [64, 65].include?(type)
          # SVCB/HTTPS target names and param envelopes are checked locally.
          # The stdlib SvcParam ClassHash default allocates permanent classes.
          get_unpack('n') # priority
          get_name
          previous_key = -1
          while @index < @limit
            key, size = get_unpack('nn')
            raise Resolv::DNS::DecodeError, 'unordered SvcParam keys' if key <= previous_key
            get_bytes(size)
            previous_key = key
          end
          nil
        elsif typeclass
          typeclass.decode_rdata(self)
        else
          data = get_bytes(length)
          raise Resolv::DNS::DecodeError, 'truncated opaque DNS data' unless data && data.bytesize == length
          nil
        end
      end
      [owner, ttl, resource, type]
    rescue StandardError
      raise Resolv::DNS::DecodeError, 'invalid DNS resource record'
    end
  end
  API_URL = 'https://api.mullvad.net/app/v1/relays'
  EXTRA_SS_PORT = 20_484
  DIRECT_IPV4_PORT = 51_820
  DIRECT_IPV6_PORT = 33_431
  IP_CANARY = 'https://1.1.1.1/cdn-cgi/trace'
  HOST_CANARY = 'https://www.gstatic.com/generate_204'
  INNER_DNS_BREAKER_THRESHOLD = 2
  INNER_DNS_BREAKER_WINDOW = 180
  INNER_DNS_BREAKER_COOLDOWN = 300
  TRANSPORT_MODES = %w[ss ipv6 ipv4].freeze
  TRANSPORT_PREFERENCES = (%w[auto] + TRANSPORT_MODES).freeze
  AUTO_TRANSPORT_ORDER = %w[ss ipv6 ipv4].freeze
  DEFAULT_TRANSPORT_PREFERENCE = 'ss'
  BUILD_ID = '20261005-local-network-recovery-1'
  SOURCE_SHA256 = Digest::SHA256.file(__FILE__).hexdigest
  # Keep recent history by capacity, not by calendar day: two files together
  # never exceed 20 MB (decimal), retaining multiple days at normal event rates.
  EVENT_LOG_FILE_BYTES = 10_000_000

  SLOT_CONFIG = {
    'a' => { mixed: 17_910, controller: 17_911 },
    'b' => { mixed: 17_920, controller: 17_921 }
  }.freeze

  DEFAULTS = {
    state_dir: File.expand_path('~/Library/Application Support/MullvadLocalAdapter'),
    profile: File.expand_path('~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/profiles/iKuuuV2Stable.yaml'),
    core: '/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo',
    pq_helper: File.basename(__FILE__) == 'mullvad-local-adapter' ? File.join(__dir__, 'mullvad-pq-negotiator') : File.expand_path('../helpers/pq-negotiator/bin/mullvad-pq-negotiator', __dir__),
    api_host: '127.0.0.1',
    api_port: 17_891,
    front_mixed: 17_890,
    front_controller: 17_892,
    bootstrap_proxy: 'http://127.0.0.1:17893',
    default_relay: 'us-sea-wg-401',
    drain_timeout: 1_800,
    metadata_ttl: 21_600,
    health_interval: 30,
    health_fail_threshold: 2,
    # 已经失败、但还没到判定阈值时，不要傻等下一个 30 秒。
    # front 故障会主动唤醒；首次失败后的复检等待压到 2 秒。
    health_recheck_interval: 2,
    recovery_cooldown: 30,
    attempt_budget: 35,
    recovery_batch_size: 2,
    recovery_round_budget: 45,
    local_network_interval: 2,
    local_network_settle: 2,
    clash_socket: "/var/run/clash-verge-service/users/#{Process.uid}/verge-mihomo.sock",
    supervisor_interval: 5,
    front_data_probe_interval: 10,
    recovery_quarantine: 900
  }.freeze

  def initialize(options)
    @options = DEFAULTS.merge(options)
    @slot_config = if @options[:worker_port_base]
                     base = Integer(@options[:worker_port_base])
                     { 'a' => { mixed: base, controller: base + 1 }, 'b' => { mixed: base + 10, controller: base + 11 } }
                   else
                     SLOT_CONFIG
                   end
    @state_dir = @options[:state_dir]
    @log_dir = @options[:log_dir] || (@state_dir == DEFAULTS[:state_dir] ? File.expand_path('~/Library/Logs/MullvadLocalAdapter') : File.join(@state_dir, 'logs'))
    @log_mutex = Mutex.new
    @mutex = Mutex.new
    @switch_mutex = Mutex.new
    @speed_test_mutex = Mutex.new
    @action_gate_mutex = Mutex.new
    @history_mutex = Mutex.new
    @ss_endpoint_mutex = Mutex.new
    @metadata_mutex = Mutex.new
    @health_wait_mutex = Mutex.new
    @health_cv = ConditionVariable.new
    @health_wake_pending = false
    @local_network_probe_mutex = Mutex.new
    @local_network_monitor_started = false
    @local_network_settle_until = 0
    @last_network_path = nil
    @account_mutex = Mutex.new
    @account_number = nil
    @account_data = nil
    @account_token = nil
    @account_capability = nil
    @city_mutex = Mutex.new
    @favorite_cities = []
    @selected_city = nil
    @city_probes = {}
    @last_city_maintenance_at = Time.at(0)
    @stop_requested = false
    @metadata = nil
    @metadata_fetched_at = nil
    @last_metadata_validation_warnings = []
    @inner_dns_observations = []
    @health_fail_streak = 0
    @dns_fail_streak = 0
    @last_auto_recovery_at = Time.at(0)
    @front_probe_failures = 0
    @front_data_probe_failures = 0
    @last_front_data_probe_at = Time.at(0)
    @action_pending = nil
    @operations = {}
    @last_recovery_generation = nil
    @last_disconnected_retry_at = Time.now
    @recovery_quarantine = {}
    @template = nil
    @protection_profile = { multihop: false, entry_city: nil, post_quantum: false }.freeze
    @protection_error = nil
    @front_pid = nil
    @workers = {}
    @worker_state_tokens = {}
    @speed_tests = {}
    @relay_history = {}
    @ss_endpoint_history = {}
    @server = nil
    @metrics = {
      started_at: Time.now.iso8601,
      metadata_refreshes: 0,
      metadata_refresh_failures: 0,
      metadata_invalid_relays: 0,
      worker_starts: 0,
      worker_start_failures: 0,
      switches: 0,
      failed_switches: 0,
      drain_completions: 0,
      drain_forced: 0,
      same_relay_reconnects: 0,
      front_connections_total: 0,
      active_connections: 0,
      draining_connections: 0,
      health_checks: 0,
      health_wg_failures: 0,
      health_dns_failures: 0,
      auto_recovery_attempts: 0,
      auto_recovery_failures: 0,
      inner_dns_breaker_trips: 0,
      inner_dns_breaker_suppressed: 0,
      speed_tests: 0,
      speed_test_failures: 0,
      front_restarts: 0,
      front_selector_repairs: 0,
      front_data_probe_failures: 0,
      worker_crashes: 0,
      worker_crash_recoveries: 0,
      drain_preemptions: 0,
      failed_path_retirements: 0,
      persistence_failures: 0
    }
    @state = {
      status: 'starting',
      build_id: BUILD_ID,
      source_sha256: SOURCE_SHA256,
      generation: 0,
      local_network: { status: 'unknown', paused: false, recovery_pending: false, epoch: 0,
                       source: 'not-observed', checked_at: nil, detail: '本机链路尚未检查' },
      active_slot: nil,
      active_relay: nil,
      active_transport: nil,
      active_transport_mode: nil,
      transport_preference: DEFAULT_TRANSPORT_PREFERENCE,
      relay_liveness: 'unknown',
      service_readiness: 'unknown',
      metadata: { live: false, cache: false, source: 'none', age_seconds: nil, error: nil, fetched_at: nil, validation_warnings: [] },
      health: {
        interval_seconds: @options[:health_interval], fail_threshold: @options[:health_fail_threshold],
        consecutive_wg_failures: 0, consecutive_dns_failures: 0,
        last_check_at: nil, last_recovery_at: nil
      },
      front: {
        mixed_port: @options[:front_mixed], controller_port: @options[:front_controller], ready: false,
        data_path: { status: 'unknown', detail: 'not checked', checked_at: nil }
      },
      api: { host: @options[:api_host], port: @options[:api_port] },
      persistence: {
        status: 'ok', relay: 'ok', transport_preference: 'ok', cities: 'ok',
        last_error: nil, last_error_at: nil
      },
      routing_policy: {
        owner: 'adapter',
        ingress_owner: 'main-clash',
        ingress_target: 'Mullvad节点 -> Mullvad-本地适配器',
        new_connections: 'adapter-front-active-worker',
        established_connections: 'graceful-drain',
        failed_path_connections: 'retire-after-replacement-ready',
        repeat_switch: 'preempt-oldest-drain',
        max_draining_workers: 1,
        last_event: nil,
        last_event_at: nil,
        last_preempted_connections: 0
      },
      workers: {},
      dns: {
        bootstrap: { status: 'unknown', detail: 'not checked' },
        inner: { status: 'unknown', detail: 'not checked' },
        clash_global: { status: 'external', detail: 'owned by main Clash; adapter does not replace it' },
        inner_breaker: { status: 'closed', observed_relays: [], threshold: INNER_DNS_BREAKER_THRESHOLD, until: nil, detail: 'no common inner-DNS failure detected' }
      },
      last_canary: nil,
      last_error: nil,
      updated_at: Time.now.iso8601
    }
  end

  def run
    prepare_state_dir
    load_relay_history
    load_ss_endpoint_history
    load_template
    load_account_manager
    load_cached_metadata
    load_city_workspace
    load_protection_profile
    trap_signals
    start_api_server
    begin
      ensure_front
    rescue StandardError => e
      record_error("front startup failed; supervisor will retry: #{e.class}: #{e.message}")
    end
    start_connection_monitor
    start_local_network_monitor
    start_control_plane_monitor
    start_active_health_monitor
    start_runtime_supervisor
    start_city_maintenance
    Thread.new do
      begin
        next if local_network_paused?
        refresh_metadata unless @metadata
        startup_relay = load_persisted_relay || @options[:default_relay]
        startup_transport = load_persisted_transport_preference || DEFAULT_TRANSPORT_PREFERENCE
        activate_startup_with_fallback(startup_relay, startup_transport, reason: 'startup')
      rescue StandardError => e
        record_error("startup activation failed: #{e.class}: #{e.message}")
      end
    end

    sleep 0.2 until @stop_requested
  ensure
    shutdown
  end

  private

  def prepare_state_dir
    FileUtils.mkdir_p(@state_dir)
    File.chmod(0o700, @state_dir)
    %w[front slots].each do |name|
      path = File.join(@state_dir, name)
      FileUtils.mkdir_p(path)
      File.chmod(0o700, path)
    end
    @slot_config.keys.each do |slot|
      path = slot_dir(slot)
      FileUtils.mkdir_p(path)
      File.chmod(0o700, path)
    end
  end

  def template_path
    File.join(@state_dir, 'wireguard-template.json')
  end

  def load_template
    if File.file?(template_path)
      @template = JSON.parse(File.read(template_path))
    else
      doc = YAML.load_file(@options[:profile]) || {}
      proxies = Array(doc['proxies'])
      candidate = proxies.find do |proxy|
        proxy.is_a?(Hash) && proxy['type'].to_s == 'wireguard' && proxy['name'].to_s.end_with?('-SS')
      end
      raise 'No active Mullvad *-SS WireGuard template found in source profile and no adapter template cache exists' unless candidate

      keep = %w[ip ipv6 private-key pre-shared-key allowed-ips reserved udp]
      @template = candidate.select { |key, _| keep.include?(key.to_s) }
      write_json_private(template_path, @template, secret: true)
    end

    raise 'WireGuard template has no private-key' if @template['private-key'].to_s.empty?
    raise 'WireGuard template has no tunnel ip' if @template['ip'].to_s.empty?
    @template['allowed-ips'] = ['0.0.0.0/0'] if Array(@template['allowed-ips']).empty?
  end

  # Account management is independent of the tunnel lifecycle. Verifying an
  # account never registers/replaces keys or starts the official VPN daemon.
  class AccountError < StandardError
    attr_reader :code
    def initialize(code, message)
      @code = code
      super(message)
    end
  end

  def load_account_manager
    capability_path = File.join(@state_dir, 'account-capability')
    @account_capability = File.file?(capability_path) ? File.read(capability_path).strip : SecureRandom.hex(32)
    @account_capability = SecureRandom.hex(32) unless @account_capability.match?(/\A[0-9a-f]{64}\z/)
    atomic_account_file(capability_path, @account_capability)
    path = File.join(@state_dir, 'account.json')
    @account_number = normalize_account(JSON.parse(File.read(path))['account_number']) if File.file?(path)
  rescue StandardError
    @account_number = @account_data = @account_token = nil
    # Account metadata must never prevent the legacy tunnel from starting.
    log_event('account-manager-unavailable', detail: 'local account metadata could not be loaded; tunnel identity retained')
  end

  def atomic_account_file(path, content)
    tmp = path + ".tmp-#{SecureRandom.hex(8)}"
    File.open(tmp, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
      file.write(content)
      file.flush
      file.fsync
    end
    File.rename(tmp, path)
  ensure
    FileUtils.rm_f(tmp) if defined?(tmp) && tmp
  end

  def normalize_account(value)
    number = value.to_s.delete(" \t\r\n-")
    raise AccountError.new('invalid_account', '账号应为 16 位数字；请从 Mullvad 账号页复制') unless number.match?(/\A\d{16}\z/)
    number
  end

  # RFC 7748 X25519 base-point multiplication, used only to identify an
  # already-configured key. No encryption or new key generation uses this.
  # Big integers are not constant-time; this local identification runs once
  # per account action, never on untrusted key input or over a public socket.
  def template_public_key(private_key = @template.fetch('private-key'))
    bytes = Base64.strict_decode64(private_key).bytes
    raise AccountError.new('invalid_key', '当前 WireGuard 私钥格式无效') unless bytes.length == 32
    bytes[0] &= 248
    bytes[31] = (bytes[31] & 127) | 64
    scalar = bytes.each_with_index.sum { |byte, i| byte << (8 * i) }
    prime = (1 << 255) - 19
    x2, z2, x3, z3, swap = 1, 0, 9, 1, 0
    254.downto(0) do |bit|
      k = (scalar >> bit) & 1
      swap ^= k
      x2, x3 = x3, x2 if swap == 1
      z2, z3 = z3, z2 if swap == 1
      swap = k
      a, b = (x2 + z2) % prime, (x2 - z2) % prime
      aa, bb = a * a % prime, b * b % prime
      e = (aa - bb) % prime
      c, d = (x3 + z3) % prime, (x3 - z3) % prime
      da, cb = d * a % prime, c * b % prime
      x3, z3 = (da + cb)**2 % prime, 9 * (da - cb)**2 % prime
      x2, z2 = aa * bb % prime, e * (aa + 121665 * e) % prime
    end
    x2, x3 = x3, x2 if swap == 1
    z2, z3 = z3, z2 if swap == 1
    result = x2 * z2.pow(prime - 2, prime) % prime
    Base64.strict_encode64(Array.new(32) { |i| (result >> (8 * i)) & 255 }.pack('C*'))
  rescue KeyError, ArgumentError
    raise AccountError.new('invalid_key', '当前 WireGuard 私钥格式无效')
  end

  def account_snapshot
    pubkey = template_public_key
    data = @account_data || {}
    devices = Array(data[:devices]).map do |device|
      { id: device['id'], name: device['name'], pubkey: device['pubkey'], created: device['created'],
        current: device['pubkey'] == pubkey }
    end
    { signed_in: !@account_number.nil?, verified: !@account_data.nil?,
      account_suffix: @account_number&.slice(-4, 4), expiry: data[:expiry],
      checked_at: data[:checked_at], public_key: pubkey,
      device_match: @account_data.nil? ? 'unknown' : (devices.any? { |d| d[:current] } ? 'matched' : 'unmatched'),
      devices: devices, account_fingerprint: @account_number && Digest::SHA256.hexdigest(@account_number) }
  end

  def account_refresh(number = @account_number)
    raise AccountError.new('not_signed_in', '请先输入 Mullvad 账号') unless number
    account = account_api('GET', 'accounts/v1/accounts/me', number: number)
    devices = account_api('GET', 'accounts/v1/devices', number: number)
    unless account.is_a?(Hash) && account['expiry'].is_a?(String) && devices.is_a?(Array) &&
           devices.all? { |d| d.is_a?(Hash) && d['id'].is_a?(String) && d['name'].is_a?(String) && d['pubkey'].is_a?(String) }
      raise AccountError.new('invalid_response', '官方账号接口格式已变化；未保存新登录')
    end
    { expiry: account['expiry'], devices: devices, checked_at: Time.now.iso8601 }
  end

  def account_api(method, path, number:, payload: nil, expected_status: nil)
    if !@account_token || @account_token[:number] != number || Time.now >= @account_token[:expires_at]
      auth = account_request('POST', 'auth/v1/token', payload: { account_number: number })
      unless auth.is_a?(Hash) && auth['access_token'].is_a?(String) && auth['expiry'].is_a?(String)
        raise AccountError.new('invalid_response', '官方登录接口格式已变化')
      end
      @account_token = { number: number, value: auth['access_token'], expires_at: Time.parse(auth['expiry']) - 60 }
    end
    begin
      account_request(method, path, token: @account_token[:value], payload: payload, expected_status: expected_status)
    rescue AccountError => e
      # A rejected token is not device revocation. Retry only after a definite
      # auth rejection, never after an ambiguous timeout on a mutating request.
      raise unless %w[http_401 invalid_access_token].include?(e.code)
      @account_token = nil
      auth = account_request('POST', 'auth/v1/token', payload: { account_number: number })
      @account_token = { number: number, value: auth.fetch('access_token'), expires_at: Time.parse(auth.fetch('expiry')) - 60 }
      account_request(method, path, token: @account_token[:value], payload: payload, expected_status: expected_status)
    end
  rescue ArgumentError, KeyError
    raise AccountError.new('invalid_response', '官方登录响应无效')
  end

  def account_request(method, path, token: nil, payload: nil, expected_status: nil)
    # curl reads credentials from stdin; no account/token is exposed in argv,
    # environment, curlrc, application events, or diagnostic reports.
    config = ["url = #{JSON.generate('https://api.mullvad.net/' + path)}", "request = #{JSON.generate(method)}",
              'header = "Content-Type: application/json"']
    config << "header = #{JSON.generate('Authorization: Bearer ' + token)}" if token
    config << "data = #{JSON.generate(JSON.generate(payload))}" if payload
    stdout, _stderr, status = Open3.capture3('/usr/bin/curl', '-q', '--config', '-', '--silent', '--show-error',
      '--max-time', '12', '--connect-timeout', '4', '--noproxy', '', *bootstrap_proxy_args,
      '--write-out', "\n%{http_code}", stdin_data: config.join("\n") + "\n")
    unless status.success?
      raise AccountError.new('api_unreachable', 'Mullvad 账号 API 未确认完成；现有隧道保留。请检查引导代理并刷新；若刚提交撤销或兑换，确认官方状态后再操作')
    end
    body, _, code = stdout.rpartition("\n")
    if expected_status && %w[200 201 204].include?(code) && code != expected_status.to_s
      raise AccountError.new('mutation_outcome_unknown', '官方注册返回了非预期成功状态；密钥已保留，请核实设备列表，不要重复提交')
    end
    unless %w[200 201 204].include?(code)
      parsed_error = JSON.parse(body) rescue {}
      error = parsed_error['code'] || parsed_error['type'] if parsed_error.is_a?(Hash)
      messages = { 'INVALID_ACCOUNT' => '账号无效', 'INVALID_VOUCHER' => '兑换码无效',
                   'VOUCHER_USED' => '兑换码已使用', 'DEVICE_NOT_FOUND' => '设备已被撤销；请刷新列表' }
      safe_code = error == 'INVALID_ACCESS_TOKEN' ? 'invalid_access_token' : "http_#{code}"
      raise AccountError.new(safe_code, messages.fetch(error, "官方接口 HTTP #{code}；请稍后刷新确认状态"))
    end
    code == '204' ? {} : JSON.parse(body)
  rescue JSON::ParserError
    raise AccountError.new('invalid_response', '官方接口响应不是有效 JSON')
  end

  def handle_account_http(sock, method, path, headers, body)
    supplied = headers['authorization'].to_s
    if headers['origin'] || !@account_capability || supplied != "Bearer #{@account_capability}"
      respond(sock, 403, { code: 'local_authorization_required', error: '账号管理只允许本机授权客户端访问' })
      return
    end
    unless @account_mutex.try_lock
      respond(sock, 409, { code: 'account_busy', error: '账号操作尚未结束，请勿重复提交' })
      return
    end
    begin
      payload = method == 'POST' ? parse_json_body(body) : {}
      case [method, path]
      when ['GET', '/account']
        respond(sock, 200, account_snapshot)
      when ['POST', '/account/login']
        number = normalize_account(payload['account_number'])
        verified = account_refresh(number)
        atomic_account_file(File.join(@state_dir, 'account.json'), JSON.generate(account_number: number))
        @account_number, @account_data = number, verified
        respond(sock, 200, account_snapshot)
      when ['POST', '/account/refresh']
        @account_data = account_refresh
        respond(sock, 200, account_snapshot)
      when ['POST', '/account/logout']
        account_path = File.join(@state_dir, 'account.json')
        File.unlink(account_path) if File.exist?(account_path)
        @account_number = @account_data = @account_token = nil
        respond(sock, 200, account_snapshot)
      when ['POST', '/account/key']
        raise AccountError.new('confirmation_required', '请主动确认查看本机私钥') unless payload['reveal'] == true
        respond(sock, 200, { private_key: @template.fetch('private-key') })
      when ['POST', '/account/devices/create']
        raise AccountError.new('confirmation_required', '请确认创建本机设备') unless payload['confirm'] == true
        raise AccountError.new('not_signed_in', '请先登录账号') unless @account_number
        pubkey = payload['public_key'].to_s
        begin
          bytes = Base64.strict_decode64(pubkey)
          raise ArgumentError unless bytes.bytesize == 32 && Base64.strict_encode64(bytes) == pubkey && bytes.bytes.any? { |b| b != 0 }
        rescue ArgumentError
          raise AccountError.new('invalid_key', '公钥格式无效，未提交注册')
        end
        begin
          device = account_api('POST', 'accounts/v1/devices', number: @account_number,
            payload: { pubkey: pubkey, hijack_dns: false }, expected_status: 201)
          unless device.is_a?(Hash) && device['id'].to_s.match?(/\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/i) &&
                 device['name'].is_a?(String) && !device['name'].empty? && device['name'].bytesize <= 256 && !device['name'].match?(/[[:cntrl:]]/) &&
                 device['pubkey'] == pubkey && device['hijack_dns'] == false &&
                 device['ipv4_address'].to_s.end_with?('/32') && IPAddr.new(device['ipv4_address']).ipv4? &&
                 device['ipv6_address'].to_s.end_with?('/128') && IPAddr.new(device['ipv6_address']).ipv6?
            raise AccountError.new('mutation_outcome_unknown', '设备注册响应未通过验证；请核实官方设备列表，密钥保留在本机')
          end
          @account_data = nil
          respond(sock, 200, device.select { |key, _| %w[id name pubkey created ipv4_address ipv6_address].include?(key) })
        rescue AccountError => e
          if %w[api_unreachable invalid_response mutation_outcome_unknown].include?(e.code) || e.code.match?(/\Ahttp_[235]/) || e.code == 'http_408'
            raise AccountError.new('mutation_outcome_unknown', '注册是否完成尚未确认；密钥已保留。请刷新设备列表核实，不要重复创建')
          end
          raise
        rescue IPAddr::InvalidAddressError
          raise AccountError.new('mutation_outcome_unknown', '设备分配地址无效；密钥保留在本机，请核实官方状态')
        end
      when ['POST', '/account/devices/remove']
        raise AccountError.new('confirmation_required', '请确认撤销此设备') unless payload['confirm'] == true
        id = payload['device_id'].to_s
        raise AccountError.new('invalid_device', '设备 ID 无效') unless id.match?(/\A[0-9a-f-]{36}\z/i)
        # Always refresh the match immediately before deletion, rather than
        # trusting a stale UI row or allowing removal of the active identity.
        @account_data = account_refresh
        device = account_snapshot[:devices].find { |d| d[:id] == id }
        raise AccountError.new('invalid_device', '设备不在当前账号列表中') unless device
        raise AccountError.new('active_device', '不能撤销本适配器当前使用的设备') if device[:current]
        account_api('DELETE', "accounts/v1/devices/#{id}", number: @account_number)
        @account_data = nil
        @account_data = account_refresh
        respond(sock, 200, account_snapshot)
      when ['POST', '/account/voucher']
        raise AccountError.new('not_signed_in', '请先登录账号') unless @account_number
        code = payload['voucher_code'].to_s.delete(' -')
        raise AccountError.new('invalid_voucher', '请输入有效兑换码') unless code.match?(/\A[A-Za-z0-9]{8,32}\z/)
        account_api('POST', 'app/v1/submit-voucher', number: @account_number, payload: { voucher_code: code })
        @account_data = nil
        @account_data = account_refresh
        respond(sock, 200, account_snapshot)
      else
        respond(sock, 404, { error: 'account endpoint not found' })
      end
    rescue AccountError => e
      respond(sock, 422, { code: e.code, error: e.message })
    rescue StandardError
      # Never pass raw authenticated responses or persistence exceptions to
      # callers/logs. A failed mutation may have succeeded upstream: refresh.
      respond(sock, 500, { code: 'account_operation_failed', error: '账号操作未确认完成，请刷新官方状态后再操作' })
    ensure
      @account_mutex.unlock
    end
  end

  # Protection is a data-path policy, not an account API setting. A rejected
  # or failed change retains the previously committed policy (including on disk).
  def normalize_protection_profile(value)
    raise ArgumentError, '连接保护设置无效' unless value.is_a?(Hash)
    data = value.transform_keys(&:to_sym)
    raise ArgumentError, '此后台尚未支持此保护选项' unless (data.keys - %i[multihop entry_city post_quantum]).empty?
    pq = data.fetch(:post_quantum, false)
    raise ArgumentError, '多跳与抗量子的组合仍在验证，暂不能同时开启' if pq == true && data[:multihop] == true
    raise ArgumentError, '抗量子必须为开启或关闭' unless [true, false].include?(pq)
    raise ArgumentError, '多跳必须为开启或关闭' unless [true, false].include?(data[:multihop])
    city = data[:entry_city].to_s
    raise ArgumentError, '请选择入口城市' if data[:multihop] && !city.match?(/\A[a-z]{2}-[a-z0-9]{3}\z/)
    { multihop: data[:multihop], entry_city: data[:multihop] ? city : nil, post_quantum: pq }.freeze
  end

  def protection_profile
    Thread.current[:adapter_protection_profile] || @mutex.synchronize { @protection_profile }
  end

  def load_protection_profile
    path = File.join(@state_dir, 'protection.json')
    return unless File.file?(path)
    @protection_profile = normalize_protection_profile(JSON.parse(File.read(path)))
  rescue StandardError
    # Never silently lower a saved protection requirement after file corruption.
    @protection_error = '连接保护配置损坏，已阻止新隧道；请明确重新应用设置'
    log_event('protection-config-invalid', detail: @protection_error)
  end

  def protection_snapshot
    active = @mutex.synchronize do
      worker = @workers[@state[:active_slot]]
      worker && public_worker_state(worker)
    end
    { profile: @mutex.synchronize { @protection_profile }, config_error: @protection_error, checked_at: Time.now.iso8601,
      effective: active, capabilities: {
        multihop: 'mihomo-nested-wireguard', shadowsocks: 'supported',
        post_quantum: File.executable?(@options[:pq_helper]) ? 'single-hop-supported' : 'requires-packaged-pq-helper', daita: 'requires-daita-tunnel-engine',
        quic: 'requires-obfuscation-helper', udp_over_tcp: 'requires-obfuscation-helper',
        lwo: 'requires-compatible-tunnel-engine'
      } }
  end

  def multihop_entries(exit_relay, mode)
    profile = protection_profile
    used = @workers.values.flat_map { |w| w[:peer_keys] || [w[:peer_key]] }
    Array(@metadata&.dig('wireguard', 'relays')).select do |r|
      r['active'] == true && r['location'] == profile[:entry_city] &&
        r['hostname'] != exit_relay['hostname'] &&
        (r['public_key'] || r['pubkey']) != (exit_relay['public_key'] || exit_relay['pubkey']) &&
        !used.include?(r['public_key'] || r['pubkey']) && transport_supported?(r, mode)
    end.sort_by { |r| [mode == 'ss' && Array(r['shadowsocks_extra_addr_in']).empty? ? 1 : 0, r['hostname']] }.first(2)
  end

  def start_api_server
    @server = TCPServer.new(@options[:api_host], @options[:api_port])
    Thread.new do
      loop do
        break if @stop_requested
        begin
          client = @server.accept
          Thread.new(client) { |sock| handle_http(sock) }
        rescue IOError, Errno::EBADF
          break
        rescue StandardError => e
          record_error("api accept error: #{e.class}: #{e.message}")
        end
      end
    end
  end

  def handle_http(sock)
    method = raw_path = nil
    headers = {}
    body = ''
    Timeout.timeout(5) do
      line = sock.gets(4096)
      return unless line
      method, raw_path, = line.split(' ', 3)
      header_bytes = 0
      while (header = sock.gets(4096))
        break if header == "\r\n" || header == "\n"
        header_bytes += header.bytesize
        raise ArgumentError, 'headers too large' if header_bytes > 16_384
        key, value = header.split(':', 2)
        headers[key.to_s.downcase] = value.to_s.strip
      end
      length = Integer(headers.fetch('content-length', '0'))
      raise ArgumentError, 'invalid body length' unless length.between?(0, 16_384)
      body = sock.read(length) if length.positive?
    end
    if method == 'POST' && headers['origin']
      respond(sock, 403, { error: 'browser-origin mutations are not accepted' })
      return
    end

    # Loopback is a transport boundary, not caller authorization. Every mutation
    # shares the owner-readable capability, including repair and diagnostics.
    if method == 'POST' && (!@account_capability || headers['authorization'] != "Bearer #{@account_capability}")
      respond(sock, 403, { error: 'local control authorization required' })
      return
    end

    path, query = raw_path.to_s.split('?', 2)
    if path.start_with?('/account')
      handle_account_http(sock, method, path, headers, body)
      return
    end
    if method == 'GET' && path.start_with?('/operations/')
      operation = operation_snapshot(path.split('/').last)
      respond(sock, operation ? 200 : 404, operation || { error: 'operation not found' })
      return
    end
    case [method, path]
    when ['GET', '/protection']
      respond(sock, 200, protection_snapshot)
    when ['POST', '/protection']
      unless !headers['origin'] && @account_capability && headers['authorization'] == "Bearer #{@account_capability}"
        respond(sock, 403, { error: 'local protection authorization required' })
        return
      end
      profile = normalize_protection_profile(parse_json_body(body))
      ensure_pq_available!(profile)
      relay = @mutex.synchronize { @state[:active_relay] } || load_persisted_relay
      raise ArgumentError, '请先选择一个出口城市和节点' if relay.to_s.empty?
      if profile[:multihop]
        raise ArgumentError, '入口城市没有可用节点' unless Array(@metadata&.dig('wireguard', 'relays')).any? { |r| r['active'] == true && r['location'] == profile[:entry_city] && r['hostname'] != relay }
      end
      accepted_async(sock, relay, 'protection-change', nil, profile: profile)
    when ['GET', '/status']
      respond(sock, 200, snapshot)
    when ['GET', '/metrics']
      respond(sock, 200, @mutex.synchronize { @metrics.dup })
    when ['GET', '/relays']
      params = URI.decode_www_form(query.to_s).to_h
      respond(sock, 200, safe_relays(params['city']))
    when ['GET', '/cities']
      respond(sock, 200, city_workspace_snapshot)
    when ['POST', '/cities']
      payload = parse_json_body(body)
      update_favorite_cities(payload['favorite_cities'])
      respond(sock, 200, city_workspace_snapshot)
    when ['POST', '/cities/select']
      payload = parse_json_body(body)
      city = payload['city'].to_s
      raise ArgumentError, '请先将城市添加到常用城市' unless @city_mutex.synchronize { @favorite_cities.include?(city) }
      relay = city_selection_candidates(city, payload['transport'] || 'auto').first
      raise ArgumentError, '此城市暂无可尝试的节点；请稍后重试或手动选择节点' unless relay
      accepted_async(sock, relay, 'city-select', payload['transport'] || 'auto')
    when ['GET', '/speedtests']
      respond(sock, 200, speed_test_snapshot)
    when ['GET', '/relay-history']
      respond(sock, 200, relay_history_snapshot)
    when ['POST', '/speedtest']
      payload = parse_json_body(body)
      relay = payload['relay'].to_s
      if relay.empty?
        respond(sock, 400, { ok: false, code: 'relay_required', error: 'relay is required' })
      else
        transport = payload['transport'].to_s
        code, result = speed_test_relay(relay, transport_preference: transport.empty? ? nil : transport)
        respond(sock, code, result)
      end
    when ['POST', '/speedtest/start']
      payload = parse_json_body(body)
      accepted_async(sock, payload['relay'].to_s, 'speedtest', payload['transport'])
    when ['POST', '/repair']
      accepted_async(sock, snapshot[:active_relay].to_s, 'repair')
    when ['POST', '/diagnose']
      accepted_async(sock, '', 'diagnose')
    when ['POST', '/cancel']
      id = parse_json_body(body)['id'].to_s
      cancelled = @action_gate_mutex.synchronize do
        operation = @operations[id]
        if operation && operation[:kind] == 'speedtest' && %w[queued running].include?(operation[:state])
          operation[:cancel_requested] = true
          operation[:message] = '正在停止测速；当前探针结束后立即清理'
          true
        else
          false
        end
      end
      respond(sock, cancelled ? 202 : 409, { ok: cancelled })
    when ['POST', '/reconnect']
      payload = parse_json_body(body)
      relay = payload['relay'].to_s
      relay = snapshot[:active_relay].to_s if relay.empty?
      if relay.empty?
        respond(sock, 409, { ok: false, error: 'No active relay to reconnect' })
      else
        transport = payload['transport'].to_s
        accepted_async(sock, relay, 'reconnect', transport.empty? ? nil : transport)
      end
    when ['POST', '/select']
      payload = parse_json_body(body)
      relay = payload['relay'].to_s
      if relay.empty?
        respond(sock, 400, { ok: false, error: 'relay is required' })
      else
        transport = payload['transport'].to_s
        accepted_async(sock, relay, 'select', transport.empty? ? nil : transport)
      end
    else
      respond(sock, 404, { error: 'not found' })
    end
  rescue JSON::ParserError, ArgumentError, Timeout::Error => e
    respond(sock, 400, { error: e.message })
  rescue StandardError => e
    respond(sock, 500, { error: "#{e.class}: #{e.message}" })
  ensure
    sock.close rescue nil
  end

  def accepted_async(sock, relay, reason, transport_preference = nil, profile: nil)
    preference = normalize_transport_preference(transport_preference || current_transport_preference)
    unless %w[repair diagnose].include?(reason)
      unless @metadata
        respond(sock, 503, { ok: false, code: 'metadata_unavailable', error: '节点列表尚未就绪，后台正在重试' })
        return
      end
      transport_candidates(preference, find_relay(relay))
    end
    id = SecureRandom.uuid
    accepted = @action_gate_mutex.synchronize do
      if @action_pending
        false
      else
        @action_pending = {
          id: id,
          relay: relay,
          reason: reason,
          transport_preference: preference,
          accepted_at: Time.now.iso8601
        }
        @operations.shift while @operations.length >= 20
        @operations[id] = {
          id: id, kind: reason, relay: relay, state: 'queued', stage: 'queued',
          message: '已收到，正在等待当前检查完成', accepted_at: Time.now.iso8601,
          cancel_requested: false
        }
        true
      end
    end
    unless accepted
      pending = @action_gate_mutex.synchronize { @action_pending && @action_pending.dup }
      respond(sock, 409, {
        ok: false,
        code: 'adapter_busy',
        error: 'another relay action is already in progress',
        pending_action: pending
      })
      return
    end

    record_routing_event('action-accepted', relay: relay, reason: reason)
    Thread.new do
      Thread.current[:adapter_operation_id] = id
      begin
        update_operation(state: 'running')
        ok = case reason
             when 'speedtest'
               deadline = monotonic_now + 20
               loop do
                 break false if operation_cancelled?
                 code, result = speed_test_relay(relay, transport_preference: preference)
                 if code == 409 && result[:code] == 'adapter_busy' && monotonic_now < deadline
                   sleep 0.2
                   next
                 end
                 update_operation(result: result[:result], error: result[:error])
                 break code == 200
               end
             when 'diagnose'
               diagnose_network
               true
             when 'repair'
               repair_connection
             when 'protection-change'
               activate(relay, reason: reason, transport_preference: preference, protection_profile: profile)
             when 'city-select'
               activate_city(find_relay(relay)['location'], preference)
             else
               activate(relay, reason: reason, transport_preference: preference)
             end
        recovered = false
        if !ok && reason == 'reconnect' && snapshot[:active_slot].nil?
          update_operation(stage: 'fallback', message: '原节点和回退都未通过，正在尝试可用备用节点')
          quarantine_relay(relay, 'manual-reconnect-failed', 60)
          recovered = activate_startup_with_fallback(relay, current_transport_preference, reason: 'health-recovery')
        end
        current = snapshot
        outcome = if operation_cancelled?
                    'cancelled'
                  elsif recovered
                    'recovered'
                  elsif ok
                    'succeeded'
                  elsif reason != 'speedtest' && current[:active_slot] && current[:relay_liveness] == 'pass'
                    'preserved'
                  else
                    'failed'
                  end
        messages = {
          'succeeded' => reason == 'speedtest' ? '测速完成' : '检查 / 操作完成',
          'recovered' => "原节点未能恢复，已自动连接 #{current[:active_relay]}",
          'cancelled' => '测速已停止，当前连接保持原样',
          'preserved' => '本次操作未完成，原连接已保留或恢复',
          'failed' => '尚未恢复连接，后台将继续有限重试'
        }
        message = if reason == 'speedtest' && outcome == 'failed'
                    '测速未完成，当前连接保持原样'
                  elsif %w[repair diagnose].include?(reason) && ok
                    current.dig(:diagnosis, :summary) || messages[outcome]
                  else
                    messages[outcome]
                  end
        old_error = operation_snapshot(id)&.dig(:error)
        update_operation(state: outcome, stage: 'finished', message: message,
                         finished_at: Time.now.iso8601, error: (ok || recovered) ? nil : (old_error || current[:last_error]))
      rescue StandardError => e
        record_error("#{reason} failed: #{e.class}: #{e.message}")
        update_operation(state: 'failed', stage: 'finished', message: '操作未完成，详见诊断',
                         error: "#{e.class}: #{e.message}", finished_at: Time.now.iso8601)
      ensure
        @action_gate_mutex.synchronize { @action_pending = nil }
        Thread.current[:adapter_operation_id] = nil
      end
    end
    # Launch before replying: a closed UI socket must not leave a permanent busy flag.
    respond(sock, 202, { ok: true, accepted: true, id: id, relay: relay, reason: reason, transport: preference })
  rescue ArgumentError, RuntimeError => e
    respond(sock, 400, { ok: false, code: 'invalid_request', error: e.message })
  end

  def monotonic_now
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def operation_snapshot(id)
    @action_gate_mutex.synchronize { @operations[id] && Marshal.load(Marshal.dump(@operations[id])) }
  end

  def update_operation(**values)
    id = Thread.current[:adapter_operation_id]
    return unless id
    @action_gate_mutex.synchronize { @operations[id]&.merge!(values) }
    if %w[succeeded recovered preserved failed cancelled].include?(values[:state])
      log_event('operation-finished', values.merge(id: id))
    end
  end

  def operation_cancelled?
    id = Thread.current[:adapter_operation_id]
    id && @action_gate_mutex.synchronize { @operations[id]&.dig(:cancel_requested) }
  end

  def candidate_attempt_allowed?(started)
    deadline = Thread.current[:adapter_recovery_deadline]
    !@stop_requested && !operation_cancelled? && network_attempt_current? && monotonic_now - started < @options[:attempt_budget] &&
      (!deadline || monotonic_now < deadline)
  end

  def action_pending?
    @action_gate_mutex.synchronize { !@action_pending.nil? }
  end

  def action_conflicts?
    @action_gate_mutex.synchronize do
      @action_pending && @action_pending[:id] != Thread.current[:adapter_operation_id]
    end
  end

  def record_routing_event(event, relay: nil, reason: nil, detail: nil, connections: nil)
    now = Time.now.iso8601
    @mutex.synchronize do
      policy = @state[:routing_policy]
      policy[:last_event] = event
      policy[:last_event_at] = now
      policy[:last_event_relay] = relay if relay
      policy[:last_event_reason] = reason if reason
      policy[:last_event_detail] = detail if detail
      policy[:last_preempted_connections] = connections.to_i unless connections.nil?
      @state[:updated_at] = now
    end
    log_event(event, relay: relay, reason: reason, detail: detail, connections: connections)
  end

  def redact_log(value)
    case value
    when Hash
      value.each_with_object({}) do |(key, item), result|
        result[key] = key.to_s.match?(/private.?key|password|token|secret|account|subscription|authorization/i) ? '[REDACTED]' : redact_log(item)
      end
    when Array
      value.map { |item| redact_log(item) }
    when String
      value.gsub(/(private[-_ ]?key|pre[-_ ]?shared[-_ ]?key|password|secret|(?:access[-_ ]?|refresh[-_ ]?)?token|authorization|account(?:[-_ ]?number)?|subscription(?:[-_ ]?url)?)\s*["']?\s*[:=]\s*["']?[^\s,"'}]+/i, '\1=[REDACTED]')
           .gsub(/Bearer\s+[A-Za-z0-9._~+\/=-]+/i, 'Bearer [REDACTED]')
           .gsub(/(?<![A-Za-z0-9+\/])[A-Za-z0-9+\/]{43}=(?![A-Za-z0-9+\/])/, '[KEY REDACTED]')
           .gsub(/\b\d{16}\b/, '[ACCOUNT REDACTED]')
           .gsub(/\b(?:\d{4}[ -]){3}\d{4}\b/, '[ACCOUNT REDACTED]')
           .gsub(%r{https?://[^/\s:@]+:[^/\s@]+@[^\s"]+}, '[CREDENTIAL URL REDACTED]')
           .gsub(%r{https?://[^\s]*[?][^\s]*}, '[URL QUERY REDACTED]')[0, 2_000]
    else
      value
    end
  end

  def log_event(event, fields = {})
    trace = { operation_id: Thread.current[:adapter_operation_id],
              recovery_id: Thread.current[:adapter_recovery_id], attempt_id: Thread.current[:adapter_attempt_id] }.compact
    entry = { at: Time.now.iso8601, event: event, build: BUILD_ID }.merge(trace).merge(redact_log(fields))
    line = JSON.generate(entry) + "\n"
    if line.bytesize > EVENT_LOG_FILE_BYTES
      line = JSON.generate(at: entry[:at], event: 'oversized-event', build: BUILD_ID,
                           original_bytes: line.bytesize, detail: 'event exceeded log capacity; payload omitted') + "\n"
    end
    @log_mutex.synchronize do
      FileUtils.mkdir_p(@log_dir, mode: 0o700)
      path = File.join(@log_dir, 'events.jsonl')
      File.rename(path, path + '.1') if File.file?(path) && File.size(path) + line.bytesize > EVENT_LOG_FILE_BYTES
      File.open(path, 'a', 0o600) { |file| file.write(line) }
    end
  rescue StandardError => e
    # Logging failure must not disable recovery or flood stderr when disk is full.
    if !@last_log_failure_at || Time.now - @last_log_failure_at > 60
      @last_log_failure_at = Time.now
      warn "event log unavailable: #{e.class}"
    end
  end

  def parse_json_body(body)
    parsed = body.to_s.empty? ? {} : JSON.parse(body)
    raise ArgumentError, 'JSON object required' unless parsed.is_a?(Hash)
    parsed
  end

  def respond(sock, code, object)
    payload = JSON.generate(object)
    text = { 200 => 'OK', 202 => 'Accepted', 400 => 'Bad Request', 403 => 'Forbidden', 404 => 'Not Found', 409 => 'Conflict', 500 => 'Internal Server Error', 503 => 'Service Unavailable' }.fetch(code, 'OK')
    sock.write("HTTP/1.1 #{code} #{text}\r\n")
    sock.write("Content-Type: application/json; charset=utf-8\r\n")
    sock.write("Cache-Control: no-store\r\n")
    sock.write("Content-Length: #{payload.bytesize}\r\n")
    sock.write("Connection: close\r\n\r\n")
    sock.write(payload)
    true
  rescue Errno::EPIPE, Errno::ECONNRESET, Errno::ENOTCONN
    # The client may cancel a request after the daemon has started writing its
    # response (Swift polling and browser refreshes do this routinely). The
    # socket is already going away, so there is no useful second response to
    # send and no incident should be recorded for the network service.
    false
  end

  def snapshot
    copy = @mutex.synchronize { Marshal.load(Marshal.dump(@state)) }
    if copy.dig(:local_network, :paused)
      copy[:status] = 'waiting_network'
      copy[:service_readiness] = 'waiting_network'
      copy[:relay_liveness] = 'unknown'
    elsif copy.dig(:local_network, :recovery_pending)
      copy[:status] = 'network_recovering'
      copy[:service_readiness] = 'network_recovering'
    end
    copy[:routing_policy][:pending_action] = @action_gate_mutex.synchronize do
      @action_pending && @action_pending.dup
    end
    copy[:operation] = @action_gate_mutex.synchronize do
      latest = @action_pending ? @operations[@action_pending[:id]] : @operations.values.last
      latest && Marshal.load(Marshal.dump(latest))
    end
    copy[:routing_policy][:quarantined_relays] = @mutex.synchronize do
      now = Time.now
      @recovery_quarantine.delete_if { |_name, entry| entry[:until] <= now }
      @recovery_quarantine.map do |name, entry|
        {
          relay: name,
          reason: entry[:reason],
          remaining_seconds: [(entry[:until] - now).ceil, 0].max
        }
      end
    end
    fetched_at = copy.dig(:metadata, :fetched_at)
    if fetched_at
      begin
        copy[:metadata][:age_seconds] = [Time.now - Time.parse(fetched_at), 0].max.round
      rescue ArgumentError
        copy[:metadata][:age_seconds] = nil
      end
    end
    copy.transform_keys(&:to_sym)
  end

  def update_state(values)
    @mutex.synchronize do
      values.each { |key, value| @state[key] = value }
      @state[:updated_at] = Time.now.iso8601
    end
  end

  def record_error(message)
    @mutex.synchronize do
      @state[:status] = @state[:active_slot] ? @state[:service_readiness] : 'degraded'
      @state[:last_error] = message
      @state[:updated_at] = Time.now.iso8601
    end
    log_event('error', message: message)
  end

  def ensure_front
    raise 'shutdown requested' if @stop_requested
    return if @front_pid && process_alive?(@front_pid)

    config = {
      'mixed-port' => @options[:front_mixed],
      'external-controller' => "127.0.0.1:#{@options[:front_controller]}",
      'allow-lan' => false,
      'mode' => 'rule',
      'log-level' => 'warning',
      'ipv6' => false,
      'tun' => { 'enable' => false },
      'dns' => { 'enable' => false },
      'proxies' => @slot_config.map do |slot, spec|
        {
          'name' => "worker-#{slot}",
          'type' => 'socks5',
          'server' => '127.0.0.1',
          'port' => spec[:mixed],
          'udp' => true
        }
      end,
      'proxy-groups' => [
        { 'name' => 'ACTIVE', 'type' => 'select', 'proxies' => @slot_config.keys.map { |slot| "worker-#{slot}" } }
      ],
      'rules' => ['MATCH,ACTIVE']
    }

    dir = File.join(@state_dir, 'front')
    path = File.join(dir, 'config.json')
    write_json_private(path, config, secret: false)
    validate_runtime_config(path, dir) if @options[:validate_configs]
    @front_pid = File.open(File.join(dir, 'core.log'), 'a', 0o600) do |log|
      Process.spawn(@options[:core], '-d', dir, '-f', path, out: log, err: log)
    end
    unless wait_controller(@options[:front_controller], 8, pid: @front_pid)
      stop_pid(@front_pid)
      @front_pid = nil
      raise 'front Mihomo did not become ready'
    end
    @mutex.synchronize do
      @state[:front][:ready] = true
      @state[:front][:pid] = @front_pid
      @state[:updated_at] = Time.now.iso8601
    end
  end

  def start_connection_monitor
    Thread.new do
      until @stop_requested
        begin
          payload = http_json(@options[:front_controller], '/connections', read_timeout: 2)
          connections = Array(payload['connections'])
          counts = @slot_config.keys.to_h do |slot|
            [slot, connections.count { |connection| Array(connection['chains']).include?("worker-#{slot}") }]
          end
          @mutex.synchronize do
            counts.each do |slot, count|
              worker = @state[:workers][slot]
              worker[:front_connection_count] = count if worker
            end
            active_slot = @state[:active_slot]
            active_count = active_slot ? counts.fetch(active_slot, 0) : 0
            draining_count = counts.sum { |slot, count| slot == active_slot ? 0 : count }
            @metrics[:front_connections_total] = connections.length
            @metrics[:active_connections] = active_count
            @metrics[:draining_connections] = draining_count
            @state[:updated_at] = Time.now.iso8601
          end
        rescue StandardError
          # Front may be starting/stopping; monitoring must not change adapter state.
        end
        sleep 1
      end
    end
  end

  def start_runtime_supervisor
    Thread.new do
      until @stop_requested
        supervise_runtime_once

        [@options[:supervisor_interval].to_i, 1].max.times do
          break if @stop_requested
          sleep 1
        end
      end
    end
  end

  def supervise_runtime_once
    %i[supervise_front_runtime supervise_worker_runtime retry_disconnected_runtime].each do |check|
      begin
        send(check)
      rescue StandardError => e
        log_event('runtime-supervisor-error', check: check, error: "#{e.class}: #{e.message}")
        warn "#{Time.now.iso8601} runtime supervisor #{check}: #{e.class}: #{e.message}"
      end
    end
  end

  def retry_disconnected_runtime
    return if @stop_requested || action_pending? || !@metadata
    return if local_network_paused? || local_network_recovery_pending?
    return if Time.now - @last_disconnected_retry_at < @options[:recovery_cooldown]
    return unless @switch_mutex.try_lock
    begin
      current = @mutex.synchronize { @state.slice(:generation, :active_slot, :active_relay) }
      return if current[:active_slot]
      @last_disconnected_retry_at = Time.now
    ensure
      @switch_mutex.unlock
    end
    activate_startup_with_fallback(
      current[:active_relay] || load_persisted_relay || @options[:default_relay],
      current_transport_preference, reason: 'startup-retry', expected_state: current
    )
  end

  def supervise_front_runtime
    return unless @switch_mutex.try_lock
    begin
      front_alive = @front_pid && process_alive?(@front_pid)
      unless front_alive
        previous_pid = @front_pid
        @front_pid = nil
        @mutex.synchronize do
          @state[:front][:ready] = false
          @state[:front].delete(:pid)
          @state[:updated_at] = Time.now.iso8601
        end

        ensure_front
        @mutex.synchronize do
          @metrics[:front_restarts] += 1 if previous_pid
          @state[:front][:restarted_at] = Time.now.iso8601 if previous_pid
        end
        record_routing_event('front-restarted', detail: "previous_pid=#{previous_pid}") if previous_pid
      end

      begin
        http_json(@options[:front_controller], '/version', open_timeout: 0.5, read_timeout: 1)
        @front_probe_failures = 0
        @mutex.synchronize { @state[:front][:controller_degraded] = false }
      rescue StandardError => e
        @front_probe_failures += 1
        @mutex.synchronize do
          @state[:front][:ready] = false
          @state[:front][:probe_failures] = @front_probe_failures
          @state[:updated_at] = Time.now.iso8601
        end
        if @front_probe_failures >= 3 && @front_pid
          return if local_network_paused? || local_network_recovery_pending?
          control_context = capture_active_context
          previous_front_pid = @front_pid
          previous_generation = @mutex.synchronize { @state[:generation] }
          @switch_mutex.unlock
          data_probe = curl_proxy_ip_test(@options[:front_mixed], IP_CANARY, 3)
          return unless @switch_mutex.try_lock
          return unless @front_pid == previous_front_pid && @mutex.synchronize { @state[:generation] == previous_generation }
          return if control_context && !active_context_current?(control_context, front: true)
          if data_probe[:status] == "pass"
            @front_probe_failures = 0
            @mutex.synchronize do
              @state[:front][:ready] = true
              @state[:front][:controller_degraded] = true
              @state[:front][:data_path] = { status: "pass", detail: data_probe[:detail], checked_at: Time.now.iso8601 }
            end
            record_routing_event("front-controller-degraded-kept", detail: "controller failed but data path passed")
            return
          end
          stale_pid = @front_pid
          stop_pid(stale_pid)
          @front_pid = nil
          @front_probe_failures = 0
          @mutex.synchronize do
            @metrics[:front_restarts] += 1
            @state[:front][:restarted_at] = Time.now.iso8601
          end
          record_routing_event('front-hung-restart', detail: "pid=#{stale_pid} #{e.class}: #{e.message}")
          ensure_front
        else
          raise e
        end
      end
      @mutex.synchronize do
        @state[:front][:ready] = true
        @state[:front][:pid] = @front_pid
        @state[:front][:probe_failures] = 0
      end

      active_slot, active_worker = @mutex.synchronize do
        slot = @state[:active_slot]
        [slot, slot && @workers[slot]]
      end
      return unless active_slot && active_worker && process_alive?(active_worker[:pid])

      payload = http_json(@options[:front_controller], '/proxies/ACTIVE', open_timeout: 0.5, read_timeout: 1)
      expected = "worker-#{active_slot}"
      current = payload['now'].to_s
      if current != expected
        select_front(active_slot)
        @mutex.synchronize { @metrics[:front_selector_repairs] += 1 }
        record_routing_event('front-selector-repaired', relay: active_worker[:relay], detail: "#{current}->#{expected}")
      end

      @switch_mutex.unlock
      supervise_front_data_path(active_slot, active_worker)
    rescue StandardError => e
      @mutex.synchronize do
        @state[:front][:ready] = false
        @state[:updated_at] = Time.now.iso8601
      end
      raise e
    ensure
      @switch_mutex.unlock if @switch_mutex.owned?
    end
  end

  def supervise_front_data_path(active_slot, active_worker)
    return if local_network_paused? || local_network_recovery_pending?
    now = Time.now
    return if (now - @last_front_data_probe_at) < @options[:front_data_probe_interval].to_i
    captured = capture_active_context
    return unless captured && captured[:slot] == active_slot && captured[:pid] == active_worker[:pid]
    @last_front_data_probe_at = now
    context = { relay: captured[:relay], slot: active_slot, generation: captured[:generation],
                front_pid: captured[:front_pid], worker_pid: captured[:pid],
                endpoint: active_worker[:endpoint], interface: active_worker[:interface], timeout_seconds: 3 }
    # Both observations are outside the switch mutex. Neither creates a tunnel.
    front_result = curl_proxy_ip_test(@options[:front_mixed], IP_CANARY, 3)
    direct_result = curl_proxy_ip_test(active_worker[:mixed_port], IP_CANARY, 3) unless front_result[:status] == 'pass'
    return unless @switch_mutex.try_lock
    begin
      unless active_context_current?(captured, front: true)
        log_event('front-result-discarded', **context, reason: 'active-context-changed')
        return
      end
      if front_result[:status] == 'pass'
        if @front_incident_id
          original = @front_incident_context || {}
          recovery = if original[:relay] != context[:relay]
                       'relay_switched'
                     elsif original[:worker_pid] != context[:worker_pid]
                       'worker_rebuilt'
                     elsif original[:front_pid] != context[:front_pid]
                       'front_restarted'
                     else
                       'without_restart'
                     end
          log_event('front-path-recovered', **context, incident_id: @front_incident_id,
                    recovery: recovery, original_context: original, front: front_result)
          @front_incident_id = @front_incident_context = nil
        end
        @front_data_probe_failures = 0
        @mutex.synchronize { @state[:front][:data_path] = { status: 'pass', detail: front_result[:detail], checked_at: now.iso8601 } }
        return
      end
      unless @front_incident_id
        @front_incident_id = SecureRandom.uuid
        @front_incident_context = context.dup
      end
      log_event('front-path-failed', **context, incident_id: @front_incident_id,
                front: front_result, worker: direct_result,
                consecutive_front_only_failures: direct_result[:status] == 'pass' ? @front_data_probe_failures + 1 : 0,
                decision: direct_result[:status] == 'pass' ? 'front_failure_threshold' : 'wake_worker_health')
      if direct_result[:status] != 'pass'
        @front_data_probe_failures = 0
        @mutex.synchronize { @state[:front][:data_path] = { status: 'backend_fail', detail: front_result[:detail], checked_at: now.iso8601 } }
        wake_health_monitor('front-and-worker-data-failed')
        return
      end
      @front_data_probe_failures += 1
      @mutex.synchronize do
        @metrics[:front_data_probe_failures] += 1
        @state[:front][:data_path] = { status: 'fail', detail: "front failed while worker direct path passed (#{@front_data_probe_failures}/2)", checked_at: now.iso8601 }
      end
      return if @front_data_probe_failures < 2
      log_event('front-repair-started', **context, incident_id: @front_incident_id,
                reason: 'two_consecutive_front_failures_with_worker_pass', front: front_result, worker: direct_result)
      stale_pid = @front_pid
      stop_pid(stale_pid) if stale_pid
      @front_pid = nil
      @front_data_probe_failures = 0
      ensure_front
      select_front(active_slot)
      repaired = capture_active_context
      @mutex.synchronize do
        @metrics[:front_restarts] += 1
        @state[:front][:restarted_at] = Time.now.iso8601
      end
    ensure
      @switch_mutex.unlock if @switch_mutex.owned?
    end
    verification = curl_proxy_ip_test(@options[:front_mixed], IP_CANARY, 3)
    return unless @switch_mutex.try_lock
    begin
      return unless repaired && active_context_current?(repaired, front: true)
      @mutex.synchronize { @state[:front][:data_path] = { status: verification[:status], detail: verification[:detail], checked_at: Time.now.iso8601 } }
      log_event('front-repair-finished', **context, incident_id: @front_incident_id,
                old_pid: stale_pid, new_pid: @front_pid, verification: verification, restored: verification[:status] == 'pass')
      @front_incident_id = @front_incident_context = nil if verification[:status] == 'pass'
      record_routing_event('front-data-path-restarted', relay: active_worker[:relay],
                           reason: verification[:status], detail: "old_pid=#{stale_pid} new_pid=#{@front_pid}")
    ensure
      @switch_mutex.unlock if @switch_mutex.owned?
    end
  rescue StandardError => e
    log_event('front-repair-error', **(context || {}), incident_id: @front_incident_id, error: "#{e.class}: #{e.message}")
    raise
  end

  def supervise_worker_runtime
    # Keep the failed worker identity until local recovery owns the rebuild.
    # A dead process during a Wi-Fi outage is not a relay-health observation.
    return if local_network_paused? || local_network_recovery_pending?
    return unless @switch_mutex.try_lock
    recovery = nil
    begin
      snapshot = @mutex.synchronize { @workers.transform_values(&:dup) }
      dead = snapshot.select { |_slot, worker| !process_alive?(worker[:pid]) }
      return if dead.empty?

      active_slot = @mutex.synchronize { @state[:active_slot] }
      active_failure = nil

      dead.each do |slot, worker|
        public_state = slot_lifecycle_state(slot)
        @mutex.synchronize { @metrics[:worker_crashes] += 1 }

        if slot == active_slot && public_state == 'active'
          active_failure = [slot, worker]
          next
        end

        stop_worker(slot)
        if public_state == 'draining'
          @mutex.synchronize { @metrics[:drain_forced] += 1 }
          record_routing_event('dead-draining-worker-retired', relay: worker[:relay], reason: 'worker-exit')
        end
      end

      return unless active_failure
      return if action_pending?

      slot, worker = active_failure
      relay = worker[:relay].to_s
      preference = current_transport_preference
      generation = @mutex.synchronize { @state[:generation] }
      @mutex.synchronize do
        @state[:active_slot] = nil
        @state[:active_transport] = nil
        @state[:active_transport_mode] = nil
        @state[:relay_liveness] = 'fail'
        @state[:service_readiness] = 'data_fail'
        @state[:status] = 'data_fail'
        @state[:last_error] = "active worker-#{slot} exited unexpectedly"
        @state[:updated_at] = Time.now.iso8601
        @metrics[:worker_crash_recoveries] += 1
        @metrics[:auto_recovery_attempts] += 1
        @state[:health][:last_attempt_at] = Time.now.iso8601
      end
      stop_worker(slot)
      record_routing_event('active-worker-crashed', relay: relay, reason: 'worker-crash-recovery')
      recovery = {
        relay: relay,
        preference: preference,
        expected_state: { generation: generation, active_slot: nil, active_relay: relay }
      }
    ensure
      @switch_mutex.unlock if @switch_mutex.owned?
    end

    return unless recovery
    with_recovery_budget('worker-crash-recovery', recovery[:relay]) do
      ok = activate(
        recovery[:relay],
        reason: 'worker-crash-recovery',
        transport_preference: recovery[:preference],
        expected_state: recovery[:expected_state]
      )
      unless ok
        return unless automatic_recovery_context_valid?(recovery[:expected_state][:generation], recovery[:relay])
        quarantine_relay(recovery[:relay], 'worker-crash-rebuild-failed')
        recovery_relay_candidates(recovery[:relay]).each do |fallback|
          break unless recovery_budget_remaining?
          break unless automatic_recovery_context_valid?(recovery[:expected_state][:generation], recovery[:relay])
          current = @mutex.synchronize do
            {
              generation: @state[:generation],
              active_slot: @state[:active_slot],
              active_relay: @state[:active_relay]
            }
          end
          recovery_handled = false
          ok = activate(
            fallback,
            reason: 'health-recovery',
            transport_preference: recovery[:preference],
            expected_state: current
          )
          break if ok
          quarantine_relay(fallback, 'recovery-candidate-failed', 300)
        end
      end
      @mutex.synchronize { @metrics[:auto_recovery_failures] += 1 unless ok }
      ok
    end
  end

  def start_control_plane_monitor
    Thread.new do
      last_full_refresh = Time.at(0)
      until @stop_requested
        begin
          if local_network_paused?
            sleep 1
            next
          end
          now = Time.now
          metadata_state = @mutex.synchronize { @state[:metadata].dup }
          stale = @metadata_fetched_at.nil? || (now - @metadata_fetched_at) >= @options[:metadata_ttl]
          if @metadata.nil? || metadata_state[:live] != true || stale || (now - last_full_refresh) >= @options[:metadata_ttl]
            refresh_metadata(force: true)
            last_full_refresh = Time.now
          else
            check_clash_global_path
          end

          # Reconnection belongs to the runtime supervisor; metadata requests
          # must never delay recovery of a disconnected data path.
        rescue StandardError => e
          set_dns_status(:bootstrap, 'degraded', "control-plane monitor: #{e.class}: #{e.message}")
        end
        30.times do
          break if @stop_requested
          sleep 1
        end
      end
    end
  end

  # This observes host attachment, never VPN routes, proxy/DNS availability or
  # remote relay ping. A live Ethernet link also counts when Wi-Fi is down.
  def read_local_network
    return @options[:local_network_probe].call if @options[:local_network_probe]
    return { status: 'unknown', source: 'unsupported-platform', detail: '本机链路检测尚未适配此系统' } unless RUBY_PLATFORM.include?('darwin')

    hardware = bounded_network_command('/usr/sbin/networksetup', '-listallhardwareports')
    interfaces = bounded_network_command('/sbin/ifconfig', '-a')
    parse_local_network(hardware, interfaces)
  rescue StandardError => e
    { status: 'unknown', source: 'macos-hardware-link', detail: "本机链路检查未完成（#{e.class}）" }
  end

  def bounded_network_command(*command)
    Open3.popen2(*command, err: File::NULL) do |input, output, child|
      input.close
      begin
        result = Timeout.timeout(1.5) do
          text = output.read(131_073)
          raise 'network observation too large' if text.bytesize > 131_072
          raise 'network observation failed' unless child.value.success?
          text
        end
        result
      ensure
        begin
          Process.kill('KILL', child.pid) if child.alive?
        rescue Errno::ESRCH
          # The command may exit between the liveness check and cleanup.
        end
        child.join
      end
    end
  end

  def parse_local_network(hardware, interfaces)
    names = hardware.scan(/^Device:\s*(\S+)/).flatten.select { |name| usable_physical_interface?(name) }.uniq
    sections = interfaces.split(/(?=^\S+: flags=)/).to_h do |section|
      [section[/\A(\S+): flags=/, 1], section]
    end
    base = { source: 'macos-hardware-link', interfaces: names }
    return base.merge(status: 'unknown', detail: '未取得完整的本机硬件接口状态') if names.empty? || names.any? { |name| !sections.key?(name) }

    ambiguous = false
    active = names.select do |name|
      section = sections.fetch(name)
      link = section[/^\s*status:\s*(\S+)/, 1]
      ambiguous = true unless %w[active inactive].include?(link)
      next false unless link == 'active' && section.lines.first.match?(/<[^>]*\bUP\b/)
      section.scan(/^\s*inet6?\s+(\S+)/).flatten.any? do |address|
        ip = IPAddr.new(address.split('%').first) rescue nil
        ip && !ip.loopback? && !ip.to_i.zero? &&
          !(ip.ipv4? && IPAddr.new('169.254.0.0/16').include?(ip)) &&
          !(ip.ipv6? && IPAddr.new('fe80::/10').include?(ip))
      end
    end
    return base.merge(status: 'available', active_interfaces: active, detail: '本机硬件链路已连接并取得地址；不代表互联网或节点已验证') unless active.empty?
    return base.merge(status: 'unknown', detail: '接口链路状态不明确；不据此判定断网') if ambiguous
    base.merge(status: 'unavailable', active_interfaces: [], detail: '本机没有已连接且取得可用地址的硬件网络接口')
  end

  def refresh_local_network
    return unless @local_network_probe_mutex.try_lock
    begin
      apply_local_network_observation(read_local_network)
    ensure
      @local_network_probe_mutex.unlock
    end
  end

  def apply_local_network_observation(observation)
    status = observation[:status]
    status = 'unknown' unless %w[available unavailable unknown].include?(status)
    event = nil
    @mutex.synchronize do
      local = @state[:local_network]
      was_paused = local[:paused]
      local.merge!(observation.slice(:source, :interfaces, :active_interfaces, :detail))
      local[:status], local[:checked_at] = status, Time.now.iso8601
      if status == 'unavailable'
        if !was_paused || @local_network_settle_until.positive?
          local[:epoch] += 1
          worker = @workers[@state[:active_slot]]
          @network_resume_path = (worker || @last_network_path || {}).slice(:relay, :transport_mode, :endpoint, :endpoint_port, :endpoint_kind, :entry_relay)
          @network_resume_path[:relay] ||= @state[:active_relay]
          local[:offline_at] = Time.now.iso8601
          local[:link_restored_at] = local[:outcome] = local[:recovery_finished_at] = nil
          @network_recovery_retry_at = nil
          event = 'local-network-unavailable'
        end
        local[:paused], local[:recovery_pending], local[:recovery_stage] = true, true, 'waiting'
        @local_network_settle_until = 0
      elsif status == 'available' && was_paused
        if @local_network_settle_until.zero?
          @local_network_settle_until = monotonic_now + @options[:local_network_settle]
          local[:link_restored_at] = Time.now.iso8601
          local[:recovery_stage] = 'settling'
          event = 'local-network-link-restored'
        end
        if monotonic_now >= @local_network_settle_until
          local[:paused] = false
          local[:recovery_stage] = 'verify-original'
          event = 'local-network-resume-requested'
        end
      elsif status == 'unknown' && was_paused
        # An observation error is not proof that the physical link recovered.
        @local_network_settle_until = 0
        local[:recovery_stage] = 'waiting'
      end
      if local[:paused] || event == 'local-network-resume-requested'
        @health_fail_streak = @dns_fail_streak = 0
        @state[:health][:consecutive_wg_failures] = @state[:health][:consecutive_dns_failures] = 0
      end
      @state[:updated_at] = Time.now.iso8601
    end
    if event
      log_event(event, **@mutex.synchronize { @state[:local_network].dup }, relay: @network_resume_path&.dig(:relay))
      wake_health_monitor(event)
    end
  end

  def local_network_paused?
    @mutex.synchronize { @state[:local_network][:paused] }
  end

  def local_network_recovery_pending?
    @mutex.synchronize { @state[:local_network][:recovery_pending] }
  end

  def network_epoch
    @mutex.synchronize { @state[:local_network][:epoch] }
  end

  def network_epoch_current?(epoch)
    @mutex.synchronize { !@state[:local_network][:paused] && @state[:local_network][:epoch] == epoch }
  end

  def network_attempt_current?
    epoch = Thread.current[:adapter_network_epoch]
    epoch ? network_epoch_current?(epoch) : !local_network_paused?
  end

  def start_local_network_monitor
    @local_network_monitor_started = true
    refresh_local_network
    Thread.new do
      until @stop_requested
        sleep [@options[:local_network_interval], 0.25].max
        break if @stop_requested
        refresh_local_network
        wake_health_monitor('local-network-resume-pending') if !local_network_paused? && local_network_recovery_pending?
      end
    end
  end

  def finish_local_network_recovery(epoch, restored:, outcome:)
    @mutex.synchronize do
      return unless @state[:local_network][:epoch] == epoch && !@state[:local_network][:paused]
      stage = restored ? 'restored' : (outcome.include?('live-partial') ? 'degraded' : 'failed')
      @state[:local_network].merge!(recovery_pending: false, recovery_stage: stage,
                                   recovery_finished_at: Time.now.iso8601, outcome: outcome)
      @last_disconnected_retry_at = Time.now
      @front_data_probe_failures = 0
      @last_front_data_probe_at = Time.at(0)
    end
    log_event('local-network-recovery-finished', restored: restored, outcome: outcome, active_relay: snapshot[:active_relay], epoch: epoch)
  end

  def recover_local_network_once
    previous_path = Thread.current[:adapter_resume_path]
    return :retry if action_pending?
    return if local_network_paused? || !@metadata
    return if @network_recovery_retry_at && monotonic_now < @network_recovery_retry_at
    epoch = network_epoch
    expected = @mutex.synchronize { @state.slice(:generation, :active_slot, :active_relay) }
    path = @mutex.synchronize { (@network_resume_path || {}).dup }
    current = capture_active_context
    if current && process_alive?(current[:pid])
      pending = @pending_network_observation
      pending = nil unless pending && pending[:context] == current && Time.now - pending[:at] < @options[:health_interval]
      canary = pending ? pending[:canary] : run_readiness_canary(current[:slot])
      return unless network_epoch_current?(epoch)
      unless @switch_mutex.try_lock
        @pending_network_observation = { context: current, canary: canary, at: pending ? pending[:at] : Time.now }
        return :retry
      end
      @pending_network_observation = nil
      begin
        return unless active_context_current?(current)
        classification = classify_canary(canary)
        if classification[:relay_liveness] == 'pass'
          ready = classification[:service_readiness] == 'ready'
          update_state(status: classification[:service_readiness], **classification, last_canary: canary,
                       last_error: ready ? nil : '原通道数据面已恢复，DNS／网页仍需复检；保留原路径')
          @mutex.synchronize { @state[:dns][:inner] = canary[:inner_dns] }
          finish_local_network_recovery(epoch, restored: ready, outcome: ready ? 'original-path-recovered' : 'original-path-live-partial')
          return
        end
        @pending_network_observation = { context: current, canary: canary, at: pending ? pending[:at] : Time.now }
      ensure
        @switch_mutex.unlock
      end
    end
    relay = current&.dig(:relay) || path[:relay] || load_persisted_relay || @options[:default_relay]
    return if action_pending? || !network_epoch_current?(epoch)
    return unless @mutex.synchronize { @state.slice(:generation, :active_slot, :active_relay) == expected && @state[:local_network][:recovery_pending] }
    preference = current_transport_preference
    with_recovery_budget('network-resume', relay) do
      @mutex.synchronize { @state[:local_network][:recovery_stage] = 'rebuild-original' }
      Thread.current[:adapter_resume_path] = path.merge(relay: relay)
      evidence = {}
      original_available = Array(@metadata.dig('wireguard', 'relays')).any? { |r| r['hostname'] == relay && r['active'] == true }
      if original_available
        ok = activate(relay, reason: 'network-resume', transport_preference: path[:transport_mode] || preference,
                      expected_state: expected, attempt_evidence: evidence)
      else
        ok = false
        evidence[:withdrawn] = true
        log_event('local-network-original-withdrawn', relay: relay, epoch: epoch)
      end
      return unless network_epoch_current?(epoch)
      return unless @mutex.synchronize { @state[:local_network][:recovery_pending] && (ok || @state[:generation] == expected[:generation]) }
      return defer_local_network_recovery(evidence) if !ok && !evidence[:relay_failed] && !evidence[:withdrawn]
      Thread.current[:adapter_resume_path] = previous_path
      if ok
        @mutex.synchronize { @state[:transport_preference] = preference }
        persist_transport_preference(preference)
      else
        return if action_conflicts?
        quarantine_relay(relay, 'network-resume-original-failed', 300) unless evidence[:withdrawn]
        @mutex.synchronize { @state[:local_network][:recovery_stage] = 'same-city-fallback' }
        recovery_relay_candidates(relay, preference: preference).each do |candidate|
          break unless recovery_budget_remaining? && network_epoch_current?(epoch)
          break if action_conflicts?
          expected = @mutex.synchronize { @state.slice(:generation, :active_slot, :active_relay) }
          evidence = {}
          ok = activate(candidate, reason: 'network-resume-fallback', transport_preference: preference,
                        expected_state: expected, attempt_evidence: evidence)
          return unless network_epoch_current?(epoch)
          return unless @mutex.synchronize { @state[:local_network][:recovery_pending] && (ok || @state[:generation] == expected[:generation]) }
          return defer_local_network_recovery(evidence) if !ok && !evidence[:relay_failed]
          break if ok
          quarantine_relay(candidate, 'network-resume-candidate-failed', 300)
        end
      end
      ready = ok && @mutex.synchronize { @state[:service_readiness] == 'ready' }
      outcome = !ok ? 'same-city-exhausted' : ready ? 'validated-rebuild' : 'original-rebuild-live-partial'
      finish_local_network_recovery(epoch, restored: ready, outcome: outcome)
    end
  ensure
    Thread.current[:adapter_resume_path] = previous_path if defined?(previous_path)
  end

  def defer_local_network_recovery(evidence)
    @network_recovery_retry_at = monotonic_now + @options[:local_network_interval]
    @mutex.synchronize { @state[:local_network][:recovery_stage] = 'local-repair' }
    log_event('local-network-recovery-deferred', detail: '没有节点数据面失败证据，等待本机组件／槽位恢复', evidence: evidence)
    nil
  end

  # 两次健康检查之间等多少秒。
  #
  # 稳态用 health_interval。一旦出现失败、但还没到判定阈值，就改用
  # health_recheck_interval 快速复检。front 后端失败还会直接唤醒；
  # 默认首次失败后等 2 秒复检，完整健康判据保持不变。
  # 已经到阈值（恢复动作已经在跑）就回到稳态节奏，避免对死链路无限快轮询。
  def health_wait_seconds
    return @options[:local_network_interval] if local_network_paused? || local_network_recovery_pending?
    interval = [@options[:health_interval].to_i, 1].max
    threshold = [@options[:health_fail_threshold].to_i, 1].max
    recheck = [@options[:health_recheck_interval].to_i, 1].max

    failing = @health_fail_streak.to_i.positive? || @dns_fail_streak.to_i.positive?
    below_threshold = @health_fail_streak.to_i < threshold && @dns_fail_streak.to_i < threshold
    failing && below_threshold ? [recheck, interval].min : interval
  end

  # Wakeups are coalesced. A backend failure no longer waits for a 30s poll,
  # and a busy transaction retries promptly instead of losing a whole cycle.
  def wake_health_monitor(reason)
    @health_wait_mutex.synchronize do
      unless @health_wake_pending
        @health_wake_pending = true
        log_event('health-check-requested', reason: reason)
      end
      @health_cv.broadcast
    end
  end

  def wait_for_health_check(timeout = nil)
    @health_wait_mutex.synchronize do
      @health_cv.wait(@health_wait_mutex, timeout || health_wait_seconds) unless @health_wake_pending || @stop_requested
      @health_wake_pending = false
    end
  end

  def capture_active_context
    @mutex.synchronize do
      slot = @state[:active_slot]
      worker = slot && @workers[slot]
      return nil unless worker && !%w[switching reconnecting].include?(@state[:status])
      { generation: @state[:generation], network_epoch: @state[:local_network][:epoch], slot: slot, relay: @state[:active_relay],
        token: worker[:instance_token], pid: worker[:pid], front_pid: @front_pid, worker: worker.dup }
    end
  end

  def active_context_current?(context, front: false)
    @mutex.synchronize do
      worker = @workers[context[:slot]]
      (context[:network_epoch].nil? || @state[:local_network][:epoch] == context[:network_epoch]) &&
        @state[:generation] == context[:generation] && @state[:active_slot] == context[:slot] &&
        @state[:active_relay] == context[:relay] && worker && worker[:instance_token] == context[:token] &&
        worker[:pid] == context[:pid] && (!front || @front_pid == context[:front_pid]) &&
        !%w[switching reconnecting].include?(@state[:status])
    end
  end

  def start_active_health_monitor
    Thread.new do
      retry_wait = nil
      until @stop_requested
        wait_for_health_check(retry_wait)
        break if @stop_requested
        result = action_pending? ? :retry : check_active_health_once
        retry_wait = result == :retry ? 0.25 : nil
      end
    end
  end

  def check_active_health_once
    return :retry if action_pending?
    return if local_network_paused?
    return recover_local_network_once if local_network_recovery_pending?

    recovery = nil
    recovery_reason = 'health-recovery'
    recovery_candidates = []
    expected_relay = nil
    expected_generation = nil
    expected_slot = nil
    recovery_requested = false
    recovery_handled = false
    dns_recovery_requested = false
    active_mode = nil
    begin
      pending = @pending_health_observation
      if pending && active_context_current?(pending[:context]) && Time.now - pending[:at] < @options[:health_interval]
        context, canary = pending.values_at(:context, :canary)
      else
        @pending_health_observation = nil
        context = capture_active_context
        return (@switch_mutex.locked? ? :retry : nil) unless context
        canary = run_readiness_canary(context[:slot])
      end
      slot, relay_name, generation = context.values_at(:slot, :relay, :generation)
      return unless relay_name
      unless @switch_mutex.try_lock
        @pending_health_observation = { context: context, canary: canary, at: pending ? pending[:at] : Time.now }
        return :retry
      end
      @pending_health_observation = nil
      unless active_context_current?(context)
        log_event('health-result-discarded', relay: relay_name, generation: generation, reason: 'active-context-changed')
        return
      end
      active_worker = context[:worker]
      active_mode = active_worker[:transport_mode].to_s.empty? ? 'ss' : active_worker[:transport_mode]
      cache_speed_test(relay_name, canary, 'active-health', active_mode)
      record_ss_endpoint_canary(relay_name, active_mode, active_worker, canary)
      classification = classify_canary(canary)
      clear_relay_quarantine(relay_name) if classification[:service_readiness] == 'ready'
      observe_inner_dns_result(relay_name, canary)
      now = Time.now
      expected_relay = relay_name
      expected_generation = generation
      expected_slot = slot
      @mutex.synchronize do
        @metrics[:health_checks] += 1
        @state[:last_canary] = canary
        @state[:dns][:inner] = canary[:inner_dns]
        @state[:relay_liveness] = classification[:relay_liveness]
        @state[:service_readiness] = classification[:service_readiness]
        @state[:status] = classification[:service_readiness] == 'ready' ? 'ready' : classification[:service_readiness]
        @state[:health][:last_check_at] = now.iso8601
        if classification[:relay_liveness] == 'pass'
          @health_fail_streak = 0
          @state[:health][:consecutive_wg_failures] = 0
          if classification[:service_readiness] == 'ready'
            @dns_fail_streak = 0
            @state[:health][:consecutive_dns_failures] = 0
            @state[:last_error] = nil
          elsif classification[:service_readiness] == 'degraded_dns'
            @dns_fail_streak += 1
            @metrics[:health_dns_failures] += 1
            @state[:health][:consecutive_dns_failures] = @dns_fail_streak
            @state[:last_error] = "active relay inner DNS failed #{@dns_fail_streak}/#{@options[:health_fail_threshold]}"
            if @dns_fail_streak >= @options[:health_fail_threshold].to_i &&
               recovery_due?(generation, now)
              dns_recovery_requested = true
            end
          else
            @dns_fail_streak = 0
            @state[:health][:consecutive_dns_failures] = 0
          end
        else
          @dns_fail_streak = 0
          @state[:health][:consecutive_dns_failures] = 0
          @health_fail_streak += 1
          @metrics[:health_wg_failures] += 1
          @state[:health][:consecutive_wg_failures] = @health_fail_streak
          @state[:last_error] = "active relay WG data canary failed #{@health_fail_streak}/#{@options[:health_fail_threshold]}"
          if @health_fail_streak >= @options[:health_fail_threshold].to_i &&
             recovery_due?(generation, now)
            recovery_requested = true
          end
        end
        @state[:updated_at] = now.iso8601
      end

      if dns_recovery_requested
        if inner_dns_breaker_open?
          @mutex.synchronize { @metrics[:inner_dns_breaker_suppressed] += 1 }
          dns_recovery_requested = false
        else
          recovery_reason = 'dns-recovery-probe'
          recovery_candidates = recovery_relay_candidates(relay_name)
          recovery = recovery_candidates.shift
        end
      elsif recovery_requested
        if active_mode == 'ss'
          current_relay = find_relay(relay_name) rescue nil
          if current_relay && ss_endpoint_candidates(current_relay).length > 1
            # Before abandoning a Relay, rotate to another SS inlet for
            # the same peer. This is still break-before-make and strictly
            # serialized, so no duplicate WireGuard peer exists.
            recovery = relay_name
            recovery_reason = 'ss-endpoint-recovery'
          end
        end
        unless recovery
          quarantine_relay(relay_name, 'active-health-failure')
          recovery_candidates = recovery_relay_candidates(relay_name)
          recovery = recovery_candidates.shift
        end
      end
    rescue StandardError => e
      record_error("active health check failed: #{e.class}: #{e.message}")
    ensure
      @switch_mutex.unlock if @switch_mutex.owned?
    end

    unless recovery && expected_relay
      if recovery_requested || dns_recovery_requested
        log_event('recovery-city-exhausted', relay: expected_relay, city: recovery_city(expected_relay), reason: 'no-eligible-same-city-candidate')
        @mutex.synchronize { @state[:last_error] = '当前城市暂无可尝试的备用节点；后台继续复检，不会跨城切换' }
      end
      return
    end
    return if action_pending?

    round_started = monotonic_now
    recovery_id = SecureRandom.uuid
    log_event('recovery-round-started', recovery_id: recovery_id, relay: expected_relay, city: recovery_city(expected_relay), reason: recovery_reason, generation: expected_generation)
    previous_recovery = Thread.current[:adapter_recovery_id]
    previous_deadline = Thread.current[:adapter_recovery_deadline]
    Thread.current[:adapter_recovery_id] = recovery_id
    Thread.current[:adapter_recovery_deadline] = round_started + @options[:recovery_round_budget]
    begin
      @last_auto_recovery_at = Time.now
      @last_recovery_generation = expected_generation
      @mutex.synchronize do
        @metrics[:auto_recovery_attempts] += 1
        @state[:health][:last_attempt_at] = @last_auto_recovery_at.iso8601
      end
      ok = activate(
        recovery,
        reason: recovery_reason,
        transport_preference: current_transport_preference,
        expected_state: {
          generation: expected_generation,
          active_slot: expected_slot,
          active_relay: expected_relay
        }
      )
      unless ok
        context_valid = automatic_recovery_context_valid?(expected_generation, expected_relay)
        unless context_valid
          @mutex.synchronize { @metrics[:auto_recovery_failures] += 1 }
          return
        end

        if recovery_reason == 'dns-recovery-probe' && inner_dns_breaker_open?
          recovery_handled = true
          record_routing_event(
            'common-dns-failure-detected',
            relay: expected_relay,
            reason: recovery_reason,
            detail: 'alternate relay also had live data but failed inner DNS; relay churn suppressed'
          )
        elsif recovery_reason == 'ss-endpoint-recovery'
          quarantine_relay(expected_relay, 'same-node-retry-failed')
          recovery_candidates = recovery_relay_candidates(expected_relay)
        else
          quarantine_relay(recovery, 'recovery-candidate-failed', 300)
          recovery_candidates = recovery_relay_candidates(expected_relay).reject { |candidate| candidate == recovery }
            .first([@options[:recovery_batch_size] - 1, 0].max)
        end

        recovery_candidates.each do |fallback_relay|
          break if monotonic_now - round_started >= @options[:recovery_round_budget]
          break if recovery_handled
          break unless automatic_recovery_context_valid?(expected_generation, expected_relay)
          current = @mutex.synchronize do
            {
              generation: @state[:generation],
              active_slot: @state[:active_slot],
              active_relay: @state[:active_relay]
            }
          end
          ok = activate(
            fallback_relay,
            reason: 'health-recovery',
            transport_preference: current_transport_preference,
            expected_state: current
          )
          break if ok
          if recovery_reason == 'dns-recovery-probe' && inner_dns_breaker_open?
            recovery_handled = true
            record_routing_event(
              'common-dns-failure-detected',
              relay: expected_relay,
              reason: recovery_reason,
              detail: 'cross-relay inner DNS failure confirmed; further failover suppressed'
            )
            break
          end
          quarantine_relay(fallback_relay, 'recovery-candidate-failed', 300)
        end
      end
      @mutex.synchronize { @metrics[:auto_recovery_failures] += 1 unless ok || recovery_handled }
    ensure
      log_event('recovery-round-finished', recovery_id: recovery_id, restored: ok, suppressed: recovery_handled, duration_ms: ((monotonic_now - round_started) * 1000).round, active_relay: snapshot[:active_relay])
      Thread.current[:adapter_recovery_id] = previous_recovery
      Thread.current[:adapter_recovery_deadline] = previous_deadline
    end
  end

  def observe_inner_dns_result(relay_name, canary)
    return unless network_attempt_current?
    data_ok = canary.dig(:ip_data, :status) == 'pass'
    dns_ok = canary.dig(:inner_dns, :status) == 'pass'
    return unless data_ok

    now = Time.now
    @mutex.synchronize do
      if dns_ok
        @inner_dns_observations.clear
        @state[:dns][:inner_breaker] = {
          status: 'closed', observed_relays: [], threshold: INNER_DNS_BREAKER_THRESHOLD,
          until: nil, detail: 'inner DNS succeeded while WG data path was live'
        }
        next
      end

      cutoff = now - INNER_DNS_BREAKER_WINDOW
      @inner_dns_observations.select! { |entry| entry[:at] >= cutoff }
      @inner_dns_observations.reject! { |entry| entry[:relay] == relay_name }
      @inner_dns_observations << { relay: relay_name, at: now }
      distinct = @inner_dns_observations.map { |entry| entry[:relay] }.uniq
      breaker = @state[:dns][:inner_breaker]
      if distinct.length >= INNER_DNS_BREAKER_THRESHOLD
        was_open = breaker[:status] == 'open' && breaker[:until] && Time.parse(breaker[:until]) > now rescue false
        until_time = now + INNER_DNS_BREAKER_COOLDOWN
        @state[:dns][:inner_breaker] = {
          status: 'open', observed_relays: distinct, threshold: INNER_DNS_BREAKER_THRESHOLD,
          until: until_time.iso8601,
          detail: 'multiple relays have live WG data but failed Mullvad inner DNS; relay churn suppressed'
        }
        @metrics[:inner_dns_breaker_trips] += 1 unless was_open
      else
        @state[:dns][:inner_breaker] = {
          status: 'closed', observed_relays: distinct, threshold: INNER_DNS_BREAKER_THRESHOLD,
          until: nil, detail: 'isolated inner-DNS failure; waiting for cross-relay evidence'
        }
      end
      @state[:updated_at] = now.iso8601
    end
  end


  def recovery_due?(generation, now = Time.now)
    @last_recovery_generation != generation || (now - @last_auto_recovery_at) >= @options[:recovery_cooldown]
  end

  def inner_dns_breaker_open?
    @mutex.synchronize do
      breaker = @state[:dns][:inner_breaker]
      return false unless breaker[:status] == 'open'
      begin
        return true if breaker[:until] && Time.parse(breaker[:until]) > Time.now
      rescue ArgumentError
        # Treat malformed/expired state as closed.
      end
      @inner_dns_observations.clear
      @state[:dns][:inner_breaker] = {
        status: 'closed', observed_relays: [], threshold: INNER_DNS_BREAKER_THRESHOLD,
        until: nil, detail: 'common inner-DNS breaker cooldown expired'
      }
      false
    end
  end

  def select_recovery_relay(current_name, preference: current_transport_preference)
    recovery_relay_candidates(current_name, preference: preference).first
  end

  def city_workspace_path
    File.join(@state_dir, 'city-workspace.json')
  end

  def load_city_workspace
    return unless File.file?(city_workspace_path)
    payload = JSON.parse(File.read(city_workspace_path))
    favorites = payload['favorite_cities']
    selected = payload['selected_city']
    raise 'invalid city workspace' unless favorites.is_a?(Array) && favorites.length <= 3 &&
      favorites.uniq == favorites && favorites.all? { |id| id.is_a?(String) && id.match?(/\A[a-z]{2}-[a-z0-9]+\z/) } &&
      (selected.nil? || favorites.include?(selected))
    @city_mutex.synchronize do
      @favorite_cities = favorites
      @selected_city = selected
    end
  rescue StandardError => e
    record_error("city workspace could not be loaded: #{e.class}: #{e.message}; using persisted relay city")
  end

  # Caller owns city_mutex; persist first, then expose the new policy.
  def persist_city_workspace(favorites, selected)
    FileUtils.mkdir_p(@state_dir)
    temporary = "#{city_workspace_path}.#{SecureRandom.hex(4)}.tmp"
    File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
      file.write(JSON.pretty_generate(version: 1, favorite_cities: favorites, selected_city: selected))
      file.flush
      file.fsync
    end
    File.rename(temporary, city_workspace_path)
  ensure
    File.delete(temporary) if temporary && File.exist?(temporary)
  end

  def update_favorite_cities(favorites)
    raise ArgumentError, '连接操作进行中，请完成后再管理城市' if action_pending?
    raise ArgumentError, '可保存 1–3 个不重复城市' unless favorites.is_a?(Array) &&
      favorites.length.between?(1, 3) && favorites.uniq == favorites
    known = Array(@metadata&.dig('wireguard', 'relays')).select { |r| r['active'] == true }.map { |r| r['location'] }.uniq
    @city_mutex.synchronize do
      # A removed metadata city can still be retained, but no invented city added.
      raise ArgumentError, '未知或无活动节点的城市' unless favorites.all? { |id| id.is_a?(String) && (known.include?(id) || @favorite_cities.include?(id)) }
      raise ArgumentError, '请先切换城市，再移除当前城市' if @selected_city && !favorites.include?(@selected_city)
      persist_city_workspace(favorites, @selected_city)
      @favorite_cities = favorites.dup
    end
    record_persistence_success(:cities)
    log_event('city-favorites-updated', favorite_cities: favorites)
  rescue ArgumentError
    raise
  rescue StandardError => e
    record_persistence_failure(:cities, e)
    raise
  end

  def select_city_for_relay(relay_name, city: nil)
    city ||= find_relay(relay_name)['location'].to_s
    return if city.empty?
    @city_mutex.synchronize do
      favorites = @favorite_cities.dup
      unless favorites.include?(city)
        favorites.pop if favorites.length >= 3
        favorites << city
      end
      persist_city_workspace(favorites, city)
      @favorite_cities, @selected_city = favorites, city
    end
    record_persistence_success(:cities)
  rescue StandardError => e
    # A committed connection must not be rolled back just because disk is full.
    # Keep the in-memory city boundary and expose persistence failure explicitly.
    @city_mutex.synchronize { @selected_city = city; @favorite_cities = (Array(@favorite_cities).first(2) + [city]).uniq } if city && !city.empty?
    record_persistence_failure(:cities, e)
  end

  def recovery_city(current_name)
    selected = @city_mutex.synchronize { @selected_city }
    return selected if selected && !selected.empty?
    relay = Array(@metadata&.dig('wireguard', 'relays')).find { |r| r['hostname'] == current_name }
    relay && relay['location'].to_s
  end

  def city_selection_candidates(city, preference = 'auto')
    current = snapshot
    candidates = ranked_city_relays(city, preference).reject { |r| relay_quarantined?(r['hostname']) }.map { |r| r['hostname'] }
    if current[:active_slot] && current[:service_readiness] == 'ready' &&
       candidates.include?(current[:active_relay])
      candidates.unshift(current[:active_relay])
    end
    candidates.uniq.first(@options[:recovery_batch_size])
  end

  def ranked_city_relays(city, preference)
    relays = Array(@metadata&.dig('wireguard', 'relays')).select { |r| r['active'] == true && r['location'].to_s == city }
    relays.select! { |r| (transport_candidates(preference, r).any? rescue false) }
    relays.sort_by do |r|
      history = recovery_history_for(r['hostname'], preference)
      tested = history && history[:last_tested_at] && (Time.parse(history[:last_tested_at]) rescue nil)
      fresh = tested && Time.now - tested < 600
      history = nil if protection_profile[:multihop] || protection_profile[:post_quantum]
    ready = history && history[:last_result] && classify_canary(history[:last_result])[:service_readiness] == 'ready'
      [relay_quarantined?(r['hostname']) ? 1 : 0, fresh && ready ? 0 : 1,
       history ? history[:consecutive_failures].to_i : 0, -(history ? history_confidence_score(history) : -1), r['hostname']]
    end
  end

  def activate_city(city, preference)
    with_recovery_budget('city-select', city, city: city) do
      city_selection_candidates(city, preference).each do |name|
        break unless recovery_budget_remaining?
        return true if activate(name, reason: 'city-select', transport_preference: preference)
        quarantine_relay(name, 'city-selection-failed', 60)
      end
      false
    end
  end

  # A round limits the start of new attempts, never interrupts an in-flight
  # lifecycle transaction. Preserve caller trace/deadline even on early return.
  def with_recovery_budget(reason, relay, city: nil)
    started = monotonic_now
    previous_id = Thread.current[:adapter_recovery_id]
    previous_deadline = Thread.current[:adapter_recovery_deadline]
    Thread.current[:adapter_recovery_id] = SecureRandom.uuid
    deadline = started + @options[:recovery_round_budget]
    Thread.current[:adapter_recovery_deadline] = previous_deadline ? [deadline, previous_deadline].min : deadline
    log_event('recovery-round-started', relay: relay, city: city || recovery_city(relay), reason: reason)
    result = yield
  ensure
    log_event('recovery-round-finished', reason: reason, result: result,
              duration_ms: ((monotonic_now - started) * 1000).round,
              active_relay: snapshot[:active_relay], service_readiness: snapshot[:service_readiness])
    Thread.current[:adapter_recovery_id] = previous_id
    Thread.current[:adapter_recovery_deadline] = previous_deadline
  end

  def recovery_budget_remaining?
    deadline = Thread.current[:adapter_recovery_deadline]
    !@stop_requested && !operation_cancelled? && !local_network_paused? && (!deadline || monotonic_now < deadline)
  end

  def city_node_evidence(name, active: false)
    history = recovery_history_for(name, 'auto')
    if protection_profile[:multihop] || protection_profile[:post_quantum]
      # Ordinary relay history does not prove this protected circuit. Active
      # evidence may come only from its current worker's actual canary.
      history = nil
      current = snapshot if active
      if current && current[:active_relay] == name && current[:active_slot] && current[:last_canary]
        history = { last_tested_at: current[:last_canary][:at], last_result: current[:last_canary],
                    transport_mode: current[:active_transport_mode] }
      end
    end
    tested = history && history[:last_tested_at]
    age = tested && (Time.now - Time.parse(tested)).to_i rescue nil
    ready = history && history[:last_result] && classify_canary(history[:last_result])[:service_readiness] == 'ready'
    probe = @city_mutex.synchronize { @city_probes[name]&.dup }
    { relay: name, transport: history && history[:transport_mode],
      evidence: relay_quarantined?(name) ? 'quarantined' : (ready && age && age < 600 ? 'recent_ready' : (tested ? 'expired_or_failed' : 'unverified')),
      checked_at: tested, age_seconds: age, outer_probe: probe, active: active }
  end

  def city_workspace_snapshot
    current = snapshot
    favorites, selected = @city_mutex.synchronize { [@favorite_cities.dup, @selected_city] }
    selected = current[:selected_city] || selected
    favorites = (favorites.first(2) + [selected]).uniq if selected && !favorites.include?(selected)
    locations = @metadata && @metadata['locations'] || {}
    cities = favorites.map do |id|
      info = locations[id] || {}
      relays = ranked_city_relays(id, 'auto')
      primary = current[:active_relay] if id == selected
      backups = relays.reject { |r| r['hostname'] == primary }.first(2).map { |r| city_node_evidence(r['hostname']) }
      { id: id, country: info['country'], city: info['city'],
        relay_count: relays.length, primary: primary && city_node_evidence(primary, active: !!current[:active_slot]),
        backups: backups, maintenance_interval_seconds: id == selected ? 30 : 180 }
    end
    { version: 1, generation: current[:generation], favorite_cities: favorites, selected_city: selected, cities: cities,
      auto_cross_city: false, backup_policy: 'outer-probe-only-until-switch', updated_at: Time.now.iso8601 }
  end

  def maintain_city_candidates_once
    return if local_network_paused? || local_network_recovery_pending?
    epoch = network_epoch
    favorites, selected = @city_mutex.synchronize { [@favorite_cities.dup, @selected_city] }
    current = snapshot
    @city_maintenance_due ||= {}
    favorites.each do |city|
      next if Time.now < (@city_maintenance_due[city] || Time.at(0))
      @city_maintenance_due[city] = Time.now + (city == selected ? 30 : 180)
      relays = ranked_city_relays(city, 'auto').reject { |r| r['hostname'] == current[:active_relay] }.first(2)
      relays.each do |relay|
        break if @stop_requested || local_network_paused?
        mode = transport_candidates('auto', relay).first
        endpoint = quick_ping_targets(relay).dig(mode, :target)
        next unless endpoint
        result = outer_ping_test(endpoint, 1_000)
        return unless network_epoch_current?(epoch)
        @city_mutex.synchronize { @city_probes[relay['hostname']] = result.merge(transport: mode, checked_at: Time.now.iso8601) }
        log_event('city-candidate-outer-probe', relay: relay['hostname'], city: city, transport: mode, result: result)
      end
    end
  end

  def start_city_maintenance
    Thread.new do
      until @stop_requested
        begin
          maintain_city_candidates_once
        rescue StandardError => e
          log_event('city-maintenance-error', error: "#{e.class}: #{e.message}")
        end
        5.times { break if @stop_requested; sleep 1 }
      end
    end
  end

  def recovery_relay_candidates(current_name, preference: current_transport_preference)
    city = recovery_city(current_name)
    return [] if city.to_s.empty?
    ranked_city_relays(city, preference).reject do |relay|
      relay['hostname'] == current_name || relay_quarantined?(relay['hostname'])
    end.first(@options[:recovery_batch_size]).map { |relay| relay['hostname'] }
  end

  def activate_startup_with_fallback(preferred_relay, preference, reason:, expected_state: nil)
    with_recovery_budget(reason, preferred_relay) do
      normalized = normalize_transport_preference(preference)
      active_relays = Array(@metadata&.dig('wireguard', 'relays')).select { |relay| relay['active'] == true }
      preferred = active_relays.find { |relay| relay['hostname'].to_s == preferred_relay.to_s }
      candidates = []
      if preferred && preferred['location'].to_s == recovery_city(preferred_relay) && !relay_quarantined?(preferred_relay)
        begin
          candidates << preferred_relay.to_s unless transport_candidates(normalized, preferred).empty?
        rescue StandardError
          # Fall through to ranked active relays.
        end
      end
      candidates.concat(recovery_relay_candidates(preferred_relay.to_s, preference: normalized))
      candidates.uniq!
      candidates = candidates.first(@options[:recovery_batch_size])

      candidates.each do |candidate|
        break unless recovery_budget_remaining?
        return false if action_conflicts?
        current = expected_state || @mutex.synchronize do
          {
            generation: @state[:generation],
            active_slot: @state[:active_slot],
            active_relay: @state[:active_relay]
          }
        end
        return false unless current[:active_slot].nil?

        ok = activate(
          candidate,
          reason: reason,
          transport_preference: normalized,
          expected_state: current
        )
        return true if ok
        return false unless automatic_recovery_context_valid?(current[:generation], current[:active_relay])

        quarantine_relay(candidate, 'startup-candidate-failed', 300)
        expected_state = @mutex.synchronize do
          {
            generation: @state[:generation],
            active_slot: @state[:active_slot],
            active_relay: @state[:active_relay]
          }
        end
      end

      record_error("no active relay could be started (preferred=#{preferred_relay})")
      false
    end
  end

  def automatic_recovery_context_valid?(generation, relay_name)
    return false if action_conflicts? || local_network_paused? || local_network_recovery_pending?
    @mutex.synchronize do
      @state[:generation] == generation && @state[:active_relay] == relay_name
    end
  end

  def recovery_history_for(relay_name, preference)
    modes = normalize_transport_preference(preference) == 'auto' ? AUTO_TRANSPORT_ORDER : [normalize_transport_preference(preference)]
    @history_mutex.synchronize do
      entries = modes.filter_map { |mode| @relay_history["#{relay_name}|#{mode}"] }
      if normalize_transport_preference(preference) == 'auto'
        ready = entries.select do |e|
          at = e[:last_tested_at] && (Time.parse(e[:last_tested_at]) rescue nil)
          at && Time.now - at < 600 && e[:last_result] && classify_canary(e[:last_result])[:service_readiness] == 'ready'
        end
        entries = ready unless ready.empty?
      end
      entry = entries.max_by { |e| e[:last_tested_at].to_s }
      entry && Marshal.load(Marshal.dump(entry))
    end
  end

  def history_confidence_score(entry)
    samples = entry[:samples].to_i
    return -1.0 if samples <= 0

    ready = entry[:ready_samples].to_i
    n = samples.to_f
    p = ready.fdiv(samples)
    z = 1.96
    z2 = z * z
    lower = (p + z2 / (2 * n) - z * Math.sqrt((p * (1 - p) + z2 / (4 * n)) / n)) / (1 + z2 / n)
    lower - [entry[:consecutive_failures].to_i, 3].min * 0.04
  end

  def quarantine_relay(relay_name, reason, seconds = nil)
    return if local_network_paused?
    name = relay_name.to_s
    return if name.empty?

    ttl = (seconds || @options[:recovery_quarantine]).to_i
    @mutex.synchronize do
      @recovery_quarantine[name] = {
        until: Time.now + [ttl, 1].max,
        reason: reason.to_s
      }
    end
  end

  def clear_relay_quarantine(relay_name)
    removed = @mutex.synchronize { @recovery_quarantine.delete(relay_name.to_s) }
    log_event('relay-quarantine-cleared', relay: relay_name, reason: 'complete-readiness-pass') if removed
  end

  def relay_quarantined?(relay_name)
    name = relay_name.to_s
    @mutex.synchronize do
      entry = @recovery_quarantine[name]
      next false unless entry
      if entry[:until] <= Time.now
        @recovery_quarantine.delete(name)
        next false
      end
      true
    end
  end

  def current_transport_preference
    @mutex.synchronize { @state[:transport_preference] || DEFAULT_TRANSPORT_PREFERENCE }
  end

  def normalize_transport_preference(value)
    normalized = value.to_s.downcase.strip
    normalized = DEFAULT_TRANSPORT_PREFERENCE if normalized.empty?
    raise "unsupported transport preference: #{value}" unless TRANSPORT_PREFERENCES.include?(normalized)
    normalized
  end

  def persisted_transport_preference_path
    File.join(@state_dir, 'last-transport-preference')
  end

  def load_persisted_transport_preference
    return nil unless File.file?(persisted_transport_preference_path)
    normalize_transport_preference(File.read(persisted_transport_preference_path).strip)
  rescue StandardError
    nil
  end

  def persist_transport_preference(preference)
    value = normalize_transport_preference(preference)
    tmp = persisted_transport_preference_path + ".tmp-#{Process.pid}"
    File.write(tmp, value + "
")
    File.chmod(0o600, tmp)
    File.rename(tmp, persisted_transport_preference_path)
    record_persistence_success(:transport_preference)
    true
  rescue StandardError => e
    record_persistence_failure('transport-preference', e)
    false
  ensure
    FileUtils.rm_f(tmp) if defined?(tmp) && File.exist?(tmp)
  end

  def persisted_relay_path
    File.join(@state_dir, 'last-relay')
  end

  def load_persisted_relay
    return nil unless File.file?(persisted_relay_path)
    value = File.read(persisted_relay_path).strip
    value.empty? ? nil : value
  rescue StandardError
    nil
  end

  def persist_relay(relay_name)
    tmp = persisted_relay_path + ".tmp-#{Process.pid}"
    File.write(tmp, relay_name.to_s + "\n")
    File.chmod(0o600, tmp)
    File.rename(tmp, persisted_relay_path)
    record_persistence_success(:relay)
    true
  rescue StandardError => e
    record_persistence_failure('relay', e)
    false
  ensure
    FileUtils.rm_f(tmp) if defined?(tmp) && File.exist?(tmp)
  end

  def record_persistence_success(kind)
    @mutex.synchronize do
      persistence = @state[:persistence]
      persistence[kind] = 'ok'
      if %i[relay transport_preference cities].all? { |component| persistence[component].nil? || persistence[component] == 'ok' }
        persistence[:status] = 'ok'
        persistence[:last_error] = nil
      end
    end
  end

  def record_persistence_failure(kind, error)
    message = "#{kind}: #{error.class}: #{error.message}"
    component = %i[relay transport_preference cities].include?(kind.to_sym) ? kind.to_sym : :transport_preference
    @mutex.synchronize do
      @metrics[:persistence_failures] += 1
      persistence = @state[:persistence]
      persistence[component] = 'degraded'
      persistence[:status] = 'degraded'
      persistence[:last_error] = message
      persistence[:last_error_at] = Time.now.iso8601
      @state[:updated_at] = Time.now.iso8601
    end
    record_routing_event('persistence-warning', detail: message)
    warn "state persistence failed: #{message}"
  end

  def bootstrap_proxy_args
    raw = @options[:bootstrap_proxy].to_s
    raise 'bootstrap proxy is required; system DNS fallback is disabled' if raw.empty?
    uri = URI(raw)
    raise 'bootstrap proxy must use local http:// listener' unless uri.scheme == 'http' && uri.host && uri.port
    address = IPAddr.new(uri.host)
    loopback = IPAddr.new('127.0.0.0/8').include?(address) || address == IPAddr.new('::1')
    raise 'bootstrap proxy must resolve to a literal loopback address' unless loopback
    ['--proxy', raw]
  rescue URI::InvalidURIError, IPAddr::InvalidAddressError => e
    raise "invalid bootstrap proxy: #{e.message}"
  end

  def validate_metadata_payload(candidate)
    raise 'metadata root must be an object' unless candidate.is_a?(Hash)

    wireguard = candidate['wireguard']
    raise 'metadata missing wireguard object' unless wireguard.is_a?(Hash)

    relays = Array(wireguard['relays'])
    raise 'metadata missing wireguard relays' if relays.empty?
    validated_port_ranges(wireguard['port_ranges'], 'wireguard port ranges')
    validated_port_ranges(wireguard['shadowsocks_port_ranges'], 'shadowsocks port ranges')

    seen = {}
    warnings = []
    valid_relays = relays.each_with_index.filter_map do |relay, index|
      validate_relay_entry(relay, index, seen)
      relay
    rescue RuntimeError => e
      warnings << e.message
      nil
    end
    @last_metadata_validation_warnings = warnings
    raise "metadata has no valid relays: #{warnings.first || 'unknown relay error'}" if valid_relays.empty?

    wireguard['relays'] = valid_relays
    valid_relays
    candidate
  end

  def validate_relay_entry(relay, index, seen)
    raise "metadata relay[#{index}] is not an object" unless relay.is_a?(Hash)

    hostname = relay['hostname'].to_s.strip
    raise "metadata relay[#{index}] has no hostname" if hostname.empty? || hostname.bytesize > 255
    raise "metadata has duplicate relay hostname: #{hostname}" if seen[hostname]
    seen[hostname] = true

    active = relay['active']
    raise "metadata relay #{hostname} has invalid active flag" unless active == true || active == false

    location = relay['location'].to_s.strip
    raise "metadata relay #{hostname} has no location" if location.empty?
    public_key = relay['public_key'].to_s.strip
    raise "metadata relay #{hostname} has no WireGuard public key" if public_key.empty?

    ipv4 = relay['ipv4_addr_in'].to_s.strip
    ipv6 = relay['ipv6_addr_in'].to_s.strip
    raise "metadata relay #{hostname} has no IP entrance" if ipv4.empty? && ipv6.empty?
    validate_ip_address(ipv4, "metadata relay #{hostname} ipv4_addr_in") unless ipv4.empty?
    validate_ip_address(ipv6, "metadata relay #{hostname} ipv6_addr_in") unless ipv6.empty?

    extras = relay['shadowsocks_extra_addr_in']
    if extras && !extras.is_a?(Array)
      raise "metadata relay #{hostname} has invalid shadowsocks_extra_addr_in"
    end
    Array(extras).each do |extra|
      validate_ip_address(extra, "metadata relay #{hostname} shadowsocks_extra_addr_in")
    end
    relay
  end

  def validate_ip_address(value, label)
    IPAddr.new(value.to_s)
  rescue IPAddr::InvalidAddressError
    raise "#{label} is not a valid IP address"
  end

  def validated_port_ranges(raw_ranges, label)
    ranges = Array(raw_ranges)
    raise "metadata missing #{label}" if ranges.empty?

    ranges.map do |range|
      unless range.is_a?(Array) && range.length == 2
        raise "metadata has invalid #{label}: #{range.inspect}"
      end
      begin
        low = Integer(range[0])
        high = Integer(range[1])
      rescue ArgumentError, TypeError
        raise "metadata has invalid #{label}: #{range.inspect}"
      end
      unless low.between?(1, 65_535) && high.between?(1, 65_535) && high >= low
        raise "metadata has invalid #{label}: #{range.inspect}"
      end
      [low, high]
    end
  end

  def wireguard_port_allowed?(port)
    validated_port_ranges(@metadata&.dig('wireguard', 'port_ranges'), 'wireguard port ranges').any? do |low, high|
      port.to_i.between?(low, high)
    end
  rescue RuntimeError
    false
  end

  def ensure_wireguard_port_allowed!(port)
    raise "WireGuard port #{port} is not in metadata port_ranges" unless wireguard_port_allowed?(port)
    port
  end

  def set_metadata_state(live:, cache:, source:, error:, fetched_at:, warnings: nil)
    @mutex.synchronize do
      @state[:metadata] = {
        live: live, cache: cache, source: source, age_seconds: nil, error: error,
        fetched_at: fetched_at&.iso8601,
        validation_warnings: Array(warnings || @last_metadata_validation_warnings).first(20)
      }
      @state[:updated_at] = Time.now.iso8601
    end
  end

  def record_metadata_validation_warnings(source)
    warnings = Array(@last_metadata_validation_warnings).compact.map(&:to_s).reject(&:empty?)
    return if warnings.empty?

    @mutex.synchronize { @metrics[:metadata_invalid_relays] += warnings.length }
    log_event('metadata-relay-rejected', source: source, count: warnings.length, warnings: warnings.first(20))
  end

  def load_cached_metadata
    cache = metadata_cache_path
    return false unless File.file?(cache)

    parsed = validate_metadata_payload(JSON.parse(File.read(cache)))
    @metadata = parsed
    @metadata_fetched_at = File.mtime(cache)
    set_metadata_state(
      live: false,
      cache: true,
      source: 'startup-cache',
      error: nil,
      fetched_at: @metadata_fetched_at
    )
    record_metadata_validation_warnings('startup-cache')
    true
  rescue JSON::ParserError, RuntimeError, SystemCallError => e
    set_metadata_state(live: false, cache: false, source: 'none', error: "startup cache invalid: #{e.message}", fetched_at: nil)
    false
  end

  def refresh_metadata(force: false)
    @metadata_mutex.synchronize do
      if !force && @metadata && @metadata_fetched_at && (Time.now - @metadata_fetched_at) < @options[:metadata_ttl]
        return @metadata
      end

      proxy_args = bootstrap_proxy_args
      parsed = nil
      last_error = nil
      3.times do
        stdout, stderr, status = Open3.capture3('curl', '-q', '-fsS', '--noproxy', '', '--max-time', '8', *proxy_args, API_URL)
        unless status.success?
          last_error = stderr.to_s.strip[0, 160]
          next
        end
        begin
          parsed = validate_metadata_payload(JSON.parse(stdout))
          break
        rescue JSON::ParserError, RuntimeError => e
          last_error = e.message
        end
      end

      unless parsed
        @mutex.synchronize { @metrics[:metadata_refresh_failures] += 1 }
        cache = metadata_cache_path
        if File.file?(cache)
          begin
            cached = validate_metadata_payload(JSON.parse(File.read(cache)))
            @metadata = cached
            @metadata_fetched_at = File.mtime(cache)
            set_metadata_state(live: false, cache: true, source: 'cache', error: last_error, fetched_at: @metadata_fetched_at)
            record_metadata_validation_warnings('cache')
            set_dns_status(:bootstrap, 'degraded', "live metadata fetch failed; using last valid cache: #{last_error}")
            check_clash_global_path
            return @metadata
          rescue JSON::ParserError, RuntimeError => e
            last_error = "#{last_error}; cache invalid: #{e.message}"
          end
        end
        set_metadata_state(live: false, cache: false, source: 'none', error: last_error, fetched_at: nil)
        raise "metadata fetch failed: #{last_error}"
      end

      @metadata = parsed
      @metadata_fetched_at = Time.now
      write_json_private(metadata_cache_path, parsed, secret: false)
      @mutex.synchronize { @metrics[:metadata_refreshes] += 1 }
      set_metadata_state(live: true, cache: true, source: 'bootstrap-proxy', error: nil, fetched_at: @metadata_fetched_at)
      record_metadata_validation_warnings('bootstrap-proxy')
      set_dns_status(:bootstrap, 'pass', 'Mullvad API fetched via dedicated main-Clash control listener')
      check_clash_global_path
      parsed
    end
  rescue JSON::ParserError => e
    @mutex.synchronize { @metrics[:metadata_refresh_failures] += 1 }
    set_metadata_state(live: false, cache: File.file?(metadata_cache_path), source: 'none', error: e.message, fetched_at: @metadata_fetched_at)
    raise "metadata JSON invalid: #{e.message}"
  rescue StandardError => e
    set_metadata_state(live: false, cache: File.file?(metadata_cache_path), source: (@metadata ? 'cache' : 'none'), error: e.message, fetched_at: @metadata_fetched_at)
    raise
  end


  def check_clash_global_path
    proxy_args = bootstrap_proxy_args
    stdout, stderr, status = Open3.capture3('curl', '-q', '-sS', '--noproxy', '', '--max-time', '5', *proxy_args, '-o', '/dev/null', '-w', '%{http_code}', HOST_CANARY)
    if status.success? && stdout.to_i == 204
      set_dns_status(:clash_global, 'pass', 'domain HTTPS through dedicated main-Clash control listener succeeded')
    else
      detail = stderr.to_s.strip[0, 160]
      detail = "HTTP #{stdout.to_i}" if detail.empty?
      set_dns_status(:clash_global, 'fail', detail)
    end
  rescue StandardError => e
    set_dns_status(:clash_global, 'fail', "#{e.class}: #{e.message}")
  end

  # Read only a local controller's non-secret fields. Never include raw Clash
  # configs, proxy definitions, credentials or account data in the report.
  def main_clash_config
    path = @options[:clash_socket]
    raise 'Clash controller socket unavailable' unless File.socket?(path)
    stdout, _stderr, status = Open3.capture3(
      'curl', '-q', '-fsS', '--max-time', '2', '--noproxy', '*',
      '--unix-socket', path, 'http://localhost/configs'
    )
    raise 'Clash controller did not answer' unless status.success?
    raw = JSON.parse(stdout)
    { status: 'pass', mixed_port: raw['mixed-port'], mode: raw['mode'], tun_enabled: raw.dig('tun', 'enable') }
  rescue StandardError => e
    { status: 'unknown', detail: e.message }
  end

  def diagnose_network
    refresh_local_network if @local_network_monitor_started
    if local_network_paused?
      report = diagnosis_from_layers(local_network: snapshot[:local_network])
      report.merge!(checked_at: Time.now.iso8601, layers: { local_network: snapshot[:local_network] },
                    scope: '硬件接口链路与地址；断网期间跳过互联网及节点测试')
      update_state(diagnosis: report)
      update_operation(message: report[:summary])
      return report
    end
    update_operation(stage: 'diagnosing', message: '正在分别检查适配器入口、Clash 入口和 DNS')
    @switch_mutex.synchronize do
      before = snapshot
      config = main_clash_config
      port = config[:mixed_port].to_i
      front_ip = spawn_probe { curl_proxy_ip_test(@options[:front_mixed], IP_CANARY, 5) }
      front_domain = spawn_probe { curl_proxy_test(@options[:front_mixed], HOST_CANARY, 5) }
      clash_ip = spawn_probe { port.positive? ? curl_proxy_ip_test(port, IP_CANARY, 5) : { status: 'unknown' } }
      clash_domain = spawn_probe { port.positive? ? curl_proxy_test(port, HOST_CANARY, 5) : { status: 'unknown' } }
      system_dns = spawn_probe do
        Timeout.timeout(3) { Addrinfo.getaddrinfo('www.gstatic.com', 443, nil, :STREAM) }
        { status: 'pass', detail: '系统解析器可解析测试域名' }
      end
      worker_probe = before[:active_slot] && @workers[before[:active_slot]] ? run_canary(before[:active_slot]) : nil
      layers = {
        adapter_ip: front_ip.value, adapter_https: front_domain.value,
        clash_ip: clash_ip.value, clash_https: clash_domain.value,
        system_dns: system_dns.value, clash_control: config
      }
      unless network_epoch_current?(before.dig(:local_network, :epoch))
        report = { code: 'local_network_changed', summary: '检查期间本机网络发生变化，结果已丢弃',
                   advice: '等待原连接恢复后重新检查。', checked_at: Time.now.iso8601,
                   layers: { local_network: snapshot[:local_network] } }
        update_state(diagnosis: report)
        update_operation(message: report[:summary])
        return report
      end
      if worker_probe
        classification = classify_canary(worker_probe)
        update_state(last_canary: worker_probe, **classification, status: classification[:service_readiness])
        @mutex.synchronize { @state[:dns][:inner] = worker_probe[:inner_dns] }
        layers[:worker] = { status: classification[:relay_liveness], readiness: classification[:service_readiness] }
      else
        layers[:worker] = { status: 'fail', detail: '没有活动连接进程' }
      end
      report = diagnosis_from_layers(layers)
      report.merge!(checked_at: Time.now.iso8601, layers: layers,
                    scope: '测试域名 www.gstatic.com 与 IP 1.1.1.1；Clash 入口结果包含其分流和上游，不能单独证明 TUN 或所有网站正常')
      update_state(diagnosis: report)
      update_operation(message: report[:summary])
      report
    end
  end

  def diagnosis_from_layers(layers)
    if layers.dig(:local_network, :paused)
      return { code: 'local_network_unavailable', summary: '本机网络已断开，正在等待恢复',
               advice: '暂停节点重试和切换；本机链路恢复后先验证原通道，必要时重建原路径，再尝试同城节点。' }
    end
    adapter_ok = layers.dig(:adapter_https, :status) == 'pass'
    clash_ok = layers.dig(:clash_https, :status) == 'pass'
    worker_ok = layers.dig(:worker, :status) == 'pass'
    if adapter_ok && clash_ok
      { code: 'paths_ok', summary: '适配器和 Clash 入口都能打开测试网页',
        advice: '无需重连。如果某个应用仍打不开，请检查它的代理 / TUN 路径、匹配规则和目标网站。' }
    elsif adapter_ok && layers.dig(:clash_https, :status) == 'fail'
      { code: 'clash_path', summary: '适配器可用，Clash 入口访问失败',
        advice: '问题范围在 Clash 的分流、DNS 或上游路径；反复换 Mullvad 节点通常无助于这条路径。' }
    elsif worker_ok && layers.dig(:adapter_ip, :status) == 'fail' && !adapter_ok
      { code: 'adapter_front', summary: '隧道能通，本地转发入口异常',
        advice: '可自动修复本地转发入口，无需重建隧道。' }
    elsif layers.dig(:worker, :readiness) == 'degraded_dns'
      { code: 'inner_dns', summary: 'Mullvad 网络通，DNS 不通',
        advice: '会检查备用节点；多个节点同时 DNS 失败时暂停盲目切换。' }
    elsif !worker_ok && clash_ok
      { code: 'mullvad_path', summary: 'Clash 测试路径可用，Mullvad 隧道未通过',
        advice: '优先恢复适配器连接，无需重启整个 Clash。' }
    elsif adapter_ok
      { code: 'clash_unknown', summary: '适配器可用，Clash 路径尚未确认',
        advice: 'Clash 控制接口不可用或检查未完成；无法据此判断 Clash 是否断网。' }
    else
      { code: 'unresolved', summary: '多条检查未通过，暂时不能确定唯一故障点',
        advice: '可能涉及 Wi-Fi、上游网络、Clash 或 Mullvad。后台会有限重试，不会因此反复重启 Clash。' }
    end
  end

  def repair_connection
    report = diagnose_network
    return false if report[:code] == 'local_network_unavailable'
    return true if %w[paths_ok clash_path clash_unknown].include?(report[:code])
    update_operation(stage: 'repairing', message: '正在恢复适配器；可用连接会保留到替代连接通过')
    begin
      supervise_front_runtime
    rescue StandardError
      # Worker recovery must still be attempted if front control is broken.
    end
    current = snapshot
    if current[:active_slot] && current[:relay_liveness] == 'pass' && current[:service_readiness] == 'ready'
      return diagnose_network[:layers].dig(:adapter_https, :status) == 'pass'
    end
    if current[:relay_liveness] == 'pass' && inner_dns_breaker_open?
      update_operation(message: '多个节点 DNS 同时失败，已暂停无效切换')
      return false
    end
    if current[:active_slot].nil?
      ok = activate_startup_with_fallback(
        current[:active_relay] || load_persisted_relay || @options[:default_relay],
        current_transport_preference, reason: 'startup-retry'
      )
    else
      ok = false
      recovery_relay_candidates(current[:active_relay]).each do |candidate|
        ok = activate(candidate, reason: 'health-recovery', transport_preference: current_transport_preference)
        break if ok
        quarantine_relay(candidate, 'repair-candidate-failed', 60)
        break if inner_dns_breaker_open?
      end
    end
    diagnose_network
    ok
  end

  def metadata_cache_path
    File.join(@state_dir, 'relays-cache.json')
  end

  def safe_relays(city = nil)
    refresh_metadata unless @metadata
    list = Array(@metadata.dig('wireguard', 'relays')).select { |r| r['active'] == true }
    list = list.select { |r| r['location'].to_s == city || r['hostname'].to_s.include?("-#{city}-") } if city && !city.empty?
    locations = @metadata['locations'].is_a?(Hash) ? @metadata['locations'] : {}
    list.map do |r|
      location = r['location'].to_s
      location_info = locations[location].is_a?(Hash) ? locations[location] : {}
      country_code, city_code = location.split('-', 2)
      {
        hostname: r['hostname'],
        location: location,
        country_code: country_code,
        city_code: city_code,
        country: location_info['country'],
        city: location_info['city'],
        provider: r['provider'],
        owned: r['owned'],
        extra_ss_ipv4: Array(r['shadowsocks_extra_addr_in']).count { |ip| ipv4?(ip) },
        transports: available_transport_modes(r),
        quick_ping: quick_ping_targets(r)
      }
    end
  rescue StandardError => e
    [{ error: "#{e.class}: #{e.message}" }]
  end

  # The daemon is the single owner of relay metadata. The UI must not reopen
  # relays-cache.json because that can disagree with the live/validated
  # snapshot used by the worker during an API refresh or cache fallback.
  def quick_ping_targets(relay)
    targets = {}
    extra = Array(relay['shadowsocks_extra_addr_in']).find { |ip| ipv4?(ip) }
    ipv4 = relay['ipv4_addr_in'].to_s
    ipv6 = relay['ipv6_addr_in'].to_s
    targets['ss'] = { target: extra || ipv4, kind: extra ? 'shadowsocks-extra-ipv4' : 'relay-ipv4' } unless (extra || ipv4).empty?
    targets['ipv4'] = { target: ipv4, kind: 'wireguard-ipv4' } unless ipv4.empty?
    targets['ipv6'] = { target: ipv6, kind: 'wireguard-ipv6' } unless ipv6.empty?
    targets
  end

  def available_transport_modes(relay)
    TRANSPORT_MODES.select { |mode| transport_supported?(relay, mode) }
  end

  def transport_supported?(relay, mode)
    case mode.to_s
    when 'ss'
      !relay['ipv4_addr_in'].to_s.empty? && !Array(@metadata&.dig('wireguard', 'shadowsocks_port_ranges')).empty?
    when 'ipv6'
      !relay['ipv6_addr_in'].to_s.empty? && wireguard_port_allowed?(DIRECT_IPV6_PORT)
    when 'ipv4'
      !relay['ipv4_addr_in'].to_s.empty? && wireguard_port_allowed?(DIRECT_IPV4_PORT)
    else
      false
    end
  end

  def transport_candidates(preference, relay)
    normalized = normalize_transport_preference(preference)
    modes = normalized == 'auto' ? AUTO_TRANSPORT_ORDER : [normalized]
    if normalized == 'auto'
      recent = @history_mutex.synchronize do
        modes.filter_map do |mode|
          entry = @relay_history["#{relay['hostname']}|#{mode}"]
          result = entry && entry[:last_result]
          at = entry && entry[:last_tested_at] && (Time.parse(entry[:last_tested_at]) rescue nil)
          [mode, at] if at && Time.now - at < 600 && result && classify_canary(result)[:service_readiness] == 'ready'
        end
      end
      modes = recent.sort_by { |_, at| -at.to_f }.map(&:first) + modes
    end
    supported = modes.uniq.select { |mode| transport_supported?(relay, mode) }
    raise "relay #{relay['hostname']} supports none of requested transports #{modes.join(',')}" if supported.empty?
    supported
  end

  def speed_test_snapshot
    @mutex.synchronize do
      Marshal.load(Marshal.dump(@speed_tests.values.sort_by { |item| [item[:relay].to_s, item[:transport_mode].to_s] }))
    end
  end

  def relay_history_path
    File.join(@state_dir, 'relay-history.json')
  end

  def load_relay_history
    return unless File.file?(relay_history_path)

    payload = JSON.parse(File.read(relay_history_path))
    legacy_latency = payload.is_a?(Hash) && payload['version'].to_i < 2
    entries = payload.is_a?(Hash) ? payload['entries'] : nil
    return unless entries.is_a?(Hash)

    loaded = {}
    latest = {}
    entries.each_value do |raw_entry|
      next unless raw_entry.is_a?(Hash)

      entry = symbolize_json_object(raw_entry)
      relay = entry[:relay].to_s
      mode = entry[:transport_mode].to_s
      next if relay.empty? || mode.empty?

      key = "#{relay}|#{mode}"
      entry[:source_counts] = symbolize_json_object(entry[:source_counts] || {})
      if legacy_latency
        # v1 latency was a full HTTP proxy-delay probe, not ICMP RTT. Keep
        # reliability counters but discard the incompatible latency aggregate.
        entry[:latency_samples] = 0
        entry[:latency_ewma_ms] = nil
        entry[:best_delay_ms] = nil
        entry[:worst_delay_ms] = nil
        entry[:last_delay_ms] = nil
      end
      loaded[key] = entry
      latest[key] = entry[:last_result] if entry[:last_result].is_a?(Hash)
    end

    @history_mutex.synchronize { @relay_history = loaded }
    @mutex.synchronize { @speed_tests.merge!(latest) }
    persist_relay_history(loaded) if legacy_latency && !loaded.empty?
  rescue StandardError => e
    warn "relay history load failed: #{e.class}: #{e.message}"
  end

  def relay_history_snapshot
    entries = @history_mutex.synchronize { Marshal.load(Marshal.dump(@relay_history.values)) }
    entries.map do |entry|
      public_entry = entry.dup
      public_entry.delete(:last_result)
      samples = public_entry[:samples].to_i
      public_entry[:readiness_rate] = samples.positive? ? public_entry[:ready_samples].to_i.fdiv(samples) : nil
      public_entry
    end.sort_by { |item| [item[:relay].to_s, item[:transport_mode].to_s] }
  end

  def record_relay_history(result)
    relay = result[:relay].to_s
    mode = result[:transport_mode].to_s
    return if relay.empty? || mode.empty?

    key = "#{relay}|#{mode}"
    tested_at = result[:tested_at].to_s.empty? ? Time.now.iso8601 : result[:tested_at].to_s
    relay_pass = result[:relay_liveness].to_s == 'pass'
    ready = relay_pass && result[:service_readiness].to_s == 'ready'
    delay = result.dig(:ping_data, :delay_ms)
    source = result[:source].to_s.empty? ? 'unknown' : result[:source].to_s

    snapshot = @history_mutex.synchronize do
      entry = (@relay_history[key] ||= {
        relay: relay,
        transport_mode: mode,
        samples: 0,
        relay_pass_samples: 0,
        ready_samples: 0,
        failed_samples: 0,
        consecutive_failures: 0,
        latency_samples: 0,
        latency_ewma_ms: nil,
        best_delay_ms: nil,
        worst_delay_ms: nil,
        last_delay_ms: nil,
        first_tested_at: tested_at,
        last_tested_at: nil,
        last_success_at: nil,
        last_failure_at: nil,
        source_counts: {}
      })

      entry[:samples] = entry[:samples].to_i + 1
      entry[:relay_pass_samples] = entry[:relay_pass_samples].to_i + 1 if relay_pass
      entry[:ready_samples] = entry[:ready_samples].to_i + 1 if ready
      entry[:failed_samples] = entry[:samples].to_i - entry[:ready_samples].to_i
      entry[:consecutive_failures] = ready ? 0 : entry[:consecutive_failures].to_i + 1
      entry[:last_tested_at] = tested_at
      entry[:last_success_at] = tested_at if ready
      entry[:last_failure_at] = tested_at unless ready
      entry[:source_counts] ||= {}
      entry[:source_counts][source.to_sym] = entry[:source_counts][source.to_sym].to_i + 1

      unless delay.nil?
        delay_value = delay.to_f
        entry[:latency_samples] = entry[:latency_samples].to_i + 1
        previous_ewma = entry[:latency_ewma_ms]
        entry[:latency_ewma_ms] = previous_ewma.nil? ? delay_value : ((previous_ewma.to_f * 0.7) + (delay_value * 0.3)).round(2)
        entry[:last_delay_ms] = delay.to_i
        entry[:best_delay_ms] = [entry[:best_delay_ms], delay.to_i].compact.min
        entry[:worst_delay_ms] = [entry[:worst_delay_ms], delay.to_i].compact.max
      end

      entry[:last_result] = Marshal.load(Marshal.dump(result))
      Marshal.load(Marshal.dump(@relay_history))
    end

    persist_relay_history(snapshot)
  rescue StandardError => e
    warn "relay history persist failed: #{e.class}: #{e.message}"
  end

  def persist_relay_history(entries)
    tmp = relay_history_path + ".tmp-#{Process.pid}"
    payload = {
      version: 2,
      updated_at: Time.now.iso8601,
      entries: entries
    }
    File.write(tmp, JSON.pretty_generate(payload))
    File.chmod(0o600, tmp)
    File.rename(tmp, relay_history_path)
  ensure
    FileUtils.rm_f(tmp) if defined?(tmp) && File.exist?(tmp)
  end


  def ss_endpoint_history_path
    File.join(@state_dir, 'ss-endpoints.json')
  end

  def load_ss_endpoint_history
    return unless File.file?(ss_endpoint_history_path)

    payload = JSON.parse(File.read(ss_endpoint_history_path))
    relays = payload.is_a?(Hash) ? payload['relays'] : nil
    return unless relays.is_a?(Hash)

    loaded = symbolize_json_object(relays)
    @ss_endpoint_mutex.synchronize { @ss_endpoint_history = loaded }
  rescue StandardError => e
    warn "SS endpoint history load failed: #{e.class}: #{e.message}"
  end

  def persist_ss_endpoint_history(snapshot)
    tmp = ss_endpoint_history_path + ".tmp-#{Process.pid}"
    payload = {
      version: 2,
      updated_at: Time.now.iso8601,
      relays: snapshot
    }
    File.write(tmp, JSON.pretty_generate(payload))
    File.chmod(0o600, tmp)
    File.rename(tmp, ss_endpoint_history_path)
  ensure
    FileUtils.rm_f(tmp) if defined?(tmp) && File.exist?(tmp)
  end

  def ss_endpoint_candidates(relay)
    relay_name = relay['hostname'].to_s
    extra = Array(relay['shadowsocks_extra_addr_in']).select { |ip| ipv4?(ip) }
    history = @ss_endpoint_mutex.synchronize do
      Marshal.load(Marshal.dump(@ss_endpoint_history[relay_name.to_sym] || @ss_endpoint_history[relay_name] || {}))
    end
    stats = history[:endpoints].is_a?(Hash) ? history[:endpoints] : {}

    if extra.empty?
      ranges = validated_port_ranges(@metadata.dig('wireguard', 'shadowsocks_port_ranges'), 'shadowsocks port ranges')
      total_ports = ranges.sum { |low, high| high - low + 1 }
      desired = [3, total_ports].min
      all_ports = if total_ports <= 512
                    ranges.flat_map { |low, high| (low..high).to_a }.uniq
                  else
                    deterministic_port_sample(ranges, relay_name, [desired * 8, 512].min)
                  end
      candidates = all_ports.map { |port| [relay.fetch('ipv4_addr_in'), port, 'relay-ipv4-random-port'] }
      ranked = rank_ss_endpoint_candidates(candidates, stats, relay_name)
      available = ranked.reject { |candidate| endpoint_cooling_down?(endpoint_stats_for(stats, candidate[0], candidate[1])) }
      available = [ranked.min_by { |candidate| endpoint_retry_at(endpoint_stats_for(stats, candidate[0], candidate[1])) }] if available.empty?
      return available.compact.first(desired)
    end

    last_good = history[:last_good].to_s
    original_order = extra.each_with_index.to_h

    ranked = extra.sort_by do |ip|
      endpoint_stats = endpoint_stats_for(stats, ip, EXTRA_SS_PORT)
      successes = endpoint_stats[:successes].to_i
      failures = endpoint_stats[:failures].to_i
      samples = successes + failures
      success_rate = samples.positive? ? successes.fdiv(samples) : 0.0
      [
        [endpoint_history_key(ip, EXTRA_SS_PORT), ip].include?(last_good) ? 0 : 1,
        endpoint_trust_rank(successes, samples, endpoint_stats[:consecutive_failures].to_i),
        endpoint_stats[:consecutive_failures].to_i,
        -success_rate,
        endpoint_stats[:last_ping_ms] || Float::INFINITY,
        original_order.fetch(ip, 9_999)
      ]
    end
    available = ranked.reject do |ip|
      endpoint_cooling_down?(endpoint_stats_for(stats, ip, EXTRA_SS_PORT))
    end
    # If every inlet is cooling down, allow just one trial, never a complete
    # sweep of known failures. A manual request can still detect a recovery.
    available = [ranked.min_by { |ip| endpoint_retry_at(endpoint_stats_for(stats, ip, EXTRA_SS_PORT)) }] if available.empty?
    available.map { |ip| [ip, EXTRA_SS_PORT, 'extra-ss-ipv4'] }
  end

  def deterministic_port_sample(ranges, relay_name, count)
    seed = Digest::SHA256.hexdigest("#{relay_name}|#{Date.today.iso8601}").to_i(16)
    random = Random.new(seed)
    ports = []
    attempts = 0
    while ports.length < count && attempts < count * 8
      low, high = ranges[attempts % ranges.length]
      ports << random.rand(low..high)
      ports.uniq!
      attempts += 1
    end
    ports
  end

  def endpoint_history_key(endpoint, port = nil)
    value = endpoint.to_s
    return value if port.nil? || port.to_i <= 0

    value.include?(':') ? "[#{value}]:#{port.to_i}" : "#{value}:#{port.to_i}"
  end

  def endpoint_stats_for(stats, endpoint, port = nil)
    key = endpoint_history_key(endpoint, port)
    stats[key.to_sym] || stats[key] || (port.nil? ? nil : (stats[endpoint.to_sym] || stats[endpoint])) || {}
  end

  def rank_ss_endpoint_candidates(candidates, stats, relay_name)
    candidates.each_with_index.sort_by do |(candidate, index)|
      endpoint_stats = endpoint_stats_for(stats, candidate[0], candidate[1])
      successes = endpoint_stats[:successes].to_i
      samples = successes + endpoint_stats[:failures].to_i
      success_rate = samples.positive? ? successes.fdiv(samples) : 0.0
      stable_order = Digest::SHA256.hexdigest("#{relay_name}|#{candidate[1]}")
      [
        endpoint_trust_rank(successes, samples, endpoint_stats[:consecutive_failures].to_i),
        endpoint_stats[:consecutive_failures].to_i,
        -success_rate,
        endpoint_stats[:last_ping_ms] || Float::INFINITY,
        stable_order,
        index
      ]
    end.map(&:first)
  end

  def endpoint_retry_at(stats)
    failures = stats[:consecutive_failures].to_i
    return Time.at(0) unless failures.positive? && stats[:last_failure_at]
    Time.parse(stats[:last_failure_at]) + [15 * (2**[failures - 1, 6].min), 600].min
  rescue ArgumentError
    Time.at(0)
  end

  def endpoint_cooling_down?(stats)
    endpoint_retry_at(stats) > Time.now
  end

  # 入口可信度分档，数字越小越先试。
  #
  # 这里以前只把 consecutive_failures 当第二排序键，后果是"从未试过"的入口
  # （consecutive_failures = 0）会排到"成功过 18 次、刚连败 2 次"的入口前面。
  # 2026-09-19 晚上就是这么翻车的：us-lax-wg-001 上 4 个从未成功过的入口
  # （.6/.7/.8/.9）被排在成功率 90% 的 .5 之前，每个白等约 29 秒，
  # 一次恢复被拖到 4 分 12 秒。
  #
  # 现在按"有没有被证明过"分档，先试证明过的，从未成功的放最后：
  #   1 有成功记录、当前没有连败（健康）
  #   2 从未试过（未知，值得一试）
  #   3 有成功记录、但当前在连败（曾经好，现在坏）
  #   4 试过但从未成功过（最差，放最后）
  def endpoint_trust_rank(successes, samples, consecutive_failures)
    return 2 if samples.zero?
    return 4 if successes.zero?
    return 3 if consecutive_failures.positive?

    1
  end

  def record_ss_endpoint_outcome(relay_name, endpoint, success:, port: nil, ping_ms: nil, error: nil)
    relay_name = relay_name.to_s
    endpoint = endpoint.to_s
    return if relay_name.empty? || endpoint.empty?

    now = Time.now.iso8601
    key = endpoint_history_key(endpoint, port)
    snapshot = @ss_endpoint_mutex.synchronize do
      relay_entry = (@ss_endpoint_history[relay_name.to_sym] ||= { last_good: nil, endpoints: {} })
      relay_entry[:endpoints] ||= {}
      endpoint_entry = (relay_entry[:endpoints][key.to_sym] ||= {
        endpoint: endpoint,
        port: port&.to_i,
        successes: 0, failures: 0, consecutive_failures: 0,
        last_success_at: nil, last_failure_at: nil, last_ping_ms: nil, last_error: nil
      })

      if success
        endpoint_entry[:successes] = endpoint_entry[:successes].to_i + 1
        endpoint_entry[:consecutive_failures] = 0
        endpoint_entry[:last_success_at] = now
        endpoint_entry[:last_error] = nil
        relay_entry[:last_good] = key
      else
        endpoint_entry[:failures] = endpoint_entry[:failures].to_i + 1
        endpoint_entry[:consecutive_failures] = endpoint_entry[:consecutive_failures].to_i + 1
        endpoint_entry[:last_failure_at] = now
        endpoint_entry[:last_error] = error.to_s[0, 240] unless error.to_s.empty?
        relay_entry[:last_good] = nil if [key, endpoint].include?(relay_entry[:last_good].to_s)
      end
      endpoint_entry[:last_ping_ms] = ping_ms.to_i if ping_ms
      Marshal.load(Marshal.dump(@ss_endpoint_history))
    end
    persist_ss_endpoint_history(snapshot)
  rescue StandardError => e
    warn "SS endpoint history persist failed: #{e.class}: #{e.message}"
  end

  def endpoint_candidates_for_transport(relay, mode)
    original = Thread.current[:adapter_resume_path]
    if original && original[:relay] == relay['hostname'] && original[:transport_mode] == mode
      inlet = [original[:endpoint], original[:endpoint_port], original[:endpoint_kind]] if mode == 'ss' && original[:endpoint_port]
      if protection_profile[:multihop] && original[:entry_relay]
        return [{ entry: original[:entry_relay], inlet: inlet }]
      end
      return [inlet] if inlet || mode != 'ss'
    end
    if protection_profile[:multihop]
      entries = multihop_entries(relay, mode)
      return entries.flat_map do |entry|
        inlets = mode.to_s == 'ss' ? ss_endpoint_candidates(entry).first(2) : [nil]
        inlets.map { |inlet| { entry: entry['hostname'], inlet: inlet } }
      end
    end
    mode.to_s == 'ss' ? ss_endpoint_candidates(relay) : [nil]
  end

  def record_ss_endpoint_canary(relay_name, mode, worker_info, canary)
    return unless network_attempt_current?
    return unless mode.to_s == 'ss' && worker_info
    return if worker_info[:entry_relay]

    classification = classify_canary(canary)
    record_ss_endpoint_outcome(
      relay_name, worker_info[:endpoint], port: worker_info[:endpoint_port],
      success: classification[:relay_liveness] == 'pass',
      ping_ms: canary.dig(:ping_data, :delay_ms)
    )
  end

  def record_ss_endpoint_failure(relay_name, mode, ss_candidate, error)
    return if error.is_a?(LocalNetworkInterrupted) || !network_attempt_current?
    return unless mode.to_s == 'ss' && ss_candidate
    return if protection_profile[:multihop] || ss_candidate.is_a?(Hash)

    record_ss_endpoint_outcome(
      relay_name, ss_candidate[0], port: ss_candidate[1], success: false, error: "#{error.class}: #{error.message}"
    )
  end

  def symbolize_json_object(value)
    case value
    when Hash
      value.each_with_object({}) { |(key, nested), out| out[key.to_sym] = symbolize_json_object(nested) }
    when Array
      value.map { |nested| symbolize_json_object(nested) }
    else
      value
    end
  end

  def cache_speed_test(relay_name, canary, source, transport_mode)
    return unless network_attempt_current?
    mode = transport_mode.to_s
    classification = classify_canary(canary)
    result = {
      relay: relay_name,
      transport_mode: mode,
      tested_at: canary[:at] || Time.now.iso8601,
      source: source,
      duration_ms: canary[:duration_ms],
      ping_data: canary[:ping_data],
      controller_probe: canary[:controller_probe],
      relay_liveness: classification[:relay_liveness],
      service_readiness: classification[:service_readiness],
      ip_data: canary[:ip_data],
      inner_dns: canary[:inner_dns],
      https_data: canary[:https_data]
    }
    route_worker = @mutex.synchronize { @workers.values.find { |worker| worker[:relay] == relay_name }&.dup }
    if route_worker && (route_worker[:entry_relay] || route_worker[:post_quantum])
      result[:entry_relay] = route_worker[:entry_relay]
      result[:multihop] = !!route_worker[:entry_relay]
      result[:post_quantum] = !!route_worker[:post_quantum]
      # Single-hop history must not become evidence for a different circuit.
    else
      @mutex.synchronize { @speed_tests["#{relay_name}|#{mode}"] = result }
      record_relay_history(result)
    end
    log_event('probe-result', relay: relay_name, transport: mode, source: source,
              entry_relay: result[:entry_relay], multihop: result[:multihop] || false, post_quantum: result[:post_quantum] || false,
              duration_ms: canary[:duration_ms], **classification,
              ip: canary.dig(:ip_data, :status), dns: canary.dig(:inner_dns, :status),
              https: canary.dig(:https_data, :status),
              evidence: classification[:service_readiness] == 'ready' ? nil :
                canary.slice(:ip_data, :inner_dns, :https_data, :controller_probe))
    result
  end

  # A user-triggered speed test is deliberately serialized and low-volume.
  # The active Relay is only tested on its existing worker. Testing another
  # transport on the active Relay would require a second same-peer instance,
  # so the API refuses that and requires an explicit transport switch instead.
  # A different Relay may temporarily use the truly idle opposite slot and is
  # never selected by the stable front.
  def speed_test_relay(relay_name, transport_preference: nil)
    previous_network_epoch = Thread.current[:adapter_network_epoch]
    if local_network_paused? || local_network_recovery_pending?
      return [503, { ok: false, code: 'local_network_unavailable', error: '本机网络正在等待恢复；原连接恢复后再测速' }]
    end
    if action_conflicts?
      return [409, { ok: false, code: 'adapter_busy', error: '已有操作正在执行' }]
    end
    unless @speed_test_mutex.try_lock
      return [409, { ok: false, code: 'speedtest_busy', error: 'another speed test is already running' }]
    end

    begin
      Thread.current[:adapter_network_epoch] = network_epoch
      refresh_metadata unless @metadata
      unless @switch_mutex.try_lock
        return [409, { ok: false, code: 'adapter_busy', error: 'adapter is switching, reconnecting, or running a health check' }]
      end

      begin
        attempt_started = monotonic_now
        active_slot, active_relay = @mutex.synchronize { [@state[:active_slot], @state[:active_relay]] }
        requested = transport_preference.nil? ? nil : normalize_transport_preference(transport_preference)
        source = nil
        canary = nil
        mode = nil

        if active_relay == relay_name
          worker = active_slot && @workers[active_slot]
          unless worker && worker[:relay] == relay_name
            return [409, {
              ok: false,
              code: 'active_worker_inconsistent',
              error: 'active relay state has no usable active worker; speed test deferred'
            }]
          end
          mode = worker[:transport_mode].to_s.empty? ? 'ss' : worker[:transport_mode]
          if requested && requested != 'auto' && requested != mode
            return [409, {
              ok: false,
              code: 'active_transport_change_required',
              error: "active relay uses #{mode}; testing #{requested} requires an explicit break-before-make transport switch"
            }]
          end
          source = 'active-worker'
          canary = run_canary(active_slot)
        else
          relay = find_relay(relay_name)
          preference = requested || 'ss'
          public_workers = @mutex.synchronize { Marshal.load(Marshal.dump(@state[:workers])) }
          unsettled_public_worker = public_workers.any? { |_slot, worker| worker[:state].to_s != 'stopped' }
          if active_slot.nil? && (!@workers.empty? || unsettled_public_worker)
            return [409, {
              ok: false,
              code: 'worker_lifecycle_busy',
              error: 'worker lifecycle is not settled; speed test deferred'
            }]
          end

          test_slot = active_slot ? (active_slot == 'a' ? 'b' : 'a') : @slot_config.keys.first
          # 对侧槽位可能还在收尾上一条隧道。切换路径早就允许抢占它，测速却直接
          # 拒绝 —— 结果就是用户按"测速其他节点"当场吃一个 409，而那个槽位还要
          # 再等十几分钟。这里对齐成同一套动作：用户点了就腾地方，不让他等。
          unless ensure_switch_slot_available(test_slot, 'speed-test', any_non_active: true)
            test_slot_state = public_workers[test_slot]
            unsettled = test_slot_state && test_slot_state[:state].to_s != 'stopped'
            return [409, {
              ok: false,
              code: 'slot_draining',
              error: "worker-#{test_slot} is still owned by another lifecycle" \
                     "#{unsettled ? " (state=#{test_slot_state[:state]})" : ''}; speed test deferred",
              retry_after_seconds: unsettled ? test_slot_state[:drain_remaining_seconds] : nil
            }]
          end

          attempts = []
          chosen = nil
          transport_candidates(preference, relay).each do |candidate_mode|
            mode_has_live_path = false
            endpoint_candidates_for_transport(relay, candidate_mode).each do |ss_candidate|
              break unless candidate_attempt_allowed?(attempt_started)
              update_operation(stage: 'testing', message: "正在检查 #{relay_name} · #{candidate_mode}")
              started = false
              worker_info = nil
              begin
                worker_info = start_worker(
                  test_slot, relay, transport_mode: candidate_mode, ss_candidate: ss_candidate
                )
                started = true
                candidate_canary = run_canary(test_slot)
                raise LocalNetworkInterrupted unless network_attempt_current?
                attempt = cache_speed_test(relay_name, candidate_canary, 'candidate-worker', candidate_mode)
                record_ss_endpoint_canary(relay_name, candidate_mode, worker_info, candidate_canary)
                attempts << attempt
                chosen ||= attempt if attempt[:relay_liveness] == 'pass'
                chosen = attempt if attempt[:service_readiness] == 'ready'
                mode_has_live_path = attempt[:relay_liveness] == 'pass'
              rescue StandardError => e
                record_ss_endpoint_failure(relay_name, candidate_mode, ss_candidate, e)
                raise if e.is_a?(LocalNetworkInterrupted)
                raise unless candidate_mode == 'ss'
              ensure
                stop_worker(test_slot) if started || @workers[test_slot]
              end

              # Once the SS outer path is live, another SS inlet will not fix an
              # inner DNS / HTTPS service problem. Avoid pointlessly testing all
              # six entries; only fall through when the data path itself failed.
              break if mode_has_live_path
            end
            break if chosen && chosen[:service_readiness] == 'ready'
          end
          chosen ||= attempts.last
          raise 'no transport attempt produced a result' unless chosen
          @mutex.synchronize do
            @metrics[:speed_tests] += 1
            @metrics[:speed_test_failures] += 1 unless chosen[:relay_liveness] == 'pass'
          end
          return [200, { ok: true, requested_transport: preference, result: chosen, attempts: attempts }]
        end

        raise LocalNetworkInterrupted unless network_attempt_current?
        result = cache_speed_test(relay_name, canary, source, mode)
        record_ss_endpoint_canary(relay_name, mode, worker, canary)
        @mutex.synchronize do
          @metrics[:speed_tests] += 1
          @metrics[:speed_test_failures] += 1 unless result[:relay_liveness] == 'pass'
        end
        [200, { ok: true, requested_transport: requested || mode, result: result, attempts: [result] }]
      rescue LocalNetworkInterrupted
        [503, { ok: false, code: 'local_network_changed', error: '测速期间本机网络发生变化，已丢弃结果；等待原连接恢复' }]
      rescue StandardError => e
        @mutex.synchronize do
          @metrics[:speed_tests] += 1
          @metrics[:speed_test_failures] += 1
        end
        [500, { ok: false, code: 'speedtest_failed', error: "#{e.class}: #{e.message}" }]
      ensure
        @switch_mutex.unlock if @switch_mutex.owned?
      end
    ensure
      @speed_test_mutex.unlock if @speed_test_mutex.owned?
      Thread.current[:adapter_network_epoch] = previous_network_epoch
    end
  end

  def slot_lifecycle_state(slot)
    @mutex.synchronize do
      worker = @state[:workers][slot]
      worker && worker[:state].to_s
    end
  end

  def slot_reusable?(slot)
    return false if @workers[slot]
    state = slot_lifecycle_state(slot)
    state.nil? || state == 'stopped'
  end

  def preferred_switch_slot(old_slot)
    if old_slot
      return old_slot == 'a' ? 'b' : 'a'
    end

    reusable = @slot_config.keys.find { |slot| slot_reusable?(slot) }
    return reusable if reusable

    # Both slots are occupied; the caller may choose to preempt a drain, but
    # prefer the one with fewer surviving old connections.
    @slot_config.keys.min_by do |slot|
      count = @workers[slot] ? front_connections_for(slot) : nil
      count.nil? ? Float::INFINITY : count
    end
  end

  def preferred_same_relay_restart_slot(old_slot)
    opposite_slot = old_slot == 'a' ? 'b' : 'a'
    slot_reusable?(opposite_slot) ? opposite_slot : old_slot
  end

  # 腾出一个槽位，好让调用方往里放新的 worker。
  #
  # 两个调用方靠它：手动切换（用户说要换节点）和测速（用户说要一个数字）。
  # 两个都是用户亲手点出来的动作，所以都不能拿"槽位忙，稍后再试"把人挡回去 ——
  # 旧隧道的收尾倒计时最长 30 分钟，让人等 30 分钟再按一次按钮不是答案。
  #
  # any_non_active = true 是测速走的宽松档：对侧槽位里只要不是正在承载流量的
  # worker，不管它是旧隧道在收尾、还是上一次留下的半成品，都可以直接停掉。
  # 切换走的是保守档（默认），只抢 'draining' 状态，行为与以前完全一致。
  def ensure_switch_slot_available(slot, reason, any_non_active: false)
    return true if slot_reusable?(slot)

    lifecycle = slot_lifecycle_state(slot)
    worker = @mutex.synchronize { @workers[slot] && @workers[slot].dup }
    return false unless worker
    # 正在承载流量的那个槽位，谁都不能碰。
    return false if any_non_active && @mutex.synchronize { @state[:active_slot] == slot }
    return false unless any_non_active || lifecycle == 'draining'

    count = front_connections_for(slot)
    emergency = any_non_active || failure_recovery_reason?(reason) || reason.to_s == 'dns-recovery-probe'
    if count.nil? && !emergency
      record_routing_event(
        'drain-preemption-deferred',
        relay: worker[:relay],
        reason: reason,
        detail: "slot=#{slot} connections=unknown"
      )
      return false
    end

    stopped = stop_worker(slot)
    return false unless stopped

    @mutex.synchronize do
      @metrics[:drain_preemptions] += 1
      @metrics[:drain_forced] += 1 if count.nil? || count.to_i.positive?
    end
    record_routing_event(
      any_non_active ? 'speedtest-slot-freed' : 'previous-drain-preempted',
      relay: worker[:relay],
      reason: reason,
      detail: "slot=#{slot} state=#{lifecycle}",
      connections: count
    )
    slot_reusable?(slot)
  end

  def failure_recovery_reason?(reason)
    %w[health-recovery worker-crash-recovery network-resume network-resume-fallback].include?(reason.to_s)
  end

  def retire_failed_path(slot, reason)
    worker = @mutex.synchronize { @workers[slot] && @workers[slot].dup }
    return unless worker

    count = front_connections_for(slot)
    stopped = stop_worker(slot)
    return unless stopped

    @mutex.synchronize { @metrics[:failed_path_retirements] += 1 }
    record_routing_event(
      'failed-path-retired',
      relay: worker[:relay],
      reason: reason,
      detail: "slot=#{slot}",
      connections: count
    )
  end

  def slot_busy_detail(slot)
    private_worker = @workers[slot]
    count = private_worker ? front_connections_for(slot) : nil
    state = slot_lifecycle_state(slot)
    "state=#{state || 'unknown'} connections=#{count.nil? ? 'unknown' : count}"
  end

  def activate(relay_name, reason:, transport_preference: nil, expected_state: nil, protection_profile: nil, attempt_evidence: nil)
    previous_network_epoch = Thread.current[:adapter_network_epoch]
    previous_profile = Thread.current[:adapter_protection_profile]
    previous_attempt = Thread.current[:adapter_attempt_id]
    return false if local_network_paused?
    Thread.current[:adapter_network_epoch] = network_epoch
    queued_at = monotonic_now
    Thread.current[:adapter_attempt_id] = SecureRandom.uuid
    log_event('activation-requested', relay: relay_name, reason: reason)
    @switch_mutex.synchronize do
      raise @protection_error if @protection_error && !protection_profile
      Thread.current[:adapter_protection_profile] = protection_profile || @protection_profile
      ensure_pq_available!(Thread.current[:adapter_protection_profile])
      log_event('activation-lock-acquired', relay: relay_name, reason: reason,
                queue_wait_ms: ((monotonic_now - queued_at) * 1000).round)
      return false if @stop_requested
      return false unless network_attempt_current?
      return false if expected_state && local_network_recovery_pending? && !%w[network-resume network-resume-fallback].include?(reason)
      return false if expected_state && action_conflicts?
      if expected_state
        current = @mutex.synchronize do
          {
            generation: @state[:generation],
            active_slot: @state[:active_slot],
            active_relay: @state[:active_relay]
          }
        end
        unless current[:generation] == expected_state[:generation] &&
               current[:active_slot] == expected_state[:active_slot] &&
               current[:active_relay] == expected_state[:active_relay]
          record_routing_event(
            'stale-recovery-suppressed',
            relay: relay_name,
            reason: reason,
            detail: "expected=#{expected_state.inspect} current=#{current.inspect}"
          )
          return false
        end
      end

      preference = normalize_transport_preference(transport_preference || current_transport_preference)
      attempt_started = monotonic_now
      update_operation(stage: 'connecting', message: "正在连接 #{relay_name}；候选通过后才切换")
      update_state(status: 'switching', last_error: nil)
      # Switching must not block for up to a minute merely because the main
      # Clash bootstrap listener is restarting. The control-plane thread owns
      # live refreshes; an already validated in-memory/cache snapshot is enough
      # to execute a data-plane switch promptly.
      refresh_metadata unless @metadata
      relay = find_relay(relay_name)
      old_slot, old_relay, old_liveness, old_readiness, old_mode, old_preference = @mutex.synchronize do
        [
          @state[:active_slot], @state[:active_relay], @state[:relay_liveness], @state[:service_readiness],
          @state[:active_transport_mode], @state[:transport_preference] || DEFAULT_TRANSPORT_PREFERENCE
        ]
      end
      old_mode ||= (old_slot && @workers[old_slot] && @workers[old_slot][:transport_mode])
      old_mode ||= 'ss' if old_slot

      if old_slot && old_relay == relay_name
        if %w[reconnect ss-endpoint-recovery protection-change network-resume].include?(reason)
          return restart_same_relay(old_slot, relay, preference, reason: reason, old_preference: old_preference, attempt_evidence: attempt_evidence)
        end
        if old_liveness != 'pass' || old_readiness != 'ready'
          return restart_same_relay(old_slot, relay, preference, reason: 'reconnect', old_preference: old_preference, attempt_evidence: attempt_evidence)
        end

        # Selecting auto on an already healthy same-Relay connection does not
        # tear it down just to chase preference order. The current actual mode
        # stays active; auto applies on the next reconnect/recovery/switch.
        if preference == 'auto' || preference == old_mode
          @mutex.synchronize do
            @state[:status] = old_readiness == 'ready' ? 'ready' : old_readiness
            @state[:transport_preference] = preference
            @state[:switch_reason] = "#{reason}-noop"
            @state[:last_error] = nil
            @state[:updated_at] = Time.now.iso8601
          end
          persist_transport_preference(preference)
          return true
        end

          return restart_same_relay(old_slot, relay, preference, reason: 'transport-change', old_preference: old_preference, attempt_evidence: attempt_evidence)
      end

      if %w[health-recovery dns-recovery-probe].include?(reason.to_s) &&
         old_slot && old_liveness == 'pass' && inner_dns_breaker_open?
        @mutex.synchronize do
          @metrics[:inner_dns_breaker_suppressed] += 1
          @state[:status] = old_readiness == 'ready' ? 'ready' : old_readiness
          @state[:last_error] = 'automatic relay recovery suppressed by common inner-DNS breaker'
          @state[:updated_at] = Time.now.iso8601
        end
        return false
      end

      new_slot = preferred_switch_slot(old_slot)
      unless ensure_switch_slot_available(new_slot, reason)
        busy_detail = slot_busy_detail(new_slot)
        @mutex.synchronize do
          @state[:status] = old_readiness == 'ready' ? 'ready' : old_readiness
          @state[:last_error] = "switch deferred: worker-#{new_slot} lifecycle is still busy (#{busy_detail})"
          @state[:updated_at] = Time.now.iso8601
        end
        return false
      end

      selected = nil
      last_canary = nil
      last_classification = nil
      last_candidate_error = nil
      transport_candidates(preference, relay).each do |mode|
        mode_has_live_path = false
        endpoint_candidates_for_transport(relay, mode).each do |ss_candidate|
          break unless candidate_attempt_allowed?(attempt_started)
          update_operation(stage: 'checking', message: "正在检查 #{relay_name} · #{mode}")
          worker_info = nil
          begin
            attempt_evidence[:attempted] = true if attempt_evidence
            worker_info = start_worker(
              new_slot, relay, transport_mode: mode, ss_candidate: ss_candidate
            )
            canary = run_readiness_canary(new_slot)
            raise LocalNetworkInterrupted unless network_attempt_current?
            cache_speed_test(relay_name, canary, 'switch-candidate', mode)
            record_ss_endpoint_canary(relay_name, mode, worker_info, canary)
            observe_inner_dns_result(relay_name, canary)
            classification = classify_canary(canary)
            attempt_evidence[:relay_failed] = classification[:relay_liveness] == 'fail' if attempt_evidence
            candidate_live = classification[:relay_liveness] == 'pass'
            mode_has_live_path = candidate_live
            use_degraded = candidate_live && (!old_slot || old_liveness != 'pass')
            if candidate_acceptable?(classification, profile: self.protection_profile,
                                     require_ready: !use_degraded || %w[protection-change network-resume-fallback].include?(reason))
              selected = [worker_info, canary, mode]
              break
            end
            last_canary = canary
            last_classification = classification
            stop_worker(new_slot)
          rescue StandardError => e
            last_candidate_error = "#{mode}: #{e.class}: #{e.message}"
            record_ss_endpoint_failure(relay_name, mode, ss_candidate, e)
            stop_worker(new_slot) if @workers[new_slot]
            raise if e.is_a?(LocalNetworkInterrupted)
            raise unless mode == 'ss' || preference == 'auto'
          end

          # A live SS data path means the inlet itself is good. If DNS / HTTPS
          # is degraded, another inlet for the same Relay is not a useful fix.
          break if mode_has_live_path
        end
        break if selected
      end

      unless selected
        classification = last_classification || { relay_liveness: 'fail', service_readiness: 'data_fail' }
        @mutex.synchronize do
          @metrics[:failed_switches] += 1
          @state[:status] = old_slot ? (old_readiness == 'ready' ? 'ready' : old_readiness) : classification[:service_readiness]
          # The active path must retain its own probe evidence after a failed
          # candidate. Candidate results are kept in speed tests / history.
          @state[:last_canary] = last_canary if last_canary && !old_slot
          @state[:last_error] = last_candidate_error || "candidate not preferred for #{relay_name}: #{classification[:service_readiness]}"
          @state[:updated_at] = Time.now.iso8601
        end
        return false
      end

      worker_info, canary, = selected
      begin
        raise LocalNetworkInterrupted unless network_attempt_current?
        select_front(new_slot)
        commit_active(
          new_slot, relay_name, worker_info, canary, reason,
          old_slot: old_slot, transport_preference: preference
        )
      rescue StandardError
        stop_worker(new_slot)
        begin
          select_front(old_slot) if old_slot && @workers[old_slot]
        rescue StandardError
          # The supervisor will retry the old selector. Never leave a live,
          # unowned candidate behind when commit failed.
        end
        raise
      end
      if old_slot && @workers[old_slot]
        if failure_recovery_reason?(reason)
          retire_failed_path(old_slot, reason)
        else
          start_drain(old_slot)
        end
      end
      true
    end
  rescue LocalNetworkInterrupted
    log_event('activation-paused-local-network', relay: relay_name, reason: reason)
    false
  rescue StandardError => e
    @mutex.synchronize { @metrics[:failed_switches] += 1 }
    record_error("activate #{relay_name} failed: #{e.class}: #{e.message}")
    false
  ensure
    if queued_at
      current = snapshot
      log_event('activation-finished', relay: relay_name, reason: reason,
                duration_ms: ((monotonic_now - queued_at) * 1000).round,
                active_relay: current[:active_relay], active_slot: current[:active_slot], status: current[:status])
    end
    Thread.current[:adapter_attempt_id] = previous_attempt
    Thread.current[:adapter_protection_profile] = previous_profile
    Thread.current[:adapter_network_epoch] = previous_network_epoch
  end

  def restart_same_relay(old_slot, relay, preference, reason:, old_preference:, attempt_evidence: nil)
    relay_name = relay['hostname']
    modes = transport_candidates(preference, relay)
    modes = modes.first(1) if %w[ss-endpoint-recovery network-resume].include?(reason)
    opposite_slot = old_slot == 'a' ? 'b' : 'a'
    # Same-peer reconnect is break-before-make anyway. Rebuild in the current
    # slot when the opposite slot is draining, rather than destroying an older
    # drain merely to obtain a staging slot.
    new_slot = preferred_same_relay_restart_slot(old_slot)

    if new_slot != old_slot && !ensure_switch_slot_available(new_slot, reason)
      busy_detail = slot_busy_detail(new_slot)
      @mutex.synchronize do
        @state[:last_error] = "same-relay reconnect deferred: worker-#{new_slot} lifecycle is still busy (#{busy_detail})"
        @state[:updated_at] = Time.now.iso8601
      end
      return false
    end

    old_worker = @workers[old_slot]
    old_mode = old_worker && old_worker[:transport_mode]
    old_mode = @mutex.synchronize { @state[:active_transport_mode] } if old_mode.to_s.empty?
    old_mode = 'ss' if old_mode.to_s.empty?

    @mutex.synchronize do
      @metrics[:same_relay_reconnects] += 1
      @state[:status] = 'reconnecting'
      @state[:active_slot] = nil
      @state[:active_transport] = nil
      @state[:active_transport_mode] = nil
      @state[:transport_preference] = preference
      @state[:relay_liveness] = 'unknown'
      @state[:service_readiness] = 'reconnecting'
      @state[:last_error] = 'same-relay transport change/reconnect is break-before-make to avoid shared WireGuard peer collision'
      @state[:updated_at] = Time.now.iso8601
    end

    stop_worker(old_slot)
    attempt_started = monotonic_now
    modes.each do |mode|
      inlets = endpoint_candidates_for_transport(relay, mode)
      inlets = inlets.first(1) if %w[ss-endpoint-recovery network-resume].include?(reason)
      inlets.each do |ss_candidate|
        break unless candidate_attempt_allowed?(attempt_started)
        update_operation(stage: 'reconnecting', message: "正在重建 #{relay_name} · #{mode}")
        worker_info = nil
        begin
          attempt_evidence[:attempted] = true if attempt_evidence
          worker_info = start_worker(
            new_slot, relay, transport_mode: mode, ss_candidate: ss_candidate
          )
          canary = run_readiness_canary(new_slot)
          raise LocalNetworkInterrupted unless network_attempt_current?
          source = case reason
                   when 'transport-change' then 'transport-change-candidate'
                   when 'ss-endpoint-recovery' then 'ss-endpoint-recovery-candidate'
                   else 'reconnect-candidate'
                   end
          cache_speed_test(relay_name, canary, source, mode)
          record_ss_endpoint_canary(relay_name, mode, worker_info, canary)
          observe_inner_dns_result(relay_name, canary)
          classification = classify_canary(canary)
          attempt_evidence[:relay_failed] = classification[:relay_liveness] == 'fail' if attempt_evidence
          if candidate_acceptable?(classification, profile: protection_profile, require_ready: reason == 'protection-change')
            select_front(new_slot)
            commit_reason = case reason
                            when 'transport-change' then 'transport-change-break-before-make'
                            when 'ss-endpoint-recovery' then 'ss-endpoint-recovery-break-before-make'
                            when 'network-resume' then 'network-resume-original'
                            else 'reconnect-break-before-make'
                            end
            commit_active(
              new_slot, relay_name, worker_info, canary, commit_reason,
              old_slot: nil, transport_preference: preference
            )
            return true
          end
          stop_worker(new_slot)
        rescue StandardError => e
          record_ss_endpoint_failure(relay_name, mode, ss_candidate, e)
          stop_worker(new_slot) if @workers[new_slot]
          raise if e.is_a?(LocalNetworkInterrupted)
          # Failure of an explicitly requested direct transport must reach
          # rollback too. It must not escape with the old worker already gone.
        end
      end
    end

    raise LocalNetworkInterrupted unless network_attempt_current?
    @mutex.synchronize { @metrics[:failed_switches] += 1 }
    if %w[ss-endpoint-recovery network-resume].include?(reason)
      update_state(
        status: 'data_fail', active_slot: nil, active_transport: nil, active_transport_mode: nil,
        transport_preference: old_preference, relay_liveness: 'fail', service_readiness: 'data_fail',
        last_error: reason == 'network-resume' ? '本机网络已恢复，原路径验证失败；将尝试同城备选' : 'all SS inlets for the active relay failed; falling back to another relay'
      )
      return false
    end

    # Roll back to the previous transport family, still without overlapping
    # peers. For SS, use the endpoint selector rather than blindly pinning a
    # previously failed inlet.
    rollback_last = nil
    Thread.current[:adapter_protection_profile] = old_worker&.dig(:protection_profile) || @protection_profile
    update_operation(stage: 'rollback', message: '新连接未通过，正在恢复原连接')
    endpoint_candidates_for_transport(relay, old_mode).first(2).each do |ss_candidate|
      begin
        rollback_info = start_worker(
          old_slot, relay, transport_mode: old_mode, ss_candidate: ss_candidate
        )
        rollback_canary = run_readiness_canary(old_slot)
        raise LocalNetworkInterrupted unless network_attempt_current?
        cache_speed_test(relay_name, rollback_canary, 'reconnect-rollback', old_mode)
        record_ss_endpoint_canary(relay_name, old_mode, rollback_info, rollback_canary)
        observe_inner_dns_result(relay_name, rollback_canary)
        rollback_classification = classify_canary(rollback_canary)
        rollback_last = [rollback_canary, rollback_classification]
        if candidate_acceptable?(rollback_classification, profile: protection_profile)
          select_front(old_slot)
          commit_active(
            old_slot, relay_name, rollback_info, rollback_canary, 'reconnect-rollback',
            old_slot: nil, transport_preference: old_preference
          )
          @mutex.synchronize { @state[:last_error] = 'requested transport failed; previous relay transport was rebuilt and restored' }
          return false
        end
        stop_worker(old_slot)
      rescue StandardError => e
        record_ss_endpoint_failure(relay_name, old_mode, ss_candidate, e)
        stop_worker(old_slot) if @workers[old_slot]
        raise if e.is_a?(LocalNetworkInterrupted)
      end
    end

    if rollback_last
      rollback_canary, rollback_classification = rollback_last
      update_state(
        status: rollback_classification[:service_readiness],
        active_slot: nil,
        active_transport: nil,
        active_transport_mode: nil,
        transport_preference: old_preference,
        relay_liveness: rollback_classification[:relay_liveness],
        service_readiness: rollback_classification[:service_readiness],
        last_canary: rollback_canary,
        last_error: 'requested transport and rollback both failed'
      )
    else
      update_state(
        status: 'data_fail', active_slot: nil, active_transport: nil, active_transport_mode: nil,
        transport_preference: old_preference, relay_liveness: 'fail', service_readiness: 'data_fail',
        last_error: 'requested transport failed and rollback could not start'
      )
    end
    false
  end

  def commit_active(new_slot, relay_name, worker_info, canary, reason, old_slot:, transport_preference:)
    raise LocalNetworkInterrupted unless network_attempt_current?
    profile = worker_info[:protection_profile] || @protection_profile
    if profile != @protection_profile || @protection_error
      # Slow write/flush/fsync happens outside the state lock and cannot change
      # the committed policy. Startup only reads protection.json, never pending
      # preparations left by an interrupted or crashed process.
      pending_profile = File.join(@state_dir, "protection.json.pending-#{SecureRandom.hex(16)}")
      atomic_account_file(pending_profile, JSON.generate(profile))
    end
    classification = classify_canary(canary)
    switched_time = Time.now
    switched_at = switched_time.iso8601
    @health_fail_streak = 0
    @dns_fail_streak = 0
    preference = normalize_transport_preference(transport_preference)
    city = worker_info[:location] || Array(@metadata&.dig('wireguard', 'relays')).find { |r| r['hostname'] == relay_name }&.dig('location')
    @mutex.synchronize do
      epoch = Thread.current[:adapter_network_epoch]
      raise LocalNetworkInterrupted if @state[:local_network][:paused] || (epoch && epoch != @state[:local_network][:epoch])
      # This rename is the policy commit point. The network observer uses this
      # same mutex: an outage is ordered either before the commit (reject, old
      # file remains) or after it (new committed policy survives for recovery).
      # A crash after rename is therefore a committed policy, not an incomplete
      # preparation. No fallible policy I/O remains after the rename.
      if pending_profile
        File.rename(pending_profile, File.join(@state_dir, 'protection.json'))
        @protection_profile = profile
        @protection_error = nil
      end
      @last_network_path = worker_info.slice(:relay, :transport_mode, :endpoint, :endpoint_port, :endpoint_kind, :entry_relay)
      unless %w[network-resume network-resume-original network-resume-fallback health-recovery worker-crash-recovery startup startup-retry].include?(reason)
        @state[:local_network][:recovery_pending] = false
      end
      @metrics[:switches] += 1
      @state[:generation] += 1
      @state[:status] = classification[:service_readiness] == 'ready' ? 'ready' : classification[:service_readiness]
      @state[:active_slot] = new_slot
      @state[:active_relay] = relay_name
      @state[:selected_city] = city if city
      @state[:active_transport] = worker_info[:transport]
      @state[:active_transport_mode] = worker_info[:transport_mode]
      @state[:transport_preference] = preference
      @state[:relay_liveness] = classification[:relay_liveness]
      @state[:service_readiness] = classification[:service_readiness]
      @state[:last_canary] = canary
      @state[:last_error] = nil
      @state[:switched_at] = switched_at
      @state[:switch_reason] = reason
      @state[:dns][:inner] = canary[:inner_dns]
      @state[:health][:consecutive_wg_failures] = 0
      @state[:health][:consecutive_dns_failures] = 0
      @state[:health][:last_recovery_at] = switched_at if reason.include?('recovery')
      @state[:updated_at] = switched_at
      @state[:workers][new_slot] = public_worker_state(worker_info).merge(state: 'active')
      if old_slot && @workers[old_slot]
        previous = public_worker_state(@workers[old_slot]).merge(
          state: 'draining',
          drain_started_at: switched_at,
          drain_deadline_at: (switched_time + @options[:drain_timeout].to_i).iso8601,
          drain_timeout_seconds: @options[:drain_timeout].to_i,
          drain_remaining_seconds: @options[:drain_timeout].to_i
        )
        @state[:workers][old_slot] = previous
      end
    end
    clear_relay_quarantine(relay_name) if classification[:service_readiness] == 'ready'
    select_city_for_relay(relay_name, city: city)
    persist_relay(relay_name)
    persist_transport_preference(preference)
    record_routing_event(
      'switch-committed',
      relay: relay_name,
      reason: reason,
      detail: "slot=#{new_slot} transport=#{worker_info[:transport_mode]} endpoint=#{worker_info[:endpoint]} entry=#{worker_info[:entry_relay] || 'none'} multihop=#{!!worker_info[:entry_relay]}"
    )
  ensure
    FileUtils.rm_f(pending_profile) if pending_profile
  end

  def candidate_acceptable?(classification, profile:, require_ready: false)
    classification[:relay_liveness] == 'pass' &&
      (!(require_ready || profile[:post_quantum]) || classification[:service_readiness] == 'ready')
  end

  def classify_canary(canary)
    ip_ok = canary.dig(:ip_data, :status) == 'pass'
    dns_ok = canary.dig(:inner_dns, :status) == 'pass'
    domain_ok = canary.dig(:https_data, :status) == 'pass'
    # The literal-IP canary is the primary data-plane check, but a successful
    # HTTPS request through the same worker is also strong proof that the WG
    # payload path is alive. Do not churn relays solely because Cloudflare's
    # diagnostic endpoint is selectively slow/unavailable.
    data_ok = ip_ok || domain_ok
    readiness = if data_ok && dns_ok && domain_ok
                  'ready'
                elsif data_ok && !dns_ok
                  'degraded_dns'
                elsif data_ok
                  'degraded_service'
                else
                  'data_fail'
                end
    { relay_liveness: data_ok ? 'pass' : 'fail', service_readiness: readiness }
  end

  def find_relay(name)
    relay = Array(@metadata.dig('wireguard', 'relays')).find { |r| r['hostname'] == name && r['active'] == true }
    raise "active relay not found: #{name}" unless relay
    public_key = relay['public_key'] || relay['pubkey']
    raise "relay has no public key: #{name}" if public_key.to_s.empty?
    relay
  end

  def start_worker(slot, relay, transport_mode: 'ss', ss_candidate: nil)
    raise 'shutdown requested' if @stop_requested
    raise LocalNetworkInterrupted unless network_attempt_current?
    raise @protection_error if @protection_error && !Thread.current[:adapter_protection_profile]
    raise "worker slot #{slot} is still owned" if @workers[slot]
    peer_key = relay['public_key'] || relay['pubkey']
    if @workers.values.any? { |worker| (worker[:peer_keys] || [worker[:peer_key]]).include?(peer_key) || worker[:relay] == relay['hostname'] }
      raise 'same WireGuard peer is already running'
    end
    mode = transport_mode.to_s
    raise "unsupported transport mode: #{mode}" unless TRANSPORT_MODES.include?(mode)
    raise "relay #{relay['hostname']} does not support #{mode}" unless transport_supported?(relay, mode)

    ensure_pq_available!(protection_profile)
    spec = @slot_config.fetch(slot)
    config, path_info = worker_tunnel_config(spec, relay, mode, ss_candidate)

    dir = slot_dir(slot)
    FileUtils.rm_f(Dir.glob(File.join(dir, '*')).select { |p| File.file?(p) })
    path = File.join(dir, 'config.json')
    pid = nil
    phase = 'bootstrap-config'
    begin
      write_json_private(path, config, secret: true)
      validate_runtime_config(path, dir) if @options[:validate_configs]
      phase = 'bootstrap-controller'
      pid = spawn_worker_core(dir, path, spec)
      if protection_profile[:post_quantum]
        log_event('pq-negotiation-started', relay: relay['hostname'], slot: slot)
        phase = 'pq-config-service'
        secrets = negotiate_pq(spec[:mixed])
        stop_pid(pid)
        pid = nil
        wireguard = config['proxies'].find { |proxy| proxy['name'] == 'MULLVAD' }
        wireguard['private-key'] = secrets.fetch('ephemeral_private_key')
        wireguard['pre-shared-key'] = secrets.fetch('preshared_keys').first
        write_json_private(path, config, secret: true)
        validate_runtime_config(path, dir) if @options[:validate_configs]
        phase = 'final-controller'
        pid = spawn_worker_core(dir, path, spec)
        # The core has loaded its configuration. Do not retain ephemeral keys
        # on disk or expose them through public worker state.
        FileUtils.rm_f(path)
        path_info[:post_quantum] = true
        path_info[:pq_helper_sha256] = Digest::SHA256.file(@options[:pq_helper]).hexdigest
        log_event('pq-negotiation-completed', relay: relay['hostname'], slot: slot,
                  helper_sha256: path_info[:pq_helper_sha256])
      end
    rescue StandardError => error
      stop_pid(pid)
      FileUtils.rm_f(path)
      @mutex.synchronize { @metrics[:worker_start_failures] += 1 }
      log_event('worker-start-failed', relay: relay['hostname'], slot: slot,
                post_quantum: !!protection_profile[:post_quantum], phase: phase, error_class: error.class.name)
      raise 'protected worker could not start; no unprotected fallback was selected'
    end

    info = {
      slot: slot,
      pid: pid,
      instance_token: SecureRandom.uuid,
      relay: relay['hostname'],
      peer_key: peer_key,
      **path_info,
      transport_mode: mode,
      location: relay['location'],
      mixed_port: spec[:mixed],
      controller_port: spec[:controller],
      started_at: Time.now.iso8601
    }
    @mutex.synchronize do
      @workers[slot] = info
      @worker_state_tokens[slot] = info[:instance_token]
      @metrics[:worker_starts] += 1
      @state[:workers][slot] = public_worker_state(info).merge(state: 'candidate')
      @state[:updated_at] = Time.now.iso8601
    end
    info
  end

  def ensure_pq_available!(profile)
    return unless profile[:post_quantum]
    raise '多跳与抗量子的组合尚未通过验收' if profile[:multihop]
    raise '抗量子组件缺失，请使用包含协商器的完整候选包' unless File.executable?(@options[:pq_helper])
    raise '模板已有专用 PSK，不能直接用于新的抗量子身份' unless @template['pre-shared-key'].to_s.empty?
  end

  def spawn_worker_core(dir, path, spec)
    pid = File.open(File.join(dir, 'core.log'), 'a', 0o600) do |log|
      Process.spawn(@options[:core], '-d', dir, '-f', path, out: log, err: log)
    end
    return pid if wait_controller(spec[:controller], 8, pid: pid)
    stop_pid(pid)
    raise 'worker controller did not become ready'
  end

  def negotiate_pq(port, ephemeral_private_key: nil)
    helper = @options[:pq_helper]
    result = nil
    Open3.popen3([helper, helper]) do |input, output, errors, child|
      drain = nil
      begin
        Timeout.timeout(28) do
          request = { parentkey: template_public_key, socks_ports: [port] }
          request[:ephemeral_private_key] = ephemeral_private_key if ephemeral_private_key
          input.write(JSON.generate(request))
          input.close
          # stderr is drained but never included in logs/API: crypto errors
          # and helper output must not escape into diagnostics.
          drain = Thread.new { errors.read }
          raw = output.read(4097).to_s
          raise 'invalid PQ result size' if raw.bytesize > 4096
          raise 'PQ helper failed' unless child.value.success?
          drain.join
          result = validate_pq_result(JSON.parse(raw))
        end
      ensure
        input.close rescue nil
        output.close rescue nil
        errors.close rescue nil
        stop_pid(child.pid) if child.alive?
        drain&.join(1)
      end
    end
    result
  end

  def validate_pq_result(value)
    raise 'invalid PQ response' unless value.is_a?(Hash) && value['schema'] == 1 &&
      value['preshared_keys'].is_a?(Array) && value['preshared_keys'].length == 1
    keys = [value['ephemeral_private_key'], value['ephemeral_public_key'], *value['preshared_keys']]
    raise 'invalid PQ key' unless keys.all? { |key| key.is_a?(String) && Base64.strict_decode64(key).bytesize == 32 }
    raise 'invalid PQ identity' unless template_public_key(value['ephemeral_private_key']) == value['ephemeral_public_key'] &&
      value['ephemeral_public_key'] != template_public_key
    value
  end

  def worker_tunnel_config(spec, relay, mode, ss_candidate)
    exit_relay = relay
    profile = protection_profile
    if profile[:multihop]
      raise ArgumentError, '旧模板带有专用 PSK，不能直接复用于双跳身份' unless @template['pre-shared-key'].to_s.empty?
      raise ArgumentError, '多跳候选缺少入口' unless ss_candidate.is_a?(Hash)
      relay = find_relay(ss_candidate[:entry])
      raise ArgumentError, '入口不符合保护策略' unless multihop_entries(exit_relay, mode).any? { |r| r['hostname'] == relay['hostname'] }
      ss_candidate = ss_candidate[:inlet]
    end
    public_key = relay['public_key'] || relay['pubkey']
    wg_name = 'MULLVAD'
    proxies = []

    wg = @template.dup
    wg.merge!(
      'name' => wg_name,
      'type' => 'wireguard',
      'public-key' => public_key,
      'persistent-keepalive' => 25,
      'remote-dns-resolve' => true,
      'dns' => ['tcp://10.64.0.1'],
      'udp' => true
    )
    %w[peers pre-shared-key reserved].each { |key| wg.delete(key) } if profile[:multihop]
    wg.delete('dialer-proxy')
    wg.delete('interface-name')
    wg.delete('ip-version')

    endpoint = nil
    port = nil
    endpoint_kind = nil
    transport_name = nil
    outer_interface = nil

    case mode
    when 'ss'
      endpoint, port, endpoint_kind = ss_candidate || ss_endpoint(relay)
      outer_interface = physical_interface(endpoint)
      inlet_name = 'SS-INLET'
      proxies << {
        'name' => inlet_name,
        'type' => 'ss',
        'server' => endpoint,
        'port' => port,
        'cipher' => 'aes-256-gcm',
        'password' => 'mullvad',
        'udp' => true,
        'interface-name' => outer_interface,
        'ip-version' => 'ipv4'
      }
      wg.merge!(
        'server' => '127.0.0.1',
        'port' => 51_820,
        'dialer-proxy' => inlet_name,
        'mtu' => 1265
      )
      transport_name = 'wireguard-over-shadowsocks'
    when 'ipv4'
      endpoint = relay.fetch('ipv4_addr_in')
      port = ensure_wireguard_port_allowed!(DIRECT_IPV4_PORT)
      outer_interface = physical_interface(endpoint)
      endpoint_kind = 'relay-ipv4-direct'
      wg.merge!(
        'server' => endpoint,
        'port' => port,
        'interface-name' => outer_interface,
        'ip-version' => 'ipv4',
        'mtu' => 1280
      )
      transport_name = 'wireguard-ipv4-direct'
    when 'ipv6'
      endpoint = relay.fetch('ipv6_addr_in')
      # Historical A/B testing on this machine found 33431 materially more
      # reliable than 51820 for the direct IPv6 outer path. Keep the endpoint
      # literal and do NOT set WG ip-version=ipv6: Mihomo propagates that dial
      # option to inner traffic, which can break the IPv4-only tunnel payload.
      port = ensure_wireguard_port_allowed!(DIRECT_IPV6_PORT)
      outer_interface = physical_interface(endpoint)
      endpoint_kind = 'relay-ipv6-direct'
      wg.merge!(
        'server' => endpoint,
        'port' => port,
        'interface-name' => outer_interface,
        'mtu' => 1280
      )
      transport_name = 'wireguard-ipv6-direct'
    end

    if profile[:multihop]
      wg['name'] = 'WG-ENTRY'
      wg['remote-dns-resolve'] = false
      wg.delete('dns')
      wg['allowed-ips'] = [exit_relay.fetch('ipv4_addr_in') + '/32']
      proxies << wg
      exit_wg = @template.dup
      %w[peers pre-shared-key reserved interface-name ip-version].each { |key| exit_wg.delete(key) }
      exit_wg.merge!('name' => wg_name, 'type' => 'wireguard',
        'server' => exit_relay.fetch('ipv4_addr_in'), 'port' => 51_820,
        'public-key' => exit_relay['public_key'] || exit_relay['pubkey'],
        'dialer-proxy' => 'WG-ENTRY', 'allowed-ips' => ['0.0.0.0/0', '::/0'],
        'persistent-keepalive' => 25, 'remote-dns-resolve' => true,
        'dns' => ['tcp://10.64.0.1'], 'udp' => true, 'mtu' => 1200)
      proxies << exit_wg
      transport_name = 'multihop-' + transport_name
    else
      proxies << wg
    end
    config = {
      'mixed-port' => spec[:mixed],
      'external-controller' => "127.0.0.1:#{spec[:controller]}",
      'allow-lan' => false,
      'mode' => 'rule',
      'log-level' => 'warning',
      'ipv6' => mode == 'ipv6',
      'tun' => { 'enable' => false },
      'dns' => { 'enable' => false },
      'proxies' => proxies,
      'proxy-groups' => [{ 'name' => 'OUT', 'type' => 'select', 'proxies' => [wg_name] }],
      'rules' => ['MATCH,OUT']
    }

    [config, { endpoint: endpoint, endpoint_port: port, endpoint_kind: endpoint_kind,
      interface: outer_interface, transport: transport_name, protection_profile: profile,
      entry_relay: profile[:multihop] ? relay['hostname'] : nil,
      entry_city: profile[:multihop] ? relay['location'] : nil,
      peer_keys: [exit_relay['public_key'] || exit_relay['pubkey'],
        (profile[:multihop] ? public_key : nil)].compact }]
  end

  def ss_endpoint(relay)
    ss_endpoint_candidates(relay).first
  end

  # 把探针丢到后台线程跑。
  #
  # 探针本身出错就等价于"这一项没通过"，不要让它掀翻整轮金丝雀 —— 并发跑的时候，
  # 一个探针抛异常会连累另外两个还没读完的结果，把一次普通的探测失败升级成
  # "整轮金丝雀失败"，反而更难定位。
  def spawn_probe
    thread = Thread.new do
      begin
        yield
      rescue StandardError => e
        { status: 'fail', detail: "#{e.class}: #{e.message}" }
      end
    end
    thread.report_on_exception = false
    thread
  end

  def run_readiness_canary(slot)
    previous = Thread.current[:adapter_skip_controller_probe]
    Thread.current[:adapter_skip_controller_probe] = true
    run_canary(slot)
  ensure
    Thread.current[:adapter_skip_controller_probe] = previous
  end

  def run_canary(slot)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    spec = @slot_config.fetch(slot)
    endpoint = @mutex.synchronize { @workers[slot] && @workers[slot][:endpoint] }

    # 探针顺序按"能不能改变结论"来排，并且一旦结论已定就早退。
    #
    # 死隧道原本要白等 29 秒：controller 8s + ip 8s + dns 8s + https 12s
    # （实测 us-dal-wg-001 一次 27469 ms 全挂）。早退之后最多 ~9 秒。
    #
    # 2026-09-20 再加一层：互不依赖的探针并发跑。
    #   · ping_data / ip_data / inner_dns 三者谁都不依赖谁，一起发出去。
    #   · controller_probe 只要求"数据面活着"，而 ip_data 一通过就已知数据面活着，
    #     所以它不必等 https_data。健康隧道上这两个各约 1.2s / 0.5s，重叠掉就是净省。
    # 依赖关系没动：https 仍然只在 DNS 通过后跑，controller 仍然只在数据面通过后跑。
    ping_thread = spawn_probe do
      endpoint ? outer_ping_test(endpoint, 1_000) : { status: 'fail', detail: 'worker endpoint unavailable' }
    end
    ip_thread = spawn_probe { curl_proxy_ip_test(spec[:mixed], IP_CANARY, 8) }
    dns_thread = spawn_probe { inner_dns_tcp_test(spec[:mixed], 'www.gstatic.com', 8) }

    ping_result = ping_thread.value
    ip_result = ip_thread.value
    # inner_dns 必须跑：dns_ok 由它决定，而 degraded_dns 和 data_fail 的区别靠它。
    dns_result = dns_thread.value

    # https_data 走 socks5h，域名解析依赖内层 DNS。内层 DNS 已经挂了的话
    # domain_ok 必然为 false，再花 12 秒等它是纯浪费。
    # 这不会改变 classify_canary 的结果：dns_ok 为 false 时，
    # data_ok = ip_ok || domain_ok 里 domain_ok 取 true 或 false，
    # 分支都只可能是 degraded_dns（ip_ok 为真）或 data_fail（ip_ok 为假）。
    https_thread = if dns_result[:status] == 'pass'
                     spawn_probe { curl_proxy_test(spec[:mixed], HOST_CANARY, 12) }
                   end

    # controller_probe 不参与就绪度判定（只进缓存快照供界面显示）。
    # 数据面已经确定不通时它只会再白等 8 秒，直接跳过。
    # ip_data 通过就已经证明数据面活着，所以这里可以先起线程，与 https_data 并行。
    controller_thread = if !Thread.current[:adapter_skip_controller_probe] && ip_result[:status] == 'pass'
                          spawn_probe { delay_test(spec[:controller], 'MULLVAD', IP_CANARY, 8_000) }
                        end

    https_result = if https_thread
                     https_thread.value
                   else
                     {
                       status: 'skip', http_code: 0, target: HOST_CANARY,
                       dependency: 'inner_dns+data',
                       detail: 'skipped: inner DNS failed, so the domain check cannot pass'
                     }
                   end

    controller_result = if Thread.current[:adapter_skip_controller_probe]
                          { status: 'skip', target: IP_CANARY, detail: 'optional controller diagnostic omitted during readiness validation' }
                        elsif controller_thread
                          controller_thread.value
                        elsif https_result[:status] == 'pass'
                          delay_test(spec[:controller], 'MULLVAD', IP_CANARY, 8_000)
                        else
                          {
                            status: 'skip', target: IP_CANARY,
                            detail: 'skipped: data path already known down'
                          }
                        end

    elapsed = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round

    {
      at: Time.now.iso8601,
      duration_ms: elapsed,
      ping_data: ping_result,
      controller_probe: controller_result,
      ip_data: ip_result,
      inner_dns: dns_result,
      https_data: https_result
    }
  end

  def outer_ping_test(endpoint, timeout_ms)
    address = IPAddr.new(endpoint.to_s)
    command = address.ipv6? ? '/sbin/ping6' : '/sbin/ping'
    stdout, stderr, status = Open3.capture3(
      command, '-n', '-c', '1', '-W', timeout_ms.to_i.to_s, endpoint.to_s
    )
    match = stdout.match(/time[=<]([0-9.]+)\s*ms/)
    if status.success? && match
      { status: 'pass', delay_ms: match[1].to_f.round, target: endpoint.to_s, detail: 'ICMP echo RTT' }
    else
      detail = stderr.to_s.strip
      detail = stdout.lines.last.to_s.strip if detail.empty?
      { status: 'fail', target: endpoint.to_s, detail: detail[0, 160] }
    end
  rescue StandardError => e
    { status: 'fail', target: endpoint.to_s, detail: "#{e.class}: #{e.message}" }
  end

  def delay_test(controller_port, proxy_name, url, timeout_ms)
    query = URI.encode_www_form(timeout: timeout_ms, url: url)
    response = http_json(controller_port, "/proxies/#{URI.encode_www_form_component(proxy_name)}/delay?#{query}")
    if response.is_a?(Hash) && response['delay'].to_i.positive?
      { status: 'pass', delay_ms: response['delay'].to_i, target: url }
    else
      { status: 'fail', detail: response.is_a?(Hash) ? response['message'].to_s : 'no delay', target: url }
    end
  rescue StandardError => e
    { status: 'fail', detail: "#{e.class}: #{e.message}", target: url }
  end

  def inner_dns_tcp_test(proxy_port, qname, timeout_seconds)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    socket = nil
    Timeout.timeout(timeout_seconds) do
      socket = socks5_connect(proxy_port, '10.64.0.1', 53, timeout_seconds)
      query_id = rand(0..65_535)
      labels = qname.split('.').map { |label| [label.bytesize].pack('C') + label }.join + "\x00"
      packet = [query_id, 0x0100, 1, 0, 0, 0].pack('n6') + labels + [1, 1].pack('n2')
      socket.write([packet.bytesize].pack('n') + packet)
      response_length = read_exact(socket, 2, timeout_seconds).unpack1('n')
      response = read_exact(socket, response_length, timeout_seconds)
      answers = validated_dns_answer_count(response, query_id, qname)
      elapsed = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
      if answers.positive?
        { status: 'pass', delay_ms: elapsed, resolver: '10.64.0.1:53/tcp', qname: qname, answers: answers }
      else
        { status: 'fail', delay_ms: elapsed, resolver: '10.64.0.1:53/tcp', qname: qname, detail: 'invalid or unrelated DNS response' }
      end
    end
  rescue StandardError => e
    { status: 'fail', resolver: '10.64.0.1:53/tcp', qname: qname, detail: "#{e.class}: #{e.message}" }
  ensure
    socket&.close rescue nil
  end

  # Decode the entire DNS frame, not just an asserted ANCOUNT. The standard
  # decoder bounds reads and rejects non-backward/cyclic compression pointers.
  # We additionally require a response to this exact IN/A question and an A
  # answer reachable through a bounded, unambiguous CNAME chain.
  def validated_dns_answer_count(response, query_id, qname)
    return 0 unless response.is_a?(String) && response.bytesize.between?(12, 65_535)

    expected = Resolv::DNS::Name.create(qname.sub(/\.\z/, '') + '.')
    answers = nil
    DnsCanaryDecoder.new(response) do |decoder|
      rid, flags, questions, answer_count, authority_count, additional_count = decoder.get_unpack('nnnnnn')
      return 0 unless rid == query_id && (flags & 0x8000).positive? &&
                      (flags & 0x7800).zero? && (flags & 0x0200).zero? &&
                      (flags & 0x0040).zero? && (flags & 0x000f).zero? && questions == 1 && answer_count.positive?
      return 0 if answer_count + authority_count + additional_count > 4096

      name = decoder.get_name
      type, klass = decoder.get_unpack('nn')
      return 0 unless valid_dns_wire_name?(name) && name == expected && type == 1 && klass == 1

      seen_opt = false
      records = Array.new(answer_count + authority_count + additional_count) do |index|
        owner, ttl, resource, record_type = decoder.get_rr
        if record_type == 41
          return 0 if seen_opt || index < answer_count + authority_count || !owner.to_a.empty? || (ttl >> 24).positive?
          seen_opt = true
        end
        return 0 unless valid_dns_wire_name?(owner)
        if resource.is_a?(Resolv::DNS::Resource::IN::CNAME)
          return 0 unless valid_dns_wire_name?(resource.name)
        end
        [owner, ttl, resource]
      end
      return 0 unless decoder.get_bytes.empty?
      answers = records.first(answer_count)
    end

    visited = {}
    current = expected
    17.times do
      return 0 if visited[current]
      visited[current] = true
      matching = answers.select { |owner, _ttl, _resource| owner == current }.map(&:last)
      addresses = matching.count { |resource| resource.is_a?(Resolv::DNS::Resource::IN::A) }
      aliases = matching.grep(Resolv::DNS::Resource::IN::CNAME).map(&:name).uniq
      return 0 if aliases.length > 1 || (addresses.positive? && !aliases.empty?)
      return addresses if addresses.positive?
      return 0 unless aliases.length == 1
      current = aliases.first
    end
    0
  rescue Resolv::DNS::DecodeError, ArgumentError, NoMethodError
    0
  end

  def valid_dns_wire_name?(name)
    labels = name.to_a.map { |label| label.to_s.bytesize }
    labels.all? { |size| size.between?(1, 63) } && labels.sum + labels.length + 1 <= 255
  end

  def socks5_connect(proxy_port, host, port, timeout_seconds)
    socket = Socket.tcp('127.0.0.1', proxy_port, connect_timeout: timeout_seconds)
    socket.write([5, 1, 0].pack('C*'))
    hello = read_exact(socket, 2, timeout_seconds).bytes
    raise 'SOCKS5 authentication negotiation failed' unless hello == [5, 0]

    address = IPAddr.new(host).hton
    request = [5, 1, 0, 1].pack('C*') + address + [port].pack('n')
    socket.write(request)
    header = read_exact(socket, 4, timeout_seconds).bytes
    raise "SOCKS5 connect failed rep=#{header[1]}" unless header[0] == 5 && header[1] == 0
    case header[3]
    when 1 then read_exact(socket, 4, timeout_seconds)
    when 4 then read_exact(socket, 16, timeout_seconds)
    when 3
      length = read_exact(socket, 1, timeout_seconds).unpack1('C')
      read_exact(socket, length, timeout_seconds)
    else
      raise "SOCKS5 unexpected address type #{header[3]}"
    end
    read_exact(socket, 2, timeout_seconds)
    socket
  rescue Exception
    socket&.close
    raise
  end

  def read_exact(io, length, timeout_seconds)
    buffer = +''
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout_seconds
    while buffer.bytesize < length
      remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      raise 'read timeout' if remaining <= 0
      ready = IO.select([io], nil, nil, remaining)
      raise 'read timeout' unless ready
      chunk = io.readpartial(length - buffer.bytesize)
      buffer << chunk
    end
    buffer
  end

  def curl_proxy_test(port, url, timeout)
    format = 'code=%{http_code} total=%{time_total}'
    stdout, stderr, status = Open3.capture3(
      'curl', '-q', '-sS', '--noproxy', '', '--max-time', timeout.to_s,
      '--proxy', "socks5h://127.0.0.1:#{port}",
      '-o', '/dev/null', '-w', format, url
    )
    code = stdout[/code=(\d+)/, 1].to_i
    evidence = { exit_code: status.exitstatus, elapsed_seconds: stdout[/total=([\d.]+)/, 1]&.to_f,
                 proxy_port: port, target: url, timeout_seconds: timeout }
    if status.success? && code >= 200 && code < 400
      { **evidence, status: 'pass', http_code: code, detail: stdout.strip, dependency: 'inner_dns+data' }
    else
      { **evidence, status: 'fail', http_code: code, detail: stderr.to_s.strip[0, 160], dependency: 'inner_dns+data' }
    end
  end

  def curl_proxy_ip_test(port, url, timeout)
    format = 'code=%{http_code} total=%{time_total}'
    stdout, stderr, status = Open3.capture3(
      'curl', '-q', '-sS', '--noproxy', '', '--max-time', timeout.to_s,
      '--proxy', "socks5://127.0.0.1:#{port}",
      '-o', '/dev/null', '-w', format, url
    )
    code = stdout[/code=(\d+)/, 1].to_i
    evidence = { exit_code: status.exitstatus, elapsed_seconds: stdout[/total=([\d.]+)/, 1]&.to_f,
                 proxy_port: port, target: url, timeout_seconds: timeout }
    if status.success? && code >= 200 && code < 400
      { **evidence, status: 'pass', http_code: code, detail: stdout.strip, dependency: 'data' }
    else
      { **evidence, status: 'fail', http_code: code, detail: stderr.to_s.strip[0, 160], dependency: 'data' }
    end
  end

  def select_front(slot)
    raise 'shutdown requested' if @stop_requested
    expected = "worker-#{slot}"
    last_error = nil

    2.times do
      begin
        response = http_json(@options[:front_controller], '/proxies/ACTIVE', method: :put, body: { name: expected })
        return true if response.nil? || response == {} || response['message'].to_s.empty?
        raise "front selector failed: #{response.inspect}"
      rescue StandardError => e
        last_error = e
        begin
          observed = http_json(@options[:front_controller], '/proxies/ACTIVE', open_timeout: 0.5, read_timeout: 1)
          return true if observed['now'].to_s == expected
        rescue StandardError
          # Retry once on the existing front before deciding it is unhealthy.
        end
        sleep 0.15
      end
    end

    raise last_error if @stop_requested

    stale_pid = @front_pid
    stop_pid(stale_pid) if stale_pid
    @front_pid = nil
    @front_probe_failures = 0
    @mutex.synchronize do
      @state[:front][:ready] = false
      @metrics[:front_restarts] += 1
    end
    record_routing_event('front-restarted-during-switch', detail: "#{last_error.class}: #{last_error.message}")
    ensure_front

    response = http_json(@options[:front_controller], '/proxies/ACTIVE', method: :put, body: { name: expected })
    return true if response.nil? || response == {} || response['message'].to_s.empty?

    raise "front selector failed after front restart: #{response.inspect}"
  end

  def start_drain(slot)
    instance_token = @mutex.synchronize do
      worker = @workers[slot]
      worker && worker[:instance_token]
    end
    return unless instance_token

    draining_relay = @mutex.synchronize { @workers[slot] && @workers[slot][:relay] }
    record_routing_event('graceful-drain-started', relay: draining_relay, reason: 'post-switch', detail: "slot=#{slot}")

    Thread.new do
      deadline = @mutex.synchronize do
        worker = @state[:workers][slot]
        raw_deadline = worker && worker[:drain_deadline_at]
        begin
          raw_deadline ? Time.parse(raw_deadline) : Time.now + @options[:drain_timeout].to_i
        rescue ArgumentError
          Time.now + @options[:drain_timeout].to_i
        end
      end
      loop do
        break unless worker_owned?(slot, instance_token)

        count = front_connections_for(slot)
        break unless worker_owned?(slot, instance_token)
        remaining = [(deadline - Time.now).ceil, 0].max
        update_worker_drain_state(slot, count, remaining, expected_token: instance_token)
        if count == 0
          stopped = stop_worker(slot, expected_token: instance_token)
          @mutex.synchronize { @metrics[:drain_completions] += 1 } if stopped
          break
        end
        if Time.now >= deadline
          stopped = stop_worker(slot, expected_token: instance_token)
          @mutex.synchronize { @metrics[:drain_forced] += 1 } if stopped
          break
        end
        sleep 1
      end
    rescue StandardError => e
      record_error("drain #{slot} failed: #{e.class}: #{e.message}")
    end
  end

  def front_connections_for(slot)
    payload = http_json(@options[:front_controller], '/connections')
    Array(payload['connections']).count do |connection|
      Array(connection['chains']).include?("worker-#{slot}")
    end
  rescue StandardError
    nil
  end

  def worker_owned?(slot, instance_token)
    @mutex.synchronize do
      worker = @workers[slot]
      worker && worker[:instance_token] == instance_token
    end
  end

  def update_worker_connection_count(slot, count, expected_token: nil)
    @mutex.synchronize do
      if expected_token
        worker = @workers[slot]
        return false unless worker && worker[:instance_token] == expected_token
        return false unless @worker_state_tokens[slot] == expected_token
      end
      public_worker = @state[:workers][slot]
      public_worker[:front_connection_count] = count if public_worker
      @state[:updated_at] = Time.now.iso8601
      true
    end
  end

  def update_worker_drain_state(slot, count, remaining_seconds, expected_token: nil)
    @mutex.synchronize do
      if expected_token
        worker = @workers[slot]
        return false unless worker && worker[:instance_token] == expected_token
        return false unless @worker_state_tokens[slot] == expected_token
      end
      public_worker = @state[:workers][slot]
      return false unless public_worker
      public_worker[:front_connection_count] = count unless count.nil?
      public_worker[:drain_remaining_seconds] = remaining_seconds
      @state[:updated_at] = Time.now.iso8601
      true
    end
  end

  def stop_worker(slot, expected_token: nil)
    # Drain callbacks share the same lifecycle lock as starts. A callback may
    # not remove a replacement config while the old process is terminating.
    unless @switch_mutex.owned?
      return @switch_mutex.synchronize { stop_worker(slot, expected_token: expected_token) }
    end
    info = @mutex.synchronize do
      worker = @workers[slot]
      return false unless worker
      return false if expected_token && worker[:instance_token] != expected_token
      @workers.delete(slot)
      worker
    end

    stop_pid(info[:pid])
    FileUtils.rm_f(File.join(slot_dir(slot), 'config.json'))
    @mutex.synchronize do
      if @worker_state_tokens[slot] == info[:instance_token]
        if @state[:workers][slot]
          @state[:workers][slot][:state] = 'stopped'
          @state[:workers][slot][:stopped_at] = Time.now.iso8601
          @state[:workers][slot][:front_connection_count] = 0
          @state[:workers][slot][:drain_remaining_seconds] = 0 if @state[:workers][slot].key?(:drain_remaining_seconds)
        end
        @state[:updated_at] = Time.now.iso8601
      end
    end
    true
  end

  def public_worker_state(info)
    {
      relay: info[:relay],
      multihop: !info[:entry_relay].nil?,
      entry_relay: info[:entry_relay],
      entry_city: info[:entry_city],
      post_quantum: !!info[:post_quantum],
      pq_helper_sha256: info[:pq_helper_sha256],
      daita: false,
      transport: info[:transport],
      transport_mode: info[:transport_mode],
      endpoint: info[:endpoint],
      endpoint_port: info[:endpoint_port],
      endpoint_kind: info[:endpoint_kind],
      interface: info[:interface],
      mixed_port: info[:mixed_port],
      started_at: info[:started_at],
      front_connection_count: 0
    }
  end

  def set_dns_status(layer, status, detail)
    @mutex.synchronize do
      @state[:dns][layer] = { status: status, detail: detail, at: Time.now.iso8601 }
      @state[:updated_at] = Time.now.iso8601
    end
  end

  def physical_interface(endpoint = nil)
    family = nil
    unless endpoint.to_s.empty?
      address = IPAddr.new(endpoint.to_s)
      family = address.ipv6? ? :ipv6 : :ipv4
      interface = route_interface_for(endpoint.to_s, family)
      return interface if usable_physical_interface?(interface)
    end

    if family
      interface = route_interface_for('default', family)
      return interface if usable_physical_interface?(interface)
    end

    interface = route_interface_for('default', nil)
    return interface if usable_physical_interface?(interface)

    fallback = network_interface_fallbacks.find { |name| usable_physical_interface?(name) }
    return fallback if fallback

    raise "unable to determine physical interface for #{endpoint || 'default route'}"
  rescue IPAddr::InvalidAddressError => e
    raise "invalid transport endpoint #{endpoint}: #{e.message}"
  end

  def route_interface_for(target, family)
    args = ['route', '-n', 'get']
    args << '-inet6' if family == :ipv6
    args << '-inet' if family == :ipv4
    args << target
    # `route` writes expected "not in table" diagnostics to stderr when this
    # machine has no route for one address family. Capture it instead of
    # inheriting daemon stderr; the caller already treats a failed lookup as a
    # normal signal and tries the next family/default/fallback.
    output, _error, status = Open3.capture3(*args)
    return nil unless status.success?
    output[/interface:\s+(\S+)/, 1]
  rescue StandardError
    nil
  end

  def network_interface_fallbacks
    output, status = Open3.capture2('scutil', '--nwi')
    return [] unless status.success?
    line = output.lines.find { |item| item.include?('Network interfaces:') }
    return [] unless line
    line.split(':', 2).last.to_s.split
  rescue StandardError
    []
  end

  def usable_physical_interface?(name)
    value = name.to_s.strip
    return false if value.empty?
    return false if value.match?(/\A(?:lo\d*|utun\d*|awdl\d*|llw\d*|feth\d*|bridge\d*|gif\d*|stf\d*)\z/)
    true
  end

  def slot_dir(slot)
    File.join(@state_dir, 'slots', slot)
  end

  def write_json_private(path, object, secret:)
    File.write(path, JSON.pretty_generate(object))
    File.chmod(secret ? 0o600 : 0o644, path)
  end

  def validate_runtime_config(path, dir)
    _stdout, _stderr, status = Open3.capture3(@options[:core], '-t', '-d', dir, '-f', path)
    raise 'Mihomo rejected generated configuration' unless status.success?
    true
  end

  def wait_controller(port, timeout_seconds, pid: nil)
    deadline = Time.now + timeout_seconds
    consecutive_successes = 0
    loop do
      return false if pid && !process_alive?(pid)
      if pid && !controller_listener_owned_by?(port, pid)
        consecutive_successes = 0
        return false if Time.now >= deadline
        sleep 0.1
        next
      end
      begin
        payload = http_json(port, '/version', open_timeout: 0.3, read_timeout: 0.3)
        if payload.is_a?(Hash) && (!pid || (process_alive?(pid) && controller_listener_owned_by?(port, pid)))
          consecutive_successes += 1
          return true if consecutive_successes >= 2
        else
          consecutive_successes = 0
        end
      rescue StandardError
        consecutive_successes = 0
      end
      return false if Time.now >= deadline
      sleep 0.1
    end
  end

  def controller_listener_owned_by?(port, pid)
    stdout, status = Open3.capture2(
      '/usr/sbin/lsof', '-nP', '-a', '-p', pid.to_i.to_s,
      "-iTCP:#{port.to_i}", '-sTCP:LISTEN', '-t'
    )
    status.success? && stdout.lines.any? { |line| line.strip == pid.to_i.to_s }
  rescue StandardError
    false
  end

  def http_json(port, path, method: :get, body: nil, open_timeout: 1, read_timeout: 5)
    uri = URI("http://127.0.0.1:#{port}#{path}")
    klass = method == :put ? Net::HTTP::Put : (method == :post ? Net::HTTP::Post : Net::HTTP::Get)
    request = klass.new(uri)
    if body
      request['Content-Type'] = 'application/json'
      request.body = JSON.generate(body)
    end
    response = Net::HTTP.start(uri.host, uri.port, nil, open_timeout: open_timeout, read_timeout: read_timeout) do |http|
      http.request(request)
    end
    raise "HTTP #{response.code} for #{path}" unless response.code.to_i.between?(200, 299)
    return {} if response.body.to_s.strip.empty?
    JSON.parse(response.body)
  end

  def process_alive?(pid)
    begin
      waited = Process.waitpid(pid, Process::WNOHANG)
      return false if waited
    rescue Errno::ECHILD
      # Not our child (or already reaped); fall back to signal-0 probing.
    end
    Process.kill(0, pid)
    true
  rescue Errno::ESRCH
    false
  rescue Errno::EPERM
    true
  end

  def stop_pid(pid)
    return unless pid
    Process.kill('TERM', pid)
    deadline = Time.now + 5
    while Time.now < deadline
      begin
        waited = Process.waitpid(pid, Process::WNOHANG)
        return if waited
      rescue Errno::ECHILD
        return unless process_alive?(pid)
      end
      sleep 0.1
    end
    Process.kill('KILL', pid) if process_alive?(pid)
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  end

  def ipv4?(value)
    IPAddr.new(value.to_s).ipv4?
  rescue IPAddr::InvalidAddressError
    false
  end

  def trap_signals
    %w[INT TERM].each do |signal|
      Signal.trap(signal) { @stop_requested = true }
    end
  end

  def shutdown
    @stop_requested = true
    @health_wait_mutex.synchronize { @health_cv.broadcast }
    @server&.close rescue nil
    @switch_mutex.synchronize do
      @workers.keys.each { |slot| stop_worker(slot) }
      stop_pid(@front_pid) if @front_pid
      @front_pid = nil
      @mutex.synchronize do
        @state[:front][:ready] = false
        @state[:status] = 'stopped'
        @state[:updated_at] = Time.now.iso8601
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  options = {}
  OptionParser.new do |parser|
    parser.banner = 'Usage: mullvad_adapter.rb [options]'
    parser.on('--state-dir PATH') { |v| options[:state_dir] = File.expand_path(v) }
    parser.on('--profile PATH') { |v| options[:profile] = File.expand_path(v) }
    parser.on('--core PATH') { |v| options[:core] = File.expand_path(v) }
    parser.on('--api-port PORT', Integer) { |v| options[:api_port] = v }
    parser.on('--front-port PORT', Integer) { |v| options[:front_mixed] = v }
    parser.on('--front-controller-port PORT', Integer) { |v| options[:front_controller] = v }
    parser.on('--worker-port-base PORT', Integer) { |v| options[:worker_port_base] = v }
    parser.on('--bootstrap-proxy URL') { |v| options[:bootstrap_proxy] = v }
    parser.on('--default-relay HOSTNAME') { |v| options[:default_relay] = v }
    parser.on('--drain-timeout SECONDS', Integer) { |v| options[:drain_timeout] = v }
    parser.on('--health-interval SECONDS', Integer) { |v| options[:health_interval] = v }
    parser.on('--health-recheck-interval SECONDS', Integer) { |v| options[:health_recheck_interval] = v }
    parser.on('--health-fail-threshold COUNT', Integer) { |v| options[:health_fail_threshold] = v }
    parser.on('--recovery-cooldown SECONDS', Integer) { |v| options[:recovery_cooldown] = v }
    parser.on('--supervisor-interval SECONDS', Integer) { |v| options[:supervisor_interval] = v }
    parser.on('--front-data-probe-interval SECONDS', Integer) { |v| options[:front_data_probe_interval] = v }
    parser.on('--recovery-quarantine SECONDS', Integer) { |v| options[:recovery_quarantine] = v }
  end.parse!

  MullvadAdapter.new(options).run
end
