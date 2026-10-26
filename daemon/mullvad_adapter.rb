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
  class LocalProbeTimeout < StandardError
    attr_reader :phase

    def initialize(phase)
      @phase = phase
      super("local probe deadline exceeded: #{phase}")
    end
  end
  # Preserve the existing local-indeterminate handling without calling a
  # spawn/pipe permission error a negative observation of the remote relay.
  class LocalProbeUnavailable < LocalProbeTimeout
    def message
      "local probe unavailable: #{phase}"
    end
    alias to_s message
  end
  # Local decoder only: never monkey-patch Resolv or allocate globally cached
  # resource classes from response-controlled type/class numbers.
  class DnsCanaryDecoder < Resolv::DNS::Message::MessageDecoder
    # Resolv 0.7 replaced ClassHash with a write-only Module. get_class is
    # unsuitable here: unknown wire values permanently allocate global classes.
    # Capture only the known IN decoders, without consulting a mutable registry.
    RESOURCE_DECODERS = %i[A AAAA CNAME NS SOA MX PTR SRV TXT HINFO MINFO LOC WKS CAA].each_with_object({}) do |name, decoders|
      next unless Resolv::DNS::Resource::IN.const_defined?(name, false)
      resource = Resolv::DNS::Resource::IN.const_get(name, false)
      decoders[[resource::TypeValue, resource::ClassValue].freeze] = resource
    end.freeze

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
      typeclass = RESOURCE_DECODERS[[type, klass]]
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
  BUILD_ID = '20261026-ss-loopback-target-1'
  SOURCE_SHA256 = Digest::SHA256.file(__FILE__).hexdigest
  STATUS_PUBLICATION_INTERVAL = 1.0
  STATUS_PUBLICATION_MAX_AGE = 3.0
  # Keep recent history by capacity, not by calendar day: two files together
  # never exceed 20 MB (decimal), retaining multiple days at normal event rates.
  EVENT_LOG_FILE_BYTES = 10_000_000

  SLOT_CONFIG = {
    'a' => { mixed: 17_910, controller: 17_911 },
    'b' => { mixed: 17_920, controller: 17_921 }
  }.freeze

  DEFAULTS = {
    state_dir: File.expand_path('~/Library/Application Support/MullvadLocalAdapter'),
    profile: nil, # Import a legacy profile only when explicitly configured.
    core: '/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo',
    pq_helper: File.basename(__FILE__) == 'mullvad-local-adapter' ? File.join(__dir__, 'mullvad-pq-negotiator') : File.expand_path('../helpers/pq-negotiator/bin/mullvad-pq-negotiator', __dir__),
    api_host: '127.0.0.1',
    api_port: 17_891,
    front_mixed: 17_890,
    front_controller: 17_892,
    bootstrap_proxy: nil, # Verified HTTPS via the system route; never infer a local listener.
    default_relay: nil, # A saved or explicitly selected city/relay supplies the destination.
    drain_timeout: 1_800,
    metadata_ttl: 21_600,
    health_interval: 30,
    health_fail_threshold: 2,
    # 已经失败、但还没到判定阈值时，不要傻等下一个 30 秒。
    # front 故障会主动唤醒；首次失败后的复检等待压到 2 秒。
    health_recheck_interval: 2,
    recovery_cooldown: 30,
    attempt_budget: 35,
    recovery_batch_size: 4,
    recovery_round_budget: 45,
    ordered_recovery_budget: 300,
    local_network_interval: 2,
    local_network_settle: 2,
    clash_socket: "/var/run/clash-verge-service/users/#{Process.uid}/verge-mihomo.sock",
    supervisor_interval: 5,
    front_data_probe_interval: 30,
    recovery_quarantine: 900
  }.freeze

  def initialize(options)
    @options = DEFAULTS.merge(options)
    # Preserve the historical implicit route for an already installed template.
    # Clean first-run state never inherits developer-machine endpoints. Explicit
    # options (including an empty proxy for system HTTPS) always take priority.
    legacy_identity = File.file?(File.join(@options[:state_dir], 'wireguard-template.json'))
    defaults_path = File.join(@options[:state_dir], 'bootstrap-defaults.json')
    @bootstrap_defaults_source = legacy_identity ? 'legacy_local_default' : 'system_default'
    if File.file?(defaults_path)
      assert_private_directory!(@options[:state_dir])
      recover_private_identity_link(defaults_path)
      defaults = JSON.parse(read_private_identity_file(defaults_path))
      unless defaults.is_a?(Hash) && defaults['schema'] == 1 && %w[legacy_local_default system_default].include?(defaults['source'])
        raise '本机引导默认值记录无效；未切换代理或节点，请检查配置'
      end
      @bootstrap_defaults_source = defaults['source']
    end
    if @bootstrap_defaults_source == 'legacy_local_default'
      @options[:bootstrap_proxy] = 'http://127.0.0.1:17893' unless options.key?(:bootstrap_proxy)
      @options[:default_relay] = 'us-sea-wg-401' unless options.key?(:default_relay)
    end
    @api_route_source = options.key?(:bootstrap_proxy) ? 'explicit_option' : @bootstrap_defaults_source
    @slot_config = if @options[:worker_port_base]
                     base = Integer(@options[:worker_port_base])
                     { 'a' => { mixed: base, controller: base + 1 }, 'b' => { mixed: base + 10, controller: base + 11 } }
                   else
                     SLOT_CONFIG
                   end
    @state_dir = @options[:state_dir]
    @log_dir = @options[:log_dir] || (@state_dir == DEFAULTS[:state_dir] ? File.expand_path('~/Library/Logs/MullvadLocalAdapter') : File.join(@state_dir, 'logs'))
    @log_mutex = Mutex.new
    @probe_event_mutex = Mutex.new
    @probe_events = []
    @probe_events_dropped = 0
    @probe_event_writer = nil
    @mutex = Mutex.new
    @switch_mutex = Mutex.new
    @ordered_recovery_mutex = Mutex.new
    @background_probe_mutex = Mutex.new
    @automatic_exhausted_rounds = 0
    @recovery_control_epoch = 0
    @recovery_stopped = false
    @speed_test_mutex = Mutex.new
    @action_gate_mutex = Mutex.new
    @history_mutex = Mutex.new
    @ss_endpoint_mutex = Mutex.new
    @metadata_mutex = Mutex.new
    @metadata_refresh_job_mutex = Mutex.new
    @ss_recovery_windows = {}
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
    @controller_secret_mutex = Mutex.new
    @controller_secrets = {}
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
      recovery: { phase: 'idle', running: false, attempt: 0, budget_seconds: @options[:ordered_recovery_budget],
                  message: '连接异常确认后：原入口重试 → 同节点备用 SS → 最多 4 个同城节点',
                  next_step: '本机断网先等待；本地入口故障先修入口，不跨城切换' },
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
    @status_publish_gate = Mutex.new
    publish_status_snapshot
  end

  def run
    prepare_state_dir
    load_relay_history
    load_ss_endpoint_history
    defaults_path = File.join(@state_dir, 'bootstrap-defaults.json')
    write_private_identity_once(defaults_path, JSON.generate(schema: 1, source: @bootstrap_defaults_source))
    load_template
    load_account_manager
    @account_only_mode = @template.nil?
    trap_signals
    start_api_server
    unless @template
      # First-run account access must not depend on a developer's Clash profile,
      # core installation or pre-existing WireGuard identity. No engine or
      # recovery thread runs in this mode; installing an identity is separate.
      @account_only_mode = true
      @state[:status] = @state[:service_readiness] = 'needs_setup'
      @state[:last_error] = '隧道尚未初始化：可管理账号与本机设备；尚未安装 WireGuard 身份。'
      sleep 0.2 until @stop_requested || !@account_only_mode
      return if @stop_requested
    end
    load_cached_metadata
    load_city_workspace
    load_protection_profile
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
        next if @stop_requested
        next if local_network_paused?
        refresh_metadata unless @metadata
        next if @first_identity_installed # Selection and tunnel validation remain explicit.
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
    FileUtils.mkdir_p(@state_dir, mode: 0o700) unless File.exist?(@state_dir) || File.symlink?(@state_dir)
    assert_private_directory!(@state_dir)
    %w[front slots].each do |name|
      path = File.join(@state_dir, name)
      Dir.mkdir(path, 0o700) unless File.exist?(path) || File.symlink?(path)
      assert_private_directory!(path)
    end
    @slot_config.keys.each do |slot|
      path = slot_dir(slot)
      Dir.mkdir(path, 0o700) unless File.exist?(path) || File.symlink?(path)
      assert_private_directory!(path)
    end
  end

  def template_path
    File.join(@state_dir, 'wireguard-template.json')
  end

  def load_template
    if File.exist?(template_path) || File.symlink?(template_path)
      recover_private_identity_link(template_path)
      @template = JSON.parse(read_private_identity_file(template_path))
    else
      return unless @options[:profile]
      doc = YAML.load_file(@options[:profile]) || {}
      proxies = Array(doc['proxies'])
      candidate = proxies.find do |proxy|
        proxy.is_a?(Hash) && proxy['type'].to_s == 'wireguard' && proxy['name'].to_s.end_with?('-SS')
      end
      raise 'No active Mullvad *-SS WireGuard template found in source profile and no adapter template cache exists' unless candidate

      keep = %w[ip ipv6 private-key pre-shared-key allowed-ips reserved udp]
      @template = candidate.select { |key, _| keep.include?(key.to_s) }
      write_private_identity_once(template_path, JSON.generate(@template))
    end

    raise 'WireGuard template has no private-key' if @template['private-key'].to_s.empty?
    raise 'WireGuard template has no tunnel ip' if @template['ip'].to_s.empty?
    @template['allowed-ips'] = ['0.0.0.0/0'] if Array(@template['allowed-ips']).empty?
  end

  def assert_private_directory!(path)
    stat = File.lstat(path)
    raise '本机身份目录不安全，未修改身份' unless stat.directory? && stat.uid == Process.uid && (stat.mode & 0o077).zero?
  end

  def read_private_identity_file(path, links: 1)
    stat = File.lstat(path)
    unless stat.file? && stat.uid == Process.uid && (stat.mode & 0o077).zero? && stat.nlink == links && stat.size <= 16_384
      raise '本机身份记录不安全，未修改身份'
    end
    File.open(path, File::RDONLY | File::NOFOLLOW) do |file|
      actual = file.stat
      raise '本机身份记录已变化' unless [actual.dev, actual.ino, actual.size, actual.nlink, actual.uid, actual.mode] == [stat.dev, stat.ino, stat.size, links, stat.uid, stat.mode]
      file.read
    end
  end

  def sync_identity_directory(path)
    File.open(File.dirname(path), File::RDONLY) { |directory| directory.fsync }
  rescue Errno::EINVAL, Errno::ENOTSUP
    # Some filesystems cannot fsync directories; file fsync still applies.
  end

  def recover_private_identity_link(path)
    pending = path + '.pending'
    return unless File.exist?(pending) || File.symlink?(pending)
    target_stat, pending_stat = File.lstat(path), File.lstat(pending)
    unless target_stat.dev == pending_stat.dev && target_stat.ino == pending_stat.ino && target_stat.nlink == 2 && pending_stat.nlink == 2
      raise '本机身份暂存记录冲突，已保留原记录'
    end
    read_private_identity_file(path, links: 2)
    read_private_identity_file(pending, links: 2)
    File.unlink(pending)
    sync_identity_directory(path)
  end

  # Atomic no-replace commit. A crash leaves either no target or the complete
  # fsynced target. Only our exact two-link pending/target pair is recoverable;
  # unrelated symlinks/hardlinks/owners or conflicting bytes always block.
  def write_private_identity_once(path, content)
    assert_private_directory!(File.dirname(path))
    pending = path + '.pending'
    if File.exist?(path) || File.symlink?(path)
      recover_private_identity_link(path)
      raise '本机身份记录已存在且不匹配，未覆盖' unless read_private_identity_file(path) == content
      return
    end
    if File.exist?(pending) || File.symlink?(pending)
      raise '本机身份暂存记录不匹配，已保留' unless read_private_identity_file(pending) == content
    else
      File.open(pending, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |file|
        file.write(content)
        file.flush
        file.fsync
      end
      sync_identity_directory(pending)
    end
    raise '本机身份暂存读回失败' unless read_private_identity_file(pending) == content
    File.link(pending, path)
    sync_identity_directory(path)
    recover_private_identity_link(path)
    raise '本机身份提交读回失败' unless read_private_identity_file(path) == content
  end

  def registration_receipt_path(binding, pubkey)
    File.join(@state_dir, 'device-registrations', binding, Digest::SHA256.hexdigest(pubkey) + '.json')
  end

  def registration_receipt(binding, pubkey)
    path = registration_receipt_path(binding, pubkey)
    return nil unless File.exist?(path) || File.symlink?(path)
    assert_private_directory!(File.dirname(File.dirname(path)))
    assert_private_directory!(File.dirname(path))
    recover_private_identity_link(path)
    value = JSON.parse(read_private_identity_file(path))
    raise '本机官方登记回执无效' unless value['schema'] == 1 && value['account_fingerprint'] == binding && value.dig('device', 'pubkey') == pubkey && valid_device_registration?(value['device'])
    value['device']
  end

  def valid_device_registration?(device)
    device.is_a?(Hash) && device['id'].to_s.match?(/\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/i) &&
      valid_account_public_key?(device['pubkey']) && device['name'].is_a?(String) && !device['name'].empty? &&
      device['name'].bytesize <= 256 && !device['name'].match?(/[[:cntrl:]]/) &&
      device['ipv4_address'].to_s.end_with?('/32') && IPAddr.new(device['ipv4_address']).ipv4? &&
      device['ipv6_address'].to_s.end_with?('/128') && IPAddr.new(device['ipv6_address']).ipv6?
  rescue IPAddr::InvalidAddressError
    false
  end

  def save_registration_receipt(device)
    binding = Digest::SHA256.hexdigest(@account_number)
    path = registration_receipt_path(binding, device.fetch('pubkey'))
    [File.dirname(File.dirname(path)), File.dirname(path)].each do |directory|
      Dir.mkdir(directory, 0o700) unless File.exist?(directory) || File.symlink?(directory)
      assert_private_directory!(directory)
    end
    safe = device.select { |key, _| %w[id name pubkey created ipv4_address ipv6_address].include?(key) }
    write_private_identity_once(path, JSON.generate(schema: 1, account_fingerprint: binding, device: safe))
    safe
  end

  def installed_draft_match(pubkey, devices)
    return {} unless @template && @account_number && @account_data
    path = File.join(@state_dir, 'identity-installation.json')
    return {} unless File.exist?(path) || File.symlink?(path)
    recover_private_identity_link(path)
    receipt = JSON.parse(read_private_identity_file(path))
    binding = Digest::SHA256.hexdigest(@account_number)
    return {} unless receipt['schema'] == 1 && receipt['account_fingerprint'] == binding && receipt['public_key'] == pubkey &&
      receipt['template_sha256'] == Digest::SHA256.hexdigest(read_private_identity_file(template_path)) &&
      devices.count { |device| device[:id] == receipt['device_id'] && device[:pubkey] == pubkey && device[:current] } == 1
    official = registration_receipt(binding, pubkey)
    return {} unless official && official['id'] == receipt['device_id'] &&
      @template['ip'] == official['ipv4_address'].sub(%r{/32\z}, '') && @template['ipv6'] == official['ipv6_address'].sub(%r{/128\z}, '')
    { activated_draft_public_key: pubkey, activated_draft_device_id: receipt['device_id'] }
  end

  def reserve_identity_install_ports
    ports = [@options[:front_mixed], @options[:front_controller], *@slot_config.values.flat_map { |slot| slot.values }].uniq
    listeners = []
    begin
      ports.each { |port| listeners << TCPServer.new('127.0.0.1', port) }
      yield
    rescue Errno::EADDRINUSE, Errno::EACCES
      raise AccountError.new('engine_running', '网络引擎端口仍被占用，未安装或更换身份')
    ensure
      listeners.reverse_each(&:close)
    end
  end

  ABANDON_SOURCE_ARCHIVES = {
    'identity-installation.json' => 'metadata.json',
    'identity-installation.json.pending' => 'metadata-pending.json',
    'wireguard-template.json.pending' => 'template-pending.json'
  }.freeze
  IDENTITY_RECORD_LIMIT = 64

  def identity_path_exists?(path)
    File.exist?(path) || File.symlink?(path)
  end

  # Read a crash-pending pair without deleting either original. Cancellation
  # archives all original bytes before it is allowed to unlink an occupant.
  def read_identity_pair(path)
    pending = path + '.pending'
    paths = [path, pending].select { |candidate| identity_path_exists?(candidate) }
    return nil if paths.empty?
    if paths.length == 2
      left, right = paths.map { |candidate| File.lstat(candidate) }
      raise '本机身份记录冲突' unless [left.dev, left.ino, left.nlink] == [right.dev, right.ino, 2] && left.nlink == 2
    end
    bytes = paths.map { |candidate| read_private_identity_file(candidate, links: paths.length) }
    raise '本机身份记录冲突' unless bytes.uniq.length == 1
    { bytes: bytes.first, paths: paths }
  end

  # Cancellation records use unique, bounded staging names. A killed writer
  # may leave a partial staging file, but never a partial canonical record.
  # Retain such orphans; only remove an exact, private two-link commit pair.
  def abandonment_staging_files(path, create: false)
    directory = File.join(@state_dir, 'identity-abandonment-staging')
    if create && !identity_path_exists?(directory)
      Dir.mkdir(directory, 0o700)
      sync_identity_directory(directory)
    end
    return [] unless identity_path_exists?(directory)
    assert_private_directory!(directory)
    names = Dir.children(directory)
    raise '本机取消暂存路径或数量无效' unless names.length <= IDENTITY_RECORD_LIMIT && names.all? { |name| name.match?(/\A[0-9a-f]{64}-[0-9a-f]{16}\z/) }
    names.each do |name|
      stat = File.lstat(File.join(directory, name))
      raise '本机取消暂存记录不安全' unless stat.file? && stat.uid == Process.uid && (stat.mode & 0o077).zero? && stat.nlink.between?(1, 2) && stat.size <= 16_384
    end
    prefix = Digest::SHA256.hexdigest(path) + '-'
    names.select { |name| name.start_with?(prefix) }.map { |name| File.join(directory, name) }
  end

  def read_abandonment_record(path)
    stages = abandonment_staging_files(path)
    return nil unless identity_path_exists?(path)
    stat = File.lstat(path)
    links = stages.select do |stage|
      candidate = File.lstat(stage)
      [candidate.dev, candidate.ino] == [stat.dev, stat.ino]
    end
    raise '本机取消暂存包含未知链接' if stages.any? { |stage| File.lstat(stage).nlink != 1 && !links.include?(stage) }
    raise '本机取消提交链接冲突' unless (stat.nlink == 1 && links.empty?) || (stat.nlink == 2 && links.length == 1)
    bytes = read_private_identity_file(path, links: stat.nlink)
    links.each { |stage| raise '本机取消提交字节冲突' unless read_private_identity_file(stage, links: 2) == bytes }
    { bytes: bytes, stages: links }
  end

  def write_abandonment_record_once(path, content)
    assert_private_directory!(File.dirname(path))
    raise '本机取消记录超限' unless content.bytesize <= 16_384
    record = read_abandonment_record(path)
    if record
      raise '本机取消记录已存在且不匹配' unless record[:bytes] == content
      record[:stages].each do |stage|
        # Recheck inode, owner, permissions and bytes immediately before unlink.
        actual = read_abandonment_record(path)
        raise '本机取消暂存链接已变化' unless actual[:bytes] == content && actual[:stages] == [stage]
        File.unlink(stage)
        sync_identity_directory(stage)
      end
      return
    end
    stages = abandonment_staging_files(path, create: true)
    stage = stages.find { |candidate| read_private_identity_file(candidate) == content }
    unless stage
      directory = File.join(@state_dir, 'identity-abandonment-staging')
      raise '本机取消暂存已达上限，原资料保留' if Dir.children(directory).length >= IDENTITY_RECORD_LIMIT
      stage = File.join(directory, Digest::SHA256.hexdigest(path) + '-' + SecureRandom.hex(8))
      File.open(stage, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |file|
        file.write(content)
        file.flush
        file.fsync
      end
      sync_identity_directory(stage)
    end
    raise '本机取消暂存读回失败' unless read_private_identity_file(stage) == content
    File.link(stage, path)
    sync_identity_directory(path)
    write_abandonment_record_once(path, content)
    raise '本机取消提交读回失败' unless read_private_identity_file(path) == content
  end

  def identity_abandonment_archive(hash, create: false)
    raise '放弃安装摘要无效' unless hash.to_s.match?(/\A[0-9a-f]{64}\z/)
    root = File.join(@state_dir, 'retired-installations')
    if create && !identity_path_exists?(root)
      Dir.mkdir(root, 0o700)
      sync_identity_directory(root)
    end
    assert_private_directory!(root)
    entries = Dir.children(root)
    raise '本机安装归档数量或路径无效' unless entries.length <= IDENTITY_RECORD_LIMIT && entries.all? { |entry| entry.match?(/\A[0-9a-f]{64}\z/) }
    path = File.join(root, hash)
    if create && !identity_path_exists?(path)
      raise '本机安装归档已达上限，未删除旧资料' if entries.length >= IDENTITY_RECORD_LIMIT
      Dir.mkdir(path, 0o700)
      sync_identity_directory(path)
    end
    assert_private_directory!(path)
    allowed = ABANDON_SOURCE_ARCHIVES.values + %w[plan.json completed.json]
    names = Dir.children(path)
    raise '本机安装归档包含未知记录' unless names.length <= allowed.length && names.all? { |name| allowed.include?(name) }
    names.each { |name| read_abandonment_record(File.join(path, name)) }
    path
  end

  def valid_installation_metadata?(value)
    value.is_a?(Hash) && value['schema'] == 1 && %w[account_fingerprint template_sha256].all? { |key| value[key].to_s.match?(/\A[0-9a-f]{64}\z/) } &&
      value['device_id'].to_s.match?(/\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/i) && valid_account_public_key?(value['public_key'])
  end

  def validate_abandonment_plan!(plan)
    raise '放弃安装记录无效' unless valid_installation_metadata?(plan) && plan['metadata_sha256'].to_s.match?(/\A[0-9a-f]{64}\z/) &&
      plan['cancelled_by_fingerprint'].to_s.match?(/\A[0-9a-f]{64}\z/) && plan['artifacts'].is_a?(Array) && plan['artifacts'].length.between?(1, 3)
    artifacts = plan['artifacts']
    raise '放弃安装路径无效' unless artifacts.map { |item| item['source'] }.uniq.length == artifacts.length &&
      artifacts.any? { |item| item['source'].start_with?('identity-installation.json') } && artifacts.all? do |item|
        item.is_a?(Hash) && ABANDON_SOURCE_ARCHIVES[item['source']] == item['archive'] && item['sha256'].to_s.match?(/\A[0-9a-f]{64}\z/) &&
          %w[dev ino size links].all? { |key| item[key].is_a?(Integer) && item[key] >= 0 } && item['size'] <= 16_384 && item['links'].between?(1, 2)
      end
    plan
  end

  def active_identity_abandonment
    record = read_abandonment_record(File.join(@state_dir, 'identity-abandonment.json'))
    return nil unless record
    plan = validate_abandonment_plan!(JSON.parse(record[:bytes]))
    { plan: plan, bytes: record[:bytes] }
  end

  def capture_identity_abandonment
    record = read_identity_pair(File.join(@state_dir, 'identity-installation.json'))
    return nil unless record
    metadata = JSON.parse(record[:bytes])
    raise '未完成安装记录无效' unless valid_installation_metadata?(metadata)
    paths = record[:paths]
    pending = File.join(@state_dir, 'wireguard-template.json.pending')
    if identity_path_exists?(pending)
      bytes = read_private_identity_file(pending)
      candidate = JSON.parse(bytes)
      raise '待安装密钥与原记录不匹配，未清理' unless Digest::SHA256.hexdigest(bytes) == metadata['template_sha256'] &&
        candidate.is_a?(Hash) && template_public_key(candidate.fetch('private-key')) == metadata['public_key']
      paths << pending
    end
    artifacts = paths.map do |path|
      stat = File.lstat(path)
      bytes = read_private_identity_file(path, links: stat.nlink)
      name = File.basename(path)
      { 'source' => name, 'archive' => ABANDON_SOURCE_ARCHIVES.fetch(name), 'sha256' => Digest::SHA256.hexdigest(bytes),
        'dev' => stat.dev, 'ino' => stat.ino, 'size' => stat.size, 'links' => stat.nlink }
    end
    plan = metadata.merge('metadata_sha256' => Digest::SHA256.hexdigest(record[:bytes]),
      'cancelled_by_fingerprint' => @account_number ? Digest::SHA256.hexdigest(@account_number) : ('0' * 64), 'artifacts' => artifacts)
    { plan: validate_abandonment_plan!(plan), bytes: JSON.generate(plan) }
  end

  def verify_abandonment_archives!(plan, plan_bytes)
    directory = identity_abandonment_archive(plan.fetch('metadata_sha256'))
    stored = read_abandonment_record(File.join(directory, 'plan.json'))
    raise '安装归档计划未确认' unless stored && stored[:bytes] == plan_bytes
    plan['artifacts'].each do |item|
      record = read_abandonment_record(File.join(directory, item.fetch('archive')))
      raise '安装归档读回不匹配' unless record && record[:bytes].bytesize == item['size'] && Digest::SHA256.hexdigest(record[:bytes]) == item['sha256']
    end
    directory
  end

  def assert_identity_abandonment_idle!
    raise AccountError.new('identity_exists', '已有已提交模板，不能放弃或清理身份') if @template || identity_path_exists?(template_path)
    unless @account_only_mode && !@stop_requested && @front_pid.nil? && @workers.empty? && @state[:workers].empty? && @state[:active_slot].nil? && !action_pending?
      raise AccountError.new('engine_running', '只能在无模板、无网络引擎的首次设置状态放弃安装')
    end
    assert_private_directory!(@state_dir)
  end

  def check_abandonment_sources!(plan)
    assert_identity_abandonment_idle!
    expected = plan['artifacts'].map { |item| item['source'] }
    ABANDON_SOURCE_ARCHIVES.each_key do |name|
      raise '安装占位出现未知新记录，未清理' if identity_path_exists?(File.join(@state_dir, name)) && !expected.include?(name)
    end
    plan['artifacts'].each do |item|
      path = File.join(@state_dir, item['source'])
      next unless identity_path_exists?(path)
      remaining_links = plan['artifacts'].count { |other| other['dev'] == item['dev'] && other['ino'] == item['ino'] && identity_path_exists?(File.join(@state_dir, other['source'])) }
      stat = File.lstat(path)
      raise '安装占位已变化，未清理' unless [stat.dev, stat.ino, stat.size, stat.nlink] == [item['dev'], item['ino'], item['size'], remaining_links]
      raise '安装占位字节已变化，未清理' unless Digest::SHA256.hexdigest(read_private_identity_file(path, links: remaining_links)) == item['sha256']
    end
  end

  def abandonment_completion_bytes(plan, plan_bytes)
    JSON.generate(schema: 1, account_fingerprint: plan['account_fingerprint'], device_id: plan['device_id'], public_key: plan['public_key'],
      metadata_sha256: plan['metadata_sha256'], plan_sha256: Digest::SHA256.hexdigest(plan_bytes))
  end

  def abandonment_index_path(binding, pubkey, create: false)
    root = File.join(@state_dir, 'abandoned-device-drafts')
    directory = File.join(root, binding)
    [root, directory].each do |path|
      if create && !identity_path_exists?(path)
        parent = File.dirname(path)
        raise '本机放弃回执已达上限' if path == directory && Dir.children(parent).length >= IDENTITY_RECORD_LIMIT
        Dir.mkdir(path, 0o700)
        sync_identity_directory(path)
      end
      return nil unless identity_path_exists?(path)
      assert_private_directory!(path)
      names = Dir.children(path)
      allowed = path == root ? names.all? { |name| name.match?(/\A[0-9a-f]{64}\z/) } : names.all? { |name| name.match?(/\A[0-9a-f]{64}\.json\z/) }
      raise '本机放弃回执路径或数量无效' unless allowed && names.length <= IDENTITY_RECORD_LIMIT
    end
    destination = File.join(directory, Digest::SHA256.hexdigest(pubkey) + '.json')
    if create && !identity_path_exists?(destination) && Dir.children(directory).length >= IDENTITY_RECORD_LIMIT
      raise '本机放弃回执数量超限，未清理原安装记录'
    end
    destination
  end

  def verified_abandonment_receipt(binding, pubkey, device_id)
    path = abandonment_index_path(binding, pubkey)
    record = path && read_abandonment_record(path)
    active = active_identity_abandonment
    if !record && active && active[:plan].values_at('account_fingerprint', 'public_key', 'device_id') == [binding, pubkey, device_id]
      directory = identity_abandonment_archive(active[:plan]['metadata_sha256'])
      record = read_abandonment_record(File.join(directory, 'completed.json'))
    end
    return nil unless record
    completion = JSON.parse(record[:bytes])
    raise '放弃安装回执绑定无效' unless completion.values_at('schema', 'account_fingerprint', 'public_key', 'device_id') == [1, binding, pubkey, device_id]
    directory = identity_abandonment_archive(completion['metadata_sha256'])
    stored = read_abandonment_record(File.join(directory, 'plan.json'))
    raise '放弃安装计划缺失' unless stored
    plan = validate_abandonment_plan!(JSON.parse(stored[:bytes]))
    verify_abandonment_archives!(plan, stored[:bytes])
    expected = abandonment_completion_bytes(plan, stored[:bytes])
    completed = read_abandonment_record(File.join(directory, 'completed.json'))
    raise '放弃安装完成回执不一致' unless completed && completed[:bytes] == expected && record[:bytes] == expected
    { account_fingerprint: binding, device_id: device_id, public_key: pubkey, metadata_sha256: completion['metadata_sha256'], receipt_sha256: Digest::SHA256.hexdigest(expected) }
  end

  def pending_identity_installation
    return nil if @template || identity_path_exists?(template_path)
    record = active_identity_abandonment || capture_identity_abandonment
    return nil unless record
    plan = record[:plan]
    proof = verified_abandonment_receipt(plan['account_fingerprint'], plan['public_key'], plan['device_id'])
    { account_fingerprint: plan['account_fingerprint'], device_id: plan['device_id'], public_key: plan['public_key'],
      metadata_sha256: plan['metadata_sha256'], has_pending_template: plan['artifacts'].any? { |item| item['source'] == 'wireguard-template.json.pending' },
      cancellation_pending: !active_identity_abandonment.nil?,
      cancellation_complete: proof && proof[:metadata_sha256] == plan['metadata_sha256'] ? true : false }
  end

  def abandon_identity_installation(payload)
    verify_account_binding!(payload)
    raise AccountError.new('confirmation_required', '请确认仅放弃本机未完成安装；官方设备和密钥不会撤销') unless payload['confirm'] == true
    raise AccountError.new('identity_busy', '连接操作尚未结束') unless @switch_mutex.try_lock
    begin
      assert_identity_abandonment_idle!
      current = active_identity_abandonment || capture_identity_abandonment
      unless current
        directory = identity_abandonment_archive(payload['expected_metadata_sha256'])
        stored = read_abandonment_record(File.join(directory, 'plan.json'))
        plan = stored && validate_abandonment_plan!(JSON.parse(stored[:bytes]))
        if plan && plan['account_fingerprint'] == payload['expected_installation_account_fingerprint'] &&
            verified_abandonment_receipt(plan['account_fingerprint'], plan['public_key'], plan['device_id'])
          return account_snapshot
        end
        raise AccountError.new('no_pending_installation', '没有可放弃的未完成安装')
      end
      plan = current[:plan]
      unless plan['metadata_sha256'] == payload['expected_metadata_sha256'] && plan['account_fingerprint'] == payload['expected_installation_account_fingerprint']
        raise AccountError.new('installation_changed', '未完成安装已变化；请刷新后重新确认')
      end
      reserve_identity_install_ports do
        assert_identity_abandonment_idle!
        directory = identity_abandonment_archive(plan['metadata_sha256'], create: true)
        index = abandonment_index_path(plan['account_fingerprint'], plan['public_key'], create: true)
        existing = read_abandonment_record(File.join(directory, 'plan.json'))
        if existing
          archived = validate_abandonment_plan!(JSON.parse(existing[:bytes]))
          raise '原安装归档与占位不匹配' unless archived.reject { |key, _| key == 'cancelled_by_fingerprint' } == plan.reject { |key, _| key == 'cancelled_by_fingerprint' }
          plan, current = archived, { plan: archived, bytes: existing[:bytes] }
        end
        unless active_identity_abandonment
          plan['artifacts'].each do |item|
            path = File.join(@state_dir, item['source'])
            bytes = read_private_identity_file(path, links: File.lstat(path).nlink)
            raise '待归档安装字节已变化' unless Digest::SHA256.hexdigest(bytes) == item['sha256']
            write_abandonment_record_once(File.join(directory, item['archive']), bytes)
          end
          write_abandonment_record_once(File.join(directory, 'plan.json'), current[:bytes])
        end
        verify_abandonment_archives!(plan, current[:bytes])
        write_abandonment_record_once(File.join(@state_dir, 'identity-abandonment.json'), current[:bytes])
        check_abandonment_sources!(plan)
        plan['artifacts'].sort_by { |item| item['source'].end_with?('.pending') ? 0 : 1 }.each do |item|
          check_abandonment_sources!(plan)
          path = File.join(@state_dir, item['source'])
          next unless identity_path_exists?(path)
          File.unlink(path)
          sync_identity_directory(path)
        end
        check_abandonment_sources!(plan)
        completion = abandonment_completion_bytes(plan, current[:bytes])
        write_abandonment_record_once(File.join(directory, 'completed.json'), completion)
        write_abandonment_record_once(index, completion)
        verified_abandonment_receipt(plan['account_fingerprint'], plan['public_key'], plan['device_id']) || raise('放弃安装完成记录未确认')
        assert_identity_abandonment_idle!
        journal = File.join(@state_dir, 'identity-abandonment.json')
        raise '取消记录发生变化' unless read_private_identity_file(journal) == current[:bytes]
        File.unlink(journal)
        sync_identity_directory(journal)
      end
      account_snapshot
    ensure
      @switch_mutex.unlock
    end
  rescue AccountError
    raise
  rescue StandardError
    raise AccountError.new('identity_abandonment_unknown', '放弃安装未确认完成；原密钥和记录保留。请只读刷新核对，不要重复注册设备')
  end

  def install_first_identity(payload)
    verify_account_binding!(payload)
    raise AccountError.new('confirmation_required', '请确认首次安装本机身份') unless payload['confirm'] == true
    raise AccountError.new('identity_busy', '连接操作尚未结束，未修改身份') unless @switch_mutex.try_lock
    begin
      assert_private_directory!(@state_dir)
      raise AccountError.new('identity_abandonment_pending', '放弃安装尚未收尾，请先完成原取消事务') if active_identity_abandonment
      if @template && template_public_key != payload['public_key']
        raise AccountError.new('identity_replacement_unsupported', '现有身份不能在此替换；已保留当前模板')
      end
      unless @template || (@account_only_mode && !@stop_requested && @front_pid.nil? && @workers.empty? && @state[:workers].empty? && @state[:active_slot].nil? && !action_pending?)
        raise AccountError.new('engine_running', '必须在无现有身份且无引擎运行的首次设置状态安装')
      end
      binding, pubkey = payload['account_fingerprint'], payload['public_key']
      official = valid_account_public_key?(pubkey) && registration_receipt(binding, pubkey)
      unless official && %w[id pubkey ipv4_address ipv6_address].all? { |key| official[key] == payload[{ 'id' => 'device_id', 'pubkey' => 'public_key' }.fetch(key, key)] }
        raise AccountError.new('registration_receipt_required', '缺少匹配账号、设备、公钥与官方地址的本机登记回执；未安装身份')
      end
      if verified_abandonment_receipt(binding, pubkey, official['id'])
        raise AccountError.new('identity_abandoned', '此旧安装已安全放弃，不能自动恢复；请显式创建新本机设备')
      end
      key = payload['private_key'].to_s
      begin
        private_bytes = Base64.strict_decode64(key)
        raise ArgumentError unless private_bytes.bytesize == 32 && Base64.strict_encode64(private_bytes) == key
      rescue ArgumentError
        raise AccountError.new('invalid_key', '本机私钥格式无效')
      end
      raise AccountError.new('invalid_key', '本机密钥与官方登记公钥不匹配') unless template_public_key(key) == pubkey
      @account_data = account_refresh
      unless @account_data[:devices].count { |device| device['id'] == official['id'] && device['pubkey'] == pubkey } == 1
        raise AccountError.new('registered_device_missing', '官方列表未唯一确认此设备归属；未安装身份')
      end
      template = { 'private-key' => key, 'ip' => official['ipv4_address'].sub(%r{/32\z}, ''),
        'ipv6' => official['ipv6_address'].sub(%r{/128\z}, ''), 'allowed-ips' => ['0.0.0.0/0', '::/0'], 'udp' => true }
      bytes = JSON.generate(template)
      installation = JSON.generate(schema: 1, account_fingerprint: binding, device_id: official['id'], public_key: pubkey, template_sha256: Digest::SHA256.hexdigest(bytes))
      if @template
        unless @template == template && read_private_identity_file(template_path) == bytes &&
            read_private_identity_file(File.join(@state_dir, 'identity-installation.json')) == installation
          raise AccountError.new('identity_replacement_unsupported', '现有模板与已确认安装记录不一致，未覆盖身份')
        end
        return account_snapshot
      end
      if File.exist?(template_path) || File.symlink?(template_path)
        recover_private_identity_link(template_path)
        unless read_private_identity_file(template_path) == bytes
          raise AccountError.new('identity_replacement_unsupported', '模板路径已有不同身份，未覆盖原文件')
        end
      end
      reserve_identity_install_ports do
        write_private_identity_once(File.join(@state_dir, 'bootstrap-defaults.json'), JSON.generate(schema: 1, source: @bootstrap_defaults_source))
        write_private_identity_once(File.join(@state_dir, 'identity-installation.json'), installation)
        write_private_identity_once(template_path, bytes)
      end
      @template = template
      @first_identity_installed = true
      @state[:status] = @state[:service_readiness] = 'identity_configured'
      @state[:last_error] = nil
      @account_only_mode = false
      account_snapshot
    ensure
      @switch_mutex.unlock
    end
  rescue AccountError
    raise
  rescue StandardError
    raise AccountError.new('identity_install_unknown', '身份安装未确认完成；已保留本机记录。请刷新状态核对，不要更换密钥或覆盖模板')
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
    pubkey = @template ? template_public_key : ''
    data = @account_data || {}
    devices = Array(data[:devices]).map do |device|
      { id: device['id'], name: device['name'], pubkey: device['pubkey'], created: device['created'],
        current: !pubkey.empty? && device['pubkey'] == pubkey }
    end
    { signed_in: !@account_number.nil?, verified: !@account_data.nil?,
      account_suffix: @account_number&.slice(-4, 4), expiry: data[:expiry],
      checked_at: data[:checked_at], public_key: pubkey,
      device_match: pubkey.empty? ? 'unconfigured' : (@account_data.nil? ? 'unknown' : (devices.any? { |d| d[:current] } ? 'matched' : 'unmatched')),
      devices: devices, account_fingerprint: @account_number && Digest::SHA256.hexdigest(@account_number),
      identity_configured: !pubkey.empty?, api_route: @options[:bootstrap_proxy].to_s.empty? ? 'system_https' : 'configured_proxy',
      api_route_source: @api_route_source, device_source: @account_data ? 'official_api' : 'not_verified',
      identity_abandonment_supported: true, pending_identity_installation: pending_identity_installation }.merge(installed_draft_match(pubkey, devices))
  end

  def verify_account_binding!(payload)
    raise AccountError.new('not_signed_in', '请先登录账号') unless @account_number
    expected = Digest::SHA256.hexdigest(@account_number)
    unless payload['account_fingerprint'] == expected
      raise AccountError.new('account_changed', '账号已变化或客户端未绑定账号；请刷新后重新确认操作')
    end
  end

  def valid_account_public_key?(key)
    return false unless key.is_a?(String)
    bytes = Base64.strict_decode64(key)
    bytes.bytesize == 32 && Base64.strict_encode64(bytes) == key && bytes.bytes.any? { |b| b != 0 }
  rescue ArgumentError
    false
  end

  def account_refresh(number = @account_number)
    raise AccountError.new('not_signed_in', '请先输入 Mullvad 账号') unless number
    account = account_api('GET', 'accounts/v1/accounts/me', number: number)
    devices = account_api('GET', 'accounts/v1/devices', number: number)
    unless account.is_a?(Hash) && account['expiry'].is_a?(String) && devices.is_a?(Array) && devices.length <= 64 &&
           devices.all? { |d| d.is_a?(Hash) && d['id'].to_s.match?(/\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/i) &&
             d['name'].is_a?(String) && !d['name'].empty? && d['name'].bytesize <= 256 && !d['name'].match?(/[[:cntrl:]]/) &&
             valid_account_public_key?(d['pubkey']) } && devices.map { |d| d['id'] }.uniq.length == devices.length &&
           devices.map { |d| d['pubkey'] }.uniq.length == devices.length
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
        verify_account_binding!(payload)
        account_path = File.join(@state_dir, 'account.json')
        File.unlink(account_path) if File.exist?(account_path)
        @account_number = @account_data = @account_token = nil
        respond(sock, 200, account_snapshot)
      when ['POST', '/account/identity/install']
        respond(sock, 200, install_first_identity(payload))
      when ['POST', '/account/identity/abandon']
        respond(sock, 200, abandon_identity_installation(payload))
      when ['POST', '/account/identity/abandonment-status']
        verify_account_binding!(payload)
        pubkey, id = payload['public_key'], payload['device_id']
        installation_binding = payload['installation_account_fingerprint'] || payload['account_fingerprint']
        raise AccountError.new('invalid_account', '原安装账号绑定无效') unless installation_binding.to_s.match?(/\A[0-9a-f]{64}\z/)
        raise AccountError.new('invalid_key', '公钥无效') unless valid_account_public_key?(pubkey)
        raise AccountError.new('invalid_device', '设备ID无效') unless id.to_s.match?(/\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/i)
        receipt = verified_abandonment_receipt(installation_binding, pubkey, id)
        if receipt && payload['expected_metadata_sha256'] && receipt[:metadata_sha256] != payload['expected_metadata_sha256']
          raise AccountError.new('installation_changed', '原安装回执已变化')
        end
        respond(sock, 200, { receipt: receipt })
      when ['POST', '/account/key']
        raise AccountError.new('confirmation_required', '请主动确认查看本机私钥') unless payload['reveal'] == true
        raise AccountError.new('identity_not_configured', '尚未安装隧道身份；新设备密钥保存在本机钥匙串') unless @template
        respond(sock, 200, { private_key: @template.fetch('private-key') })
      when ['POST', '/account/devices/reconcile']
        verify_account_binding!(payload)
        pubkey = payload['public_key']
        raise AccountError.new('invalid_key', '公钥格式无效') unless valid_account_public_key?(pubkey)
        @account_data = account_refresh
        device = account_snapshot[:devices].find { |d| d[:pubkey] == pubkey }
        unless device
          raise AccountError.new('draft_not_found', '官方列表尚未找到本机待注册公钥；密钥保留，未重复注册。请稍后再次核对')
        end
        # Listing proves registration only. It does not invent assigned tunnel
        # addresses or install this identity into the running template.
        saved = registration_receipt(payload['account_fingerprint'], pubkey)
        device = device.merge(registration: saved) if saved && saved['id'] == device[:id]
        respond(sock, 200, device)
      when ['POST', '/account/devices/create']
        raise AccountError.new('confirmation_required', '请确认创建本机设备') unless payload['confirm'] == true
        verify_account_binding!(payload)
        pubkey = payload['public_key'].to_s
        raise AccountError.new('invalid_key', '公钥格式无效，未提交注册') unless valid_account_public_key?(pubkey)
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
          safe_device = save_registration_receipt(device)
          @account_data = nil
          respond(sock, 200, safe_device)
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
        verify_account_binding!(payload)
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
        verify_account_binding!(payload)
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
    start_status_publisher
    Thread.new do
      loop do
        break if @stop_requested
        begin
          client = @server.accept
          accepted_at = monotonic_now
          Thread.new(client, accepted_at) { |sock, accepted| handle_http(sock, accepted) }
        rescue IOError, Errno::EBADF
          break
        rescue StandardError => e
          record_error("api accept error: #{e.class}: #{e.message}")
        end
      end
    end
  end

  def handle_http(sock, accepted_at = monotonic_now)
    handler_started = monotonic_now
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
    if @account_only_mode && method == 'POST' && path != '/metadata/refresh'
      respond(sock, 409, { code: 'identity_not_configured', error: '隧道尚未初始化；当前仅开放账号与设备管理，未启动网络引擎' })
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
      request_id = headers['x-adapter-request-id'].to_s
      request_id = nil unless request_id.match?(/\A[0-9a-fA-F-]{36}\z/)
      timing = { request_id: request_id, dispatch_ms: ((handler_started - accepted_at) * 1000).round,
                 request_read_ms: ((monotonic_now - handler_started) * 1000).round }
      log_probe_event('status-request-received', timing)
      status_started = monotonic_now
      begin
        respond_status(sock, timing: timing)
      ensure
        log_probe_event('status-request-finished', timing.merge(response_ms: ((monotonic_now - status_started) * 1000).round))
      end
    when ['GET', '/metrics']
      respond(sock, 200, @mutex.synchronize { @metrics.dup })
    when ['GET', '/metadata']
      respond(sock, 200, @mutex.synchronize { @state[:metadata].dup })
    when ['POST', '/metadata/refresh']
      respond(sock, 202, request_metadata_refresh)
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
    when ['POST', '/recovery']
      command = parse_json_body(body)['action'].to_s
      raise ArgumentError, 'unsupported recovery action' unless %w[retry-current retry-round stop].include?(command)
      if command == 'stop'
        interrupt_ordered_recovery(stopped: true)
        respond(sock, 202, { ok: true })
      else
        relay = @mutex.synchronize { @state[:active_relay] } || load_persisted_relay
        raise ArgumentError, '请先选择节点' if relay.to_s.empty?
        accepted_async(sock, relay, command)
      end
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
  rescue LocalProbeTimeout => e
    log_probe_event('local-status-write-timeout', phase: e.phase)
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
    admission_epoch = @mutex.synchronize { @recovery_control_epoch }
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

    preserve_stop = %w[diagnose speedtest].include?(reason) && @mutex.synchronize { @recovery_stopped }
    recovery_ticket = interrupt_ordered_recovery(stopped: preserve_stop, expected_epoch: admission_epoch)
    record_routing_event('action-accepted', relay: relay, reason: reason)
    Thread.new do
      Thread.current[:adapter_operation_id] = id
      Thread.current[:adapter_recovery_request_epoch] = recovery_ticket
      begin
        unless recovery_ticket
          update_operation(state: 'cancelled', stage: 'finished', message: '请求已被较新的停止操作取消', finished_at: Time.now.iso8601)
          next
        end
        update_operation(state: 'running')
        action_evidence = {}
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
             when 'retry-current', 'retry-round'
               run_ordered_recovery(relay, reason: reason, current_only: reason == 'retry-current', manual: true)
             when 'repair'
               repair_connection
             when 'protection-change'
               activate(relay, reason: reason, transport_preference: preference, protection_profile: profile,
                        attempt_evidence: action_evidence)
             when 'city-select'
               activate_city(find_relay(relay)['location'], preference)
             else
               activate(relay, reason: reason, transport_preference: preference, attempt_evidence: action_evidence)
             end
        recovered = false
        if !ok && reason == 'reconnect' && !action_evidence[:local_failure] && snapshot[:active_slot].nil?
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
                  elsif reason != 'speedtest' && current[:active_slot] && current[:relay_liveness] == 'pass' &&
                        !current.dig(:local_network, :paused) && !current.dig(:local_network, :recovery_pending)
                    'preserved'
                  else
                    'failed'
                  end
        messages = {
          'succeeded' => reason == 'speedtest' ? '测速完成' : '检查 / 操作完成',
          'recovered' => "原节点未能恢复，已自动连接 #{current[:active_relay]}",
          'cancelled' => reason == 'speedtest' ? '测速已停止，当前连接保持原样' : '恢复已停止，当前通道保留',
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
        Thread.current[:adapter_recovery_request_epoch] = nil
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
      log_probe_event('operation-finished', values.merge(id: id))
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
    writer = event == 'action-accepted' ? :log_probe_event : :log_event
    send(writer, event, relay: relay, reason: reason, detail: detail, connections: connections)
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
    entry = { at: Time.now.iso8601, event: event, build: BUILD_ID, source_sha256: SOURCE_SHA256 }.merge(trace).merge(redact_log(fields))
    line = JSON.generate(entry) + "\n"
    if line.bytesize > EVENT_LOG_FILE_BYTES
      line = JSON.generate(at: entry[:at], event: 'oversized-event', build: BUILD_ID, source_sha256: SOURCE_SHA256,
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

  # Deadline handling and child cleanup must never wait for the log file or
  # its mutex. One writer drains a bounded queue; a slow disk cannot create
  # unbounded threads or buffers. Preserve observation time across that wait.
  def log_probe_event(event, fields = {})
    trace = { operation_id: Thread.current[:adapter_operation_id],
              recovery_id: Thread.current[:adapter_recovery_id], attempt_id: Thread.current[:adapter_attempt_id] }.compact
    entry = trace.merge(fields).merge(at: Time.now.iso8601)
    @probe_event_mutex.synchronize do
      if @probe_events.length >= 128
        @probe_events.shift
        @probe_events_dropped += 1
      end
      @probe_events << [event, entry]
      unless @probe_event_writer&.alive?
        @probe_event_writer = Thread.new do
          Thread.current.name = 'adapter-probe-events'
          loop do
            item = @probe_event_mutex.synchronize do
              if @probe_events.empty?
                @probe_event_writer = nil
                nil
              else
                name, values = @probe_events.shift
                dropped = @probe_events_dropped
                @probe_events_dropped = 0
                [name, dropped.positive? ? values.merge(dropped_probe_events: dropped) : values]
              end
            end
            break unless item
            log_event(*item)
          end
        end
      end
    end
    nil
  rescue StandardError
    # Diagnostics are best effort even when the OS cannot create a writer
    # thread. Never replace a probe timeout/cancellation with a logging error.
    nil
  end

  def parse_json_body(body)
    parsed = body.to_s.empty? ? {} : JSON.parse(body)
    raise ArgumentError, 'JSON object required' unless parsed.is_a?(Hash)
    parsed
  end

  def respond(sock, code, object)
    respond_json(sock, code, JSON.generate(object))
  end

  def respond_json(sock, code, payload, headers: {})
    text = { 200 => 'OK', 202 => 'Accepted', 400 => 'Bad Request', 403 => 'Forbidden', 404 => 'Not Found', 409 => 'Conflict', 500 => 'Internal Server Error', 503 => 'Service Unavailable' }.fetch(code, 'OK')
    sock.write("HTTP/1.1 #{code} #{text}\r\n")
    sock.write("Content-Type: application/json; charset=utf-8\r\n")
    sock.write("Cache-Control: no-store\r\n")
    headers.each { |name, value| sock.write("#{name}: #{value}\r\n") }
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

  # The public read path only consumes an immutable publication. In particular,
  # it must not queue behind a profile commit, history work, or operation lock.
  # Internal control decisions continue using the authoritative snapshot below.
  def respond_status(sock, timing: {})
    Timeout.timeout(1, LocalProbeTimeout, 'status-response') do
      write_status_publication(sock, timing)
    end
  end

  def write_status_publication(sock, timing)
    publication = @status_publication
    unless publication
      return respond(sock, 503, { code: 'status_snapshot_unavailable', error: '本机状态尚未发布' })
    end
    age_ms = [(monotonic_now - publication[:captured_at]) * 1000, 0].max.round
    headers = { 'X-Adapter-Status-Age-Ms' => age_ms,
                'X-Adapter-Status-Capture-Ms' => publication[:capture_ms],
                'X-Adapter-Dispatch-Ms' => timing.fetch(:dispatch_ms, 0),
                'X-Adapter-Request-Read-Ms' => timing.fetch(:request_read_ms, 0) }
    headers['X-Adapter-Request-Id'] = timing[:request_id] if timing[:request_id]
    if age_ms > (STATUS_PUBLICATION_MAX_AGE * 1000).to_i
      body = { code: 'status_snapshot_stale', error: '本机服务仍能响应，状态发布暂缓', snapshot_age_ms: age_ms }
      return respond_json(sock, 503, JSON.generate(body), headers: headers)
    end
    respond_json(sock, 200, publication[:json], headers: headers)
  end

  def start_status_publisher
    return if @status_publisher&.alive?
    @status_publisher = Thread.new do
      Thread.current.name = 'adapter-status-publication'
      previous_tick = monotonic_now
      until @stop_requested
        previous_tick = publish_status_tick(previous_tick)
        sleep STATUS_PUBLICATION_INTERVAL
      end
    end
  end

  def publish_status_tick(previous_tick)
    published = publish_status_snapshot
    now = monotonic_now
    publication = @status_publication
    age = publication && now - publication[:captured_at]
    delayed = now - previous_tick > STATUS_PUBLICATION_MAX_AGE
    stale = !published && (!age || age > STATUS_PUBLICATION_MAX_AGE)
    if (delayed || stale) && (!@last_status_delay_event || now - @last_status_delay_event >= 30)
      @last_status_delay_event = now
      log_probe_event('status-publication-delayed',
                      reason: stale ? @status_publication_defer_reason || 'publisher_busy' : 'loop_delayed',
                      interval_ms: ((now - previous_tick) * 1000).round,
                      snapshot_age_ms: age && (age * 1000).round)
    end
    now
  end

  def publish_status_snapshot
    return false unless @status_publish_gate.try_lock
    begin
      started = monotonic_now
      unless @mutex.try_lock
        @status_publication_defer_reason = 'state_busy'
        return false
      end
      begin
        # Capture time precedes the copy, so serialisation/scheduling delay is
        # included in the reported age rather than resetting freshness later.
        captured_at = monotonic_now
        copy = Marshal.load(Marshal.dump(@state))
        now = Time.now
        quarantine = @recovery_quarantine.filter_map do |name, entry|
          next if entry[:until] <= now
          { relay: name, reason: entry[:reason], remaining_seconds: [(entry[:until] - now).ceil, 0].max }
        end
        copy[:routing_policy][:quarantined_relays] = Marshal.load(Marshal.dump(quarantine))
      ensure
        @mutex.unlock
      end
      unless @action_gate_mutex.try_lock
        @status_publication_defer_reason = 'action_busy'
        return false
      end
      begin
        pending = @action_pending
        latest = pending ? @operations[pending[:id]] : @operations.values.last
        copy[:routing_policy][:pending_action] = pending && Marshal.load(Marshal.dump(pending))
        copy[:operation] = latest && Marshal.load(Marshal.dump(latest))
      ensure
        @action_gate_mutex.unlock
      end
      decorate_status_snapshot(copy)
      json = JSON.generate(copy).freeze
      @status_publication = { json: json, captured_at: captured_at,
                              capture_ms: [(monotonic_now - started) * 1000, 0].max.round }.freeze
      @status_publication_defer_reason = nil
      true
    rescue StandardError
      # Never publish partial state, renew its age on error, or do disk/network
      # logging here. Age/error response remains available without these locks.
      @status_publication_defer_reason = 'capture_error'
      false
    ensure
      @status_publish_gate.unlock
    end
  end

  def decorate_status_snapshot(copy)
    decorate_recovery_snapshot(copy)
    if copy.dig(:local_network, :paused)
      copy[:status] = copy[:service_readiness] = 'waiting_network'
      copy[:relay_liveness] = 'unknown'
    elsif copy.dig(:local_network, :recovery_pending)
      copy[:status] = copy[:service_readiness] = 'network_recovering'
    end
    fetched_at = copy.dig(:metadata, :fetched_at)
    if fetched_at
      begin
        copy[:metadata][:age_seconds] = [Time.now - Time.parse(fetched_at), 0].max.round
      rescue ArgumentError
        copy[:metadata][:age_seconds] = nil
      end
    end
    copy
  end

  def snapshot
    copy = @mutex.synchronize { Marshal.load(Marshal.dump(@state)) }
    decorate_recovery_snapshot(copy)
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
      'secret' => controller_secret(@options[:front_controller]),
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
    write_json_private(path, config, secret: true)
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
    return if @ordered_recovery_mutex.locked? || ordered_recovery_blocked?
    return if local_network_paused? || local_network_recovery_pending?
    ordered = @mutex.synchronize { @state[:recovery][:started_at] }
    return if !ordered && Time.now - @last_disconnected_retry_at < @options[:recovery_cooldown]
    return unless @switch_mutex.try_lock
    begin
      current = @mutex.synchronize { @state.slice(:generation, :active_slot, :active_relay) }
      return if current[:active_slot]
      @last_disconnected_retry_at = Time.now
    ensure
      @switch_mutex.unlock
    end
    relay = current[:active_relay] || load_persisted_relay || @options[:default_relay]
    run_ordered_recovery(relay, reason: 'startup-retry', expected_state: current)
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
          data_probe = front_service_probe(@options[:front_mixed])
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
    rescue LocalProbeTimeout => e
      log_probe_event('front-observation-deferred', phase: e.phase, reason: 'local-probe-timeout-not-front-failure')
      nil
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

  # Background observers do not queue or pile up while another observation is
  # in flight. The lifecycle lock and status publication remain independent.
  def with_background_probe
    acquired = @background_probe_mutex.try_lock
    return :retry unless acquired
    yield
  ensure
    @background_probe_mutex.unlock if acquired
  end

  def supervise_front_data_path(active_slot, active_worker)
    return if action_pending? || @ordered_recovery_mutex.locked?
    with_background_probe { observe_front_data_path(active_slot, active_worker) }
  end

  def observe_front_data_path(active_slot, active_worker)
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
    front_result = front_service_probe(@options[:front_mixed])
    direct_result = front_service_probe(active_worker[:mixed_port]) unless front_result[:status] == 'pass'
    return unless @switch_mutex.try_lock
    begin
      unless active_context_current?(captured, front: true)
        log_event('front-result-discarded', **context, reason: 'active-context-changed')
        return
      end
      if front_result[:status] == 'pass'
        if front_result[:observation] == 'alternate-https' && !@front_target_degraded
          log_event('front-target-degraded', **context, primary_status: front_result[:primary_status],
                    alternate_status: 'pass', decision: 'keep-live-front')
        end
        @front_target_degraded = front_result[:observation] == 'alternate-https'
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
    verification = front_service_probe(@options[:front_mixed])
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
  rescue LocalProbeTimeout => e
    log_probe_event('front-observation-deferred', **(context || {}), phase: e.phase,
              reason: 'local-probe-timeout-not-front-failure')
    nil
  rescue StandardError => e
    log_event('front-repair-error', **(context || {}), incident_id: @front_incident_id, error: "#{e.class}: #{e.message}")
    raise
  end

  def front_service_probe(port)
    primary = curl_proxy_ip_test(port, IP_CANARY, 3)
    return primary if primary[:status] == 'pass'

    alternate = curl_proxy_test(port, HOST_CANARY, 3)
    if alternate[:status] == 'pass'
      alternate.merge(observation: 'alternate-https', primary_status: primary[:status],
                      primary_exit_code: primary[:exit_code])
    else
      primary.merge(alternate: alternate)
    end
  end

  def supervise_worker_runtime
    # Keep the failed worker identity until local recovery owns the rebuild.
    # A dead process during a Wi-Fi outage is not a relay-health observation.
    return if local_network_paused? || local_network_recovery_pending? || @ordered_recovery_mutex.locked? || ordered_recovery_blocked?
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
        @state[:relay_liveness] = 'unknown'
        @state[:service_readiness] = 'data_fail'
        @state[:status] = 'data_fail'
        @state[:last_error] = "active worker-#{slot} exited unexpectedly"
        @state[:updated_at] = Time.now.iso8601
        @metrics[:worker_crash_recoveries] += 1
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
    run_ordered_recovery(recovery[:relay], reason: 'worker-crash-recovery', expected_state: recovery[:expected_state])
  end

  def start_control_plane_monitor
    Thread.new do
      until @stop_requested
        begin
          if local_network_paused?
            sleep 1
            next
          end
          observe_control_plane_once

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

  def observe_control_plane_once
    metadata_state = @mutex.synchronize { @state[:metadata].dup }
    stale = @metadata_fetched_at.nil? || (Time.now - @metadata_fetched_at) >= @options[:metadata_ttl]
    if @metadata.nil? || metadata_state[:live] != true || stale
      return if monotonic_now < (@metadata_background_retry_at || 0)
      begin
        refresh_metadata(force: true, background: true)
      ensure
        live = @mutex.synchronize { @state.dig(:metadata, :live) == true }
        @metadata_background_failures = live ? 0 : (@metadata_background_failures || 0) + 1
        delay = live ? 0 : [30 * (2**[[@metadata_background_failures - 1, 0].max, 4].min), 300].min
        @metadata_background_retry_at = monotonic_now + delay
      end
    else
      return if action_pending? || @ordered_recovery_mutex.locked? || ordered_recovery_blocked?
      with_background_probe { check_clash_global_path }
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
    families = []
    active = names.select do |name|
      section = sections.fetch(name)
      link = section[/^\s*status:\s*(\S+)/, 1]
      ambiguous = true unless %w[active inactive].include?(link)
      next false unless link == 'active' && section.lines.first.match?(/<[^>]*\bUP\b/)
      valid = section.scan(/^\s*inet6?\s+(\S+)/).flatten.filter_map do |address|
        ip = IPAddr.new(address.split('%').first) rescue nil
        next unless ip && !ip.loopback? && !ip.to_i.zero? &&
          !(ip.ipv4? && IPAddr.new('169.254.0.0/16').include?(ip)) &&
          !(ip.ipv6? && IPAddr.new('fe80::/10').include?(ip))
        ip
      end
      families.concat(valid.map { |ip| ip.ipv4? ? 'ipv4' : 'ipv6' })
      !valid.empty?
    end
    return base.merge(status: 'available', active_interfaces: active, address_families: families.uniq, detail: '本机硬件链路已连接并取得地址；不代表互联网或节点已验证') unless active.empty?
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
    interface_change = nil
    @mutex.synchronize do
      local = @state[:local_network]
      before = Array(local[:active_interfaces]).sort
      after = Array(observation[:active_interfaces]).sort
      if status == 'available' && local[:status] == 'available' && before != after
        interface_change = { previous: before, current: after, epoch: local[:epoch] }
      end
      was_paused = local[:paused]
      local.merge!(observation.slice(:source, :interfaces, :active_interfaces, :address_families, :detail))
      local[:status], local[:checked_at] = status, Time.now.iso8601
      if status == 'unavailable'
        if !was_paused || @local_network_settle_until.positive?
          local[:epoch] += 1
          @automatic_exhausted_rounds = 0
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
    log_event('local-network-interface-set-changed', **interface_change) if interface_change
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
    token = Thread.current[:adapter_recovery_token]
    return false if token && (@mutex.synchronize { token != @recovery_control_epoch } || action_conflicts?)
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

  def reconcile_validated_local_recovery(classification, at)
    return unless classification[:service_readiness] == 'ready'
    @automatic_exhausted_rounds = 0
    local = @state[:local_network]
    return if local[:paused] || local[:recovery_pending]
    return unless %w[failed degraded local-repair].include?(local[:recovery_stage])
    local.merge!(recovery_stage: 'restored', outcome: 'subsequent-path-validated', recovery_finished_at: at)
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
    return if ordered_recovery_blocked?
    ok = run_ordered_recovery(relay, reason: 'network-resume', expected_state: expected, original_path: path)
    return unless network_epoch_current?(epoch)
    return defer_local_network_recovery(local_failure: 'ordered-local-deferred') if @mutex.synchronize { @state.dig(:recovery, :phase) == 'local_wait' }
    return unless @mutex.synchronize { %w[restored exhausted].include?(@state.dig(:recovery, :phase)) }
    ready = ok && @mutex.synchronize { @state[:service_readiness] == 'ready' }
    finish_local_network_recovery(epoch, restored: ready, outcome: ok ? (ready ? 'validated-rebuild' : 'original-rebuild-live-partial') : 'same-city-exhausted')

  rescue LocalProbeTimeout => error
    # Resume verification runs before the ordinary health-check rescue. Keep
    # the owner alive and the original path reserved on a local observation
    # failure; a later iteration must be able to finish the same epoch.
    if epoch && network_epoch_current?(epoch)
      defer_local_network_recovery(local_failure: error.phase)
    end
    log_probe_event('network-resume-probe-deferred', phase: error.phase, epoch: epoch,
                    reason: 'local-observation-not-relay-failure')
    nil
  ensure
    Thread.current[:adapter_resume_path] = previous_path if defined?(previous_path)
  end

  def defer_local_network_recovery(evidence)
    @network_recovery_retry_at = monotonic_now + @options[:local_network_interval]
    @mutex.synchronize { @state[:local_network][:recovery_stage] = 'local-repair' }
    log_probe_event('local-network-recovery-deferred', detail: '没有节点数据面失败证据，等待本机组件／槽位恢复', evidence: evidence)
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
    requested = @health_wait_mutex.synchronize do
      fresh = !@health_wake_pending
      @health_wake_pending = true
      @health_cv.broadcast
      fresh
    end
    log_probe_event('health-check-requested', reason: reason) if requested
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
    return @active_health_monitor if @active_health_monitor&.alive?
    @active_health_monitor = Thread.new do
      Thread.current.name = 'adapter-active-health'
      retry_wait = nil
      log_probe_event('health-monitor-started')
      until @stop_requested
        begin
          wait_for_health_check(retry_wait)
          break if @stop_requested
          result = with_background_probe { action_pending? ? :retry : check_active_health_once }
          retry_wait = result == :retry ? 0.25 : nil
        rescue StandardError => error
          # Protect the entire iteration, including network-resume work and
          # wait/admission code outside check_active_health_once's inner rescue.
          log_probe_event('health-monitor-error', error_class: error.class.name,
                          phase: error.respond_to?(:phase) ? error.phase : nil)
          retry_wait = [@options[:local_network_interval], 0.25].max
        end
      end
    ensure
      log_probe_event('health-monitor-stopped', reason: @stop_requested ? 'shutdown' : 'unexpected-exit')
    end
  end

  def check_active_health_once
    return :retry if action_pending? || @ordered_recovery_mutex.locked?
    return if local_network_paused?
    return recover_local_network_once if local_network_recovery_pending?

    expected_relay = nil
    expected_generation = nil
    expected_slot = nil
    recovery_requested = false
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
        reconcile_validated_local_recovery(classification, now.iso8601)
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

    rescue LocalProbeTimeout => e
      log_probe_event('health-local-deferred', relay: expected_relay || context&.dig(:relay), phase: e.phase,
                reason: 'local-probe-timeout-not-relay-failure')
      return :retry
    rescue StandardError => e
      record_error("active health check failed: #{e.class}: #{e.message}")
    ensure
      @switch_mutex.unlock if @switch_mutex.owned?
    end

    if recovery_requested && expected_relay
      return if ordered_recovery_blocked?
      return run_ordered_recovery(expected_relay, reason: 'health-recovery',
                                  expected_state: { generation: expected_generation, active_slot: expected_slot, active_relay: expected_relay })
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
        evidence = {}
        return true if activate(name, reason: 'city-select', transport_preference: preference, attempt_evidence: evidence)
        return false if evidence[:local_failure]
        quarantine_relay(name, 'city-selection-failed', 60)
      end
      false
    end
  end

  # A round limits the start of new attempts, never interrupts an in-flight
  # lifecycle transaction. Preserve caller trace/deadline even on early return.
  # One recovery owner. State publication never waits for this lifecycle gate.
  def ordered_recovery_blocked?
    @mutex.synchronize do
      @recovery_stopped || (@recovery_retry_at && monotonic_now < @recovery_retry_at)
    end
  end

  def interrupt_ordered_recovery(stopped:, expected_epoch: nil)
    token = @mutex.synchronize do
      return nil if expected_epoch && expected_epoch != @recovery_control_epoch
      @recovery_control_epoch += 1
      @recovery_stopped = stopped
      @recovery_retry_at = nil
      if stopped || @state[:recovery][:running]
        @state[:recovery].merge!(phase: stopped ? 'stopped' : 'interrupted',
                               message: stopped ? '自动恢复已停止；当前通道保留，可手动重试' : '正在结束上一轮，随后执行你的操作',
                               next_step: stopped ? '点击重试原节点或重新自动恢复' : '等待当前有界检查完成并清理')
      end
      @recovery_control_epoch
    end
    if stopped
      @action_gate_mutex.synchronize do
        operation = @action_pending && @operations[@action_pending[:id]]
        operation[:cancel_requested] = true if operation && %w[retry-current retry-round].include?(operation[:kind])
      end
    end
    wake_health_monitor('recovery-control')
    token
  end

  def recovery_progress(phase, **fields)
    @mutex.synchronize do
      token = Thread.current[:adapter_recovery_token]
      return if token && token != @recovery_control_epoch
      @state[:recovery].merge!(phase: phase, updated_at: Time.now.iso8601, **fields)
    end
    log_event('recovery-progress', phase: phase, **fields.reject { |key, _| key.to_s.start_with?('_') })
  end

  def decorate_recovery_snapshot(copy)
    recovery = copy[:recovery]
    return unless recovery
    now = monotonic_now
    started = recovery.delete(:_started_mono)
    finished = recovery.delete(:_finished_mono)
    retry_at = recovery.delete(:_retry_mono)
    recovery[:elapsed_seconds] = started ? [(finished || now) - started, 0].max.round : 0
    recovery[:remaining_seconds] = [recovery[:budget_seconds].to_i - recovery[:elapsed_seconds], 0].max
    recovery[:retry_in_seconds] = retry_at ? [(retry_at - now).ceil, 0].max : nil
  end

  # Reuse catalogue-authorized inlet tuples and their history ranking. The
  # bounded ladder explicitly re-tests cooling inlets, but never invents one.
  def recovery_inlets(relay_name, mode, original = nil)
    return [] unless local_transport_available?(mode)
    relay = find_relay(relay_name)
    entry_name = original&.dig(:entry_relay)
    if protection_profile[:multihop]
      entry = entry_name ? find_relay(entry_name) : multihop_entries(relay, mode).first
      return [] unless entry && entry['hostname'] != relay_name
      entries = mode == 'ss' ? ss_endpoint_candidates(entry, include_cooling: true) : [nil]
      return entries.map { |inlet| { entry: entry['hostname'], inlet: inlet } }
    end
    mode == 'ss' ? ss_endpoint_candidates(relay, include_cooling: true) : [nil]
  rescue RuntimeError, ArgumentError
    [] # A withdrawn relay/entry must not be resurrected from a saved path.
  end

  def original_recovery_inlet(path, relay_name, mode)
    return nil unless path && path[:relay] == relay_name && path[:transport_mode] == mode
    relay = find_relay(path[:entry_relay] || relay_name)
    inlet = nil
    if mode == 'ss'
      ip, port = path.values_at(:endpoint, :endpoint_port)
      return nil unless ipv4?(ip) && port
      extra = Array(relay['shadowsocks_extra_addr_in'])
      authorized = extra.include?(ip) && port.to_i == EXTRA_SS_PORT
      ranges = validated_port_ranges(@metadata.dig('wireguard', 'shadowsocks_port_ranges'), 'shadowsocks port ranges')
      authorized ||= relay['ipv4_addr_in'] == ip && ranges.any? { |low, high| port.to_i.between?(low, high) }
      return nil unless authorized
      inlet = [ip, port.to_i, path[:endpoint_kind]]
    end
    candidate = path[:entry_relay] ? { entry: path[:entry_relay], inlet: inlet } : inlet
    { candidate: candidate }
  rescue RuntimeError, ArgumentError
    nil
  end

  def recovery_inlet_key(candidate)
    entry = candidate.is_a?(Hash) ? candidate[:entry] : nil
    inlet = candidate.is_a?(Hash) ? candidate[:inlet] : candidate
    [entry, inlet&.first, inlet&.[](1)]
  end

  def recovery_wait(seconds)
    target = monotonic_now + seconds
    while monotonic_now < target
      return false unless network_attempt_current? && !@stop_requested
      sleep [target - monotonic_now, 0.1].min
    end
    true
  end

  def run_ordered_recovery(relay_name, reason:, expected_state: nil, original_path: nil, current_only: false, manual: false)
    # Manual callers have already invalidated the old token, so its bounded
    # attempt cleans up before the new owner starts. Automatic callers never queue.
    request_epoch = Thread.current[:adapter_recovery_request_epoch] || @mutex.synchronize { @recovery_control_epoch }
    return false unless manual ? @ordered_recovery_mutex.lock : @ordered_recovery_mutex.try_lock
    previous = %i[adapter_recovery_token adapter_recovery_id adapter_recovery_deadline adapter_network_epoch adapter_recovery_inlet].to_h { |key| [key, Thread.current[key]] }
    started = monotonic_now
    ok = false
    entered = false
    begin
      return false if !manual && ordered_recovery_blocked?
      return false if @stop_requested || operation_cancelled? || local_network_paused? || action_conflicts?
      current = @mutex.synchronize { @state.slice(:generation, :active_slot, :active_relay) }
      return false if expected_state && expected_state != current
      generation = current[:generation]
      path = original_path
      path = @mutex.synchronize { (@workers[current[:active_slot]] || @last_network_path || {}).dup } if !path || path.empty?
      preference = current_transport_preference
      mode = current_only ? (path[:transport_mode] || (preference == 'auto' ? 'ss' : preference)) : (preference == 'auto' ? 'ss' : preference)
      token = @mutex.synchronize do
        @recovery_control_epoch if !@recovery_stopped && request_epoch == @recovery_control_epoch
      end
      return false unless token
      Thread.current[:adapter_recovery_token] = token
      Thread.current[:adapter_network_epoch] = network_epoch
      Thread.current[:adapter_recovery_id] = SecureRandom.uuid
      Thread.current[:adapter_recovery_deadline] = started + @options[:ordered_recovery_budget]
      entered = true
      @last_auto_recovery_at = Time.now
      @last_recovery_generation = generation
      city = recovery_city(relay_name)
      @mutex.synchronize do
        return false unless token == @recovery_control_epoch && !@recovery_stopped
        @metrics[:auto_recovery_attempts] += 1
        @state[:health][:last_attempt_at] = Time.now.iso8601
        @recovery_retry_at = nil
        @state[:recovery] = { phase: 'original', running: true, attempt: 0, original_relay: relay_name,
                              city: city, budget_seconds: @options[:ordered_recovery_budget],
                              _started_mono: started, started_at: Time.now.iso8601 }
      end
      log_event('recovery-round-started', relay: relay_name, reason: reason, policy: 'original-ss-city', budget_seconds: @options[:ordered_recovery_budget])
      inlets = recovery_inlets(relay_name, mode, path)
      original = original_recovery_inlet(path, relay_name, mode)
      primary = original ? original[:candidate] : (mode == 'ss' ? rotating_ss_recovery_inlets(relay_name, inlets).first : inlets.first)
      has_primary = original || !inlets.empty?
      plan = has_primary ? (original ? [0, 1, 5] : [0]).each_with_index.map { |delay, index| [original ? 'original' : 'current_relay', relay_name, primary, delay, index + 1, 0, mode] } : []
      city_candidates = []
      unless current_only
        alternate_pool = mode == 'ss' ? rotating_ss_recovery_inlets(relay_name, inlets, excluding: [recovery_inlet_key(primary)]) : []
        alternate_pool.first(3).each_with_index do |inlet, index|
          plan << ['alternate_ss', relay_name, inlet, 0, index + 1, 0, mode]
        end
        city_candidates = recovery_relay_candidates(relay_name, preference: preference).first(4)
        city_candidates.each_with_index do |candidate, index|
          pool = recovery_inlets(candidate, mode)
          pool = rotating_ss_recovery_inlets(candidate, pool) if mode == 'ss'
          pool.first(2).each_with_index do |inlet, inlet_index|
            plan << ['same_city', candidate, inlet, 0, inlet_index + 1, index + 1, mode]
          end
        end
        if preference == 'auto'
          [relay_name, *city_candidates].uniq.each_with_index do |candidate, city_index|
            %w[ipv6 ipv4].each do |fallback_mode|
              fallback_relay = Array(@metadata&.dig('wireguard', 'relays')).find { |item| item['hostname'] == candidate && item['active'] == true }
              next unless fallback_relay && transport_supported?(fallback_relay, fallback_mode)
              pool = recovery_inlets(candidate, fallback_mode)
              pool.first(1).each { |inlet| plan << ['transport_fallback', candidate, inlet, 0, 1, city_index, fallback_mode] }
            end
          end
        end
      end
      plan.each_with_index do |(phase, relay, inlet, delay, inlet_index, city_index, candidate_mode), plan_index|
        break unless recovery_budget_remaining? && network_attempt_current?
        break unless @mutex.synchronize { @state[:generation] == generation }
        next_step = %w[original current_relay].include?(phase) ? '原入口最多 3 次 → 同节点最多 3 个备用 SS → 最多 4 个同城节点；最后才是 IPv6/IPv4' : phase == 'alternate_ss' ? '备用入口仍失败，再试同城节点；每节点最多 2 个入口' : '继续下一个同城候选；不跨城，也不转为直连回落'
        next_step = 'SS 候选已失败；依次验证同城 IPv6/IPv4，仍无 DIRECT 回落' if phase == 'transport_fallback'
        fields = { target_relay: relay, inlet_attempt: inlet_index, city_attempt: city_index,
                   next_step: next_step, _retry_mono: delay.positive? ? monotonic_now + delay : nil }
        endpoint = inlet.is_a?(Hash) ? inlet[:inlet] : inlet
        fields.merge!(endpoint: endpoint&.first, endpoint_port: endpoint&.[](1), transport: candidate_mode)
        recovery_progress(delay.positive? ? 'retry_wait' : phase, **fields,
                          message: delay.positive? ? "上次已清理，等待 #{delay} 秒后重试原入口" : "正在验证 #{relay} 的#{phase == 'original' ? '原入口' : phase == 'current_relay' ? '当前官方入口（原入口已不可用）' : phase == 'alternate_ss' ? '备用 SS' : phase == 'transport_fallback' ? candidate_mode.upcase + ' 保底入口' : '同城入口'}")
        break unless recovery_wait(delay) && recovery_budget_remaining? && network_attempt_current?
        @mutex.synchronize { @state[:recovery][:attempt] += 1 }
        recovery_progress(phase, _retry_mono: nil, message: "正在建立并验证 #{relay} · 第 #{inlet_index} 次入口尝试")
        Thread.current[:adapter_recovery_inlet] = { relay: relay, mode: candidate_mode, candidate: inlet }
        evidence = {}
        expected = @mutex.synchronize { @state.slice(:generation, :active_slot, :active_relay) }
        resuming = reason == 'network-resume' || (manual && local_network_recovery_pending?)
        activation_reason = resuming ? (relay == relay_name ? 'network-resume' : 'network-resume-fallback') : 'ordered-recovery'
        ok = activate(relay, reason: activation_reason, transport_preference: preference, expected_state: expected, attempt_evidence: evidence)
        record_ss_recovery_attempt(relay, inlet) if candidate_mode == 'ss' && phase != 'original' && evidence[:attempted] && !evidence[:local_failure]
        break unless network_attempt_current?
        if ok
          ready = @mutex.synchronize { @state[:service_readiness] == 'ready' }
          if manual && resuming
            finish_local_network_recovery(Thread.current[:adapter_network_epoch], restored: ready,
                                          outcome: ready ? 'manual-validated-rebuild' : 'manual-rebuild-live-partial')
          end
          recovery_progress('restored', message: ready ? '连接已恢复，IP、DNS、HTTPS 已验证' : '数据通道已恢复；DNS或部分网页仍异常，保留当前节点复检', next_step: '继续监测当前连接；不再尝试其余候选')
          break
        end
        if evidence[:local_failure] || !evidence[:attempted] || !evidence[:relay_failed]
          log_probe_event('recovery-local-deferred', relay: relay, phase: evidence[:local_failure] || 'candidate-not-started', reason: 'ordered-local-indeterminate')
          recovery_progress('local_wait', message: '本机组件或槽位未就绪，暂停换节点', next_step: '清理完成后有限重试；这不计为节点失效')
          break
        end
        if plan[plan_index + 1]&.[](1) != relay
          quarantine_relay(relay, 'ordered-inlets-failed', 300)
        end
      end
      unless ok || !network_attempt_current? || @mutex.synchronize { @state.dig(:recovery, :phase) == 'local_wait' }
        recovery_progress('exhausted', message: monotonic_now >= Thread.current[:adapter_recovery_deadline] ? '本轮恢复预算已用完' : '本轮允许的入口与同城候选均未恢复连接',
                          next_step: '冷却后再试一轮；也可手动重试原节点或选择同城候选。Mac 尚无链式保底')
      end
      ok
    rescue LocalProbeTimeout => error
      recovery_progress('local_wait', message: '本机组件等待超时，暂不继续换节点', next_step: '清理完成后再试；不记为远端节点失效') if entered
      log_probe_event('recovery-local-deferred', relay: relay_name, phase: error.phase, reason: 'ordered-local-indeterminate')
      false
    ensure
      if entered
        valid = network_attempt_current?
        @mutex.synchronize do
          @metrics[:auto_recovery_failures] += 1 unless ok || !valid || @state.dig(:recovery, :phase) == 'local_wait'
          state = @state[:recovery]
          state[:running] = false
          state[:_finished_mono] = monotonic_now
          unless valid
            state[:phase] = @recovery_stopped ? 'stopped' : (@state[:local_network][:paused] ? 'waiting_network' : 'interrupted')
            state[:message] = @recovery_stopped ? '自动恢复已停止，当前通道保留' : '环境或操作已变化，旧恢复结果已作废'
            state[:next_step] = @recovery_stopped ? '可手动重试' : '本机联网稳定后先验证原路径；手动操作优先'
          end
          unless ok || @recovery_stopped || !valid
            if state[:phase] == 'exhausted'
              @automatic_exhausted_rounds += 1 unless manual
              base = [@options[:recovery_cooldown].to_f, 1].max
              delay = [base * (2**[[@automatic_exhausted_rounds - 1, 0].max, 2].min), [base, 120].max].min
              state[:exhausted_rounds] = @automatic_exhausted_rounds
              state[:retry_delay_seconds] = delay
              state[:next_step] = "多入口共同失败，#{delay.ceil} 秒后再试；手动重试仍可立即开始"
            else
              delay = state[:phase] == 'local_wait' ? @options[:local_network_interval] : @options[:recovery_cooldown]
            end
            @recovery_retry_at = monotonic_now + delay
            state[:_retry_mono] = @recovery_retry_at
          end
          @last_disconnected_retry_at = Time.now
        end
        log_event('recovery-round-finished', restored: ok && valid, duration_ms: ((monotonic_now - started) * 1000).round,
                  outcome: @mutex.synchronize { @state[:recovery][:phase] })
      end
      previous.each { |key, value| Thread.current[key] = value }
      @ordered_recovery_mutex.unlock
    end
  end

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
      backups = relays.reject { |r| r['hostname'] == primary }.first(4).map { |r| city_node_evidence(r['hostname']) }
      { id: id, country: info['country'], city: info['city'],
        relay_count: relays.length, primary: primary && city_node_evidence(primary, active: !!current[:active_slot]),
        backups: backups, maintenance_interval_seconds: id == selected ? 30 : 180 }
    end
    { version: 1, generation: current[:generation], favorite_cities: favorites, selected_city: selected, cities: cities,
      auto_cross_city: false, backup_policy: 'outer-probe-only-until-switch', updated_at: Time.now.iso8601 }
  end

  def maintain_city_candidates_once
    return if action_pending? || @ordered_recovery_mutex.locked? || ordered_recovery_blocked?
    return if local_network_paused? || local_network_recovery_pending?
    with_background_probe { maintain_one_city_candidate }
  end

  def maintain_one_city_candidate
    current = snapshot
    return unless current[:active_slot] && current[:service_readiness] == 'ready'
    epoch = network_epoch
    now = monotonic_now
    return if @city_probe_next_at && now < @city_probe_next_at
    favorites, selected = @city_mutex.synchronize { [@favorite_cities.dup, @selected_city] }
    @city_probe_due ||= {}
    candidates = favorites.flat_map do |city|
      ranked_city_relays(city, 'auto').reject { |r| r['hostname'] == current[:active_relay] }.first(4).map { |relay| [city, relay] }
    end
    names = candidates.map { |_city, relay| relay['hostname'] }
    @city_probe_due.select! { |name, _| names.include?(name) }
    city, relay = candidates.select { |_city, r| now >= @city_probe_due.fetch(r['hostname'], 0) }
                            .min_by { |_city, r| @city_probe_due.fetch(r['hostname'], 0) }
    return unless relay
    # At most one ICMP request every 5s across all favorite cities, including
    # unknown/timeout observations. Never create a backup WireGuard tunnel.
    @city_probe_next_at = now + 5
    @city_probe_due[relay['hostname']] = now + (city == selected ? 30 : 180)
    mode = transport_candidates('auto', relay).first
    endpoint = quick_ping_targets(relay).dig(mode, :target)
    return unless endpoint
    begin
      result = outer_ping_test(endpoint, 1_000)
    rescue LocalProbeTimeout => error
      result = { status: 'unknown', target: endpoint, local_failure: error.phase,
                 detail: 'ICMP observation timed out; tunnel availability is not determined' }
    end
    return unless network_epoch_current?(epoch)
    @city_mutex.synchronize { @city_probes[relay['hostname']] = result.merge(transport: mode, checked_at: Time.now.iso8601) }
    log_probe_event('city-candidate-outer-probe', relay: relay['hostname'], city: city, transport: mode, result: result)
  end

  def start_city_maintenance
    Thread.new do
      until @stop_requested
        begin
          maintain_city_candidates_once
        rescue StandardError => e
          log_probe_event('city-maintenance-error', error_class: e.class.name,
                          phase: e.respond_to?(:phase) ? e.phase : nil)
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
    if normalize_transport_preference(preference) == 'auto'
      return false if @mutex.synchronize { !@state[:active_slot].nil? }
      @mutex.synchronize { @state[:transport_preference] = 'auto' }
      # A service/UI update must not discard a route validated moments ago.
      # This is one bounded startup verification, not background SS preemption.
      recent = @history_mutex.synchronize do
        TRANSPORT_MODES.filter_map do |mode|
          history = @relay_history["#{preferred_relay}|#{mode}"]
          tested = history && history[:last_tested_at] && (Time.parse(history[:last_tested_at]) rescue nil)
          [mode, tested] if tested && Time.now - tested < 90 && history[:last_result] && classify_canary(history[:last_result])[:service_readiness] == 'ready'
        end.max_by { |_, tested| tested }
      end
      relay = Array(@metadata&.dig('wireguard', 'relays')).find { |item| item['hostname'] == preferred_relay && item['active'] == true }
      if recent && relay && relay['location'] == recovery_city(preferred_relay) && transport_supported?(relay, recent.first) && local_transport_available?(recent.first)
        mode = recent.first
        inlet = mode == 'ss' ? ss_endpoint_candidates(relay).first : nil
        previous_pin = Thread.current[:adapter_recovery_inlet]
        begin
          Thread.current[:adapter_recovery_inlet] = { relay: preferred_relay, mode: mode, candidate: inlet }
          evidence = {}
          return true if activate(preferred_relay, reason: 'startup-preserve', transport_preference: 'auto', expected_state: expected_state, attempt_evidence: evidence)
          return false if evidence[:local_failure] || !network_attempt_current?
        ensure
          Thread.current[:adapter_recovery_inlet] = previous_pin
        end
      end
      return run_ordered_recovery(preferred_relay, reason: reason, expected_state: expected_state)
    end
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

        evidence = {}
        ok = activate(
          candidate,
          reason: reason,
          transport_preference: normalized,
          expected_state: current,
          attempt_evidence: evidence
        )
        return true if ok
        if evidence[:local_failure]
          log_probe_event('recovery-local-deferred', relay: candidate, phase: evidence[:local_failure], reason: 'local-bootstrap')
          return false
        end
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
    return ['--proxy', '', '--noproxy', '*'] if raw.empty?
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
    validate_ip_address(ipv4, "metadata relay #{hostname} ipv4_addr_in", family: :ipv4) unless ipv4.empty?
    validate_ip_address(ipv6, "metadata relay #{hostname} ipv6_addr_in", family: :ipv6) unless ipv6.empty?

    extras = relay['shadowsocks_extra_addr_in']
    if extras && !extras.is_a?(Array)
      raise "metadata relay #{hostname} has invalid shadowsocks_extra_addr_in"
    end
    Array(extras).each do |extra|
      validate_ip_address(extra, "metadata relay #{hostname} shadowsocks_extra_addr_in")
    end
    relay
  end

  def validate_ip_address(value, label, family: nil)
    address = IPAddr.new(value.to_s)
    raise "#{label} has the wrong address family" if family && !address.public_send("#{family}?")
    address
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
      @state[:metadata] = @state[:metadata].slice(:last_attempt_at, :refreshing, :revision, :next_refresh_at, :relay_count, :cache_error).merge(
        live: live, cache: cache, source: source, age_seconds: nil, error: error,
        fetched_at: fetched_at&.iso8601,
        validation_warnings: Array(warnings || @last_metadata_validation_warnings).first(20)
      )
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

  # Coalesce explicit UI updates with the existing catalogue owner, independently
  # of connection/recovery admission. No lifecycle operation is queued here.
  def request_metadata_refresh
    @metadata_refresh_job_mutex.synchronize do
      if @metadata_refresh_thread&.alive? || @metadata_mutex.locked?
        return { accepted: false, refreshing: true }
      end
      @mutex.synchronize { @state[:metadata][:refreshing] = true }
      @metadata_refresh_thread = Thread.new do
        refresh_metadata(force: true, background: true, nonblocking: true)
      rescue StandardError => error
        log_probe_event('metadata-refresh-error', error_class: error.class.name)
      end
      { accepted: true, refreshing: true }
    end
  end

  def persist_metadata_cache(payload)
    path = metadata_cache_path
    temporary = "#{path}.pending-#{Process.pid}-#{SecureRandom.hex(6)}"
    File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
      file.write(JSON.generate(payload))
      file.flush
      file.fsync
    end
    File.rename(temporary, path)
  ensure
    FileUtils.rm_f(temporary) if temporary
  end

  def metadata_cache_valid?
    warnings = @last_metadata_validation_warnings
    File.file?(metadata_cache_path) && !!validate_metadata_payload(JSON.parse(File.read(metadata_cache_path)))
  rescue JSON::ParserError, RuntimeError, SystemCallError
    false
  ensure
    @last_metadata_validation_warnings = warnings
  end

  def refresh_metadata(force: false, background: false, nonblocking: false)
    acquired = (background || nonblocking) ? @metadata_mutex.try_lock : @metadata_mutex.lock
    return @metadata unless acquired
    begin
      if !force && @metadata && @metadata_fetched_at && (Time.now - @metadata_fetched_at) < @options[:metadata_ttl]
        return @metadata
      end
      @mutex.synchronize do
        @state[:metadata].merge!(refreshing: true, last_attempt_at: Time.now.iso8601)
      end
      proxy_args = bootstrap_proxy_args
      parsed = nil
      last_error = nil
      (background ? 1 : 3).times do
        stdout, stderr, status = Open3.capture3('curl', '-q', '-fsS', '--noproxy', '', '--max-time', '8', *proxy_args, API_URL)
        unless status.success?
          last_error = stderr.to_s.strip[0, 160]
          next
        end
        begin
          parsed = validate_metadata_payload(JSON.parse(stdout))
          break
        rescue JSON::ParserError, RuntimeError => error
          last_error = error.message
        end
      end
      unless parsed
        @mutex.synchronize { @metrics[:metadata_refresh_failures] += 1 }
        # Never replace a newer valid in-memory catalogue with an older disk file.
        if @metadata
          set_metadata_state(live: false, cache: metadata_cache_valid?, source: 'memory', error: last_error, fetched_at: @metadata_fetched_at)
          set_dns_status(:bootstrap, 'degraded', 'live metadata fetch failed; retaining last validated catalogue')
          return @metadata
        end
        if load_cached_metadata
          set_metadata_state(live: false, cache: true, source: 'cache', error: last_error, fetched_at: @metadata_fetched_at)
          return @metadata
        end
        set_metadata_state(live: false, cache: false, source: 'none', error: last_error, fetched_at: nil)
        raise "metadata fetch failed: #{last_error}"
      end
      cache_error = nil
      begin
        persist_metadata_cache(parsed)
        cache_valid = true
      rescue StandardError => error
        cache_error = error.class.name
        cache_valid = metadata_cache_valid?
      end
      @metadata = parsed
      @metadata_fetched_at = Time.now
      @mutex.synchronize { @metrics[:metadata_refreshes] += 1 }
      route = @options[:bootstrap_proxy].to_s.empty? ? 'system-https' : 'bootstrap-proxy'
      set_metadata_state(live: true, cache: cache_valid, source: route, error: nil, fetched_at: @metadata_fetched_at)
      summary = { cache_error: cache_error, relay_count: parsed.dig('wireguard', 'relays').length,
                  revision: Digest::SHA256.hexdigest(JSON.generate(parsed)),
                  next_refresh_at: (@metadata_fetched_at + @options[:metadata_ttl]).iso8601 }
      @mutex.synchronize { @state[:metadata].merge!(summary) }
      record_metadata_validation_warnings(route)
      set_dns_status(:bootstrap, 'pass', "Mullvad API fetched via #{route}")
      check_clash_global_path unless background
      parsed
    rescue StandardError => error
      set_metadata_state(live: false, cache: metadata_cache_valid?, source: (@metadata ? 'memory' : 'none'), error: error.message, fetched_at: @metadata_fetched_at)
      raise
    ensure
      @mutex.synchronize { @state[:metadata][:refreshing] = false }
      @metadata_mutex.unlock
    end
  end


  def check_clash_global_path
    if @options[:bootstrap_proxy].to_s.empty?
      set_dns_status(:clash_global, 'external', '未配置 Clash 引导代理；系统路由 HTTPS 不证明 Clash 入口可用')
      return
    end
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
    return false if current[:relay_liveness] == 'pass' # DNS/service degradation is not a dead tunnel.
    relay = current[:active_relay] || load_persisted_relay || @options[:default_relay]
    ok = run_ordered_recovery(relay, reason: 'manual-repair', manual: true)
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

  def local_transport_available?(mode)
    local = @mutex.synchronize { @state[:local_network].dup }
    return true unless local[:status] == 'available' && local.key?(:address_families)
    Array(local[:address_families]).include?(mode.to_s == 'ipv6' ? 'ipv6' : 'ipv4')
  end

  def transport_candidates(preference, relay)
    normalized = normalize_transport_preference(preference)
    modes = normalized == 'auto' ? AUTO_TRANSPORT_ORDER : [normalized]
    pinned = Thread.current[:adapter_recovery_inlet]
    modes = [pinned[:mode]] if pinned && pinned[:relay] == relay['hostname']
    supported = modes.uniq.select { |mode| transport_supported?(relay, mode) && local_transport_available?(mode) }
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

  # Dedicated SS addresses and primary-address SS ports are simultaneous
  # official paths, not mutually exclusive. Keep the pool separate from the
  # small per-transaction selection window.
  def ss_catalogue_candidates(relay)
    extra = Array(relay['shadowsocks_extra_addr_in']).select { |ip| ipv4?(ip) }.uniq
    candidates = extra.map { |ip| [ip, EXTRA_SS_PORT, 'extra-ss-ipv4'] }
    raw_ranges = @metadata&.dig('wireguard', 'shadowsocks_port_ranges')
    ranges = Array(raw_ranges).empty? ? [] : validated_port_ranges(raw_ranges, 'shadowsocks port ranges')
    if ipv4?(relay['ipv4_addr_in']) && !ranges.empty?
      total = ranges.sum { |low, high| high - low + 1 }
      ports = total <= 512 ? ranges.flat_map { |low, high| (low..high).to_a }.uniq : deterministic_port_sample(ranges, relay['hostname'], 512)
      candidates.concat(ports.map { |port| [relay['ipv4_addr_in'], port, 'relay-ipv4-ss-port'] })
    end
    candidates.uniq { |ip, port, _| [ip, port] }
  end

  def diversify_ss_candidates(candidates)
    result = candidates.dup
    # Within a tiny fallback window cover both officially supported SS paths,
    # instead of spending all slots on dedicated addresses on one fixed port.
    primary = result.index { |candidate| candidate[2] == 'relay-ipv4-ss-port' }
    result.insert(1, result.delete_at(primary)) if primary && primary > 1
    result
  end

  def ss_endpoint_candidates(relay, include_cooling: false)
    name = relay['hostname'].to_s
    history = @ss_endpoint_mutex.synchronize do
      Marshal.load(Marshal.dump(@ss_endpoint_history[name.to_sym] || @ss_endpoint_history[name] || {}))
    end
    stats = history[:endpoints].is_a?(Hash) ? history[:endpoints] : {}
    ranked = rank_ss_endpoint_candidates(ss_catalogue_candidates(relay), stats, name)
    last_good = history[:last_good].to_s
    ranked = ranked.each_with_index.sort_by do |candidate, index|
      preferred = [endpoint_history_key(candidate[0], candidate[1]), candidate[0]].include?(last_good) && endpoint_stats_for(stats, candidate[0], candidate[1])[:consecutive_failures].to_i.zero?
      [preferred ? 0 : 1, index]
    end.map(&:first)
    ranked = diversify_ss_candidates(ranked)
    return ranked if include_cooling
    available = ranked.reject { |candidate| endpoint_cooling_down?(endpoint_stats_for(stats, candidate[0], candidate[1])) }
    available = [ranked.min_by { |candidate| endpoint_retry_at(endpoint_stats_for(stats, candidate[0], candidate[1])) }] if available.empty?
    available.compact.first(6)
  end

  def ss_candidate_authorized?(relay, candidate)
    if @metadata
      current = Array(@metadata.dig('wireguard', 'relays')).find { |item| item['hostname'] == relay['hostname'] && item['active'] == true }
      return false unless current && current['public_key'] == relay['public_key']
      relay = current
    end
    ip, port = candidate
    return false unless ipv4?(ip) && port.is_a?(Integer) && port.between?(1, 65_535)
    return true if Array(relay['shadowsocks_extra_addr_in']).include?(ip) && port == EXTRA_SS_PORT
    relay['ipv4_addr_in'] == ip && validated_port_ranges(@metadata.dig('wireguard', 'shadowsocks_port_ranges'), 'shadowsocks port ranges').any? { |low, high| port.between?(low, high) }
  rescue RuntimeError
    false
  end

  # Original short retries deliberately repeat one exact path. Only the
  # fallback queue rotates; planning never consumes an unstarted candidate.
  def rotating_ss_recovery_inlets(relay_name, inlets, excluding: [])
    pool = inlets.uniq { |inlet| recovery_inlet_key(inlet) }
    keys = pool.map { |inlet| recovery_inlet_key(inlet) }
    fingerprint = Digest::SHA256.hexdigest(JSON.generate(keys.sort_by { |key| key.map(&:to_s) }))
    @ss_endpoint_mutex.synchronize do
      window = @ss_recovery_windows[relay_name]
      if !window || window[:fingerprint] != fingerprint
        window = @ss_recovery_windows[relay_name] = { fingerprint: fingerprint, seen: [] }
      end
      eligible = pool.reject { |inlet| excluding.include?(recovery_inlet_key(inlet)) }
      unseen = eligible.reject { |inlet| window[:seen].include?(recovery_inlet_key(inlet)) }
      if unseen.empty? && !eligible.empty?
        window[:seen].clear
        unseen = eligible
      end
      primary_index = unseen.index { |inlet| (inlet.is_a?(Hash) ? inlet[:inlet] : inlet)&.[](2) == 'relay-ipv4-ss-port' }
      unseen.insert(1, unseen.delete_at(primary_index)) if primary_index && primary_index > 1
      unseen
    end
  end

  def record_ss_recovery_attempt(relay_name, inlet)
    @ss_endpoint_mutex.synchronize do
      window = @ss_recovery_windows[relay_name]
      window[:seen] |= [recovery_inlet_key(inlet)] if window
    end
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
        candidate[2] == 'extra-ss-ipv4' ? 0 : 1,
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
    pinned = Thread.current[:adapter_recovery_inlet]
    return [pinned[:candidate]] if pinned && pinned[:relay] == relay['hostname'] && pinned[:mode] == mode
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
    mode.to_s == 'ss' ? ss_endpoint_candidates(relay).first(3) : [nil]
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
    # Ordered attempts score only actual data-canary outcomes, not local launch errors.
    return if Thread.current[:adapter_recovery_token]
    return if error.is_a?(LocalNetworkInterrupted) || error.is_a?(LocalProbeTimeout) || !network_attempt_current?
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

  def worker_failure_log_summary(worker)
    return { status: 'unavailable', reason: 'worker-not-registered' } unless worker
    path = File.join(slot_dir(worker[:slot]), 'core.log')
    stat = File.lstat(path)
    return { status: 'unavailable', reason: 'not-regular-file' } unless stat.file? && !stat.symlink?
    tail = File.open(path, File::RDONLY | File::NOFOLLOW) do |file|
      file.seek([file.size - 16_384, 0].max)
      file.read(16_384).to_s
    end
    text = tail.encode('UTF-8', invalid: :replace, undef: :replace)
    categories = {
      inner_tcp_timeout: /dial tcp .*context deadline exceeded/i,
      inner_dns_failure: /dns resolve failed|all DNS requests failed/i,
      network_unreachable: /network is unreachable|no route to host/i,
      permission_denied: /operation not permitted|permission denied/i,
      connection_refused: /connection refused/i,
      ss_authentication_error: /(?:shadowsocks|ss).*(?:authentication failed|invalid tag|decrypt.*fail)/i
    }
    { status: 'captured', tail_bytes: tail.bytesize, file_bytes: stat.size,
      categories: categories.transform_values { |pattern| text.lines.count { |line| pattern.match?(line) } },
      handshake: 'not-exposed-by-engine-controller', udp_packets: 'not-measured',
      interpretation: 'inner TCP failure does not establish SS reachability or WireGuard handshake failure' }
  rescue StandardError => error
    { status: 'unavailable', error_class: error.class.name }
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
    if classification[:relay_liveness] == 'fail'
      log_probe_event('worker-failure-evidence', relay: relay_name, worker_instance: route_worker&.dig(:instance_token),
                      endpoint: route_worker&.dig(:endpoint), endpoint_port: route_worker&.dig(:endpoint_port),
                      interface: route_worker&.dig(:interface), evidence: worker_failure_log_summary(route_worker))
    end
    log_event('probe-result', relay: relay_name, transport: mode, source: source,
              endpoint: route_worker&.dig(:endpoint), endpoint_port: route_worker&.dig(:endpoint_port),
              interface: route_worker&.dig(:interface), generation: @mutex.synchronize { @state[:generation] },
              network_epoch: network_epoch, worker_instance: route_worker&.dig(:instance_token),
              entry_relay: result[:entry_relay], multihop: result[:multihop] || false, post_quantum: result[:post_quantum] || false,
              duration_ms: canary[:duration_ms], **classification,
              ip: canary.dig(:ip_data, :status), dns: canary.dig(:inner_dns, :status),
              https: canary.dig(:https_data, :status),
              phase_duration_ms: { ip: canary.dig(:ip_data, :wall_duration_ms),
                                   dns: canary.dig(:inner_dns, :delay_ms),
                                   https: canary.dig(:https_data, :wall_duration_ms) }.compact,
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
    %w[health-recovery ordered-recovery worker-crash-recovery network-resume network-resume-fallback].include?(reason.to_s)
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
    raise '隧道尚未初始化；请先安装本机 WireGuard 身份' if @account_only_mode
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
        if %w[reconnect ss-endpoint-recovery protection-change network-resume ordered-recovery].include?(reason)
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
            if e.is_a?(LocalProbeTimeout)
              attempt_evidence[:local_failure] = e.phase if attempt_evidence
              raise
            end
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
  rescue LocalProbeTimeout => error
    attempt_evidence[:local_failure] = error.phase if attempt_evidence
    log_event('activation-local-deferred', relay: relay_name, phase: error.phase)
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
    local_probe_error = nil
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
          if e.is_a?(LocalProbeTimeout)
            attempt_evidence[:local_failure] = e.phase if attempt_evidence
            local_probe_error = e
            break
          end
          raise if e.is_a?(LocalNetworkInterrupted)
          # Failure of an explicitly requested direct transport must reach
          # rollback too. It must not escape with the old worker already gone.
        end
      end
      break if local_probe_error
    end

    raise LocalNetworkInterrupted unless network_attempt_current?
    @mutex.synchronize { @metrics[:failed_switches] += 1 }
    if Thread.current[:adapter_recovery_token] || %w[ss-endpoint-recovery network-resume].include?(reason)
      if local_probe_error
        update_state(status: 'degraded', active_slot: nil, active_transport: nil, active_transport_mode: nil,
                     transport_preference: old_preference, relay_liveness: 'unknown', service_readiness: 'degraded',
                     last_error: '本机隧道组件未就绪；保留原节点意图，等待本地组件重建')
        return false
      end
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
        local_probe_error = nil
        attempt_evidence.delete(:local_failure) if attempt_evidence
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
        if e.is_a?(LocalProbeTimeout)
          local_probe_error = e
          attempt_evidence[:local_failure] = e.phase if attempt_evidence
          break
        end
        raise if e.is_a?(LocalNetworkInterrupted)
      end
    end

    if local_probe_error
      update_state(status: 'degraded', active_slot: nil, active_transport: nil, active_transport_mode: nil,
                   transport_preference: old_preference, relay_liveness: 'unknown', service_readiness: 'degraded',
                   last_error: '本机隧道组件未就绪，原连接暂未重建；后台继续重试原路径')
    elsif rollback_last
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
      token = Thread.current[:adapter_recovery_token]
      raise LocalNetworkInterrupted if token && token != @recovery_control_epoch
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
      unless token
        @state[:recovery] = { phase: 'idle', running: false, attempt: 0, budget_seconds: @options[:ordered_recovery_budget],
                              message: '当前连接已建立；异常确认后再按顺序恢复',
                              next_step: '原入口重试 → 备用 SS → 最多 4 个同城节点；Mac 尚无链式保底' }
      end
      @last_network_path = worker_info.slice(:relay, :transport_mode, :endpoint, :endpoint_port, :endpoint_kind, :entry_relay)
      unless %w[network-resume network-resume-original network-resume-fallback health-recovery worker-crash-recovery startup startup-retry].include?(reason)
        @state[:local_network][:recovery_pending] = false
      end
      reconcile_validated_local_recovery(classification, switched_at)
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
    if !data_ok && %i[ip_data inner_dns https_data].any? { |key| canary.dig(key, :local_failure) || canary.dig(key, :status) == 'unknown' }
      return { relay_liveness: 'unknown', service_readiness: 'unknown' }
    end
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
    unless @switch_mutex.owned?
      return @switch_mutex.synchronize { start_worker(slot, relay, transport_mode: transport_mode, ss_candidate: ss_candidate) }
    end
    raise '隧道尚未初始化；请先安装本机 WireGuard 身份' if @account_only_mode
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
    info = {
      slot: slot, pid: nil, instance_token: SecureRandom.uuid,
      relay: relay['hostname'], peer_key: peer_key, **path_info,
      transport_mode: mode, location: relay['location'],
      mixed_port: spec[:mixed], controller_port: spec[:controller],
      started_at: Time.now.iso8601
    }
    register = lambda do |spawned|
      pid = spawned
      info[:pid] = spawned
      @mutex.synchronize do
        @workers[slot] = info.dup
        @worker_state_tokens[slot] = info[:instance_token]
        @state[:workers][slot] = public_worker_state(info).merge(state: 'starting')
      end
    end
    worker_ready = cleanup_attempted = false
    phase = 'bootstrap-config'
    begin
      write_json_private(path, config, secret: true)
      validate_runtime_config(path, dir) if @options[:validate_configs]
      phase = 'bootstrap-controller'
      pid = spawn_worker_core(dir, path, spec, &register)
      if protection_profile[:post_quantum]
        log_event('pq-negotiation-started', relay: relay['hostname'], slot: slot)
        phase = 'pq-config-service'
        secrets = negotiate_pq(spec[:mixed])
        stop_worker(slot)
        pid = nil
        wireguard = config['proxies'].find { |proxy| proxy['name'] == 'MULLVAD' }
        wireguard['private-key'] = secrets.fetch('ephemeral_private_key')
        wireguard['pre-shared-key'] = secrets.fetch('preshared_keys').first
        write_json_private(path, config, secret: true)
        validate_runtime_config(path, dir) if @options[:validate_configs]
        phase = 'final-controller'
        pid = spawn_worker_core(dir, path, spec, &register)
        # The core has loaded its configuration. Do not retain ephemeral keys
        # on disk or expose them through public worker state.
        FileUtils.rm_f(path)
        path_info[:post_quantum] = true
        path_info[:pq_helper_sha256] = Digest::SHA256.file(@options[:pq_helper]).hexdigest
        log_event('pq-negotiation-completed', relay: relay['hostname'], slot: slot,
                  helper_sha256: path_info[:pq_helper_sha256])
      end
    rescue StandardError => error
      cleanup_attempted = true
      # Keep the registered owner/config when cleanup is uncertain. A later
      # attempt cannot reserve this slot or peer until stop_worker succeeds.
      if @workers[slot]
        stop_worker(slot)
      elsif pid
        stop_pid(pid)
      end
      FileUtils.rm_f(path)
      @mutex.synchronize { @metrics[:worker_start_failures] += 1 }
      log_event('worker-start-failed', relay: relay['hostname'], slot: slot,
                post_quantum: !!protection_profile[:post_quantum], phase: phase, error_class: error.class.name)
      raise error if error.is_a?(LocalProbeTimeout)
      raise 'protected worker could not start; no unprotected fallback was selected'
    end

    info.merge!(pid: pid, **path_info)
    @mutex.synchronize do
      @workers[slot] = info
      @worker_state_tokens[slot] = info[:instance_token]
      @metrics[:worker_starts] += 1
      @state[:workers][slot] = public_worker_state(info).merge(state: 'candidate')
      @state[:updated_at] = Time.now.iso8601
    end
    worker_ready = true
    log_probe_event('worker-path-started', **info.slice(:slot, :relay, :transport_mode, :endpoint, :endpoint_port, :endpoint_kind, :interface),
              worker_instance: info[:instance_token], network_epoch: network_epoch)
    info
  ensure
    # Thread.kill bypasses rescue clauses, but never the resource cleanup path.
    if info && !worker_ready && !cleanup_attempted && @workers[slot]&.dig(:instance_token) == info[:instance_token]
      stop_worker(slot)
    end
  end

  def ensure_pq_available!(profile)
    return unless profile[:post_quantum]
    raise '多跳与抗量子的组合尚未通过验收' if profile[:multihop]
    raise '抗量子组件缺失，请使用包含协商器的完整候选包' unless File.executable?(@options[:pq_helper])
    raise '模板已有专用 PSK，不能直接用于新的抗量子身份' unless @template['pre-shared-key'].to_s.empty?
  end

  def spawn_worker_core(dir, path, spec)
    pid = nil
    Thread.handle_interrupt(Object => :never) do
      pid = File.open(File.join(dir, 'core.log'), 'a', 0o600) do |log|
        Process.spawn(@options[:core], '-d', dir, '-f', path, out: log, err: log)
      end
      yield pid
    end
    return pid if wait_controller(spec[:controller], 8, pid: pid)
    raise LocalProbeTimeout, 'worker-controller'
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

  # Recover only a missing HTTPS hostname from the client's TLS ClientHello.
  # Pure-IP connections may carry stale/system-resolved destinations that the
  # tunnel DNS never saw. A recovered hostname is resolved by the WG outbound's
  # own in-tunnel resolver; no local/system DNS or DIRECT fallback is added.
  # Preserve explicit domain requests and private/literal-only protocols.
  def https_destination_recovery_config
    {
      'enable' => true,
      'force-dns-mapping' => false,
      'parse-pure-ip' => true,
      'override-destination' => true,
      'sniff' => { 'TLS' => { 'ports' => [443, 8443] } },
      'skip-domain' => ['+.local', '+.lan', '+.localhost'],
      'skip-dst-address' => %w[0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8
                               169.254.0.0/16 172.16.0.0/12 192.168.0.0/16
                               224.0.0.0/4 240.0.0.0/4 ::/128 ::1/128 fc00::/7 fe80::/10 ff00::/8]
    }
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
      raise LocalProbeUnavailable, 'catalogue-inlet-withdrawn' unless ss_candidate_authorized?(relay, [endpoint, port])
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
        # This is the destination INSIDE the SS UDP envelope, interpreted by
        # the remote Mullvad SS service. It is not the local machine's loopback
        # route: SS-INLET remains responsible for the physical remote endpoint.
        # Using the relay's public WG address here can silently drop handshakes.
        'server' => '127.0.0.1',
        'port' => 51_820,
        'dialer-proxy' => inlet_name,
        # A dual-stack userspace WG interface must satisfy IPv6's minimum MTU,
        # even when its outer SS transport uses IPv4.
        'mtu' => 1280
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
        'dns' => ['tcp://10.64.0.1'], 'udp' => true, 'mtu' => 1280)
      proxies << exit_wg
      transport_name = 'multihop-' + transport_name
    else
      proxies << wg
    end
    config = {
      'mixed-port' => spec[:mixed],
      'external-controller' => "127.0.0.1:#{spec[:controller]}",
      'secret' => controller_secret(spec[:controller]),
      'allow-lan' => false,
      'mode' => 'rule',
      'log-level' => 'warning',
      'ipv6' => mode == 'ipv6',
      'sniffer' => https_destination_recovery_config,
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
    trace = %i[adapter_operation_id adapter_recovery_id adapter_attempt_id].to_h { |key| [key, Thread.current[key]] }
    thread = Thread.new do
      trace.each { |key, value| Thread.current[key] = value }
      begin
        yield
      rescue LocalProbeTimeout => e
        { status: 'unknown', local_timeout: e.phase }
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
    deadline = started + canary_budget_seconds
    probes = []
    spec = @slot_config.fetch(slot)
    raise LocalProbeTimeout, 'canary-state-busy' unless @mutex.try_lock
    begin
      endpoint = @workers[slot] && @workers[slot][:endpoint]
    ensure
      @mutex.unlock
    end

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
    # Keep the UI's optional RTT sample, but do not let it hold traffic
    # readiness hostage. A result still pending at readiness is omitted.
    ping_thread = spawn_probe do
      endpoint ? outer_ping_test(endpoint, 1_000) : { status: 'fail', detail: 'worker endpoint unavailable' }
    end
    ip_thread = spawn_probe { curl_proxy_ip_test(spec[:mixed], IP_CANARY, 8) }
    dns_thread = spawn_probe { inner_dns_tcp_test(spec[:mixed], 'www.gstatic.com', 8) }
    probes.concat([ping_thread, ip_thread, dns_thread])

    ip_result = await_probe(ip_thread, deadline, 'ip-data')
    # inner_dns 必须跑：dns_ok 由它决定，而 degraded_dns 和 data_fail 的区别靠它。
    dns_result = await_probe(dns_thread, deadline, 'inner-dns')

    # https_data 走 socks5h，域名解析依赖内层 DNS。内层 DNS 已经挂了的话
    # domain_ok 必然为 false，再花 12 秒等它是纯浪费。
    # 这不会改变 classify_canary 的结果：dns_ok 为 false 时，
    # data_ok = ip_ok || domain_ok 里 domain_ok 取 true 或 false，
    # 分支都只可能是 degraded_dns（ip_ok 为真）或 data_fail（ip_ok 为假）。
    https_thread = if dns_result[:status] == 'pass'
                     spawn_probe { curl_proxy_test(spec[:mixed], HOST_CANARY, 12) }
                   end
    probes << https_thread if https_thread

    # controller_probe 不参与就绪度判定（只进缓存快照供界面显示）。
    # 数据面已经确定不通时它只会再白等 8 秒，直接跳过。
    # ip_data 通过就已经证明数据面活着，所以这里可以先起线程，与 https_data 并行。
    controller_thread = if !Thread.current[:adapter_skip_controller_probe] && ip_result[:status] == 'pass'
                          spawn_probe { delay_test(spec[:controller], 'MULLVAD', IP_CANARY, 8_000) }
                        end
    probes << controller_thread if controller_thread

    https_result = if https_thread
                     await_probe(https_thread, deadline, 'https-data')
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
                          await_probe(controller_thread, deadline, 'controller-delay')
                        elsif https_result[:status] == 'pass'
                          controller_thread = spawn_probe { delay_test(spec[:controller], 'MULLVAD', IP_CANARY, 8_000) }
                          probes << controller_thread
                          await_probe(controller_thread, deadline, 'controller-delay')
                        else
                          {
                            status: 'skip', target: IP_CANARY,
                            detail: 'skipped: data path already known down'
                          }
                        end

    ping_result = if Thread.current[:adapter_skip_controller_probe]
                    ping_thread.join(0) ? ping_thread.value : { status: 'skip', detail: 'optional ICMP result not ready' }
                  else
                    await_probe(ping_thread, deadline, 'outer-ping')
                  end
    elapsed = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round

    local_failure = [ip_result, dns_result, https_result].filter_map { |r| r[:local_failure] }.first
    if local_failure && ip_result[:status] != 'pass' && https_result[:status] != 'pass'
      raise LocalProbeUnavailable, local_failure
    end
    {
      at: Time.now.iso8601,
      duration_ms: elapsed,
      ping_data: ping_result,
      controller_probe: controller_result,
      ip_data: ip_result,
      inner_dns: dns_result,
      https_data: https_result
    }
  ensure
    Array(probes).each { |probe| probe.kill if probe.alive? }
    Array(probes).each { |probe| probe.join(0.4) }
  end

  def canary_budget_seconds
    Thread.current[:adapter_skip_controller_probe] ? 24 : 34
  end

  def await_probe(thread, deadline, phase)
    remaining = deadline - monotonic_now
    unless remaining.positive? && thread.join(remaining)
      log_probe_event('local-probe-timeout', phase: phase, reason: 'aggregate-deadline')
      raise LocalProbeTimeout, phase
    end
    result = thread.value
    raise LocalProbeTimeout, result[:local_timeout] if result[:local_timeout]
    result
  end

  def outer_ping_test(endpoint, timeout_ms)
    address = IPAddr.new(endpoint.to_s)
    command = address.ipv6? ? '/sbin/ping6' : '/sbin/ping'
    arguments = [command, '-n', '-c', '1']
    arguments.concat(['-W', timeout_ms.to_i.to_s]) unless address.ipv6?
    arguments << endpoint.to_s
    stdout, stderr, status = capture_probe_command(
      *arguments,
      timeout_seconds: timeout_ms.to_f / 1000 + 1, phase: 'outer-ping'
    )
    match = stdout.match(/time[=<]([0-9.]+)\s*ms/)
    if status.success? && match
      { status: 'pass', delay_ms: match[1].to_f.round, target: endpoint.to_s, detail: 'ICMP echo RTT' }
    else
      detail = stderr.to_s.strip
      detail = stdout.lines.last.to_s.strip if detail.empty?
      { status: 'fail', target: endpoint.to_s, detail: detail[0, 160] }
    end
  rescue LocalProbeTimeout
    raise
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
  rescue LocalProbeTimeout => e
    { status: 'unknown', local_failure: e.phase, resolver: '10.64.0.1:53/tcp', qname: qname }
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
    socket = nil
    begin
      socket = Socket.tcp('127.0.0.1', proxy_port, connect_timeout: timeout_seconds)
      socket.write([5, 1, 0].pack('C*'))
      hello = read_exact(socket, 2, timeout_seconds).bytes
      raise 'SOCKS5 authentication negotiation failed' unless hello == [5, 0]
    rescue StandardError
      raise LocalProbeUnavailable, 'local-socks-handshake'
    end

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
    stdout, stderr, status, command_ms = capture_probe_command(
      'curl', '-q', '-sS', '--noproxy', '', '--max-time', timeout.to_s,
      '--proxy', "socks5h://127.0.0.1:#{port}",
      '-o', '/dev/null', '-w', format, url,
      timeout_seconds: timeout + 1, phase: 'https-data'
    )
    code = stdout[/code=(\d+)/, 1].to_i
    evidence = { exit_code: status.exitstatus, wall_duration_ms: command_ms, elapsed_seconds: stdout[/total=([\d.]+)/, 1]&.to_f,
                 proxy_port: port, target: url, timeout_seconds: timeout }
    if [5, 7].include?(status.exitstatus)
      return { **evidence, status: 'unknown', http_code: code, local_failure: 'local-socks-connect' }
    end
    if status.success? && code >= 200 && code < 400
      { **evidence, status: 'pass', http_code: code, detail: stdout.strip, dependency: 'inner_dns+data' }
    else
      { **evidence, status: 'fail', http_code: code, detail: stderr.to_s.strip[0, 160], dependency: 'inner_dns+data' }
    end
  end

  def curl_proxy_ip_test(port, url, timeout)
    format = 'code=%{http_code} total=%{time_total}'
    stdout, stderr, status, command_ms = capture_probe_command(
      'curl', '-q', '-sS', '--noproxy', '', '--max-time', timeout.to_s,
      '--proxy', "socks5://127.0.0.1:#{port}",
      '-o', '/dev/null', '-w', format, url,
      timeout_seconds: timeout + 1, phase: 'ip-data'
    )
    code = stdout[/code=(\d+)/, 1].to_i
    evidence = { exit_code: status.exitstatus, wall_duration_ms: command_ms, elapsed_seconds: stdout[/total=([\d.]+)/, 1]&.to_f,
                 proxy_port: port, target: url, timeout_seconds: timeout }
    if [5, 7].include?(status.exitstatus)
      return { **evidence, status: 'unknown', http_code: code, local_failure: 'local-socks-connect' }
    end
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
      worker
    end

    begin
      stop_pid(info[:pid])
    rescue SystemCallError => error
      log_probe_event('worker-cleanup-deferred', slot: slot, relay: info[:relay], error_class: error.class.name)
      raise LocalProbeUnavailable, 'worker-cleanup'
    end
    @mutex.synchronize { @workers.delete(slot) if @workers[slot]&.dig(:instance_token) == info[:instance_token] }
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
    _stdout, _stderr, status = capture_probe_command(@options[:core], '-t', '-d', dir, '-f', path,
                                                   timeout_seconds: 8, phase: 'config-validation')
    raise 'Mihomo rejected generated configuration' unless status.success?
    true
  end

  def wait_controller(port, timeout_seconds, pid: nil)
    deadline = monotonic_now + timeout_seconds
    consecutive_successes = 0
    loop do
      return false if pid && !process_alive?(pid)
      remaining = deadline - monotonic_now
      return false unless remaining.positive?
      if pid && !controller_listener_owned_by?(port, pid, timeout_seconds: [remaining, 0.5].min)
        consecutive_successes = 0
        return false if monotonic_now >= deadline
        sleep [0.1, deadline - monotonic_now].min.clamp(0, 0.1)
        next
      end
      begin
        remaining = deadline - monotonic_now
        return false unless remaining.positive?
        request_timeout = [remaining / 2, 0.3].min
        payload = Timeout.timeout(remaining, LocalProbeTimeout, 'controller-http') do
          http_json(port, '/version', open_timeout: request_timeout, read_timeout: request_timeout)
        end
        remaining = deadline - monotonic_now
        if remaining.positive? && payload.is_a?(Hash) && (!pid || (process_alive?(pid) &&
           controller_listener_owned_by?(port, pid, timeout_seconds: [remaining, 0.5].min)))
          consecutive_successes += 1
          return true if consecutive_successes >= 2
        else
          consecutive_successes = 0
        end
      rescue StandardError
        consecutive_successes = 0
      end
      return false if monotonic_now >= deadline
      sleep [0.1, deadline - monotonic_now].min.clamp(0, 0.1)
    end
  end

  def controller_listener_owned_by?(port, pid, timeout_seconds: 0.5)
    stdout, _stderr, status = capture_probe_command(
      '/usr/sbin/lsof', '-nP', '-a', '-p', pid.to_i.to_s,
      "-iTCP:#{port.to_i}", '-sTCP:LISTEN', '-t',
      timeout_seconds: timeout_seconds, phase: 'controller-listener'
    )
    status.success? && stdout.lines.any? { |line| line.strip == pid.to_i.to_s }
  rescue StandardError
    false
  end

  # Only short-lived probes use this runner. Each owns a new process group;
  # cancellation/timeout cannot signal an existing front, worker or shell.
  # Drain both pipes concurrently, cap retained output, and never join an
  # Open3 waiter indefinitely after a child ignores its own timeout.
  def capture_probe_command(*argv, timeout_seconds:, phase:)
    started = monotonic_now
    deadline = started + timeout_seconds
    spawned_at = nil
    last_poll_at = started
    max_poll_gap = 0.0
    outputs = [String.new(encoding: Encoding::BINARY), String.new(encoding: Encoding::BINARY)]
    readers, writers = [], []
    pid = status = nil
    complete = false
    Thread.handle_interrupt(Object => :never) do
      2.times do
        reader, writer = IO.pipe
        readers << reader
        writers << writer
      end
      pid = Process.spawn(*argv, in: File::NULL, out: writers[0], err: writers[1], pgroup: true)
    end
    spawned_at = last_poll_at = monotonic_now
    writers.each(&:close)
    streams = readers.each_with_index.to_h
    until status && streams.empty?
      status ||= Process.waitpid2(pid, Process::WNOHANG)&.last
      now = monotonic_now
      max_poll_gap = [max_poll_gap, now - last_poll_at].max
      last_poll_at = now
      remaining = deadline - now
      if remaining <= 0
        log_probe_event('local-command-timeout', phase: phase, budget_ms: (timeout_seconds * 1000).round,
                        duration_ms: ((now - started) * 1000).round,
                        spawn_ms: ((spawned_at - started) * 1000).round,
                        capture_ms: ((now - spawned_at) * 1000).round,
                        max_poll_gap_ms: (max_poll_gap * 1000).round,
                        child_reaped: !status.nil?, open_streams: streams.length)
        raise LocalProbeTimeout, phase
      end
      ready = IO.select(streams.keys, nil, nil, [remaining, 0.025].min)
      Array(ready&.first).each do |io|
        chunk = io.read_nonblock(16_384, exception: false)
        if chunk.nil?
          streams.delete(io)
          io.close
        elsif chunk != :wait_readable
          buffer = outputs[streams.fetch(io)]
          buffer << chunk.byteslice(0, [65_536 - buffer.bytesize, chunk.bytesize].min)
        end
      end
    end
    complete = true
    if spawned_at - started > 0.25 || max_poll_gap > 0.25
      log_probe_event('local-command-delayed', phase: phase,
                      duration_ms: ((monotonic_now - started) * 1000).round,
                      spawn_ms: ((spawned_at - started) * 1000).round,
                      max_poll_gap_ms: (max_poll_gap * 1000).round)
    end
    [*outputs.map { |output| output.force_encoding(Encoding::UTF_8).scrub }, status,
     ((monotonic_now - started) * 1000).round]
  rescue SystemCallError => e
    log_probe_event('local-command-unavailable', phase: phase,
                    operation: pid ? 'capture' : 'spawn', error_class: e.class.name,
                    duration_ms: ((monotonic_now - started) * 1000).round)
    raise LocalProbeUnavailable, phase
  ensure
    # These are probe children only. KILL also closes inherited output pipes
    # held by descendants. Bounded reap preserves caller responsiveness.
    if pid && !complete
      terminate_probe_group(pid, phase, child_unreaped: status.nil?)
      unless status
        reap_deadline = monotonic_now + 0.25
        begin
          loop do
            break if Process.waitpid(pid, Process::WNOHANG)
            if monotonic_now >= reap_deadline
              Process.detach(pid)
              break
            end
            sleep 0.005
          end
        rescue Errno::ECHILD
          nil
        end
      end
    end
    (readers.to_a + writers.to_a).each { |io| io.close unless io.closed? }
  end

  def terminate_probe_group(pid, phase, child_unreaped:)
    Process.kill('KILL', -pid)
  rescue Errno::ESRCH
    nil
  rescue Errno::EPERM
    # A denied group signal must not replace the original timeout/cancellation
    # or skip pipe closure/reaping. Fall back only to our own, unreaped child;
    # never resolve or signal other processes by name.
    log_probe_event('local-command-cleanup-deferred', phase: phase, operation: 'group-signal',
                    error_class: 'Errno::EPERM', child_unreaped: child_unreaped)
    return unless child_unreaped
    begin
      # waitpid also proves this PID is still our child. An already reaped
      # group leader may have been reused while a descendant held the pipe.
      Process.kill('KILL', pid) unless Process.waitpid(pid, Process::WNOHANG)
    rescue Errno::ECHILD
      nil
    rescue Errno::ESRCH
      nil
    rescue Errno::EPERM
      log_probe_event('local-command-cleanup-deferred', phase: phase, operation: 'child-signal',
                      error_class: 'Errno::EPERM', child_unreaped: true)
    end
  end

  # Credentials belong to this daemon's managed controller lifetime, never the
  # public UI capability or a general snapshot. Every generated config uses it.
  def controller_secret(port)
    @controller_secret_mutex.synchronize { @controller_secrets[Integer(port)] ||= SecureRandom.hex(32).freeze }
  end

  def http_json(port, path, method: :get, body: nil, open_timeout: 1, read_timeout: 5)
    uri = URI("http://127.0.0.1:#{port}#{path}")
    klass = method == :put ? Net::HTTP::Put : (method == :post ? Net::HTTP::Post : Net::HTTP::Get)
    request = klass.new(uri)
    request['Authorization'] = "Bearer #{controller_secret(port)}"
    if body
      request['Content-Type'] = 'application/json'
      request.body = JSON.generate(body)
    end
    response = Net::HTTP.start(uri.host, uri.port, nil, open_timeout: open_timeout, read_timeout: read_timeout, max_retries: 0) do |http|
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
    reap_deadline = monotonic_now + 2
    while process_alive?(pid)
      raise LocalProbeTimeout, 'worker-stop' if monotonic_now >= reap_deadline
      sleep 0.05
    end
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
