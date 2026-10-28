# frozen_string_literal: true

# Account control-plane observations never hold the tunnel/switch mutex. A
# successful old list is retained as history, not presented as a fresh result.
module AccountLifecycle
  ACCOUNT_REFRESH_SECONDS = 300
  ACCOUNT_FAILURE_RECHECK_SECONDS = 60

  def initialize(options)
    @account_info_mutex = Mutex.new
    @account_observations = {}
    @registration_observation = {}
    @published_account_snapshot = nil
    super
  end

  def account_health_summary
    (@account_info_mutex ||= Mutex.new).synchronize do
      account_health_summary_unlocked
    end
  end

  def account_health_summary_unlocked
      @account_observations ||= {}
      @registration_observation ||= {}
      info = @account_observations[@account_number] || {}
      checked = info[:checked_at]
      fresh = checked && !info[:error_code] && Time.now - Time.parse(checked) <= ACCOUNT_REFRESH_SECONDS
      registration = @registration_observation.reject { |key, _| %i[public_key account_number block_recovery].include?(key) }
      registration[:fresh] = !!(registration[:checked_at] && Time.now - Time.parse(registration[:checked_at]) <= ACCOUNT_REFRESH_SECONDS)
      { signed_in: !@account_number.nil?, state: @account_number.nil? ? 'signed_out' : info[:refreshing] ? 'refreshing' : fresh ? 'current' : info[:error_code] ? 'error' : 'stale',
        checked_at: checked, last_attempt_at: info[:last_attempt_at], error_code: info[:error_code],
        refresh_interval_seconds: ACCOUNT_REFRESH_SECONDS, api_route: @account_route_kind,
        device: registration }
  end

  def decorate_status_snapshot(copy)
    value = super
    return false unless value
    unless @account_info_mutex.try_lock
      @status_publication_defer_reason = 'account_observation_busy'
      return false
    end
    begin
      value[:account_health] = account_health_summary_unlocked
    ensure
      @account_info_mutex.unlock
    end
    value
  end

  def account_snapshot
    value = super
    profiles = identity_profiles_document['profiles'] rescue []
    health = account_health_summary
    info = @account_info_mutex.synchronize { (@account_observations[@account_number] || {}).dup }
    # Old fixtures/callers may have supplied a verified official response without
    # the refresh wrapper; its checked_at is still a real timestamp, not now.
    checked = value[:checked_at]
    fresh = checked && Time.now - Time.parse(checked) <= ACCOUNT_REFRESH_SECONDS && !info[:error_code]
    value.merge(verified: !!fresh, freshness: health.merge(checked_at: checked),
                device_source: value[:verified] ? (fresh ? 'official_api' : 'cached_official_api') : 'not_verified',
                api_route: @account_route_kind || value[:api_route], identity_save_supported: true,
                profile_warning: @account_profile_warning, devices_limit: 5, devices_full: value[:devices].length >= 5,
                saved_identities: value[:saved_identities].map { |item|
                  profile = profiles.find { |p| p['id'] == item[:id] }
                  item.merge(managing: profile && profile['account_number'] == @account_number, account_fingerprint: profile && Digest::SHA256.hexdigest(profile['account_number']))
                })
  end

  def saved_identity_snapshot
    super
  rescue MullvadAdapter::AccountError
    { identity_switch_supported: false, active_identity_id: nil, saved_identities: [],
      identity_store_error: '本机保存身份无法验证，原文件保留；仍可输入账号管理官方设备' }
  end

  def persist_saved_management_login(number)
    super
  rescue MullvadAdapter::AccountError => error
    raise unless error.code == 'identity_store_invalid'
    false
  end

  def remember_verified_identity_name
    return unless @account_number && @account_data
    data = identity_profiles_document
    selected = data['profiles'].select { |profile| profile['account_number'] == @account_number }
    return if selected.empty?
    selected.each do |profile|
      device = @account_data[:devices].find { |item| item['pubkey'] == profile['public_key'] }
      profile['registration_checked_at'] = @account_data[:checked_at]
      profile['registration_status'] = device ? 'matched' : 'unmatched'
      if device
        profile['device_name'], profile['device_id'], profile['name_source'] = device['name'], device['id'], 'official_api'
      end
    end
    write_identity_profiles(data)
    @account_profile_warning = nil
  rescue StandardError
    @account_profile_warning = '官方列表已读取，但本机名称缓存未保存；原文件保留'
    nil
  end

  def current_identity_profile
    return unless @template
    pubkey = template_public_key
    data = identity_profiles_document
    selected = data['profiles'].find { |p| p['id'] == data['active_id'] && p['public_key'] == pubkey }
    return selected if selected
    matches = data['profiles'].select { |p| p['public_key'] == pubkey }
    matches.first if matches.length == 1
  rescue MullvadAdapter::AccountError
    nil
  end

  def publish_account_snapshot
    @published_account_snapshot = Marshal.load(Marshal.dump(account_snapshot))
  rescue StandardError
    nil # Preserve the last coherent snapshot; never read across a writer.
  end

  def account_refresh(number = @account_number)
    raise MullvadAdapter::AccountError.new('not_signed_in', '请先输入 Mullvad 账号') unless number
    @account_info_mutex.synchronize do
      @account_observations[number] ||= {}
      @account_observations[number].merge!(refreshing: true, last_attempt_at: Time.now.iso8601)
    end
    data = super(number)
    @account_info_mutex.synchronize do
      @account_observations[number].merge!(refreshing: false, error_code: nil, checked_at: data[:checked_at])
    end
    observe_device_registration(number, data)
    data
  rescue MullvadAdapter::AccountError => error
    @account_info_mutex.synchronize do
      @account_observations[number]&.merge!(refreshing: false, error_code: error.code)
    end
    raise
  end

  def observe_device_registration(number, data)
    return unless @template
    pubkey = template_public_key
    profile = current_identity_profile
    return unless profile && profile['account_number'] == number # A different management account cannot revoke a tunnel.
    matched = data[:devices].any? { |device| device['pubkey'] == pubkey }
    @account_info_mutex.synchronize do
      previous = @registration_observation
      was_verified = (previous[:public_key] == pubkey && previous[:state] == 'registered') ||
        %w[official_api saved_official_response].include?(profile['name_source'])
      @registration_observation = { state: matched ? 'registered' : 'missing', checked_at: data[:checked_at],
        public_key: pubkey, account_number: number, block_recovery: !matched && (was_verified || previous[:block_recovery]),
        message: matched ? '本机公钥仍在官方设备列表中' : '最新官方列表没有本机公钥；请核对账号，或创建并启用新设备' }
    end
  end

  def identity_registration_blocked?
    @account_info_mutex.synchronize { @registration_observation[:block_recovery] == true }
  end

  def invalidate_identity_observation
    @account_info_mutex.synchronize { @registration_observation = {} }
  end

  def snapshot
    super.merge(account_health: account_health_summary)
  end

  def handle_account_http(sock, method, path, headers, body)
    # A long API transaction must not make local status reads look unreachable.
    if method == 'GET' && path == '/account' && !headers['origin'] &&
       @account_capability && headers['authorization'] == "Bearer #{@account_capability}" && @account_mutex.locked? && @published_account_snapshot
      cached = Marshal.load(Marshal.dump(@published_account_snapshot))
      cached[:management_busy] = true
      cached[:freshness] = (cached[:freshness] || {}).merge(state: 'refreshing')
      respond(sock, 200, cached)
      return
    end
    Thread.current[:adapter_account_deadline] = monotonic_now + 45
    super
  ensure
    Thread.current[:adapter_account_api_route] = nil
    Thread.current[:adapter_account_deadline] = nil
  end

  def manage_saved_account(payload)
    profile = identity_profiles_document['profiles'].find { |p| p['id'] == payload['id'] }
    raise MullvadAdapter::AccountError.new('identity_not_found', '保存的账号不存在，请刷新列表') unless profile
    number = profile['account_number']
    data = account_refresh(number)
    atomic_account_file(File.join(@state_dir, 'account.json'), JSON.generate(account_number: number))
    persist_saved_management_login(number)
    @account_number, @account_data = number, data
    remember_verified_identity_name
    account_snapshot
  end

  def save_registered_identity(payload)
    verify_account_binding!(payload)
    raise MullvadAdapter::AccountError.new('confirmation_required', '请确认保存新设备到本机') unless payload['confirm'] == true
    binding, pubkey = payload.values_at('account_fingerprint', 'public_key')
    official = valid_account_public_key?(pubkey) && registration_receipt(binding, pubkey)
    unless official && %w[id ipv4_address ipv6_address].all? { |key| official[key] == payload[key == 'id' ? 'device_id' : key] }
      raise MullvadAdapter::AccountError.new('registration_receipt_required', '缺少账号、公钥与官方地址一致的注册回执；未保存')
    end
    template = { 'private-key' => payload['private_key'], 'ip' => official['ipv4_address'].delete_suffix('/32'),
                 'ipv6' => official['ipv6_address'].delete_suffix('/128') }
    profile = identity_profile_record(number: @account_number, template: template, device: official)
    @account_data = account_refresh
    raise MullvadAdapter::AccountError.new('registered_device_missing', '最新官方列表未找到新设备，请核对后重试；未启用') unless @account_data[:devices].any? { |d| d['id'] == official['id'] && d['pubkey'] == pubkey }
    data = identity_profiles_document
    previous = data['profiles'].find { |p| p['id'] == profile['id'] }
    raise MullvadAdapter::AccountError.new('identity_store_full', '本机保存的身份已达上限，未覆盖旧身份') if !previous && data['profiles'].length >= 8
    if previous
      raise MullvadAdapter::AccountError.new('identity_changed', '已有身份记录与新回执不一致，未覆盖') unless previous['template'] == profile['template']
    else
      data['profiles'] << profile
      write_identity_profiles(data)
    end
    account_snapshot
  end

  def discover_account_api_route
    ports = [@options[:front_mixed], *@slot_config.values.map { |s| s[:mixed] }]
    route = AccountApiRoutes.new(proxy: @options[:bootstrap_proxy],
      cache_path: File.join(@state_dir, 'account-api-addresses.json'), excluded_proxy_ports: ports).select
    @account_info_mutex.synchronize { @account_route_kind = route[:kind] }
    route[:args]
  rescue AccountApiRoutes::Error
    raise MullvadAdapter::AccountError.new('api_route_unavailable', '账号服务暂不可达：独立引导代理和官方 HTTPS 引导均未通过。可重新输入账号；这不表示设备已撤销。')
  end

  def start_account_monitor
    @account_monitor = Thread.new do
      until @stop_requested
        5.times { break if @stop_requested; sleep 1 }
        break if @stop_requested
        begin
          check_account_registration_once
        rescue StandardError
          log_probe_event('account-refresh-deferred', reason: 'account-monitor-unavailable')
        end
      end
    end
  end

  def check_account_registration_once
    return false if connections_stopped? || local_network_paused? || !@account_mutex.try_lock
    begin
      own = current_identity_profile
      [@account_number, own && own['account_number']].compact.uniq.each do |number|
        info = @account_info_mutex.synchronize { (@account_observations[number] || {}).dup }
        age = info[:last_attempt_at] ? Time.now - Time.parse(info[:last_attempt_at]) : Float::INFINITY
        unhealthy = @mutex.synchronize { @state[:service_readiness] == 'data_fail' }
        interval = info[:error_code] || unhealthy ? ACCOUNT_FAILURE_RECHECK_SECONDS : ACCOUNT_REFRESH_SECONDS
        next if age < interval
        begin
          Thread.current[:adapter_account_deadline] = monotonic_now + 45
          data = account_refresh(number)
          @account_data = data if number == @account_number
          remember_verified_identity_name if number == @account_number
        rescue MullvadAdapter::AccountError
          # Preserve last official list as stale. Never mutate a remote device.
        ensure
          Thread.current[:adapter_account_api_route] = nil
          Thread.current[:adapter_account_deadline] = nil
        end
      end
      publish_account_snapshot
      true
    ensure
      @account_mutex.unlock
    end
  end
end
