# frozen_string_literal: true

require_relative 'minitest_dependencies'
require 'tmpdir'
require 'stringio'
require 'timeout'
require_relative 'mullvad_adapter'

class MullvadAccountLifecycleTest < Minitest::Test
  ACCOUNT_A = '1234567890123456'
  ACCOUNT_B = '1234567890123478'
  PRIVATE_A = Base64.strict_encode64(['77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'].pack('H*'))
  PUBLIC_A = Base64.strict_encode64(['8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'].pack('H*'))
  PRIVATE_B = Base64.strict_encode64(['5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'].pack('H*'))
  PUBLIC_B = Base64.strict_encode64(['de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'].pack('H*'))
  DEVICE_A = '11111111-1111-1111-1111-111111111111'
  DEVICE_B = '22222222-2222-2222-2222-222222222222'
  DEVICE_C = '33333333-3333-3333-3333-333333333333'

  class MemorySocket
    attr_reader :response

    def initialize(request)
      @request = StringIO.new(request)
      @response = +''
    end

    def gets(limit) = @request.gets(limit)
    def read(length) = @request.read(length)
    def write(data) = @response << data
    def close; end
  end

  def setup
    @dir = Dir.mktmpdir('account-lifecycle')
    @adapter = MullvadAdapter.new(state_dir: @dir)
    @template_a = { 'private-key' => PRIVATE_A, 'ip' => '10.64.0.2', 'ipv6' => 'fc00::2' }
    @template_b = { 'private-key' => PRIVATE_B, 'ip' => '10.64.0.3', 'ipv6' => 'fc00::3' }
    @device_a = device(DEVICE_A, PUBLIC_A, @template_a, 'alpha device')
    @device_b = device(DEVICE_B, PUBLIC_B, @template_b, 'beta device')
    @adapter.instance_variable_set(:@template, @template_a.dup)
    @profile_a = @adapter.send(:identity_profile_record, number: ACCOUNT_A, template: @template_a, device: @device_a)
    @profile_b = @adapter.send(:identity_profile_record, number: ACCOUNT_B, template: @template_b, device: @device_b)
    @adapter.send(:write_identity_profiles, {
      'schema' => 1, 'revision' => 0, 'active_id' => @profile_a['id'],
      'management_account_number' => ACCOUNT_A, 'profiles' => [@profile_a, @profile_b]
    })
    @adapter.send(:load_account_manager)
    @devices = { ACCOUNT_A => [@device_a.dup], ACCOUNT_B => [@device_b.dup] }
    @api_calls = []
    @failed_device_lists = []
    install_api_mock
    assert_equal 200, login(ACCOUNT_A).first
  end

  def teardown
    Thread.current[:adapter_account_api_route] = nil
    @adapter&.instance_variable_get(:@probe_event_writer)&.join(2)
    FileUtils.remove_entry(@dir)
  end

  def device(id, pubkey, template, name)
    { 'id' => id, 'name' => name, 'pubkey' => pubkey, 'created' => '2026-01-01T00:00:00Z',
      'ipv4_address' => "#{template['ip']}/32", 'ipv6_address' => "#{template['ipv6']}/128" }
  end

  def install_api_mock
    calls, devices, failures, tokens = @api_calls, @devices, @failed_device_lists, {}
    @adapter.define_singleton_method(:account_request) do |method, path, token: nil, payload: nil, **_options|
      calls << [method, path, token, payload]
      if path == 'auth/v1/token'
        number = payload[:account_number] || payload['account_number']
        access_token = "fixture-token-#{number}"
        tokens[access_token] = number
        return { 'access_token' => access_token, 'expiry' => (Time.now + 3600).iso8601 }
      end
      number = tokens.fetch(token) { raise 'test fixture saw an unexpected token' }
      case path
      when 'accounts/v1/accounts/me'
        { 'expiry' => '2030-01-01T00:00:00Z' }
      when 'accounts/v1/devices'
        if failures.include?(number)
          raise MullvadAdapter::AccountError.new('api_unreachable', 'synthetic offline fixture')
        end
        devices.fetch(number).map(&:dup)
      else
        raise "unexpected mocked endpoint #{path}"
      end
    end
  end

  def request(path, payload = nil, authorized: true, origin: nil, bound: true)
    if payload && bound && @adapter.instance_variable_get(:@account_number)
      payload = { 'account_fingerprint' => Digest::SHA256.hexdigest(@adapter.instance_variable_get(:@account_number)) }.merge(payload)
    end
    method = payload ? 'POST' : 'GET'
    body = payload ? JSON.generate(payload) : ''
    headers = authorized ? "Authorization: Bearer #{@adapter.instance_variable_get(:@account_capability)}\r\n" : ''
    headers += "Origin: #{origin}\r\n" if origin
    sock = MemorySocket.new("#{method} #{path} HTTP/1.1\r\n#{headers}Content-Length: #{body.bytesize}\r\n\r\n#{body}")
    @adapter.send(:handle_http, sock)
    [sock.response.split[1].to_i, JSON.parse(sock.response.split("\r\n\r\n", 2).last), sock.response]
  end

  def login(number)
    request('/account/login', { 'account_number' => number })
  end

  def test_manage_saved_account_refreshes_other_account_without_switching_tunnel_identity
    workers = @adapter.instance_variable_get(:@workers)
    workers['a'] = { pid: 111, relay: 'fixture-relay' }
    template_before = Marshal.dump(@adapter.instance_variable_get(:@template))
    workers_before = Marshal.dump(workers)
    generation_before = @adapter.send(:snapshot)[:generation]

    code, result, raw = request('/account/identities/manage', { 'id' => @profile_b['id'] })

    assert_equal 200, code
    assert_equal '3456', result['saved_identities'].find { |item| item['id'] == @profile_a['id'] }['account_suffix']
    assert_equal ACCOUNT_B[-4, 4], result['account_suffix']
    assert_equal @profile_a['id'], result['active_identity_id']
    assert result['saved_identities'].find { |item| item['id'] == @profile_b['id'] }['managing']
    assert_equal 'matched', result['saved_identities'].find { |item| item['id'] == @profile_b['id'] }['registration_status']
    assert_equal template_before, Marshal.dump(@adapter.instance_variable_get(:@template))
    assert_equal workers_before, Marshal.dump(workers)
    assert_equal generation_before, @adapter.send(:snapshot)[:generation]
    assert_equal ACCOUNT_B, JSON.parse(File.read(File.join(@dir, 'account.json')))['account_number']
    assert_equal ACCOUNT_B, JSON.parse(File.read(@adapter.send(:identity_profiles_path)))['management_account_number']
    refute_includes raw, ACCOUNT_A
    refute_includes raw, ACCOUNT_B
    refute_includes raw, PRIVATE_A
    refute_includes raw, PRIVATE_B
    refute_includes raw, 'fixture-token'
  end

  def test_failed_saved_account_login_retains_prior_management_login_and_official_list
    previous_account_file = File.binread(File.join(@dir, 'account.json'))
    previous_profiles = File.binread(@adapter.send(:identity_profiles_path))
    previous_data = Marshal.dump(@adapter.instance_variable_get(:@account_data))
    template_before = Marshal.dump(@adapter.instance_variable_get(:@template))
    workers = @adapter.instance_variable_get(:@workers)
    workers['a'] = { pid: 222 }
    generation_before = @adapter.send(:snapshot)[:generation]
    @failed_device_lists << ACCOUNT_B

    code, error = request('/account/identities/manage', { 'id' => @profile_b['id'] })

    assert_equal 422, code
    assert_equal 'api_unreachable', error['code']
    assert_equal ACCOUNT_A, @adapter.instance_variable_get(:@account_number)
    assert_equal previous_account_file, File.binread(File.join(@dir, 'account.json'))
    assert_equal previous_profiles, File.binread(@adapter.send(:identity_profiles_path))
    assert_equal previous_data, Marshal.dump(@adapter.instance_variable_get(:@account_data))
    assert_equal template_before, Marshal.dump(@adapter.instance_variable_get(:@template))
    assert_equal({ 'a' => { pid: 222 } }, workers)
    assert_equal generation_before, @adapter.send(:snapshot)[:generation]
  end

  def test_explicit_login_reads_official_list_and_preserves_unverifiable_identity_store
    path = @adapter.send(:identity_profiles_path)
    damaged = "{\"schema\":1,\"profiles\":[\"truncated local identity data\"]}\n".b
    File.binwrite(path, damaged)

    code, result = login(ACCOUNT_A)

    assert_equal 200, code
    assert_equal true, result['signed_in']
    assert_equal true, result['verified']
    assert_equal ACCOUNT_A[-4, 4], result['account_suffix']
    assert_equal [DEVICE_A], result['devices'].map { |item| item['id'] }
    assert_equal false, result['identity_switch_supported']
    assert_equal damaged, File.binread(path)
    assert @api_calls.any? { |call| call[1] == 'accounts/v1/devices' }
  end

  def test_optional_verified_name_cache_write_failure_keeps_official_refresh_success
    path = @adapter.send(:identity_profiles_path)
    original = File.binread(path)
    @adapter.define_singleton_method(:write_identity_profiles) do |_data|
      raise IOError, 'synthetic optional cache write failure'
    end
    @api_calls.clear

    code, result = request('/account/refresh', {})

    assert_equal 200, code
    assert_equal true, result['verified']
    assert_equal 'official_api', result['device_source']
    assert_equal [DEVICE_A], result['devices'].map { |item| item['id'] }
    assert_match(/名称缓存未保存/, result['profile_warning'])
    assert_equal original, File.binread(path)
    assert_equal %w[accounts/v1/accounts/me accounts/v1/devices], @api_calls.map { |call| call[1] }
  end

  def test_failed_refresh_keeps_last_official_list_marked_stale_without_secrets
    previous_devices = Marshal.dump(@adapter.instance_variable_get(:@account_data)[:devices])
    previous_checked_at = @adapter.instance_variable_get(:@account_data)[:checked_at]
    @failed_device_lists << ACCOUNT_A

    code, error = request('/account/refresh', {})
    assert_equal 422, code
    assert_equal 'api_unreachable', error['code']
    @failed_device_lists.clear

    status, snapshot, raw = request('/account')

    assert_equal 200, status
    assert_equal false, snapshot['verified']
    assert_equal 'error', snapshot.dig('freshness', 'state')
    assert_equal 'cached_official_api', snapshot['device_source']
    assert_equal previous_checked_at, snapshot['checked_at']
    assert_equal previous_devices, Marshal.dump(@adapter.instance_variable_get(:@account_data)[:devices])
    assert_equal DEVICE_A, snapshot['devices'].find { |item| item['current'] }['id']
    [ACCOUNT_A, ACCOUNT_B, PRIVATE_A, PRIVATE_B, 'fixture-token', 'access_token'].each do |secret|
      refute_includes raw, secret
    end
  end

  def test_cached_account_read_bypasses_held_management_mutex
    request('/account') # Populate the last published safe snapshot first.
    @adapter.instance_variable_get(:@account_mutex).lock

    result = Timeout.timeout(0.5) { request('/account') }

    assert_equal 200, result[0]
    assert_equal true, result[1]['management_busy']
    assert_equal ACCOUNT_A[-4, 4], result[1]['account_suffix']
    refute_includes result[2], ACCOUNT_A
    refute_includes result[2], PRIVATE_A
    refute_includes result[2], 'fixture-token'
  ensure
    @adapter.instance_variable_get(:@account_mutex).unlock if @adapter.instance_variable_get(:@account_mutex).owned?
  end

  def test_busy_read_returns_coherent_last_account_snapshot_during_other_account_login
    request('/account')
    published = Marshal.load(Marshal.dump(@adapter.instance_variable_get(:@published_account_snapshot)))
    refute_nil published
    @adapter.instance_variable_get(:@account_mutex).lock
    @adapter.instance_variable_set(:@account_number, ACCOUNT_B)
    @adapter.instance_variable_set(:@account_data, {
      expiry: '2040-01-01T00:00:00Z', devices: [@device_b], checked_at: '2040-01-02T03:04:05Z'
    })
    @adapter.instance_variable_get(:@account_observations)[ACCOUNT_B] = {
      checked_at: '2040-01-02T03:04:05Z', last_attempt_at: '2040-01-02T03:04:05Z', error_code: nil
    }
    @adapter.instance_variable_set(:@registration_observation, {
      state: 'missing', checked_at: '2040-01-02T03:04:05Z', public_key: PUBLIC_B,
      account_number: ACCOUNT_B, block_recovery: true, message: 'synthetic B observation'
    })

    code, result = Timeout.timeout(0.5) { request('/account') }

    assert_equal 200, code
    assert_equal true, result['management_busy']
    assert_equal 'refreshing', result.dig('freshness', 'state')
    assert_equal published[:account_suffix], result['account_suffix']
    assert_equal published[:checked_at], result['checked_at']
    assert_equal published[:freshness][:checked_at], result.dig('freshness', 'checked_at')
    assert_equal [DEVICE_A], result['devices'].map { |item| item['id'] }
    assert_equal 'registered', result.dig('freshness', 'device', 'state')
    refute_includes JSON.generate(result), ACCOUNT_B
    refute_includes JSON.generate(result), DEVICE_B
  ensure
    @adapter.instance_variable_get(:@account_mutex).unlock if @adapter.instance_variable_get(:@account_mutex).owned?
  end

  def test_registration_background_monitor_observes_300_second_healthy_cadence
    info = @adapter.instance_variable_get(:@account_observations)[ACCOUNT_A]
    @api_calls.clear
    info[:last_attempt_at] = (Time.now - 299).iso8601
    @adapter.instance_variable_get(:@state)[:service_readiness] = 'ready'
    assert @adapter.send(:check_account_registration_once)
    assert_empty @api_calls

    info[:last_attempt_at] = (Time.now - 301).iso8601
    assert @adapter.send(:check_account_registration_once)
    assert_equal 2, @api_calls.count { |call| call[1] == 'accounts/v1/accounts/me' || call[1] == 'accounts/v1/devices' }
  end

  def test_failed_data_path_uses_60_second_registration_recheck_cadence
    info = @adapter.instance_variable_get(:@account_observations)[ACCOUNT_A]
    @api_calls.clear
    @adapter.instance_variable_get(:@state)[:service_readiness] = 'data_fail'
    info[:last_attempt_at] = (Time.now - 59).iso8601
    assert @adapter.send(:check_account_registration_once)
    assert_empty @api_calls

    info[:last_attempt_at] = (Time.now - 61).iso8601
    assert @adapter.send(:check_account_registration_once)
    assert_equal 2, @api_calls.count { |call| call[1] == 'accounts/v1/accounts/me' || call[1] == 'accounts/v1/devices' }
  end

  def test_registration_monitor_does_not_queue_behind_account_operation
    @api_calls.clear
    mutex = @adapter.instance_variable_get(:@account_mutex)
    mutex.lock

    refute @adapter.send(:check_account_registration_once)

    assert_empty @api_calls
  ensure
    mutex.unlock if mutex&.owned?
  end

  def test_fresh_missing_previously_confirmed_device_blocks_recovery
    @devices[ACCOUNT_A] = []
    info = @adapter.instance_variable_get(:@account_observations)[ACCOUNT_A]
    info[:last_attempt_at] = (Time.now - 301).iso8601

    assert @adapter.send(:check_account_registration_once)

    observation = @adapter.send(:account_health_summary)[:device]
    assert_equal 'missing', observation[:state]
    assert_equal true, @adapter.send(:identity_registration_blocked?)
    refute @adapter.send(:run_ordered_recovery, 'fixture-relay', reason: 'health-recovery')
    [ACCOUNT_A, PRIVATE_A, PUBLIC_A].each { |secret| refute JSON.generate(observation).include?(secret) }
  end

  def test_missing_key_on_different_management_account_does_not_block_current_identity
    @adapter.instance_variable_set(:@account_number, ACCOUNT_B)
    @adapter.instance_variable_set(:@account_data, { expiry: '2030-01-01T00:00:00Z', devices: [@device_b], checked_at: Time.now.iso8601 })
    @devices[ACCOUNT_B] = [] # The active tunnel key belongs only to account A.
    @devices[ACCOUNT_A] = [@device_a.dup]
    observations = @adapter.instance_variable_get(:@account_observations)
    observations[ACCOUNT_A][:last_attempt_at] = (Time.now - 301).iso8601
    observations[ACCOUNT_B] = { last_attempt_at: (Time.now - 301).iso8601 }

    assert @adapter.send(:check_account_registration_once)

    assert_equal 'registered', @adapter.send(:account_health_summary)[:device][:state]
    refute @adapter.send(:identity_registration_blocked?)
  end

  def test_same_key_in_nonactive_account_cannot_overwrite_active_registration_observation
    shared_template = { 'private-key' => PRIVATE_A, 'ip' => '10.64.0.3', 'ipv6' => 'fc00::3' }
    shared_device = device(DEVICE_B, PUBLIC_A, shared_template, 'same-key on another account')
    profile_b = @adapter.send(:identity_profile_record, number: ACCOUNT_B, template: shared_template, device: shared_device)
    @adapter.send(:write_identity_profiles, {
      'schema' => 1, 'revision' => 0, 'active_id' => @profile_a['id'],
      'management_account_number' => ACCOUNT_A, 'profiles' => [@profile_a, profile_b]
    })
    before = @adapter.instance_variable_get(:@registration_observation).dup
    assert_equal 'registered', before[:state]
    refute before[:block_recovery]
    @devices[ACCOUNT_B] = []

    code, result = request('/account/identities/manage', { 'id' => profile_b['id'] })

    assert_equal 200, code
    assert_equal ACCOUNT_B[-4, 4], result['account_suffix']
    assert_equal @profile_a['id'], result['active_identity_id']
    assert_equal before, @adapter.instance_variable_get(:@registration_observation)
    assert_equal 'registered', @adapter.send(:account_health_summary)[:device][:state]
    refute @adapter.send(:identity_registration_blocked?)
  end

  def test_save_registered_identity_requires_receipt_private_key_and_exact_allocated_addresses
    request('/account')
    new_template = { 'private-key' => PRIVATE_B, 'ip' => '10.64.0.4', 'ipv6' => 'fc00::4' }
    official = device(DEVICE_C, PUBLIC_B, new_template, 'new fixture device')
    @adapter.send(:save_registration_receipt, official)
    valid = { 'confirm' => true, 'public_key' => PUBLIC_B, 'private_key' => PRIVATE_B, 'device_id' => DEVICE_C,
      'ipv4_address' => official['ipv4_address'], 'ipv6_address' => official['ipv6_address'] }
    before_bytes = File.binread(@adapter.send(:identity_profiles_path))
    before_template = Marshal.dump(@adapter.instance_variable_get(:@template))

    mismatch_cases = [
      valid.merge('device_id' => DEVICE_B),
      valid.merge('ipv4_address' => '10.64.0.99/32'),
      valid.merge('ipv6_address' => 'fc00::99/128'),
      valid.merge('private_key' => PRIVATE_A)
    ]
    mismatch_cases.each do |payload|
      code, error = request('/account/identity/save', payload)
      assert_equal 422, code
      refute_equal nil, error['code']
      assert_equal before_bytes, File.binread(@adapter.send(:identity_profiles_path))
      assert_equal before_template, Marshal.dump(@adapter.instance_variable_get(:@template))
    end

    @devices[ACCOUNT_A] << official
    workers = @adapter.instance_variable_get(:@workers)
    workers['a'] = { pid: 333 }
    generation_before = @adapter.send(:snapshot)[:generation]
    code, result = request('/account/identity/save', valid)

    assert_equal 200, code
    saved = result['saved_identities'].find { |item| item['public_key'] == PUBLIC_B }
    refute_nil saved
    assert_equal @profile_a['id'], result['active_identity_id']
    assert_equal before_template, Marshal.dump(@adapter.instance_variable_get(:@template))
    assert_equal 333, workers['a'][:pid]
    assert_equal generation_before, @adapter.send(:snapshot)[:generation]
    assert_equal PUBLIC_B, @adapter.send(:identity_profiles_document)['profiles'].find { |profile| profile['public_key'] == PUBLIC_B }['public_key']
  end
end
