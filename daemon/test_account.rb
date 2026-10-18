# frozen_string_literal: true
require 'minitest/autorun'
require 'tmpdir'
require 'stringio'
require_relative 'mullvad_adapter'

class MullvadAccountTest < Minitest::Test
  # RFC 7748 public test vectors; these are not real credentials.
  PRIVATE = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
  PUBLIC = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
  NUMBER = '1234567890123456'
  CURRENT = '11111111-1111-1111-1111-111111111111'
  OTHER = '22222222-2222-2222-2222-222222222222'
  class Socket
    attr_reader :response
    def initialize(request)
      @request, @response = StringIO.new(request), +''
    end
    def gets(limit) = @request.gets(limit)
    def read(length) = @request.read(length)
    def write(data) = @response << data
    def close; end
  end

  def setup
    @dir = Dir.mktmpdir('mullvad-account')
    @adapter = MullvadAdapter.new(state_dir: @dir)
    @adapter.instance_variable_set(:@template, { 'private-key' => Base64.strict_encode64([PRIVATE].pack('H*')), 'ip' => '10.0.0.2' })
    @adapter.send(:load_account_manager)
    @calls = []
    @devices = [device(CURRENT, Base64.strict_encode64([PUBLIC].pack('H*'))), device(OTHER, 'another-test-public-key')]
    devices, calls = @devices, @calls
    @adapter.define_singleton_method(:account_request) do |method, path, **args|
      calls << [method, path, args]
      case path
      when 'auth/v1/token' then { 'access_token' => 'test-token', 'expiry' => (Time.now + 3600).iso8601 }
      when 'accounts/v1/accounts/me' then { 'expiry' => '2030-01-01T00:00:00Z' }
      when 'accounts/v1/devices' then devices.dup
      when "accounts/v1/devices/#{OTHER}"
        devices.reject! { |d| d['id'] == OTHER }
        {}
      when 'app/v1/submit-voucher' then { 'time_added' => 100, 'new_expiry' => '2030-01-01T00:00:00Z' }
      else raise "unexpected request #{path}"
      end
    end
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def device(id, pubkey)
    { 'id' => id, 'pubkey' => pubkey, 'name' => 'example animal', 'created' => '2020-01-01T00:00:00Z' }
  end

  def request(path, payload = nil, authorized: true, origin: nil)
    method = payload.nil? ? 'GET' : 'POST'
    body = payload ? JSON.generate(payload) : ''
    headers = authorized ? "Authorization: Bearer #{@adapter.instance_variable_get(:@account_capability)}\r\n" : ''
    headers += "Origin: #{origin}\r\n" if origin
    sock = Socket.new("#{method} #{path} HTTP/1.1\r\n#{headers}Content-Length: #{body.bytesize}\r\n\r\n#{body}")
    @adapter.send(:handle_http, sock)
    [sock.response.split[1].to_i, JSON.parse(sock.response.split("\r\n\r\n", 2).last), sock.response]
  end

  def login
    request('/account/login', { account_number: NUMBER })
  end

  def test_public_key_matches_rfc7748_vectors
    assert_equal Base64.strict_encode64([PUBLIC].pack('H*')), @adapter.send(:template_public_key)
    second = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
    @adapter.instance_variable_get(:@template)['private-key'] = Base64.strict_encode64([second].pack('H*'))
    assert_equal Base64.strict_encode64(['de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'].pack('H*')), @adapter.send(:template_public_key)
  end

  def test_all_account_reads_and_key_reveal_require_local_capability
    assert_equal 403, request('/account', authorized: false).first
    assert_equal 403, request('/account/key', { reveal: true }, authorized: false).first
    assert_equal 403, request('/account', origin: 'https://malicious.invalid').first
    assert_empty @calls
  end

  def test_login_matches_real_template_without_changing_tunnel_or_key
    before = Marshal.dump(@adapter.instance_variable_get(:@template))
    code, snapshot, raw = login
    assert_equal 200, code
    assert_equal 'matched', snapshot['device_match']
    assert_equal CURRENT, snapshot['devices'].find { |d| d['current'] }['id']
    assert_equal '3456', snapshot['account_suffix']
    refute_includes raw, NUMBER
    refute_includes raw, Base64.strict_encode64([PRIVATE].pack('H*'))
    assert_includes raw, 'Cache-Control: no-store'
    assert_equal before, Marshal.dump(@adapter.instance_variable_get(:@template))
    assert_equal 0o600, File.stat(File.join(@dir, 'account.json')).mode & 0o777
    assert_equal 0o600, File.stat(File.join(@dir, 'account-capability')).mode & 0o777
    refute_includes File.read(File.join(@dir, 'account.json')), 'test-token'
  end

  def test_unmatched_account_is_not_reported_as_current_device
    @devices.shift
    code, snapshot = login
    assert_equal 200, code
    assert_equal 'unmatched', snapshot['device_match']
    refute snapshot['devices'].any? { |d| d['current'] }
  end

  def test_failed_login_preserves_prior_account_and_persisted_credentials
    login
    old = File.read(File.join(@dir, 'account.json'))
    @adapter.define_singleton_method(:account_refresh) { |_number| raise MullvadAdapter::AccountError.new('api_unreachable', 'test failure') }
    assert_equal 422, request('/account/login', { account_number: '9999999999999999' }).first
    assert_equal NUMBER, @adapter.instance_variable_get(:@account_number)
    assert_equal old, File.read(File.join(@dir, 'account.json'))
  end

  def test_current_device_cannot_be_deleted_even_with_confirmation
    login
    code, payload = request('/account/devices/remove', { device_id: CURRENT, confirm: true })
    assert_equal 422, code
    assert_equal 'active_device', payload['code']
    refute @calls.any? { |c| c.first == 'DELETE' }
  end

  def test_other_device_delete_rechecks_official_list_and_requires_confirmation
    login
    assert_equal 422, request('/account/devices/remove', { device_id: OTHER }).first
    @calls.clear
    code, data = request('/account/devices/remove', { device_id: OTHER, confirm: true })
    assert_equal 200, code
    assert_equal CURRENT, data['devices'].first['id']
    delete_index = @calls.index { |c| c.first == 'DELETE' }
    assert @calls[0...delete_index].any? { |c| c[1] == 'accounts/v1/devices' }
    assert_equal 1, @calls.count { |c| c.first == 'DELETE' }
  end

  def test_logout_forgets_credentials_and_preserves_template
    login
    before = Marshal.dump(@adapter.instance_variable_get(:@template))
    assert_equal false, request('/account/logout', {})[1]['signed_in']
    refute File.exist?(File.join(@dir, 'account.json'))
    assert_nil @adapter.instance_variable_get(:@account_token)
    assert_equal before, Marshal.dump(@adapter.instance_variable_get(:@template))
  end

  def test_key_is_only_returned_on_explicit_reveal
    assert_equal 422, request('/account/key', {}).first
    code, data = request('/account/key', { reveal: true })
    assert_equal 200, code
    assert_equal Base64.strict_encode64([PRIVATE].pack('H*')), data['private_key']
    refute request('/status')[1].key?('private_key')
  end

  def test_create_sends_only_public_key_and_retains_current_template
    login
    before = Marshal.dump(@adapter.instance_variable_get(:@template))
    key = Base64.strict_encode64([PUBLIC].pack('H*'))
    calls = []
    @adapter.define_singleton_method(:account_api) do |method, path, **args|
      calls << [method, path, args]
      { 'id' => '33333333-3333-3333-3333-333333333333', 'name' => 'test bird', 'pubkey' => key,
        'hijack_dns' => false, 'ipv4_address' => '10.1.2.3/32', 'ipv6_address' => 'fc00::3/128' }
    end
    assert_equal 422, request('/account/devices/create', { public_key: key }).first
    assert_empty calls
    code, data, raw = request('/account/devices/create', { public_key: key, confirm: true })
    assert_equal 200, code
    assert_equal key, data['pubkey']
    assert_equal 1, calls.length
    assert_equal ['POST', 'accounts/v1/devices'], calls.first[0, 2]
    assert_equal 201, calls.first.last[:expected_status]
    assert_equal({ pubkey: key, hijack_dns: false }, calls.first.last[:payload])
    refute_includes raw, Base64.strict_encode64([PRIVATE].pack('H*'))
    assert_equal before, Marshal.dump(@adapter.instance_variable_get(:@template))
  end

  def test_create_unknown_outcome_is_reported_without_resubmission
    login
    count = 0
    @adapter.define_singleton_method(:account_api) do |*args, **options|
      count += 1
      raise MullvadAdapter::AccountError.new('api_unreachable', 'synthetic timeout')
    end
    key = Base64.strict_encode64([PUBLIC].pack('H*'))
    code, data = request('/account/devices/create', { public_key: key, confirm: true })
    assert_equal 422, code
    assert_equal 'mutation_outcome_unknown', data['code']
    assert_equal 1, count
  end

  def test_tokens_are_cached_and_refreshed_once_on_definite_auth_rejection
    calls = []
    @adapter.define_singleton_method(:account_request) do |method, path, **args|
      calls << [method, path, args]
      if path == 'auth/v1/token'
        { 'access_token' => "token-#{calls.length}", 'expiry' => (Time.now + 3600).iso8601 }
      elsif calls.count { |c| c[1] == 'example' } == 1
        raise MullvadAdapter::AccountError.new('invalid_access_token', 'rejected')
      else
        {}
      end
    end
    @adapter.send(:account_api, 'GET', 'example', number: NUMBER)
    @adapter.send(:account_api, 'GET', 'example', number: NUMBER)
    assert_equal 2, calls.count { |c| c[1] == 'auth/v1/token' }
    assert_equal 3, calls.count { |c| c[1] == 'example' }
  end

  def test_ambiguous_mutation_failure_is_not_retried
    count = 0
    @adapter.instance_variable_set(:@account_token, { number: NUMBER, value: 'test-token', expires_at: Time.now + 3600 })
    @adapter.define_singleton_method(:account_request) do |*args, **kwargs|
      count += 1
      raise MullvadAdapter::AccountError.new('api_unreachable', 'timeout')
    end
    assert_raises(MullvadAdapter::AccountError) { @adapter.send(:account_api, 'POST', 'app/v1/submit-voucher', number: NUMBER) }
    assert_equal 1, count
  end

  def test_account_operations_do_not_acquire_switch_mutex
    @adapter.instance_variable_get(:@switch_mutex).lock
    assert_equal 200, login.first
  ensure
    @adapter.instance_variable_get(:@switch_mutex).unlock
  end

  def test_account_busy_returns_without_waiting_or_duplicate_submission
    @adapter.instance_variable_get(:@account_mutex).lock
    assert_equal 409, login.first
    assert_empty @calls
  ensure
    @adapter.instance_variable_get(:@account_mutex).unlock
  end

  def test_authenticated_curl_keeps_credentials_out_of_process_arguments_and_sanitizes_errors
    @adapter.singleton_class.remove_method(:account_request)
    captured = nil
    capture = lambda do |*args, **options|
      captured = [args, options]
      [JSON.generate(type: 'INVALID_VOUCHER', detail: NUMBER) + "\n400", 'private upstream error', Struct.new(:success?).new(true)]
    end
    original = Open3.method(:capture3)
    Open3.singleton_class.send(:define_method, :capture3, capture)
    error = begin
      assert_raises(MullvadAdapter::AccountError) do
        @adapter.send(:account_request, 'POST', 'app/v1/submit-voucher', token: 'sensitive-test-token', payload: { voucher_code: 'test-voucher' })
      end
    ensure
      Open3.singleton_class.send(:define_method, :capture3, original)
    end
    refute_includes captured.first.join(' '), 'sensitive-test-token'
    refute_includes captured.first.join(' '), 'test-voucher'
    assert_includes captured.last[:stdin_data], 'sensitive-test-token'
    assert_equal '兑换码无效', error.message
    refute_includes error.message, NUMBER
  end

  def test_corrupt_account_metadata_does_not_prevent_tunnel_startup
    File.write(File.join(@dir, 'account.json'), '{invalid')
    @adapter.send(:load_account_manager)
    assert_nil @adapter.instance_variable_get(:@account_number)
    assert_equal Base64.strict_encode64([PUBLIC].pack('H*')), @adapter.send(:template_public_key)
  end
end
