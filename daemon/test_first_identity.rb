# frozen_string_literal: true
require_relative 'minitest_dependencies'
require 'tmpdir'
require 'stringio'
require_relative 'mullvad_adapter'

class MullvadFirstIdentityTest < Minitest::Test
  PRIVATE = Base64.strict_encode64(['77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'].pack('H*'))
  PUBLIC = Base64.strict_encode64(['8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'].pack('H*'))
  NUMBER = '1234567890123456'
  DEVICE = '33333333-3333-3333-3333-333333333333'
  class Socket
    attr_reader :response
    def initialize(request) = (@request, @response = StringIO.new(request), +'')
    def gets(length) = @request.gets(length)
    def read(length) = @request.read(length)
    def write(value) = @response << value
    def close; end
  end

  def setup
    @dir = Dir.mktmpdir('mullvad-first-identity')
    @adapter = MullvadAdapter.new(state_dir: @dir)
    @adapter.send(:prepare_state_dir)
    @adapter.send(:load_account_manager)
    @adapter.instance_variable_set(:@account_number, NUMBER)
    @adapter.instance_variable_set(:@account_only_mode, true)
    @official = { 'id' => DEVICE, 'name' => 'test bird', 'pubkey' => PUBLIC, 'created' => '2026-01-01T00:00:00Z',
      'ipv4_address' => '10.64.0.2/32', 'ipv6_address' => 'fc00:bbbb::2/128' }
    @adapter.send(:save_registration_receipt, @official)
    @devices = [@official.dup]
    @reads, @ports = [], []
    devices, reads, ports = @devices, @reads, @ports
    @adapter.define_singleton_method(:account_refresh) do |*|
      reads << :official
      { expiry: '2030-01-01T00:00:00Z', devices: devices.dup, checked_at: Time.now.iso8601 }
    end
    @adapter.define_singleton_method(:reserve_identity_install_ports) do |&block|
      ports << :reserved
      begin
        block.call
      ensure
        ports << :released
      end
    end
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def payload
    { 'confirm' => true, 'account_fingerprint' => Digest::SHA256.hexdigest(NUMBER), 'device_id' => DEVICE,
      'public_key' => PUBLIC, 'private_key' => PRIVATE, 'ipv4_address' => @official['ipv4_address'], 'ipv6_address' => @official['ipv6_address'] }
  end

  def request(values = payload, authorized: true, origin: nil, action: 'identity/install')
    body = JSON.generate(values)
    headers = authorized ? "Authorization: Bearer #{@adapter.instance_variable_get(:@account_capability)}\r\n" : ''
    headers += "Origin: #{origin}\r\n" if origin
    sock = Socket.new("POST /account/#{action} HTTP/1.1\r\n#{headers}Content-Length: #{body.bytesize}\r\n\r\n#{body}")
    @adapter.send(:handle_http, sock)
    [sock.response.split[1].to_i, JSON.parse(sock.response.split("\r\n\r\n", 2).last), sock.response]
  end

  def test_first_install_uses_bound_official_addresses_and_private_key_without_ready_claim
    code, snapshot, raw = request
    assert_equal 200, code
    assert_equal true, snapshot['identity_configured']
    assert_equal PUBLIC, snapshot['activated_draft_public_key']
    assert_equal DEVICE, snapshot['activated_draft_device_id']
    assert_equal [:official], @reads
    assert_equal [:reserved, :released], @ports
    template = JSON.parse(File.read(@adapter.send(:template_path)))
    assert_equal PRIVATE, template['private-key']
    assert_equal '10.64.0.2', template['ip']
    assert_equal 'fc00:bbbb::2', template['ipv6']
    assert_equal %w[0.0.0.0/0 ::/0], template['allowed-ips']
    refute template.key?('server')
    refute template.key?('public-key')
    assert_equal 'identity_configured', @adapter.send(:snapshot)[:service_readiness]
    refute @adapter.send(:snapshot).dig(:front, :ready)
    assert_equal 0o600, File.stat(@adapter.send(:template_path)).mode & 0o777
    assert_equal 1, File.stat(@adapter.send(:template_path)).nlink
    refute_includes raw, PRIVATE
    refute_includes raw, NUMBER
  end

  def test_same_identity_completion_is_idempotent_but_another_private_key_cannot_replace_it
    assert_equal 200, request.first
    bytes = File.binread(@adapter.send(:template_path))
    assert_equal 200, request.first
    assert_equal [:reserved, :released], @ports
    changed = payload.merge('private_key' => Base64.strict_encode64('x' * 32))
    assert_equal 'invalid_key', request(changed)[1]['code']
    assert_equal bytes, File.binread(@adapter.send(:template_path))
  end

  def test_caller_addresses_and_missing_receipt_are_not_official_evidence
    assert_equal 'registration_receipt_required', request(payload.merge('ipv4_address' => '10.64.0.99/32'))[1]['code']
    File.unlink(@adapter.send(:registration_receipt_path, Digest::SHA256.hexdigest(NUMBER), PUBLIC))
    assert_equal 'registration_receipt_required', request[1]['code']
    refute File.exist?(@adapter.send(:template_path))
    assert_empty @reads
    assert_empty @ports
  end

  def test_binding_and_confirmation_are_checked_before_any_official_read_or_local_commit
    assert_equal 'account_changed', request(payload.merge('account_fingerprint' => 'b' * 64))[1]['code']
    assert_equal 'confirmation_required', request(payload.merge('confirm' => false))[1]['code']
    assert_equal 403, request(authorized: false).first
    assert_equal 403, request(origin: 'https://example.invalid').first
    assert_empty @reads
    assert_empty @ports
    refute File.exist?(@adapter.send(:template_path))
  end

  def test_existing_live_or_local_identity_is_never_replaced
    @adapter.instance_variable_set(:@front_pid, 99999)
    assert_equal 'engine_running', request[1]['code']
    @adapter.instance_variable_set(:@front_pid, nil)
    File.write(@adapter.send(:template_path), 'original identity', mode: 'w', perm: 0o600)
    assert_equal 422, request.first
    assert_equal 'original identity', File.read(@adapter.send(:template_path))
    refute File.exist?(File.join(@dir, 'identity-installation.json'))
  end

  def test_fresh_official_removal_blocks_installation
    @devices.clear
    assert_equal 'registered_device_missing', request[1]['code']
    refute File.exist?(@adapter.send(:template_path))
    assert_empty @ports
  end

  def test_symlink_hardlink_and_public_template_paths_are_never_followed
    target = File.join(@dir, 'unrelated')
    File.write(target, 'protected', mode: 'w', perm: 0o600)
    File.symlink(target, @adapter.send(:template_path))
    assert_equal 422, request.first
    assert_equal 'protected', File.read(target)
    File.unlink(@adapter.send(:template_path))
    File.link(target, @adapter.send(:template_path))
    assert_equal 422, request.first
    assert_equal 'protected', File.read(target)
    File.unlink(@adapter.send(:template_path))
    File.write(@adapter.send(:template_path), 'protected', mode: 'w', perm: 0o644)
    assert_equal 422, request.first
    assert_equal 'protected', File.read(@adapter.send(:template_path))
  end

  def test_precommit_failure_preserves_setup_and_can_retry_the_exact_identity
    path = @adapter.send(:template_path)
    @adapter.define_singleton_method(:write_private_identity_once) do |target, content|
      raise IOError, 'injected private write failure' if target == path
      super(target, content)
    end
    assert_equal 'identity_install_unknown', request[1]['code']
    refute File.exist?(path)
    assert @adapter.instance_variable_get(:@account_only_mode)
    assert_nil @adapter.instance_variable_get(:@template)
    @adapter.singleton_class.remove_method(:write_private_identity_once)
    assert_equal 200, request.first
  end

  def test_crash_after_atomic_link_recovers_only_its_exact_pending_hardlink
    path = @adapter.send(:template_path)
    pid = fork do
      @adapter.define_singleton_method(:sync_identity_directory) do |target|
        Process.exit!(73) if target == path && File.exist?(path) && File.exist?(path + '.pending')
        super(target)
      end
      request
      Process.exit!(74)
    end
    Process.wait(pid)
    assert_equal 73, $?.exitstatus
    assert_equal 2, File.stat(path).nlink
    @adapter.send(:load_template)
    assert_equal 1, File.stat(path).nlink
    refute File.exist?(path + '.pending')
    assert_equal PUBLIC, @adapter.send(:template_public_key)
  end

  def test_real_listener_conflict_blocks_the_commit_without_touching_existing_listener
    listener = TCPServer.new('127.0.0.1', 0)
    @adapter.instance_variable_get(:@options)[:front_mixed] = listener.addr[1]
    @adapter.singleton_class.remove_method(:reserve_identity_install_ports)
    assert_equal 'engine_running', request[1]['code']
    refute listener.closed?
    refute File.exist?(@adapter.send(:template_path))
  ensure
    listener&.close
  end

  def test_reconcile_recovers_only_the_retained_official_creation_receipt
    code, device, raw = request(payload.slice('account_fingerprint', 'public_key'), action: 'devices/reconcile')
    assert_equal 200, code
    assert_equal @official['ipv4_address'], device.dig('registration', 'ipv4_address')
    refute_includes raw, PRIVATE
    File.unlink(@adapter.send(:registration_receipt_path, Digest::SHA256.hexdigest(NUMBER), PUBLIC))
    code, device = request(payload.slice('account_fingerprint', 'public_key'), action: 'devices/reconcile')
    assert_equal 200, code
    refute device.key?('registration')
    refute device.key?('ipv4_address')
  end

  def test_locks_and_engine_reservations_cover_both_receipt_and_template_commits
    observations, ports = [], @ports
    @adapter.define_singleton_method(:write_private_identity_once) do |path, bytes|
      observations << [File.basename(path), @account_mutex.locked?, @switch_mutex.locked?, ports.dup]
      super(path, bytes)
    end
    assert_equal 200, request.first
    assert_equal %w[bootstrap-defaults.json identity-installation.json wireguard-template.json], observations.map(&:first)
    assert observations.all? { |(_, account, switch, reservations)| account && switch && reservations == [:reserved] }
  end

  def test_crash_before_template_commit_keeps_account_only_and_exact_retry_recovers
    path = @adapter.send(:template_path)
    pid = fork do
      @adapter.define_singleton_method(:write_private_identity_once) do |target, bytes|
        Process.exit!(71) if target == path
        super(target, bytes)
      end
      request
      Process.exit!(72)
    end
    Process.wait(pid)
    assert_equal 71, $?.exitstatus
    refute File.exist?(path)
    assert @adapter.instance_variable_get(:@account_only_mode)
    assert_equal 200, request.first
    assert_equal PUBLIC, @adapter.send(:template_public_key)
  end

  def test_restart_after_install_keeps_clean_route_and_cannot_guess_a_city_or_relay
    assert_equal 200, request.first
    restarted = MullvadAdapter.new(state_dir: @dir)
    restarted.send(:load_template)
    restarted.send(:load_city_workspace)
    restarted.instance_variable_set(:@metadata, { 'wireguard' => { 'relays' => [{ 'hostname' => 'us-sea-wg-401', 'location' => 'us-sea', 'active' => true }] } })
    attempts = []
    restarted.define_singleton_method(:activate) { |name, **| attempts << name; true }
    assert_nil restarted.instance_variable_get(:@options)[:default_relay]
    assert_equal ['--proxy', '', '--noproxy', '*'], restarted.send(:bootstrap_proxy_args)
    assert_equal 'system_default', restarted.instance_variable_get(:@api_route_source)
    assert_nil restarted.send(:recovery_city, nil)
    refute restarted.send(:activate_startup_with_fallback, nil, 'auto', reason: 'startup')
    assert_empty attempts
  end

  def test_missing_core_does_not_exit_account_server_when_normal_lifecycle_resumes
    assert_equal 200, request.first
    calls = []
    @adapter.define_singleton_method(:trap_signals) {}
    @adapter.define_singleton_method(:start_api_server) { calls << :api }
    @adapter.define_singleton_method(:ensure_front) { raise 'mock core unavailable' }
    %i[start_connection_monitor start_local_network_monitor start_control_plane_monitor start_active_health_monitor start_runtime_supervisor].each do |name|
      @adapter.define_singleton_method(name) { calls << name }
    end
    @adapter.define_singleton_method(:start_city_maintenance) { calls << :maintenance; @stop_requested = true }
    @adapter.define_singleton_method(:shutdown) { calls << :shutdown }
    @adapter.run
    assert_equal :api, calls.first
    assert_includes calls, :start_runtime_supervisor
    assert_includes calls, :maintenance
    assert_equal :shutdown, calls.last
    assert_includes @adapter.send(:snapshot)[:last_error], 'mock core unavailable'
    refute_equal 'ready', @adapter.send(:snapshot)[:service_readiness]
  end
end
