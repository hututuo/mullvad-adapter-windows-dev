# frozen_string_literal: true
require_relative 'test_reliability'
require 'minitest/mock'
require 'rbconfig'

class MullvadAuditReliabilityTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('adapter-audit-regressions')
    @adapter = MullvadAdapter.new(state_dir: @dir, validate_configs: false)
  end

  def teardown
    @adapter.instance_variable_get(:@probe_event_writer)&.join(2)
    FileUtils.remove_entry(@dir)
  end

  def test_managed_controller_requests_include_the_matching_private_credential
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    expected = @adapter.send(:controller_secret, port)
    refute_equal expected, @adapter.send(:controller_secret, port + 1)
    refute_equal expected, MullvadAdapter.new(state_dir: @dir).send(:controller_secret, port)
    request = Queue.new
    serving = Thread.new do
      client = server.accept
      headers = []
      while (line = client.gets) && line != "\r\n"
        headers << line
      end
      request << headers.join
      client.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
      client.close
    end
    assert_equal({}, @adapter.send(:http_json, port, '/version'))
    assert_includes Timeout.timeout(1) { request.pop }, "Authorization: Bearer #{expected}"
    refute_includes JSON.generate(@adapter.send(:snapshot)), expected
    assert serving.join(1)
  ensure
    server&.close
    serving&.kill
  end

  def test_front_configuration_is_private_and_authenticates_its_controller
    @adapter.send(:prepare_state_dir)
    @adapter.define_singleton_method(:wait_controller) { |*_, **_| true }
    Process.stub(:spawn, 900_001) { @adapter.send(:ensure_front) }
    path = File.join(@dir, 'front', 'config.json')
    config = JSON.parse(File.read(path))
    assert_equal @adapter.send(:controller_secret, @adapter.instance_variable_get(:@options)[:front_controller]), config['secret']
    assert_equal 0o600, File.stat(path).mode & 0o777
  end

  def test_unconfirmed_bootstrap_cleanup_retains_slot_and_peer_until_reaped
    @adapter.send(:prepare_state_dir)
    @adapter.instance_variable_set(:@account_only_mode, false)
    @adapter.define_singleton_method(:transport_supported?) { |*_| true }
    @adapter.define_singleton_method(:worker_tunnel_config) do |*args|
      [{ 'proxies' => [] }, { endpoint: '192.0.2.1', transport: 'fixture', peer_keys: ['peer'] }]
    end
    @adapter.define_singleton_method(:wait_controller) { |*_, **_| false }
    calls = 0
    @adapter.define_singleton_method(:stop_pid) { |_| raise MullvadAdapter::LocalProbeTimeout, 'worker-stop' }
    relay = { 'hostname' => 'fixture', 'public_key' => 'peer' }
    Process.stub(:spawn, ->(*_, **_) { calls += 1; 900_001 }) do
      assert_raises(MullvadAdapter::LocalProbeTimeout) { @adapter.send(:start_worker, 'a', relay) }
      assert_equal 900_001, @adapter.instance_variable_get(:@workers).dig('a', :pid)
      assert_raises(RuntimeError) { @adapter.send(:start_worker, 'a', relay) }
      assert_raises(RuntimeError) { @adapter.send(:start_worker, 'b', relay) }
      assert_equal 1, calls
    end
    @adapter.define_singleton_method(:stop_pid) { |_| nil }
    assert @adapter.send(:stop_worker, 'a')
    assert_empty @adapter.instance_variable_get(:@workers)
  end

  def test_closed_local_listener_is_indeterminate_not_a_relay_failure
    listener = TCPServer.new('127.0.0.1', 0)
    port = listener.addr[1]
    listener.close
    @adapter.instance_variable_set(:@slot_config, { 'a' => { mixed: port, controller: port } })
    @adapter.instance_variable_set(:@workers, { 'a' => { endpoint: nil } })
    failure = assert_raises(MullvadAdapter::LocalProbeUnavailable) { @adapter.send(:run_readiness_canary, 'a') }
    assert_includes %w[local-socks-connect local-socks-handshake], failure.phase
    refute_equal 'fail', @adapter.send(:classify_canary, ip_data: { status: 'unknown', local_failure: failure.phase })[:relay_liveness]
  end

  def test_cancel_during_bootstrap_reaps_registered_owner
    @adapter.send(:prepare_state_dir)
    @adapter.instance_variable_set(:@account_only_mode, false)
    @adapter.define_singleton_method(:transport_supported?) { |*_| true }
    @adapter.define_singleton_method(:worker_tunnel_config) do |*_|
      [{ 'proxies' => [] }, { peer_keys: ['fixture-peer'] }]
    end
    entered = Queue.new
    @adapter.define_singleton_method(:wait_controller) { |*_, **_| entered << true; sleep 30 }
    spawn = Process.method(:spawn)
    pid = runner = nil
    Process.stub(:spawn, ->(*_, **_) { pid = spawn.call(RbConfig.ruby, '-e', 'sleep 30') }) do
      runner = Thread.new { @adapter.send(:start_worker, 'a', { 'hostname' => 'fixture', 'public_key' => 'fixture-peer' }) }
      Timeout.timeout(2) { entered.pop }
      assert_equal pid, @adapter.instance_variable_get(:@workers).dig('a', :pid)
      runner.kill
      assert runner.join(2)
      assert_empty @adapter.instance_variable_get(:@workers)
      assert_raises(Errno::ESRCH) { Process.kill(0, pid) }
      pid = nil
    end
  ensure
    runner&.kill
    runner&.join(2)
    if pid
      begin Process.kill('KILL', pid); rescue Errno::ESRCH; end
      begin Process.waitpid(pid); rescue Errno::ECHILD; end
    end
  end

  def test_remote_socks_rejection_remains_negative_evidence
    status = Struct.new(:exitstatus) { def success?; false; end }.new(97)
    @adapter.define_singleton_method(:capture_probe_command) { |*_, **_| ['code=000 total=0.01', '', status, 10] }
    assert_equal 'fail', @adapter.send(:curl_proxy_ip_test, 19000, 'http://192.0.2.1', 1)[:status]
    assert_equal 'fail', @adapter.send(:curl_proxy_test, 19000, 'https://example.invalid', 1)[:status]
  end

  def test_independent_success_is_preserved_despite_another_local_probe_failure
    canary = { ip_data: { status: 'unknown', local_failure: 'local-socks-connect' }, inner_dns: { status: 'pass' }, https_data: { status: 'pass' } }
    assert_equal 'pass', @adapter.send(:classify_canary, canary)[:relay_liveness]
    assert_equal 'fail', @adapter.send(:classify_canary, ip_data: { status: 'fail' }, inner_dns: { status: 'fail' })[:relay_liveness]
  end

  def test_stop_and_wake_do_not_wait_for_event_file_mutex
    log = @adapter.instance_variable_get(:@log_mutex)
    log.lock
    stop = Thread.new { @adapter.send(:interrupt_ordered_recovery, stopped: true) }
    assert stop.join(0.3), 'stop must finish while log I/O remains blocked'
    refute @adapter.instance_variable_get(:@health_wait_mutex).locked?
    assert @adapter.instance_variable_get(:@recovery_stopped)
  ensure
    log&.unlock if log&.owned?
    stop&.join(1)
  end

  def test_cancel_at_spawn_return_reaps_the_owned_child
    entered, release = Queue.new, Queue.new
    pid = nil
    trace = TracePoint.new(:c_return) do |tp|
      if Thread.current[:audit_spawn] && tp.method_id == :spawn
        pid = tp.return_value
        entered << true
        release.pop
      end
    end
    trace.enable
    runner = Thread.new do
      Thread.current[:audit_spawn] = true
      @adapter.send(:capture_probe_command, RbConfig.ruby, '-e', 'sleep 30', timeout_seconds: 1, phase: 'fixture')
    end
    Timeout.timeout(2) { entered.pop }
    runner.kill
    release << true
    assert runner.join(1), 'cancel must finish after atomic PID registration'
    assert_raises(Errno::ESRCH) { Process.kill(0, pid) }
    pid = nil
  ensure
    trace&.disable
    release << true if release
    runner&.kill
    runner&.join(1)
    if pid
      begin Process.kill('KILL', pid); rescue Errno::ESRCH; end
      begin Process.waitpid(pid); rescue Errno::ECHILD; end
    end
  end

  def test_slow_status_reader_is_bounded_without_waiting_for_logs
    @adapter.send(:publish_status_snapshot)
    socket = Object.new
    socket.define_singleton_method(:write) { |_| sleep 30 }
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    error = assert_raises(MullvadAdapter::LocalProbeTimeout) { @adapter.send(:respond_status, socket) }
    assert_equal 'status-response', error.phase
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 1.5
  end

  def test_status_correlation_is_returned_and_logged_without_holding_response_for_log_io
    @adapter.send(:publish_status_snapshot)
    client, server = Socket.pair(:UNIX, :STREAM, 0)
    request_id = SecureRandom.uuid
    log = @adapter.instance_variable_get(:@log_mutex)
    log.lock
    serving = Thread.new { @adapter.send(:handle_http, server, Process.clock_gettime(Process::CLOCK_MONOTONIC) - 0.02) }
    client.write("GET /status HTTP/1.1\r\nX-Adapter-Request-Id: #{request_id}\r\n\r\n")
    response = Timeout.timeout(1) { client.read }
    assert_includes response, "X-Adapter-Request-Id: #{request_id}"
    assert_operator response[/X-Adapter-Dispatch-Ms: (\d+)/, 1].to_i, :>=, 20
    assert serving.join(1)
    log.unlock
    @adapter.instance_variable_get(:@probe_event_writer)&.join(1)
    rows = File.readlines(File.join(@dir, 'logs', 'events.jsonl')).map { |line| JSON.parse(line) }
    assert_equal %w[status-request-received status-request-finished], rows.map { |r| r['event'] }
    assert rows.all? { |r| r['request_id'] == request_id }
  ensure
    log&.unlock if log&.owned?
    client&.close
    server&.close unless server&.closed?
    serving&.join(1)
  end
end
