# frozen_string_literal: true

require_relative 'test_reliability'
require 'rbconfig'
require 'minitest/mock'

class MullvadRuntimeDeadlineTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('mullvad-runtime-deadlines')
    @adapter = ReliabilityAdapter.new(@dir)
  end

  def teardown
    @adapter.instance_variable_get(:@probe_event_writer)&.join(1)
    FileUtils.rm_rf(@dir)
  end

  def persisted_probe_events
    @adapter.instance_variable_get(:@probe_event_writer)&.join(1)
    File.readlines(File.join(@dir, 'logs', 'events.jsonl'))
  end

  def run_child(script, timeout: 1)
    @adapter.send(:capture_probe_command, RbConfig.ruby, '-e', script,
                  timeout_seconds: timeout, phase: 'fixture')
  ensure
    @adapter.instance_variable_get(:@probe_event_writer)&.join(1)
  end

  # Capture ownership at spawn, not through a child-written file. Under load
  # the deadline can correctly kill Ruby before its interpreter runs the script.
  def run_tracked_child(script, timeout:, phase: 'fixture')
    spawn = Process.method(:spawn)
    Process.stub(:spawn, lambda { |*args, **options| @fixture_child_pid = spawn.call(*args, **options) }) do
      @adapter.send(:capture_probe_command, RbConfig.ruby, '-e', script,
                    timeout_seconds: timeout, phase: phase)
    end
  end

  def test_probe_timeout_and_owned_child_cleanup_do_not_wait_for_the_log_mutex
    path = File.join(@dir, 'blocked-log-child')
    mutex = @adapter.instance_variable_get(:@log_mutex)
    mutex.lock
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    runner = Thread.new do
      begin
        run_tracked_child("File.write(#{path.dump}, Process.pid); sleep 30",
                          timeout: 0.2, phase: 'blocked-log')
      rescue MullvadAdapter::LocalProbeTimeout => error
        error
      end
    end
    assert runner.join(0.8), 'probe deadline/cleanup must finish while another thread owns the logger'
    error = runner.value
    assert_kind_of MullvadAdapter::LocalProbeTimeout, error
    assert_equal 'blocked-log', error.phase
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.8
    pid = @fixture_child_pid
    assert_raises(Errno::ESRCH) { Process.kill(0, pid) }
    assert_raises(Errno::ECHILD) { Process.waitpid(pid, Process::WNOHANG) }
    mutex.unlock
    assert @adapter.instance_variable_get(:@probe_event_writer)&.join(1)
    event = JSON.parse(persisted_probe_events.last)
    assert_equal 'local-command-timeout', event['event']
    assert_operator event.fetch('spawn_ms'), :>=, 0
    assert_operator event.fetch('max_poll_gap_ms'), :>=, 0
  ensure
    mutex&.unlock if mutex&.owned?
    runner&.join(1)
  end

  def test_slow_spawn_is_distinguished_from_capture_wait_without_logging_arguments
    spawn = Process.method(:spawn)
    Process.stub(:spawn, lambda { |*args, **options| sleep 0.12; spawn.call(*args, **options) }) do
      assert_raises(MullvadAdapter::LocalProbeTimeout) do
        run_child('sleep 30 # private fixture', timeout: 0.05)
      end
    end
    event = JSON.parse(persisted_probe_events.last)
    assert_equal 'local-command-timeout', event['event']
    assert_operator event.fetch('spawn_ms'), :>=, 120
    assert_operator event.fetch('capture_ms'), :<, 100
    refute_includes JSON.generate(event), 'private fixture'
  end

  def test_writer_thread_creation_failure_cannot_replace_local_timeout
    Thread.stub(:new, ->(*_, **_) { raise ThreadError, 'fixture thread limit' }) do
      assert_raises(MullvadAdapter::LocalProbeTimeout) { run_child('sleep 30', timeout: 0.1) }
    end
    assert_equal 1, @adapter.instance_variable_get(:@probe_events).length
    @adapter.send(:log_probe_event, 'fixture-writer-recovered')
    assert @adapter.instance_variable_get(:@probe_event_writer)&.join(1)
    events = persisted_probe_events.map { |line| JSON.parse(line) }
    assert_equal %w[local-command-timeout fixture-writer-recovered], events.map { |event| event['event'] }
  end

  def test_probe_child_events_retain_parent_attempt_trace
    keys = %i[adapter_operation_id adapter_recovery_id adapter_attempt_id]
    previous = keys.to_h { |key| [key, Thread.current[key]] }
    keys.each { |key| Thread.current[key] = "fixture-#{key}" }
    probe = @adapter.send(:spawn_probe) { run_child('sleep 30', timeout: 0.1) }
    assert_equal 'fixture', probe.value[:local_timeout]
    event = JSON.parse(persisted_probe_events.last)
    assert_equal 'fixture-adapter_operation_id', event['operation_id']
    assert_equal 'fixture-adapter_recovery_id', event['recovery_id']
    assert_equal 'fixture-adapter_attempt_id', event['attempt_id']
  ensure
    previous&.each { |key, value| Thread.current[key] = value }
  end

  def test_slow_log_writer_has_one_bounded_queue_and_reports_discarded_entries
    entered = Queue.new
    release = Queue.new
    original = @adapter.method(:log_event)
    @adapter.define_singleton_method(:log_event) do |name, fields|
      if fields[:fixture] == 'first'
        entered << true
        release.pop
      end
      original.call(name, fields)
    end
    @adapter.send(:log_probe_event, 'fixture', fixture: 'first')
    Timeout.timeout(1) { entered.pop }
    writer = @adapter.instance_variable_get(:@probe_event_writer)
    200.times { |i| @adapter.send(:log_probe_event, 'fixture', sequence: i) }
    assert_equal 128, @adapter.instance_variable_get(:@probe_events).size
    assert_same writer, @adapter.instance_variable_get(:@probe_event_writer)
    release << true
    assert writer.join(1)
    events = persisted_probe_events.map { |line| JSON.parse(line) }
    assert_equal 129, events.length
    assert_equal 72, events.sum { |event| event.fetch('dropped_probe_events', 0) }
    assert_equal 199, events.last['sequence']
  ensure
    release << true if release
  end

  def test_runner_drains_both_streams_without_unbounded_retention
    stdout, stderr, status, elapsed = run_child('STDOUT.write("a" * 200_000); STDERR.write("b" * 200_000)')
    assert status.success?
    assert_equal 65_536, stdout.bytesize
    assert_equal 65_536, stderr.bytesize
    assert_operator elapsed, :<, 1000
  end

  def test_hung_probe_is_killed_and_reaped_without_waiting_for_its_own_timeout
    path = File.join(@dir, 'child-pid')
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    error = assert_raises(MullvadAdapter::LocalProbeTimeout) do
      run_tracked_child("File.write(#{path.dump}, Process.pid); trap('TERM') {}; sleep 30", timeout: 0.25)
    end
    assert_equal 'fixture', error.phase
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 1
    pid = @fixture_child_pid
    assert_raises(Errno::ESRCH) { Process.kill(0, pid) }
    assert_raises(Errno::ECHILD) { Process.waitpid(pid, Process::WNOHANG) }
    event = JSON.parse(persisted_probe_events.last)
    assert_equal 'local-command-timeout', event['event']
    assert_equal MullvadAdapter::SOURCE_SHA256, event['source_sha256']
    refute_includes JSON.generate(event), path
  end

  def test_descendant_holding_output_pipe_cannot_wedge_runner_after_parent_exits
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_raises(MullvadAdapter::LocalProbeTimeout) do
      run_child('fork { sleep 30 }; exit!', timeout: 0.25)
    end
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 1
  end

  def test_group_signal_permission_error_preserves_timeout_and_reaps_owned_child
    path = File.join(@dir, 'permission-child-pid')
    kill = Process.method(:kill)
    signals = []
    denied_group = lambda do |signal, pid|
      signals << [signal, pid]
      raise Errno::EPERM if pid.negative?
      kill.call(signal, pid)
    end
    Process.stub(:kill, denied_group) do
      error = assert_raises(MullvadAdapter::LocalProbeTimeout) do
        run_tracked_child("File.write(#{path.dump}, Process.pid); sleep 30", timeout: 0.25)
      end
      assert_equal 'fixture', error.phase
    end
    pid = @fixture_child_pid
    assert_equal [['KILL', -pid], ['KILL', pid]], signals
    assert_raises(Errno::ESRCH) { kill.call(0, pid) }
    assert_raises(Errno::ECHILD) { Process.waitpid(pid, Process::WNOHANG) }
  end

  def test_denied_child_cleanup_is_bounded_and_does_not_mask_timeout
    path = File.join(@dir, 'denied-child-pid')
    signals = []
    deny = lambda { |signal, pid| signals << [signal, pid]; raise Errno::EPERM }
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    Process.stub(:kill, deny) do
      assert_raises(MullvadAdapter::LocalProbeTimeout) do
        run_child("File.write(#{path.dump}, Process.pid); sleep 0.6", timeout: 0.25)
      end
    end
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 1.2
    pid = File.read(path).to_i
    assert_equal [['KILL', -pid], ['KILL', pid]], signals
    events = persisted_probe_events.map { |line| JSON.parse(line) }
    assert_equal %w[group-signal child-signal], events.select { |e| e['event'] == 'local-command-cleanup-deferred' }.map { |e| e['operation'] }
  ensure
    begin
      if path && File.file?(path)
        pid = File.read(path).to_i
        Process.kill('KILL', pid) unless Process.waitpid(pid, Process::WNOHANG)
      end
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    end
  end

  def test_reaped_group_leader_is_never_signalled_by_positive_pid
    signals = []
    Process.stub(:kill, lambda { |signal, pid| signals << [signal, pid]; raise Errno::EPERM }) do
      @adapter.send(:terminate_probe_group, 99_999, 'fixture', child_unreaped: false)
    end
    assert_equal [['KILL', -99_999]], signals
  end

  def test_local_spawn_permission_failure_is_indeterminate_without_secret_arguments
    Process.stub(:spawn, ->(*_, **_) { raise Errno::EPERM }) do
      error = assert_raises(MullvadAdapter::LocalProbeUnavailable) { run_child('private fixture argument') }
      assert_kind_of MullvadAdapter::LocalProbeTimeout, error
      assert_equal 'fixture', error.phase
      assert_equal 'local probe unavailable: fixture', error.message
    end
    event = JSON.parse(persisted_probe_events.last)
    assert_equal 'local-command-unavailable', event['event']
    assert_equal 'spawn', event['operation']
    assert_equal 'Errno::EPERM', event['error_class']
    refute_includes JSON.generate(event), 'private fixture argument'
  end

  def test_cancelled_probe_thread_reaps_only_its_own_child
    path = File.join(@dir, 'cancel-pid')
    thread = Thread.new { run_child("File.write(#{path.dump}, Process.pid); sleep 30", timeout: 20) }
    Timeout.timeout(2) { sleep 0.005 until File.exist?(path) }
    pid = File.read(path).to_i
    thread.kill
    assert thread.join(1), 'probe cleanup must not retain an unbounded Open3 waiter'
    assert_raises(Errno::ESRCH) { Process.kill(0, pid) }
  ensure
    thread&.kill
    thread&.join(1)
  end

  def test_controller_budget_includes_stuck_listener_ownership_command
    runner = @adapter.method(:capture_probe_command)
    @adapter.define_singleton_method(:process_alive?) { |_| true }
    @adapter.define_singleton_method(:capture_probe_command) do |*_, timeout_seconds:, phase:|
      runner.call(RbConfig.ruby, '-e', 'sleep 30', timeout_seconds: timeout_seconds, phase: phase)
    end
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    refute @adapter.send(:wait_controller, 12_345, 0.15, pid: 99_999)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.7
  end

  def test_canary_aggregate_deadline_does_not_wait_forever_for_a_probe_thread
    # Use the real canary coordinator, with no sockets/engines and a hung leaf.
    @adapter.define_singleton_method(:run_canary, MullvadAdapter.instance_method(:run_canary))
    @adapter.define_singleton_method(:canary_budget_seconds) { 0.08 }
    @adapter.instance_variable_get(:@workers)['a'] = { endpoint: '192.0.2.1' }
    @adapter.define_singleton_method(:outer_ping_test) { |*_| raise 'readiness must not run optional ICMP' }
    @adapter.define_singleton_method(:curl_proxy_ip_test) { |*_| sleep 30 }
    @adapter.define_singleton_method(:inner_dns_tcp_test) { |*_| { status: 'pass' } }
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_raises(MullvadAdapter::LocalProbeTimeout) { @adapter.send(:run_readiness_canary, 'a') }
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.7
  end

  def test_optional_icmp_cannot_delay_successful_readiness
    @adapter.define_singleton_method(:run_canary, MullvadAdapter.instance_method(:run_canary))
    @adapter.instance_variable_get(:@workers)['a'] = { endpoint: '192.0.2.1' }
    @adapter.define_singleton_method(:outer_ping_test) { |*_| sleep 30 }
    @adapter.define_singleton_method(:curl_proxy_ip_test) { |*_| { status: 'pass' } }
    @adapter.define_singleton_method(:inner_dns_tcp_test) { |*_| { status: 'pass' } }
    @adapter.define_singleton_method(:curl_proxy_test) { |*_| { status: 'pass' } }
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result = @adapter.send(:run_readiness_canary, 'a')
    assert_equal 'ready', @adapter.send(:classify_canary, result)[:service_readiness]
    assert_equal 'skip', result.dig(:ping_data, :status)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.7
  end

  def test_literal_ip_failure_with_working_domain_does_not_restart_front_or_wake_recovery
    @adapter.seed_active
    @adapter.instance_variable_get(:@options)[:front_data_probe_interval] = 0
    @adapter.instance_variable_set(:@front_pid, 77_777)
    @adapter.define_singleton_method(:curl_proxy_ip_test) { |*_| { status: 'fail', exit_code: 28 } }
    @adapter.define_singleton_method(:curl_proxy_test) { |*_| { status: 'pass', http_code: 204 } }
    worker = @adapter.instance_variable_get(:@workers).fetch('a')
    3.times { @adapter.send(:supervise_front_data_path, 'a', worker) }
    assert_equal 77_777, @adapter.instance_variable_get(:@front_pid)
    assert_equal 'pass', @adapter.send(:snapshot).dig(:front, :data_path, :status)
    refute @adapter.instance_variable_get(:@health_wake_pending)
    events = persisted_probe_events.map { |line| JSON.parse(line) }
    assert_equal 1, events.count { |event| event['event'] == 'front-target-degraded' }
    refute events.any? { |event| event['event'] == 'front-repair-started' }
  end

  def test_local_candidate_timeout_preserves_active_worker_and_is_not_recorded_as_bad_ss
    @adapter.seed_active
    original = @adapter.method(:start_worker)
    @adapter.define_singleton_method(:start_worker) do |slot, relay, **options|
      raise MullvadAdapter::LocalProbeTimeout, 'worker-controller' if relay['hostname'] == 'two'
      original.call(slot, relay, **options)
    end
    evidence = {}
    refute @adapter.send(:activate, 'two', reason: 'health-recovery', attempt_evidence: evidence)
    assert_equal 'worker-controller', evidence[:local_failure]
    refute evidence[:relay_failed]
    assert_equal 'one', @adapter.send(:snapshot)[:active_relay]
    assert_equal ['a'], @adapter.instance_variable_get(:@workers).keys
    refute File.exist?(File.join(@dir, 'ss-endpoints.json')), 'local failure must not poison SS history'
  end

  def test_local_probe_timeout_does_not_increment_remote_failure_streak
    @adapter.seed_active
    @adapter.define_singleton_method(:run_readiness_canary) do |_|
      raise MullvadAdapter::LocalProbeTimeout, 'ip-data'
    end
    assert_equal :retry, @adapter.send(:check_active_health_once)
    assert_equal 0, @adapter.instance_variable_get(:@health_fail_streak)
    assert_equal 'ready', @adapter.send(:snapshot)[:status]
    assert_equal 0, @adapter.instance_variable_get(:@metrics)[:auto_recovery_attempts]
  end

  def test_automatic_recovery_defers_local_bootstrap_failure_without_burning_other_relays
    @adapter.seed_active
    @adapter.instance_variable_set(:@health_fail_streak, 1)
    @adapter.define_singleton_method(:run_readiness_canary) do |_|
      { ip_data: { status: 'fail' }, inner_dns: { status: 'fail' }, https_data: { status: 'skip' } }
    end
    @adapter.define_singleton_method(:ss_endpoint_candidates) { |_, **_|  [['192.0.2.1', 20_484, 'fixture']] }
    @adapter.define_singleton_method(:recovery_relay_candidates) { |*_, **_| %w[two three] }
    attempts = []
    @adapter.define_singleton_method(:start_worker) do |_, relay, **_|
      attempts << relay['hostname']
      raise MullvadAdapter::LocalProbeTimeout, 'worker-controller'
    end
    @adapter.send(:check_active_health_once)
    assert_equal ['one'], attempts
    quarantine = @adapter.instance_variable_get(:@recovery_quarantine)
    refute quarantine.key?('two')
    refute quarantine.key?('three')
    assert_equal 'one', @adapter.send(:snapshot)[:active_relay]
    events = persisted_probe_events.map { |line| JSON.parse(line) }
    assert events.any? { |event| event['event'] == 'recovery-local-deferred' }
  end

  def test_front_local_probe_deadline_is_not_a_negative_front_observation
    @adapter.seed_active
    @adapter.instance_variable_get(:@options)[:front_data_probe_interval] = 0
    @adapter.instance_variable_set(:@front_pid, 77_777)
    @adapter.define_singleton_method(:curl_proxy_ip_test) { |*_| raise MullvadAdapter::LocalProbeTimeout, 'ip-data' }
    @adapter.send(:supervise_front_data_path, 'a', @adapter.instance_variable_get(:@workers).fetch('a'))
    assert_equal 77_777, @adapter.instance_variable_get(:@front_pid)
    assert_equal 0, @adapter.instance_variable_get(:@front_data_probe_failures)
    refute @adapter.instance_variable_get(:@health_wake_pending)
    events = persisted_probe_events.map { |line| JSON.parse(line) }
    assert events.any? { |event| event['event'] == 'front-observation-deferred' }
    refute events.any? { |event| event['event'] == 'front-path-failed' }
  end

  def test_controller_failure_does_not_restart_a_front_with_working_alternate_service
    @adapter.seed_active
    @adapter.instance_variable_set(:@front_pid, 77_777)
    @adapter.instance_variable_set(:@front_probe_failures, 2)
    @adapter.define_singleton_method(:process_alive?) { |_| true }
    @adapter.define_singleton_method(:http_json) { |*_, **_| raise 'fixture controller unavailable' }
    @adapter.define_singleton_method(:curl_proxy_ip_test) { |*_| { status: 'fail' } }
    @adapter.define_singleton_method(:curl_proxy_test) { |*_| { status: 'pass' } }
    @adapter.send(:supervise_front_runtime)
    assert_equal 77_777, @adapter.instance_variable_get(:@front_pid)
    assert @adapter.send(:snapshot).dig(:front, :controller_degraded)
    refute @adapter.events.any? { |event| event.first == :stop }
  end

  def test_slow_drip_controller_response_cannot_reset_total_startup_budget
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    writer = Thread.new do
      socket = server.accept
      while (line = socket.gets) && line != "\r\n"
        # Consume only the request headers.
      end
      socket.write("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
      100.times { socket.write(' '); sleep 0.01 }
    rescue IOError, SystemCallError
      nil
    ensure
      socket&.close
    end
    writer.report_on_exception = false
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    refute @adapter.send(:wait_controller, port, 0.15)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.7
  ensure
    server&.close
    writer&.kill
    writer&.join(1)
  end

  def test_startup_local_controller_failure_does_not_quarantine_or_try_next_relay
    attempts = []
    @adapter.define_singleton_method(:start_worker) do |_, relay, **_|
      attempts << relay['hostname']
      raise MullvadAdapter::LocalProbeTimeout, 'worker-controller'
    end
    refute @adapter.send(:activate_startup_with_fallback, 'one', 'ss', reason: 'startup')
    assert_equal ['one'], attempts
    assert_empty @adapter.instance_variable_get(:@recovery_quarantine)
  end

  def test_worker_crash_local_bootstrap_failure_preserves_city_intent_without_quarantine
    @adapter.seed_active
    @adapter.define_singleton_method(:process_alive?) { |_| false }
    attempts = []
    @adapter.define_singleton_method(:start_worker) do |_, relay, **_|
      attempts << relay['hostname']
      raise MullvadAdapter::LocalProbeTimeout, 'worker-controller'
    end
    @adapter.send(:supervise_worker_runtime)
    assert_equal ['one'], attempts
    assert_empty @adapter.instance_variable_get(:@recovery_quarantine)
    assert_equal 'one', @adapter.send(:snapshot)[:active_relay]
    assert_equal 'unknown', @adapter.send(:snapshot)[:relay_liveness]
    assert_equal 0, @adapter.instance_variable_get(:@metrics)[:auto_recovery_failures]
  end

  def test_same_peer_local_bootstrap_timeout_is_unknown_not_remote_failure
    @adapter.seed_active
    attempts = []
    @adapter.define_singleton_method(:start_worker) do |_, relay, **_|
      attempts << relay['hostname']
      raise MullvadAdapter::LocalProbeTimeout, 'worker-controller'
    end
    evidence = {}
    refute @adapter.send(:activate, 'one', reason: 'ss-endpoint-recovery', attempt_evidence: evidence)
    assert_equal ['one'], attempts
    assert_equal 'worker-controller', evidence[:local_failure]
    assert_equal 'unknown', @adapter.send(:snapshot)[:relay_liveness]
    refute evidence[:relay_failed]
    assert_empty @adapter.instance_variable_get(:@recovery_quarantine)
  end

  def test_explicit_reconnect_with_local_rollback_failure_does_not_quarantine_or_fallback
    @adapter.seed_active
    attempts = []
    @adapter.define_singleton_method(:start_worker) do |_, relay, **_|
      attempts << relay['hostname']
      raise MullvadAdapter::LocalProbeTimeout, 'worker-controller'
    end
    sock = StringIO.new
    @adapter.send(:accepted_async, sock, 'one', 'reconnect', 'ss')
    Timeout.timeout(2) { sleep 0.001 while @adapter.send(:action_pending?) }
    assert_equal %w[one one], attempts, 'one candidate and one local rollback, without exhausting other relays'
    assert_equal 'unknown', @adapter.send(:snapshot)[:relay_liveness]
    assert_empty @adapter.instance_variable_get(:@recovery_quarantine)
    refute File.exist?(File.join(@dir, 'ss-endpoints.json'))
  end

  def test_manual_repair_local_bootstrap_failure_does_not_quarantine_candidate
    @adapter.seed_active
    @adapter.instance_variable_get(:@state).merge!(status: 'data_fail', relay_liveness: 'fail', service_readiness: 'data_fail')
    @adapter.define_singleton_method(:diagnose_network) { { code: 'mullvad_path' } }
    @adapter.define_singleton_method(:supervise_front_runtime) { nil }
    @adapter.define_singleton_method(:recovery_relay_candidates) { |*_, **_| %w[two three] }
    attempts = []
    @adapter.define_singleton_method(:start_worker) do |_, relay, **_|
      attempts << relay['hostname']
      raise MullvadAdapter::LocalProbeTimeout, 'worker-controller'
    end
    refute @adapter.send(:repair_connection)
    assert_equal ['one'], attempts
    assert_empty @adapter.instance_variable_get(:@recovery_quarantine)
  end
end
