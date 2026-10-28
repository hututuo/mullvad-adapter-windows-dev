# frozen_string_literal: true

require_relative 'minitest_dependencies'
require 'tmpdir'
require 'stringio'
require 'timeout'
require_relative 'mullvad_adapter'

class MullvadConnectionControlTest < Minitest::Test
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
    @dir = Dir.mktmpdir('connection-control')
    @adapter = MullvadAdapter.new(state_dir: @dir)
    @adapter.instance_variable_set(:@account_capability, 'a' * 64)
  end

  def teardown
    @adapter&.instance_variable_get(:@probe_event_writer)&.join(2)
    FileUtils.remove_entry(@dir)
  end

  def request_disconnect(authorized: true, origin: nil)
    headers = authorized ? "Authorization: Bearer #{@adapter.instance_variable_get(:@account_capability)}\r\n" : ''
    headers += "Origin: #{origin}\r\n" if origin
    sock = MemorySocket.new("POST /disconnect HTTP/1.1\r\n#{headers}Content-Length: 0\r\n\r\n")
    @adapter.send(:handle_http, sock)
    [sock.response.split[1].to_i, JSON.parse(sock.response.split("\r\n\r\n", 2).last), sock.response]
  end

  def wait_for_operation(id, state)
    Timeout.timeout(2) do
      Thread.pass until @adapter.send(:operation_snapshot, id)&.dig(:state) == state
    end
    @adapter.send(:operation_snapshot, id)
  end

  def test_disconnect_requires_local_capability_and_rejects_browser_origin
    calls = 0
    @adapter.define_singleton_method(:request_disconnect) do
      calls += 1
      { id: 'fixture-receipt' }
    end

    assert_equal 403, request_disconnect(authorized: false).first
    assert_equal 403, request_disconnect(origin: 'https://example.invalid').first
    assert_equal 0, calls

    code, body = request_disconnect
    assert_equal 202, code
    assert_equal({ 'id' => 'fixture-receipt' }, body)
    assert_equal 1, calls
  end

  def test_disconnect_cancels_pending_action_stops_every_owned_process_and_keeps_account_api_available
    workers = @adapter.instance_variable_get(:@workers)
    workers['a'] = { pid: 101, relay: 'fixture-a' }
    workers['b'] = { pid: 202, relay: 'fixture-b' }
    @adapter.instance_variable_set(:@front_pid, 303)
    stopped_workers = []
    stopped_pids = []
    @adapter.define_singleton_method(:stop_worker) do |slot|
      stopped_workers << slot
      @workers.delete(slot)
      true
    end
    @adapter.define_singleton_method(:stop_pid) do |pid|
      stopped_pids << pid
      nil
    end

    pending_id = 'existing-recovery-operation'
    @adapter.instance_variable_get(:@action_gate_mutex).synchronize do
      @adapter.instance_variable_get(:@operations)[pending_id] = {
        id: pending_id, kind: 'retry-round', state: 'running', cancel_requested: false
      }
      @adapter.instance_variable_set(:@action_pending, { id: pending_id, kind: 'retry-round' })
    end

    receipt = @adapter.send(:request_disconnect)
    id = receipt.fetch(:id)
    assert_equal 'succeeded', wait_for_operation(id, 'succeeded')[:state]

    assert_equal %w[a b], stopped_workers.sort
    assert_equal [303], stopped_pids
    assert_empty workers
    assert_nil @adapter.instance_variable_get(:@front_pid)
    assert @adapter.send(:connections_stopped?)
    assert_equal true, @adapter.send(:connection_control_snapshot)[:account_management_available]
    assert_equal true, @adapter.send(:operation_snapshot, pending_id)[:cancel_requested]
    refute @adapter.send(:network_attempt_current?)
    assert_equal 'stopped', @adapter.send(:snapshot)[:status]
  end

  def test_duplicate_disconnect_while_cleanup_is_in_progress_returns_same_receipt
    @adapter.instance_variable_get(:@switch_mutex).lock
    first = @adapter.send(:request_disconnect)
    Timeout.timeout(2) do
      Thread.pass until @adapter.send(:operation_snapshot, first[:id])&.dig(:state) == 'running'
    end
    second = @adapter.send(:request_disconnect)

    assert_equal first, second
    assert_equal 1, @adapter.instance_variable_get(:@operations).values.count { |operation| operation[:kind] == 'disconnect' }
    assert_equal 'running', @adapter.send(:operation_snapshot, first[:id])[:state]
  ensure
    @adapter.instance_variable_get(:@switch_mutex).unlock if @adapter.instance_variable_get(:@switch_mutex).owned?
    thread = @adapter.instance_variable_get(:@disconnect_thread)
    thread&.join(2)
  end

  def test_stop_intent_persists_and_supervisor_methods_do_not_restart_services_after_reload
    @adapter.define_singleton_method(:stop_worker) { |slot| @workers.delete(slot); true }
    @adapter.define_singleton_method(:stop_pid) { |_pid| nil }
    @adapter.instance_variable_get(:@workers)['a'] = { pid: 404 }
    @adapter.instance_variable_set(:@front_pid, 505)
    id = @adapter.send(:request_disconnect).fetch(:id)
    wait_for_operation(id, 'succeeded')
    assert_equal({ 'schema' => 1, 'stopped' => true }, JSON.parse(File.read(@adapter.send(:connection_control_path))))

    reloaded = MullvadAdapter.new(state_dir: @dir)
    reloaded.send(:load_connection_control)
    assert reloaded.send(:connections_stopped?)

    %i[ensure_front supervise_front_runtime supervise_worker_runtime retry_disconnected_runtime].each do |method|
      result = ConnectionControl.instance_method(method).bind(reloaded).call
      assert_nil result, "#{method} should return before reaching the tunnel implementation while stopped"
    end
    assert_equal 'stopped', reloaded.send(:snapshot)[:status]
    assert_equal true, reloaded.send(:connection_control_snapshot)[:account_management_available]
  end

  def test_stop_cancels_old_recovery_epoch_and_does_not_allow_stale_resume
    old_epoch = @adapter.instance_variable_get(:@mutex).synchronize { @adapter.instance_variable_get(:@recovery_control_epoch) }
    @adapter.define_singleton_method(:stop_worker) { |_slot| true }
    @adapter.define_singleton_method(:stop_pid) { |_pid| nil }
    id = @adapter.send(:request_disconnect).fetch(:id)
    wait_for_operation(id, 'succeeded')

    assert_operator @adapter.instance_variable_get(:@mutex).synchronize { @adapter.instance_variable_get(:@recovery_control_epoch) }, :>, old_epoch
    error = assert_raises(MullvadAdapter::LocalNetworkInterrupted) do
      @adapter.send(:resume_connections_for_user, expected_epoch: old_epoch)
    end
    assert_instance_of MullvadAdapter::LocalNetworkInterrupted, error
    assert @adapter.send(:connections_stopped?)
    assert_equal({ 'schema' => 1, 'stopped' => true }, JSON.parse(File.read(@adapter.send(:connection_control_path))))
  end

  def test_cleanup_uncertainty_is_reported_as_pending_not_stopped
    @adapter.instance_variable_get(:@workers)['a'] = { pid: 606 }
    @adapter.define_singleton_method(:stop_worker) do |_slot|
      raise MullvadAdapter::LocalProbeUnavailable, 'fixture-worker-cleanup'
    end
    @adapter.define_singleton_method(:stop_pid) { |_pid| nil }

    id = @adapter.send(:request_disconnect).fetch(:id)
    operation = wait_for_operation(id, 'failed')
    snapshot = @adapter.send(:snapshot)

    assert_equal 'failed', operation[:state]
    assert_equal 'stop_pending', snapshot[:status]
    refute_equal 'stopped', snapshot[:service_readiness]
    assert @adapter.send(:connections_stopped?)
    assert_equal '停止尚未确认完成；已禁止新建连接，请重试并保留诊断', snapshot.dig(:connection_control, :stop_error)
    assert_equal({ 'schema' => 1, 'stopped' => true }, JSON.parse(File.read(@adapter.send(:connection_control_path))))
  end

  def test_failed_stop_persistence_still_cleans_data_plane_and_fails_operation
    workers = @adapter.instance_variable_get(:@workers)
    workers['a'] = { pid: 701 }
    @adapter.instance_variable_set(:@front_pid, 702)
    stopped_workers = []
    stopped_pids = []
    control_path = @adapter.send(:connection_control_path)
    original_atomic_write = @adapter.method(:atomic_account_file)
    @adapter.define_singleton_method(:atomic_account_file) do |path, content|
      raise IOError, 'synthetic stop-state write failure' if path == control_path
      original_atomic_write.call(path, content)
    end
    @adapter.define_singleton_method(:stop_worker) do |slot|
      stopped_workers << slot
      @workers.delete(slot)
      true
    end
    @adapter.define_singleton_method(:stop_pid) do |pid|
      stopped_pids << pid
      nil
    end

    id = @adapter.send(:request_disconnect).fetch(:id)
    operation = wait_for_operation(id, 'failed')
    stop_error = @adapter.send(:connection_control_snapshot)[:stop_error]

    assert_equal 'failed', operation[:state]
    assert_equal ['a'], stopped_workers
    assert_equal [702], stopped_pids
    assert_empty workers
    assert_nil @adapter.instance_variable_get(:@front_pid)
    assert @adapter.send(:connections_stopped?)
    refute_nil stop_error
    refute_empty stop_error
    assert_match(/保存|停止/, stop_error)
    assert_equal stop_error, operation[:error]
    refute File.exist?(control_path), 'a failed mocked write must not leave a stop record'
  end

  def test_worker_stop_failure_still_attempts_remaining_workers_and_front
    workers = @adapter.instance_variable_get(:@workers)
    workers['a'] = { pid: 801 }
    workers['b'] = { pid: 802 }
    @adapter.instance_variable_set(:@front_pid, 803)
    attempted_workers = []
    attempted_pids = []
    @adapter.define_singleton_method(:stop_worker) do |slot|
      attempted_workers << slot
      raise MullvadAdapter::LocalProbeUnavailable, 'synthetic first worker cleanup failure' if slot == 'a'
      @workers.delete(slot)
      true
    end
    @adapter.define_singleton_method(:stop_pid) do |pid|
      attempted_pids << pid
      nil
    end

    id = @adapter.send(:request_disconnect).fetch(:id)
    operation = wait_for_operation(id, 'failed')
    snapshot = @adapter.send(:snapshot)

    assert_equal 'failed', operation[:state]
    assert_equal %w[a b], attempted_workers.sort
    assert_equal [803], attempted_pids
    assert_equal({ 'a' => { pid: 801 } }, workers)
    assert_nil @adapter.instance_variable_get(:@front_pid)
    assert @adapter.send(:connections_stopped?)
    assert_equal 'stop_pending', snapshot[:status]
    assert_equal '停止尚未确认完成；已禁止新建连接，请重试并保留诊断', snapshot.dig(:connection_control, :stop_error)
  end
end
