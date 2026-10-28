# frozen_string_literal: true

# Stop data-plane work while retaining the independent local account API.
# A persisted manual stop survives launchd restarts. Only an explicit connection
# operation resumes it; monitoring and closing the UI cannot resume traffic.
module ConnectionControl
  def initialize(options)
    @connection_control_mutex = Mutex.new
    @connections_stopped = false
    @connection_stop_id = nil
    @connection_stop_error = nil
    super
  end

  def connection_control_path
    File.join(@state_dir, 'connection-control.json')
  end

  def load_connection_control
    return unless File.exist?(connection_control_path) || File.symlink?(connection_control_path)
    data = JSON.parse(read_private_identity_file(connection_control_path))
    raise 'invalid connection control' unless data == { 'schema' => 1, 'stopped' => true } || data == { 'schema' => 1, 'stopped' => false }
    @connections_stopped = data['stopped']
  rescue StandardError
    @connections_stopped = true
    @connection_stop_error = '停止状态记录无法验证；保持停止，可明确重新连接'
  end

  def connections_stopped?
    @connections_stopped == true
  end

  def connection_control_snapshot
    { stopped: connections_stopped?, stop_operation_id: @connection_stop_id,
      stop_error: @connection_stop_error, account_management_available: true }
  end

  def snapshot
    value = super.merge(connection_control: connection_control_snapshot)
    operation = @action_gate_mutex.synchronize { @operations[@connection_stop_id]&.dup }
    decorate_connection_snapshot(value, operation)
  end

  def decorate_status_snapshot(copy)
    value = super
    return false unless value
    unless @action_gate_mutex.try_lock
      @status_publication_defer_reason = 'action_busy'
      return false
    end
    begin
      operation = @operations[@connection_stop_id]&.dup
    ensure
      @action_gate_mutex.unlock
    end
    value[:connection_control] = connection_control_snapshot
    decorate_connection_snapshot(value, operation)
  end

  def decorate_connection_snapshot(value, operation)
    if connections_stopped?
      state = operation && %w[queued running].include?(operation[:state]) ? 'stopping' : @workers.empty? && !@front_pid ? 'stopped' : 'stop_pending'
      value.merge!(status: state, service_readiness: state, relay_liveness: 'unknown')
    end
    value
  end

  def network_attempt_current?
    !connections_stopped? && super
  end

  def ensure_front
    return if connections_stopped?
    super
  end

  def supervise_front_runtime
    return if connections_stopped?
    super
  end

  def supervise_worker_runtime
    return if connections_stopped?
    super
  end

  def retry_disconnected_runtime
    return if connections_stopped? || identity_registration_blocked?
    super
  end

  def observe_control_plane_once
    return if connections_stopped?
    super
  end

  def check_active_health_once
    return if connections_stopped?
    super
  end

  def maintain_city_candidates_once
    return if connections_stopped?
    super
  end

  def resume_connections_for_user(expected_epoch: nil)
    @connection_control_mutex.synchronize do
      raise MullvadAdapter::LocalNetworkInterrupted if expected_epoch && @mutex.synchronize { @recovery_control_epoch != expected_epoch }
      state = @action_gate_mutex.synchronize { @operations[@connection_stop_id]&.dig(:state) }
      raise MullvadAdapter::AccountError.new('connection_stopping', '停止尚未完成，请等待清理后再连接') if %w[queued running].include?(state)
      atomic_account_file(connection_control_path, JSON.generate(schema: 1, stopped: false)) if connections_stopped?
      @connections_stopped = false
      @connection_stop_error = nil
    end
  end

  def request_disconnect
    @connection_control_mutex.synchronize do
      existing = @action_gate_mutex.synchronize { @operations[@connection_stop_id]&.dup }
      return { id: existing[:id] } if existing && %w[queued running].include?(existing[:state])
      @connections_stopped = true
      begin
        atomic_account_file(connection_control_path, JSON.generate(schema: 1, stopped: true))
        @connection_stop_error = nil
      rescue StandardError
        @connection_stop_error = '本次已暂停连接，但停止意图未成功保存；重启前请再次停止'
      end
      interrupt_ordered_recovery(stopped: true)
      id = SecureRandom.uuid
      @connection_stop_id = id
      @action_gate_mutex.synchronize do
        @operations.each_value { |op| op[:cancel_requested] = true if %w[queued running].include?(op[:state]) }
        @operations[id] = { id: id, kind: 'disconnect', state: 'queued', stage: 'stopping',
          message: '停止恢复与测速，正在清理全部连接；账号管理保留', accepted_at: Time.now.iso8601 }
      end
      @mutex.synchronize { @state[:generation] += 1 }
      @disconnect_thread = Thread.new do
        Thread.current[:adapter_operation_id] = id
        begin
          update_operation(state: 'running')
          deadline = monotonic_now + 45
          until @switch_mutex.try_lock
            raise MullvadAdapter::LocalProbeTimeout, 'disconnect-cleanup' if monotonic_now >= deadline
            sleep 0.05
          end
          begin
            cleanup_errors = []
            @workers.keys.each do |slot|
              begin
                stop_worker(slot)
              rescue StandardError
                cleanup_errors << slot
              end
            end
            begin
              stop_pid(@front_pid) if @front_pid
              @front_pid = nil
            rescue StandardError
              cleanup_errors << 'front'
            end
            raise MullvadAdapter::LocalProbeUnavailable, 'disconnect-worker-pending' unless cleanup_errors.empty? && @workers.empty?
            @last_network_path = @network_resume_path = nil
            @mutex.synchronize do
              @state.merge!(active_slot: nil, active_transport: nil, active_transport_mode: nil, last_canary: nil,
                            status: 'stopped', service_readiness: 'stopped', relay_liveness: 'unknown')
              @state[:front][:ready] = false
              @state[:front].delete(:pid)
              @state[:local_network][:recovery_pending] = false
              @state[:recovery].merge!(phase: 'stopped', running: false, message: '连接和自动恢复已停止', next_step: '可管理账号；选择城市或启用身份后重新连接')
            end
          ensure
            @switch_mutex.unlock
          end
          if @connection_stop_error
            update_operation(state: 'failed', stage: 'finished', error: @connection_stop_error, message: @connection_stop_error, finished_at: Time.now.iso8601)
          else
            update_operation(state: 'succeeded', stage: 'finished', message: '全部隧道、转发入口和自动恢复已停止；账号管理可用', finished_at: Time.now.iso8601)
          end
        rescue StandardError
          @connection_stop_error = '停止尚未确认完成；已禁止新建连接，请重试并保留诊断'
          update_operation(state: 'failed', stage: 'finished', error: @connection_stop_error, message: @connection_stop_error, finished_at: Time.now.iso8601)
        end
      end
      { id: id }
    end
  end
end
