#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'csv'
require 'net/http'
require 'open3'
require 'timeout'
require 'fileutils'
require 'time'
require 'optparse'

# Independent local observer: never sends an Internet request or changes the
# controller, tunnel, route or identity. Only fixed loopback HTTP GETs are used.
class OfflineFlightRecorder
  VERSION = '20261025-1'
  PORTS = { 'a' => [17_910, 17_911], 'b' => [17_920, 17_921] }.freeze
  MAX_FILE = 2_000_000
  WG_EVENTS = {
    'initiation_requested' => 'Sending handshake initiation',
    'response_authenticated' => 'Received handshake response',
    'initiation_authenticated' => 'Received handshake initiation',
    'response_requested' => 'Sending handshake response',
    'response_rejected' => 'Received invalid response message',
    'initiation_rejected' => 'Received invalid initiation message',
    'response_decode_failed' => 'Failed to decode response message',
    'initiation_decode_failed' => 'Failed to decode initiation message',
    'keypair_derivation_failed' => 'Failed to derive keypair',
    'initiation_create_failed' => 'Failed to create initiation message',
    'initiation_send_failed' => 'Failed to send handshake initiation',
    'response_create_failed' => 'Failed to create response message',
    'response_send_failed' => 'Failed to send handshake response',
    'keepalive_requested' => 'Sending keepalive packet',
    'keepalive_authenticated' => 'Receiving keepalive packet',
    'invalid_mac1' => 'Received packet with invalid mac1',
    'invalid_cookie' => 'Could not decrypt invalid cookie response'
  }.freeze

  def self.wg_event(line)
    item = JSON.parse(line)
    text = item['payload']
    return unless text.is_a?(String) && text.start_with?('[WG](')
    return 'handshake_retry' if text.match?(/Handshake did not complete after \d+ seconds, retrying/)
    return 'handshake_exhausted' if text.match?(/Handshake did not complete after \d+ attempts, giving up/)
    WG_EVENTS.find { |_key, literal| text.include?(literal) }&.first
  rescue JSON::ParserError, TypeError
    nil
  end

  def self.udp_counters(csv, expected)
    result = {}
    pid = nil
    columns = nil
    CSV.parse(csv).each do |row|
      if row[0].to_s.empty?
        columns = row.each_with_index.to_h
      elsif row[0].to_s.match?(/\.\d+\z/) && !row[0].start_with?('udp')
        pid = row[0][/\.(\d+)\z/, 1].to_i
      elsif row[0].to_s.start_with?('udp') && columns && expected.key?(pid)
        interface = row[columns['interface']]
        next unless interface == expected[pid] && interface != 'lo0'
        incoming = row[columns['bytes_in']].to_s
        outgoing = row[columns['bytes_out']].to_s
        next unless incoming.match?(/\A\d+\z/) && outgoing.match?(/\A\d+\z/)
        sum = (result[pid] ||= { rx_bytes: 0, tx_bytes: 0, sockets: 0 })
        sum[:rx_bytes] += incoming.to_i
        sum[:tx_bytes] += outgoing.to_i
        sum[:sockets] += 1
      end
    end
    result
  end

  def initialize(state_dir:, log_dir:, command: nil, status_reader: nil)
    @state_dir, @log_dir = state_dir, log_dir
    @command = command || method(:command)
    @status_reader = status_reader || method(:read_status)
    @write_mutex = Mutex.new
    @watchers = {}
    @last_state = {}
    @previous = {}
    @watch_retry = {}
    @prelude = []
    @incident = nil
    @last_incident_write = 0
    @last_emit = 0
    @stop = false
  end

  def write(event, fields = {})
    line = JSON.generate({ at: Time.now.iso8601, event: event, recorder: VERSION }.merge(fields)) + "\n"
    return if line.bytesize > 32_768
    @write_mutex.synchronize do
      FileUtils.mkdir_p(@log_dir, mode: 0o700)
      path = File.join(@log_dir, 'flight-recorder.jsonl')
      raise IOError if File.symlink?(@log_dir) || File.symlink?(path) || File.symlink?(path + '.1')
      File.rename(path, path + '.1') if File.file?(path) && File.size(path) + line.bytesize > MAX_FILE
      File.open(path, File::WRONLY | File::APPEND | File::CREAT | File::NOFOLLOW, 0o600) do |f|
        raise IOError unless f.stat.file? && f.stat.uid == Process.uid && f.stat.nlink == 1
        f.chmod(0o600)
        f.write(line)
      end
    end
  rescue StandardError
    # No unbounded stderr, no impact on tunnel/recovery if disk is unavailable.
    nil
  end

  def command(*args)
    output = ''.b
    Open3.popen3(*args) do |input, out, err, child|
      input.close
      readers = [out, err].map.with_index do |pipe, i|
        Thread.new do
          begin
            loop do
              chunk = pipe.readpartial(4096)
              output << chunk if i.zero? && output.bytesize + chunk.bytesize <= 65_536
            end
          rescue EOFError, IOError
            nil
          end
        end
      end
      begin
        Timeout.timeout(2) { child.value; readers.each(&:join) }
        allowed_absence = args.first == '/usr/sbin/lsof' && child.value.exitstatus == 1
        raise IOError unless child.value.success? || allowed_absence
      ensure
        if child.alive?
          Process.kill('KILL', child.pid) rescue nil
          child.join(1)
        end
        [out, err].each { |p| p.close unless p.closed? }
        readers.each { |r| r.join(0.2) }
      end
    end
    output.force_encoding('UTF-8').scrub
  end

  def remember_incident(sample, fault)
    created = false
    temporary = nil
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    path = File.join(@log_dir, 'flight-incident.json')
    previous = File.join(@log_dir, 'flight-incident.previous.json')
    if fault && !@incident
      FileUtils.mkdir_p(@log_dir, mode: 0o700)
      raise IOError if File.symlink?(@log_dir) || File.symlink?(path) || File.symlink?(previous)
      File.rename(path, previous) if File.file?(path)
      @incident = { started_at: Time.now.iso8601, kind: sample[:state_fresh] ? 'data-not-ready' : 'status-unavailable',
                    before: @prelude.last(8), first: sample, status: 'observing', latest: sample }
      @last_incident_write = 0
    end
    if @incident
      @incident[:latest] = sample
      @incident.merge!(status: 'ready-observed', finished_at: Time.now.iso8601) unless fault
      if !fault || now - @last_incident_write >= 10
        raise IOError if File.symlink?(path)
        bytes = JSON.generate(@incident)
        bytes = JSON.generate(@incident.merge(before: [])) if bytes.bytesize > 65_536
        raise IOError if bytes.bytesize > 65_536
        temporary = "#{path}.#{Process.pid}.tmp"
        File.open(temporary, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |f|
          created = true
          f.write(bytes); f.flush; f.fsync
        end
        File.rename(temporary, path)
        @last_incident_write = now
      end
      @incident = nil unless fault
    end
    @prelude << sample
    @prelude.shift while @prelude.size > 8
  rescue StandardError => e
    write('incident-snapshot-unavailable', error_class: e.class.name)
  ensure
    File.unlink(temporary) if created && temporary && File.file?(temporary)
  end

  def read_status
    Net::HTTP.start('127.0.0.1', 17_891, nil, open_timeout: 0.5, read_timeout: 1, max_retries: 0) do |http|
      bytes = +''
      http.request(Net::HTTP::Get.new('/status')) do |response|
        raise IOError unless response.code == '200'
        response.read_body do |part|
          raise IOError if bytes.bytesize + part.bytesize > 1_048_576
          bytes << part
        end
      end
      JSON.parse(bytes)
    end
  end

  def listener_pids
    ports = PORTS.values.flatten
    args = ports.flat_map { |p| ["-iTCP:#{p}"] }
    text = @command.call('/usr/sbin/lsof', '-nP', '-Fpn', *args, '-sTCP:LISTEN')
    pid = nil
    result = {}
    text.each_line do |line|
      pid = line[1..].to_i if line.match?(/\Ap\d+/)
      if line.start_with?('n') && pid && (port = line[/:(\d+)\s*\z/, 1]) && ports.include?(port.to_i)
        result[port.to_i] = pid
      end
    end
    result
  end

  def controller_credential(slot)
    path = File.join(@state_dir, 'slots', slot, 'config.json')
    File.open(path, File::RDONLY | File::NOFOLLOW) do |f|
      stat = f.stat
      raise IOError unless stat.file? && stat.uid == Process.uid && stat.size <= 2_097_152
      config = JSON.parse(f.read)
      secret = config.fetch('secret')
      raise IOError unless secret.is_a?(String) && secret.bytesize.between?(16, 256)
      secret
    end
  end

  def start_watcher(slot, pid, context)
    old = @watchers[slot]
    return if old && old[:pid] == pid && old[:context][:started_at] == context[:started_at] && old[:thread]&.alive?
    retry_key = [slot, pid, context[:started_at]]
    return if Process.clock_gettime(Process::CLOCK_MONOTONIC) < @watch_retry.fetch(retry_key, 0)
    stop_watcher(slot)
    secret = controller_credential(slot)
    watch = { pid: pid, context: context, mutex: Mutex.new, counts: Hash.new(0), status: 'connecting' }
    @watchers[slot] = watch
    watch[:thread] = Thread.new do
      begin
        # Plain HTTP streaming GET. Does NOT change global engine log level.
        Net::HTTP.start('127.0.0.1', PORTS.fetch(slot)[1], nil, open_timeout: 1, read_timeout: 60, max_retries: 0) do |http|
          request = Net::HTTP::Get.new('/logs?level=debug')
          request['Authorization'] = "Bearer #{secret}"
          http.request(request) do |response|
            raise IOError unless response.code == '200'
            watch[:mutex].synchronize { watch[:status] = 'streaming'; watch[:since] = Time.now.iso8601 }
            buffer = +''
            response.read_body do |chunk|
              buffer << chunk
              while (newline = buffer.index("\n"))
                line = buffer.slice!(0, newline + 1)
                next if line.bytesize > 65_536
                kind = self.class.wg_event(line)
                if kind
                  watch[:mutex].synchronize do
                    watch[:counts][kind] += 1
                    watch[:last_event_at] = Time.now.iso8601
                  end
                end
              end
              raise IOError if buffer.bytesize > 65_536
            end
          end
        end
      rescue StandardError => e
        watch[:mutex].synchronize { watch[:status] = 'disconnected'; watch[:error_class] = e.class.name }
      ensure
        watch[:mutex].synchronize { watch[:status] = 'closed' if watch[:status] == 'streaming' }
        secret.replace('')
      end
    end
  rescue StandardError => e
    @watch_retry[retry_key] = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 30
    @watch_retry.shift while @watch_retry.size > 8
    write('handshake-observation-unavailable', context.merge(error_class: e.class.name))
  end

  def stop_watcher(slot)
    watch = @watchers.delete(slot)
    return unless watch
    thread = watch[:thread]
    thread&.kill
    thread&.join(1)
    write('handshake-observation-ended', watch[:context].merge(watch[:mutex].synchronize do
      { counts: watch[:counts].dup, coverage: watch[:status], since: watch[:since] }
    end))
  end

  def tick
    state_fresh = true
    begin
      state = @status_reader.call
      raise IOError unless state.is_a?(Hash)
      @last_state = state
    rescue StandardError
      state_fresh = false
      state = @last_state
    end
    listeners = listener_pids
    contexts = {}
    PORTS.each do |slot, (mixed, control)|
      pid = listeners[mixed]
      if !pid || listeners[control] != pid
        stop_watcher(slot)
        next
      end
      worker = state.fetch('workers', {})[slot] || {}
      context = { slot: slot, pid: pid, relay: worker['relay'], started_at: worker['started_at'],
                  interface: worker['interface'], endpoint: worker['endpoint'], endpoint_port: worker['endpoint_port'] }
      contexts[pid] = context
      start_watcher(slot, pid, context)
    end
    expected = contexts.transform_values { |context| context[:interface] }
    counters = {}
    begin
      unless expected.empty?
        args = expected.keys.flat_map { |pid| ['-p', pid.to_s] }
        csv = @command.call('/usr/bin/nettop', '-n', '-m', 'udp', '-L', '1', '-x', '-J', 'interface,bytes_in,bytes_out', *args)
        counters = self.class.udp_counters(csv, expected)
      end
    rescue StandardError => e
      udp_error = e.class.name
    end
    observed = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    samples = contexts.map do |pid, context|
      current = counters[pid]
      old = @previous[pid]
      delta = if current && old && current[:rx_bytes] >= old[:rx_bytes] && current[:tx_bytes] >= old[:tx_bytes]
                { rx_delta: current[:rx_bytes] - old[:rx_bytes], tx_delta: current[:tx_bytes] - old[:tx_bytes],
                  interval_ms: ((observed - old[:observed]) * 1000).round }
              else
                { rx_delta: nil, tx_delta: nil }
              end
      @previous[pid] = current && current.merge(observed: observed)
      watcher = @watchers[context[:slot]]
      wg = watcher && watcher[:mutex].synchronize do
        { status: watcher[:status], since: watcher[:since], last_event_at: watcher[:last_event_at], counts: watcher[:counts].dup }
      end
      context.merge(udp: current, udp_error: udp_error, delta: delta, wg: wg)
    end
    @previous.select! { |pid, _| contexts.key?(pid) }
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    signature = [state_fresh, state['generation'], state['service_readiness'], contexts.keys.sort]
    fault = !state_fresh || state['service_readiness'] != 'ready'
    sample = { state_fresh: state_fresh, readiness: state['service_readiness'],
            generation: state['generation'], network_epoch: state.dig('local_network', 'epoch'),
            network_paused: state.dig('local_network', 'paused'), recovery_phase: state.dig('recovery', 'phase'),
            observed_at: Time.now.iso8601,
            scope: 'worker-physical-interface-udp; live-log-observations-no-replay', workers: samples }
    remember_incident(sample, fault)
    if fault || signature != @last_signature || now - @last_emit >= 30
      write('local-flight-sample', sample)
      @last_signature, @last_emit = signature, now
    end
    samples
  rescue StandardError => e
    write('local-flight-sample-unavailable', error_class: e.class.name)
    []
  end

  def run(seconds: nil)
    FileUtils.mkdir_p(@log_dir, mode: 0o700)
    lock = File.open(File.join(@log_dir, 'flight-recorder.lock'), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600)
    owned = lock.flock(File::LOCK_EX | File::LOCK_NB)
    return unless owned
    write('flight-recorder-started', internet_requests: false)
    deadline = seconds && Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    until @stop || (deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline)
      tick
      10.times { break if @stop; sleep 0.2 }
    end
  ensure
    @watchers.keys.each { |slot| stop_watcher(slot) }
    write('flight-recorder-stopped') if owned
    lock&.close
  end

  def stop = (@stop = true)
end

if $PROGRAM_NAME == __FILE__
  opts = { state_dir: File.expand_path('~/Library/Application Support/MullvadLocalAdapter'),
           log_dir: File.expand_path('~/Library/Logs/MullvadLocalAdapter') }
  seconds = nil
  OptionParser.new do |p|
    p.on('--state-dir PATH') { |v| opts[:state_dir] = File.expand_path(v) }
    p.on('--log-dir PATH') { |v| opts[:log_dir] = File.expand_path(v) }
    p.on('--seconds N', Integer) { |v| seconds = v }
  end.parse!
  recorder = OfflineFlightRecorder.new(**opts)
  %w[INT TERM].each { |signal| Signal.trap(signal) { recorder.stop } }
  recorder.run(seconds: seconds)
end
