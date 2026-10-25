# frozen_string_literal: true
require_relative 'minitest_dependencies'
require_relative '../scripts/diagnostics/offline_flight_recorder'
require 'tmpdir'

class OfflineFlightRecorderTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('offline-flight')
    @state = { 'service_readiness' => 'ready', 'generation' => 4,
      'workers' => { 'a' => { 'relay' => 'fixture', 'interface' => 'en0', 'started_at' => 'fixture-start' } } }
    @offline = false
    @udp_fail = false
    @rx, @tx = 100, 200
    reader = -> { raise IOError if @offline; @state }
    command = lambda do |binary, *args|
      if binary.end_with?('lsof')
        "p123\nn127.0.0.1:17910\nn127.0.0.1:17911\n"
      elsif binary.end_with?('nettop')
        raise IOError if @udp_fail
        raise 'DNS lookup must be disabled' unless args.include?('-n')
        ",interface,bytes_in,bytes_out,\ncore.123,,900,900,\nudp6 *.123<->*.*,en0,#{@rx},#{@tx},\nudp4 127.0.0.1:17910<->*:*,lo0,800,700,\n"
      else
        raise 'unexpected command'
      end
    end
    @recorder = OfflineFlightRecorder.new(state_dir: @dir, log_dir: File.join(@dir, 'logs'), command: command, status_reader: reader)
    @recorder.define_singleton_method(:start_watcher) { |*_| nil }
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def events
    File.readlines(File.join(@dir, 'logs', 'flight-recorder.jsonl')).map { |line| JSON.parse(line) }
  end

  def test_udp_excludes_loopback_and_keeps_sampling_when_status_is_unavailable
    first = @recorder.tick.first
    assert_equal 100, first.dig(:udp, :rx_bytes)
    assert_nil first.dig(:delta, :rx_delta)
    @offline = true
    @tx += 75
    second = @recorder.tick.first
    assert_equal 0, second.dig(:delta, :rx_delta)
    assert_equal 75, second.dig(:delta, :tx_delta)
    assert_operator second.dig(:delta, :interval_ms), :>=, 0
    refute events.last['state_fresh']
    assert_equal 123, events.last.dig('workers', 0, 'pid')
  end

  def test_counter_reset_is_unknown_not_negative_or_fake_zero_traffic
    @recorder.tick
    @rx = 2
    sample = @recorder.tick.first
    assert_nil sample.dig(:delta, :rx_delta)
    assert_equal 2, sample.dig(:udp, :rx_bytes)
  end

  def test_udp_failure_does_not_prevent_local_state_evidence
    @udp_fail = true
    sample = @recorder.tick.first
    assert_nil sample[:udp]
    assert_equal 'IOError', sample[:udp_error]
    assert_equal 'local-flight-sample', events.last['event']
  end

  def test_only_allowlisted_handshake_names_escape_not_raw_keys_or_endpoints
    event = ->(text) { OfflineFlightRecorder.wg_event(JSON.generate('payload' => text, 'type' => 'debug')) }
    assert_equal 'response_authenticated', event.call('[WG](MULLVAD) peer(PRIVATE) - Received handshake response')
    assert_equal 'handshake_retry', event.call('[WG](MULLVAD) Handshake did not complete after 5 seconds, retrying (try 2)')
    assert_equal 'response_rejected', event.call('[WG](MULLVAD) Received invalid response message from 192.0.2.1')
    assert_equal 'keypair_derivation_failed', event.call('[WG](MULLVAD) Failed to derive keypair: SECRET')
    assert_nil event.call('[WG](MULLVAD) created wireguard ipc conf private_key=SECRET')
    assert_nil event.call('[TCP] user.example - Received handshake response')
    assert_nil OfflineFlightRecorder.wg_event('bad-json SECRET')
  end

  def test_recording_is_capacity_bounded_and_private
    170.times { @recorder.write('fixture', padding: 'x' * 25_000) }
    files = Dir.glob(File.join(@dir, 'logs', '*'))
    assert_equal 2, files.size
    assert_operator files.sum { |p| File.size(p) }, :<=, 4_000_000
    files.each { |p| assert_equal 0o600, File.stat(p).mode & 0o777 }
  end

  def test_writer_refuses_symlink_without_touching_target
    FileUtils.mkdir_p(File.join(@dir, 'logs'))
    target = File.join(@dir, 'unrelated')
    File.write(target, 'keep')
    File.symlink(target, File.join(@dir, 'logs', 'flight-recorder.jsonl'))
    @recorder.write('fixture')
    assert_equal 'keep', File.read(target)
  end

  def test_credentials_require_owned_regular_file_and_never_enter_output
    FileUtils.mkdir_p(File.join(@dir, 'slots', 'a'))
    path = File.join(@dir, 'slots', 'a', 'config.json')
    File.write(path, JSON.generate('secret' => 'test-secret' * 4, 'private-key' => 'NEVER-LOG'))
    assert_equal 'test-secret' * 4, @recorder.controller_credential('a')
    @recorder.tick
    refute_includes JSON.generate(events), 'test-secret'
    refute_includes JSON.generate(events), 'NEVER-LOG'
  end

  def test_fault_start_is_preserved_while_latest_and_recovery_are_updated
    @recorder.tick
    @state['service_readiness'] = 'data_fail'
    @recorder.tick
    path = File.join(@dir, 'logs', 'flight-incident.json')
    first = JSON.parse(File.read(path))
    assert_equal 'data-not-ready', first['kind']
    assert_equal 'ready', first.dig('before', 0, 'readiness')
    assert_equal 'data_fail', first.dig('first', 'readiness')
    @state['service_readiness'] = 'ready'
    @recorder.tick
    restored = JSON.parse(File.read(path))
    assert_equal first['first'], restored['first']
    assert_equal 'ready-observed', restored['status']
    @offline = true
    @recorder.tick
    assert_equal 'status-unavailable', JSON.parse(File.read(path))['kind']
    assert_equal restored, JSON.parse(File.read(File.join(@dir, 'logs', 'flight-incident.previous.json')))
    assert_operator File.size(path), :<=, 65_536
  end
end
