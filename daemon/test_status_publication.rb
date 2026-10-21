# frozen_string_literal: true

require_relative 'minitest_dependencies'
require 'tmpdir'
require 'stringio'
require 'timeout'
require_relative 'mullvad_adapter'

class MullvadStatusPublicationTest < Minitest::Test
  class StatusSocket
    attr_reader :response

    def initialize
      @response = +''
    end

    def write(data)
      @response << data
      data.bytesize
    end
  end

  class HttpSocket
    attr_reader :response

    def initialize(request)
      @request = StringIO.new(request)
      @response = +''
      @closed = false
    end

    def gets(limit = nil) = @request.gets(limit)
    def read(length = nil) = @request.read(length)

    def write(data)
      @response << data
      data.bytesize
    end

    def closed? = @closed
    def close = (@closed = true)
  end

  def setup
    @dir = Dir.mktmpdir('mullvad-status-publication')
    @adapter = MullvadAdapter.new(state_dir: @dir)
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def set_generation(generation)
    mutex = @adapter.instance_variable_get(:@mutex)
    mutex.synchronize do
      @adapter.instance_variable_get(:@state)[:generation] = generation
    end
  end

  def publication
    @adapter.instance_variable_get(:@status_publication)
  end

  def request_status
    socket = StatusSocket.new
    @adapter.send(:respond_status, socket)
    parse_response(socket.response)
  end

  def parse_response(response)
    status_line, rest = response.split("\r\n", 2)
    header_text, body = rest.to_s.split("\r\n\r\n", 2)
    headers = header_text.to_s.lines.each_with_object({}) do |line, result|
      name, value = line.split(':', 2)
      result[name.downcase] = value.to_s.strip if name && value
    end
    [status_line.to_s.split[1].to_i, headers, JSON.parse(body.to_s)]
  end

  # Queue rendezvous and a bounded wait make a lock regression fail without
  # using a sleep to guess when another thread has run.
  def bounded_call(timeout: 1.0, &block)
    result = Queue.new
    thread = Thread.new do
      begin
        result << [:ok, block.call]
      rescue StandardError => error
        result << [:error, error]
      end
    end
    kind, value = Timeout.timeout(timeout) { result.pop }
    raise value if kind == :error
    value
  ensure
    if thread
      thread.kill if thread.alive?
      thread.join
    end
  end

  def test_status_returns_published_generation_while_both_state_locks_are_held
    set_generation(41)
    assert @adapter.send(:publish_status_snapshot)
    expected_json = publication.fetch(:json)
    assert expected_json.frozen?

    locks = %i[@mutex @action_gate_mutex].map { |name| @adapter.instance_variable_get(name) }
    locks.each(&:lock)
    begin
      code, _headers, body = bounded_call { request_status }
      assert_equal 200, code
      assert_equal 41, body['generation']
      assert_equal 41, JSON.parse(expected_json)['generation']
    ensure
      locks.reverse_each { |lock| lock.unlock if lock.owned? }
    end
  end

  def test_handle_http_status_route_returns_cached_generation_while_locks_are_held
    set_generation(52)
    assert @adapter.send(:publish_status_snapshot)

    locks = %i[@mutex @action_gate_mutex].map { |name| @adapter.instance_variable_get(name) }
    locks.each(&:lock)
    begin
      socket = HttpSocket.new("GET /status HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
      code, _headers, body = bounded_call do
        @adapter.send(:handle_http, socket)
        parse_response(socket.response)
      end
      assert_equal 200, code
      assert_equal 52, body['generation']
      assert socket.closed?
    ensure
      locks.reverse_each { |lock| lock.unlock if lock.owned? }
    end
  end

  def test_publisher_returns_false_promptly_when_either_lock_is_busy
    %i[@mutex @action_gate_mutex].each do |name|
      lock = @adapter.instance_variable_get(name)
      lock.lock
      begin
        assert_equal false, bounded_call { @adapter.send(:publish_status_snapshot) }, name.to_s
      ensure
        lock.unlock if lock.owned?
      end
    end
  end

  def test_stale_publication_reports_stale_then_refreshes_after_lock_release
    set_generation(7)
    assert @adapter.send(:publish_status_snapshot)
    stale = publication.merge(
      captured_at: Process.clock_gettime(Process::CLOCK_MONOTONIC) - 3.1
    ).freeze
    @adapter.instance_variable_set(:@status_publication, stale)

    lock = @adapter.instance_variable_get(:@mutex)
    lock.lock
    begin
      code, _headers, body = bounded_call { request_status }
      assert_equal 503, code
      assert_equal 'status_snapshot_stale', body['code']
      assert_equal false, bounded_call { @adapter.send(:publish_status_snapshot) }
    ensure
      lock.unlock if lock.owned?
    end

    set_generation(8)
    assert @adapter.send(:publish_status_snapshot)
    code, _headers, body = request_status
    assert_equal 200, code
    assert_equal 8, body['generation']
  end

  def test_published_json_does_not_change_when_live_state_is_mutated
    set_generation(100)
    assert @adapter.send(:publish_status_snapshot)
    saved_json = publication.fetch(:json)
    saved_publication = publication

    set_generation(101)

    assert_same saved_publication, publication
    assert_same saved_json, publication.fetch(:json)
    assert_equal 100, JSON.parse(saved_json)['generation']
    assert_equal 101, @adapter.instance_variable_get(:@state)[:generation]
  end

  def test_missing_publication_returns_unavailable_without_waiting_for_locks
    @adapter.instance_variable_set(:@status_publication, nil)
    locks = %i[@mutex @action_gate_mutex].map { |name| @adapter.instance_variable_get(name) }
    locks.each(&:lock)
    begin
      code, _headers, body = bounded_call { request_status }
      assert_equal 503, code
      assert_equal 'status_snapshot_unavailable', body['code']
    ensure
      locks.reverse_each { |lock| lock.unlock if lock.owned? }
    end
  end

  def test_success_headers_are_numeric_and_do_not_expose_private_values
    @adapter.instance_variable_set(:@account_capability, 'status-private-capability-sentinel')
    @adapter.instance_variable_set(:@account_number, '1234567890123456')
    assert @adapter.send(:publish_status_snapshot)

    code, headers, body = request_status
    assert_equal 200, code
    assert_match(/\A\d+\z/, headers.fetch('x-adapter-status-age-ms'))
    assert_match(/\A\d+\z/, headers.fetch('x-adapter-status-capture-ms'))
    refute_includes JSON.generate(body), 'status-private-capability-sentinel'
    refute_includes JSON.generate(body), '1234567890123456'
  end
end
