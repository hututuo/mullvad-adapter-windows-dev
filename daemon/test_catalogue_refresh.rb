# frozen_string_literal: true

require_relative 'minitest_dependencies'
require 'base64'
require 'json'
require 'minitest/mock'
require 'open3'
require 'stringio'
require 'tmpdir'
require 'timeout'
require_relative 'mullvad_adapter'

class CatalogueRefreshTest < Minitest::Test
  class CommandStatus
    def initialize(success)
      @success = success
    end

    def success? = @success
  end

  class FakeSocket
    attr_reader :output

    def initialize(request)
      @input = StringIO.new(request)
      @output = StringIO.new
    end

    def gets(limit = nil)
      limit ? @input.gets(limit) : @input.gets
    end

    def read(length)
      @input.read(length)
    end

    def write(value)
      @output.write(value)
    end

    def close
      true
    end
  end

  def setup
    @dir = Dir.mktmpdir('catalogue-refresh')
    @adapter = MullvadAdapter.new(state_dir: @dir)
    @cache_path = @adapter.send(:metadata_cache_path)
    @capability = 'a' * 64
    @adapter.instance_variable_set(:@account_capability, @capability)
    @adapter.instance_variable_set(:@account_only_mode, true)
  end

  def teardown
    thread = @adapter&.instance_variable_get(:@metadata_refresh_thread)
    thread&.join(1)
    FileUtils.rm_rf(@dir) if @dir
  end

  def test_wrong_family_primary_addresses_are_rejected_from_the_catalogue
    valid = relay('valid-relay')
    wrong_ipv4 = relay('wrong-ipv4').merge('ipv4_addr_in' => '2001:db8::9')
    wrong_ipv6 = relay('wrong-ipv6').merge('ipv6_addr_in' => '192.0.2.9')
    payload = catalogue([wrong_ipv4, wrong_ipv6, valid])

    result = @adapter.send(:validate_metadata_payload, payload)

    assert_equal ['valid-relay'], result.dig('wireguard', 'relays').map { |entry| entry.fetch('hostname') }
    assert_equal 2, @adapter.instance_variable_get(:@last_metadata_validation_warnings).length
  end

  def test_cache_write_failure_preserves_previous_bytes_and_removes_partial_file
    old_payload = catalogue([relay('old-relay')])
    @adapter.send(:persist_metadata_cache, old_payload)
    previous_bytes = File.binread(@cache_path)
    original_open = File.method(:open)

    failing_open = lambda do |path, *args, **kwargs, &block|
      if path.to_s.start_with?("#{@cache_path}.pending-") && block
        original_open.call(path, *args, **kwargs) do |file|
          original_write = file.method(:write)
          file.define_singleton_method(:write) do |bytes|
            original_write.call(bytes.byteslice(0, 12))
            raise Errno::ENOSPC, 'injected cache write failure'
          end
          block.call(file)
        end
      else
        original_open.call(path, *args, **kwargs, &block)
      end
    end

    assert_raises(Errno::ENOSPC) do
      File.stub(:open, failing_open) do
        @adapter.send(:persist_metadata_cache, catalogue([relay('new-relay')]))
      end
    end

    assert_equal previous_bytes, File.binread(@cache_path)
    assert @adapter.send(:metadata_cache_valid?)
    assert_empty Dir.glob("#{@cache_path}.pending-*")
  end

  def test_cache_rename_failure_preserves_previous_bytes
    old_payload = catalogue([relay('old-relay')])
    @adapter.send(:persist_metadata_cache, old_payload)
    previous_bytes = File.binread(@cache_path)
    original_rename = File.method(:rename)
    failing_rename = lambda do |source, destination|
      raise IOError, 'injected cache rename failure' if destination.to_s == @cache_path

      original_rename.call(source, destination)
    end

    assert_raises(IOError) do
      File.stub(:rename, failing_rename) do
        @adapter.send(:persist_metadata_cache, catalogue([relay('new-relay')]))
      end
    end

    assert_equal previous_bytes, File.binread(@cache_path)
    assert @adapter.send(:metadata_cache_valid?)
    assert_empty Dir.glob("#{@cache_path}.pending-*")
  end

  def test_live_refresh_survives_cache_rename_failure_and_reports_cache_error
    old_payload = catalogue([relay('cached-relay')])
    @adapter.send(:persist_metadata_cache, old_payload)
    old_bytes = File.binread(@cache_path)
    refute_nil @adapter.send(:load_cached_metadata)
    new_payload = catalogue([relay('fresh-relay')])
    original_rename = File.method(:rename)
    failing_rename = lambda do |source, destination|
      raise IOError, 'injected cache rename failure' if destination.to_s == @cache_path

      original_rename.call(source, destination)
    end
    fetch = ->(*) { [JSON.generate(new_payload), '', CommandStatus.new(true)] }

    result = nil
    Open3.stub(:capture3, fetch) do
      File.stub(:rename, failing_rename) do
        result = @adapter.send(:refresh_metadata, force: true, background: true)
      end
    end

    assert_equal ['fresh-relay'], result.dig('wireguard', 'relays').map { |entry| entry.fetch('hostname') }
    assert_equal 'fresh-relay', @adapter.instance_variable_get(:@metadata).dig('wireguard', 'relays', 0, 'hostname')
    metadata_state = @adapter.send(:snapshot).dig(:metadata)
    assert_equal true, metadata_state[:live]
    assert_equal true, metadata_state[:cache]
    assert_equal 'IOError', metadata_state[:cache_error]
    assert_equal old_bytes, File.binread(@cache_path)
    assert @adapter.send(:metadata_cache_valid?)
  end

  def test_failed_refresh_keeps_newer_memory_and_its_timestamp_instead_of_loading_old_cache
    @adapter.send(:persist_metadata_cache, catalogue([relay('cached-relay')]))
    memory_payload = catalogue([relay('memory-relay')])
    fetched_at = Time.now - 3_600
    @adapter.instance_variable_set(:@metadata, memory_payload)
    @adapter.instance_variable_set(:@metadata_fetched_at, fetched_at)
    @adapter.send(:set_metadata_state, live: true, cache: true, source: 'system-https', error: nil, fetched_at: fetched_at)
    failure = ->(*) { ['', 'injected API failure', CommandStatus.new(false)] }

    result = Open3.stub(:capture3, failure) do
      @adapter.send(:refresh_metadata, force: true, background: true)
    end

    assert_same memory_payload, result
    assert_same memory_payload, @adapter.instance_variable_get(:@metadata)
    assert_equal fetched_at, @adapter.instance_variable_get(:@metadata_fetched_at)
    metadata_state = @adapter.send(:snapshot).dig(:metadata)
    assert_equal 'memory-relay', @adapter.instance_variable_get(:@metadata).dig('wireguard', 'relays', 0, 'hostname')
    assert_equal fetched_at.iso8601, metadata_state[:fetched_at]
    assert_equal 'memory', metadata_state[:source]
  end

  def test_failed_refresh_cache_fallback_keeps_the_cache_timestamp
    @adapter.send(:persist_metadata_cache, catalogue([relay('cached-relay')]))
    cached_at = Time.now - 7_200
    File.utime(cached_at, cached_at, @cache_path)
    expected_mtime = File.mtime(@cache_path)
    failure = ->(*) { ['', 'injected API failure', CommandStatus.new(false)] }

    result = Open3.stub(:capture3, failure) do
      @adapter.send(:refresh_metadata, force: true, background: true)
    end

    assert_equal 'cached-relay', result.dig('wireguard', 'relays', 0, 'hostname')
    assert_equal expected_mtime, @adapter.instance_variable_get(:@metadata_fetched_at)
    assert_equal expected_mtime.iso8601, @adapter.send(:snapshot).dig(:metadata, :fetched_at)
  end

  def test_metadata_refresh_request_is_async_coalesced_and_independent_of_switch_lifecycle
    entered = Queue.new
    release = Queue.new
    calls = Queue.new
    adapter = @adapter
    adapter.define_singleton_method(:refresh_metadata) do |**options|
      calls << options
      entered << true
      release.pop
      @mutex.synchronize { @state[:metadata][:refreshing] = false }
    end
    pending = { id: 'existing-action', reason: 'select' }
    adapter.instance_variable_get(:@action_gate_mutex).synchronize do
      adapter.instance_variable_set(:@action_pending, pending)
    end
    metadata_mutex = adapter.instance_variable_get(:@metadata_mutex)
    metadata_mutex.lock
    locked_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    locked_receipt = adapter.send(:request_metadata_refresh)
    locked_elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - locked_started
    metadata_mutex.unlock
    assert_equal({ accepted: false, refreshing: true }, locked_receipt)
    assert_operator locked_elapsed, :<, 0.25
    assert_nil adapter.instance_variable_get(:@metadata_refresh_thread)

    switch_mutex = adapter.instance_variable_get(:@switch_mutex)
    switch_mutex.lock

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    first = adapter.send(:request_metadata_refresh)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    Timeout.timeout(1) { entered.pop }
    second = adapter.send(:request_metadata_refresh)

    assert_equal({ accepted: true, refreshing: true }, first)
    assert_equal({ accepted: false, refreshing: true }, second)
    assert_operator elapsed, :<, 0.25
    assert_equal({ force: true, background: true, nonblocking: true }, Timeout.timeout(1) { calls.pop })
    assert_same pending, adapter.instance_variable_get(:@action_pending)
    assert switch_mutex.owned?, 'refresh request must not lock/unlock the switch mutex'
  ensure
    switch_mutex.unlock if switch_mutex&.owned?
    release << true if release
    adapter&.instance_variable_get(:@metadata_refresh_thread)&.join(1)
  end

  def test_manual_refresh_http_route_is_protected_and_works_in_account_only_mode
    calls = Queue.new
    adapter = @adapter
    adapter.define_singleton_method(:refresh_metadata) do |**options|
      calls << options
      @mutex.synchronize { @state[:metadata][:refreshing] = false }
    end

    unauthenticated = http_request('POST', '/metadata/refresh')
    assert_equal 403, unauthenticated.first

    browser_request = http_request('POST', '/metadata/refresh',
      headers: { 'Authorization' => "Bearer #{@capability}", 'Origin' => 'http://localhost' })
    assert_equal 403, browser_request.first
    assert_empty calls

    status, body = http_request('POST', '/metadata/refresh',
      headers: { 'Authorization' => "Bearer #{@capability}" })
    assert_equal 202, status
    assert_equal({ 'accepted' => true, 'refreshing' => true }, body)
    assert_equal({ force: true, background: true, nonblocking: true }, Timeout.timeout(1) { calls.pop })
    @adapter.instance_variable_get(:@metadata_refresh_thread)&.join(1)
  end

  def test_get_relays_uses_fresh_memory_without_triggering_an_api_fetch
    current = catalogue([relay('memory-relay')])
    @adapter.instance_variable_set(:@metadata, current)
    calls = Queue.new
    @adapter.define_singleton_method(:refresh_metadata) { |**options| calls << options }

    status, rows = http_request('GET', '/relays')

    assert_equal 200, status
    assert_equal ['memory-relay'], rows.map { |entry| entry.fetch('hostname') }
    assert_raises(ThreadError) { calls.pop(true) }
  end

  private

  def http_request(method, path, headers: {}, body: '')
    lines = ["#{method} #{path} HTTP/1.1", 'Host: 127.0.0.1']
    headers.each { |name, value| lines << "#{name}: #{value}" }
    lines << "Content-Length: #{body.bytesize}" unless body.empty?
    socket = FakeSocket.new((lines + ['', body]).join("\r\n"))
    @adapter.send(:handle_http, socket)
    response_headers, response_body = socket.output.string.split("\r\n\r\n", 2)
    status = response_headers.lines.first.split[1].to_i
    [status, JSON.parse(response_body)]
  end

  def catalogue(relays)
    {
      'locations' => { 'us-sjc' => { 'country' => 'US', 'city' => 'San Jose' } },
      'wireguard' => {
        'port_ranges' => [[33_431, 33_431], [51_820, 51_820]],
        'shadowsocks_port_ranges' => [[20_484, 20_484]],
        'relays' => relays
      }
    }
  end

  def relay(hostname)
    {
      'hostname' => hostname,
      'active' => true,
      'location' => 'us-sjc',
      'public_key' => Base64.strict_encode64('public-fixture-key'.ljust(32, "\0")),
      'ipv4_addr_in' => '192.0.2.1',
      'ipv6_addr_in' => '2001:db8::1',
      'shadowsocks_extra_addr_in' => ['192.0.2.2']
    }
  end
end
