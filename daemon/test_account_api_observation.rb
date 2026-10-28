# frozen_string_literal: true
require_relative 'minitest_dependencies'
require 'tmpdir'
require_relative 'mullvad_adapter'

class AccountAPIObservationTest < Minitest::Test
  Status = Struct.new(:exitstatus) do
    def success? = exitstatus == 0
  end

  def setup
    @dir = Dir.mktmpdir('api-observation')
    @adapter = MullvadAdapter.new(state_dir: @dir)
  end

  def teardown
    Thread.current[:adapter_account_api_route] = nil
    Thread.current[:adapter_account_deadline] = nil
    Thread.current[:adapter_account_request_id] = nil
    @adapter.instance_variable_get(:@probe_event_writer)&.join(2)
    FileUtils.remove_entry(@dir)
  end

  def selector(**options)
    AccountApiRoutes.new(proxy: nil, cache_path: File.join(@dir, 'addresses.json'), **options)
  end

  def with_curl(response)
    original = Open3.method(:capture3)
    Open3.singleton_class.send(:define_method, :capture3) { |*args, **options| response.call(*args, **options) }
    yield
  ensure
    Open3.singleton_class.send(:define_method, :capture3, original)
  end

  def test_numeric_telemetry_distinguishes_tls_wait_from_waiting_for_http
    body, metrics = AccountApiRoutes.split_response("private response body\n000|0.001|0.040|0.000|0.000|8.000|000")
    result = AccountApiRoutes.observation(Status.new(28), metrics, route: 'direct_seed')
    assert_equal 'private response body', body
    assert_equal 'tls_handshake', result[:phase]
    assert_equal 40, result[:tcp_ms]
    assert_equal 8000, result[:total_ms]
    refute_includes JSON.generate(result), 'private response body'
    result = AccountApiRoutes.observation(Status.new(28), { tcp_ms: 40, tls_ms: 100, http_code: 0 }, route: 'direct_seed')
    assert_equal 'http_response', result[:phase]
    result = AccountApiRoutes.observation(Status.new(28), { tcp_ms: 40, tls_ms: 0, proxy_http_code: 0 }, route: 'configured_proxy')
    assert_equal 'connection_wait', result[:phase] # Proxy CONNECT not confirmed; cannot call this official TLS failure.
  end

  def test_failure_records_are_safe_and_certificate_errors_do_not_disable_tls
    events = []
    seen = []
    runner = lambda do |argv, timeout:|
      seen << argv
      ["SECRET_BODY\n000|0|0.02|0|0|0.03|000", 'PRIVATE_KEY_OR_TOKEN_IN_STDERR', Status.new(60)]
    end
    error = assert_raises(AccountApiRoutes::Error) { selector(runner: runner, observer: ->(v) { events << v }).select }
    assert_equal 'certificate', error.diagnostic[:phase]
    assert events.all? { |e| e[:phase] == 'certificate' }
    refute_match(/SECRET_BODY|PRIVATE_KEY_OR_TOKEN_IN_STDERR/, JSON.generate(events) + error.message)
    refute seen.flatten.any? { |arg| %w[-k --insecure -L --location].include?(arg) }
  end

  def test_recent_route_is_reused_then_expires_or_is_invalidated
    now = 0.0
    calls = 0
    runner = ->(_argv, timeout:) { calls += 1; ["[\"45.83.223.197:443\"]\n200", '', Status.new(0)] }
    route = selector(runner: runner, clock: -> { now })
    assert_equal 'direct_seed', route.select[:kind]
    assert_equal true, route.select[:reused]
    assert_equal 1, calls
    now = AccountApiRoutes::ROUTE_REUSE_SECONDS + 1
    route.select
    assert_equal 2, calls
    route.invalidate
    route.select
    assert_equal 3, calls
  end

  def test_network_epoch_change_invalidates_the_memory_route
    calls = 0
    route = selector(runner: ->(_argv, timeout:) { calls += 1; ["[\"45.83.223.197:443\"]\n200", '', Status.new(0)] })
    @adapter.instance_variable_set(:@account_api_selector, route)
    @adapter.send(:discover_account_api_route)
    @adapter.send(:discover_account_api_route)
    assert_equal 1, calls
    @adapter.instance_variable_get(:@state)[:local_network][:epoch] += 1
    @adapter.send(:discover_account_api_route)
    assert_equal 2, calls
  end

  def test_discovery_time_is_deducted_before_authenticated_request
    now = 0.0
    @adapter.define_singleton_method(:monotonic_now) { now }
    @adapter.define_singleton_method(:discover_account_api_route) { now += 24; ['--proxy', '', '--noproxy', '*'] }
    Thread.current[:adapter_account_deadline] = 30.0
    timeout = nil
    with_curl(lambda { |*argv, **_options|
      timeout = argv[argv.index('--max-time') + 1].to_f
      ["{}\n200", '', Status.new(0)]
    }) { @adapter.send(:account_request, 'GET', 'accounts/v1/devices') }
    assert_equal 6, timeout
  end

  def test_expired_transaction_does_not_start_authenticated_curl
    now = 0.0
    @adapter.define_singleton_method(:monotonic_now) { now }
    @adapter.define_singleton_method(:discover_account_api_route) { now = 31; ['--proxy', ''] }
    Thread.current[:adapter_account_deadline] = 30.0
    with_curl(->(*) { flunk 'request started after discovery exhausted transaction' }) do
      error = assert_raises(MullvadAdapter::AccountError) { @adapter.send(:account_request, 'GET', 'accounts/v1/devices') }
      assert_equal 'api_deadline_exceeded', error.code
    end
  end

  def test_mutation_transport_failure_is_not_replayed_and_invalidates_cached_route
    calls = 0
    invalidations = 0
    @adapter.define_singleton_method(:discover_account_api_route) { ['--proxy', ''] }
    @adapter.define_singleton_method(:invalidate_account_api_route) { invalidations += 1 }
    with_curl(lambda { |*argv, **options|
      calls += 1
      refute_includes argv.join(' '), 'PRIVATE_TOKEN'
      assert_includes options[:stdin_data], 'PRIVATE_TOKEN'
      ["\n000|0.001|0.04|0|0|8|000", 'SECRET_STDERR', Status.new(28)]
    }) do
      error = assert_raises(MullvadAdapter::AccountError) { @adapter.send(:account_request, 'DELETE', 'accounts/v1/devices/sensitive-device-id', token: 'PRIVATE_TOKEN') }
      refute_match(/PRIVATE_TOKEN|SECRET_STDERR|sensitive-device-id/, error.message)
    end
    assert_equal 1, calls
    assert_equal 1, invalidations
    @adapter.instance_variable_get(:@probe_event_writer)&.join(2)
    events = Dir.glob(File.join(@dir, '**', '*jsonl')).map { |p| File.read(p) }.join
    refute_match(/PRIVATE_TOKEN|SECRET_STDERR|sensitive-device-id/, events)
    assert_equal 'device_remove', @adapter.send(:account_health_summary)[:api_last_result][:endpoint]
  end

  def test_http_401_does_not_treat_known_official_response_as_a_transport_failure
    @adapter.define_singleton_method(:discover_account_api_route) { ['--proxy', ''] }
    @adapter.define_singleton_method(:invalidate_account_api_route) { flunk 'HTTP 401 is an authentication response, not a failed transport' }
    with_curl(->(*) { ["{}\n401", '', Status.new(0)] }) do
      error = assert_raises(MullvadAdapter::AccountError) { @adapter.send(:account_request, 'GET', 'accounts/v1/devices') }
      assert_equal 'http_401', error.code
    end
  end
  def test_slow_success_can_use_the_larger_attempt_budget
    now = 0.0
    observed_timeout = nil
    runner = lambda do |_argv, timeout:|
      observed_timeout = timeout
      now += 5
      ["[\"45.83.223.197:443\"]\n200", '', Status.new(0)]
    end
    assert_equal 'direct_seed', selector(clock: -> { now }, runner: runner).select[:kind]
    assert_operator observed_timeout, :>=, 5
  end

  def test_curl_peer_address_is_validated_without_logging_arbitrary_fields
    _body, metrics = AccountApiRoutes.split_response("{}\n200|0.01|0.03|0.07|0.1|0.2|000|45.83.223.196")
    assert_equal '45.83.223.196', metrics[:peer_ip]
    _body, metrics = AccountApiRoutes.split_response("{}\n200|0.01|0.03|0.07|0.1|0.2|000|PRIVATE_TOKEN")
    refute metrics.key?(:peer_ip)
    refute_includes JSON.generate(metrics), 'PRIVATE_TOKEN'
  end

  def test_another_accounts_failure_does_not_replace_selected_accounts_request_evidence
    @adapter.instance_variable_set(:@account_number, '1234567890123456')
    Thread.current[:adapter_account_observation_account] = '1234567890123478'
    @adapter.send(:record_account_api_observation, phase: 'tls_handshake', outcome: 'timeout', message: 'synthetic failure')
    assert_nil @adapter.send(:account_health_summary)[:api_last_result]
  ensure
    Thread.current[:adapter_account_observation_account] = nil
  end

end
