# frozen_string_literal: true

require_relative 'minitest_dependencies'
require 'tmpdir'
require_relative 'account_api_routes'

class AccountApiRoutesTest < Minitest::Test
  class Status
    def initialize(success)
      @success = success
    end

    def success? = @success
  end

  def setup
    @directory = Dir.mktmpdir('account-api-routes')
    File.chmod(0o700, @directory)
    @cache_path = File.join(@directory, 'api-addresses.json')
  end

  def teardown
    FileUtils.remove_entry(@directory)
  end

  def write_cache(addresses:, last_success: nil, mode: 0o600)
    File.write(@cache_path, JSON.generate(addresses: addresses, last_success: last_success), mode: 'w', perm: mode)
  end

  def success(body = '["45.83.223.197:443"]')
    ["#{body}\n200", '', Status.new(true)]
  end

  def failure(code = '000')
    ["\n#{code}", 'synthetic diagnostic that must not escape', Status.new(false)]
  end

  def route(args)
    index = args.index('--resolve')
    return [:direct, args[index + 1]] if index
    return [:configured_proxy, nil] if args.include?('--proxy') && args[args.index('--proxy') + 1] != ''
    return [:system_https, nil] if args.include?('--noproxy') && args[args.index('--noproxy') + 1] == '*'

    [:unknown, nil]
  end

  def new_selector(**overrides)
    AccountApiRoutes.new(proxy: nil, cache_path: @cache_path, **overrides)
  end

  def test_uses_cached_success_then_independent_proxy_then_official_seed
    write_cache(addresses: ['45.83.223.197:443'], last_success: '45.83.223.198:443')
    calls = []
    runner = lambda do |argv, timeout:|
      calls << [argv, timeout]
      case calls.length
      when 1 then failure
      when 2 then failure
      when 3 then success
      else flunk 'the selector should return on the first successful route'
      end
    end

    selected = new_selector(proxy: 'http://127.0.0.1:7890', runner: runner).select

    assert_equal 'direct_seed', selected[:kind]
    assert_equal ['45.83.223.197:443'], selected[:addresses]
    assert_equal [:direct, :configured_proxy, :direct], calls.map { |argv, _| route(argv).first }
    assert_equal 'api.mullvad.net:443:45.83.223.198', calls[0][0][calls[0][0].index('--resolve') + 1]
    assert_equal 'api.mullvad.net:443:45.83.223.196', calls[2][0][calls[2][0].index('--resolve') + 1]
    assert_includes selected[:args], '--resolve'
    assert_equal JSON.generate(addresses: ['45.83.223.197:443'], last_success: '45.83.223.196:443'), File.read(@cache_path)
    assert_equal 0o600, File.stat(@cache_path).mode & 0o777
    assert_equal 1, File.stat(@cache_path).nlink
  end

  def test_uses_configured_proxy_when_cached_direct_route_fails
    write_cache(addresses: ['45.83.223.197:443'], last_success: '45.83.223.198:443')
    calls = []
    runner = lambda do |argv, timeout:|
      calls << argv
      calls.length == 1 ? failure : success
    end

    selected = new_selector(proxy: 'http://127.0.0.1:7890', runner: runner).select

    assert_equal 'configured_proxy', selected[:kind]
    assert_equal [:direct, :configured_proxy], calls.map { |argv| route(argv).first }
    assert_equal ['--proxy', 'http://127.0.0.1:7890', '--noproxy', ''], selected[:args]
  end

  def test_configured_proxy_precedes_seed_when_no_direct_success_is_cached
    calls = []
    runner = lambda do |argv, timeout:|
      calls << argv
      calls.length == 1 ? failure : success
    end

    selected = new_selector(proxy: 'http://127.0.0.1:7890', runner: runner).select

    assert_equal 'direct_seed', selected[:kind]
    assert_equal [:configured_proxy, :direct], calls.map { |argv| route(argv).first }
  end

  def test_excluded_adapter_proxy_port_is_never_used
    calls = []
    runner = lambda do |argv, timeout:|
      calls << argv
      success
    end

    selected = new_selector(proxy: 'http://127.0.0.1:17890', excluded_proxy_ports: [17_890], runner: runner).select

    assert_equal 'direct_seed', selected[:kind]
    refute calls.any? { |argv| route(argv).first == :configured_proxy }
  end

  def test_system_https_is_final_fallback_with_environment_proxies_disabled
    calls = []
    runner = lambda do |argv, timeout:|
      calls << argv
      calls.length == 1 ? failure : success
    end

    selected = new_selector(runner: runner).select

    assert_equal 'system_https', selected[:kind]
    assert_equal [:direct, :system_https], calls.map { |argv| route(argv).first }
    assert_equal ['--proxy', '', '--noproxy', '*'], selected[:args]
  end

  def test_ipv6_cache_address_uses_curl_resolve_syntax_without_changing_url_host
    write_cache(addresses: ['[2606:4700:4700::1111]:443'], last_success: '[2606:4700:4700::1111]:443')
    captured = nil
    runner = lambda do |argv, timeout:|
      captured = argv
      success
    end

    selected = new_selector(runner: runner).select

    assert_equal 'direct_cached', selected[:kind]
    resolve = captured[captured.index('--resolve') + 1]
    assert_equal 'api.mullvad.net:443:[2606:4700:4700::1111]', resolve
    assert_equal 'https://api.mullvad.net/app/v1/api-addrs', captured.last
  end

  def test_probe_is_credential_free_tls_verified_and_never_follows_redirects
    captured = nil
    runner = lambda do |argv, timeout:|
      captured = argv
      success
    end

    new_selector(proxy: 'http://127.0.0.1:7890', runner: runner).select

    assert_includes captured, 'https://api.mullvad.net/app/v1/api-addrs'
    refute captured.any? { |arg| arg.match?(/Authorization|Bearer|account_number|test-token/i) }
    refute captured.any? { |arg| %w[-k --insecure -L --location].include?(arg) }
    assert_equal ['GET'], captured.each_with_index.filter_map { |arg, index| captured[index + 1] if arg == '--request' }
    assert_equal 1, captured.count { |arg| arg == 'https://api.mullvad.net/app/v1/api-addrs' }
    assert_equal 8.0, captured[captured.index('--max-time') + 1].to_f
    assert_equal 4.0, captured[captured.index('--connect-timeout') + 1].to_f
  end

  def test_invalid_proxy_and_network_errors_do_not_leak_raw_details
    calls = []
    runner = lambda do |argv, timeout:|
      calls << argv
      ["proxy credential or account body\n503", 'secret stderr', Status.new(true)]
    end
    selector = new_selector(proxy: 'http://user:password@127.0.0.1:7890', runner: runner)

    error = assert_raises(AccountApiRoutes::Error) { selector.select }

    assert_equal 'route_unavailable', error.code
    refute_includes error.message, 'password'
    refute_includes error.message, 'proxy credential'
    refute calls.any? { |argv| argv.any? { |arg| arg.include?('password') } }
  end

  def test_rejects_private_and_malformed_api_address_lists_without_overwriting_cache
    write_cache(addresses: ['45.83.223.197:443'], last_success: '45.83.223.197:443')
    original = File.binread(@cache_path)
    invalid = [
      '["127.0.0.1:443"]', '["10.1.2.3:443"]', '["169.254.1.1:443"]',
      '["100.64.0.1:443"]', '["192.0.2.1:443"]', '["224.0.0.1:443"]',
      '["[::1]:443"]', '["[fe80::1]:443"]', '["[fc00::1]:443"]',
      '["[ff02::1]:443"]', '["45.83.223.197:80"]', 'not json', '[]',
      JSON.generate(Array.new(17, '45.83.223.197:443'))
    ]
    responses = invalid.flat_map { |body| [["#{body}\n200", '', Status.new(true)]] }
    runner = lambda do |argv, timeout:|
      responses.shift || failure
    end

    error = assert_raises(AccountApiRoutes::Error) do
      new_selector(runner: runner).select
    end

    assert_equal 'route_unavailable', error.code
    assert_equal original, File.binread(@cache_path)
  end

  def test_limits_addresses_and_deduplicates_valid_official_response
    list = ['45.83.223.197:443', '45.83.223.197:443', '[2606:4700:4700::1111]:443']
    runner = ->(_argv, timeout:) { ["#{JSON.generate(list)}\n200", '', Status.new(true)] }

    selected = new_selector(runner: runner).select

    assert_equal ['45.83.223.197:443', '[2606:4700:4700::1111]:443'], selected[:addresses]
    cache = JSON.parse(File.read(@cache_path))
    assert_equal selected[:addresses], cache['addresses']
  end

  def test_unsafe_cache_symlink_is_not_followed_or_overwritten
    target = File.join(@directory, 'target.json')
    target_bytes = JSON.generate(addresses: ['45.83.223.197:443'], last_success: nil)
    File.write(target, target_bytes, mode: 'w', perm: 0o600)
    File.symlink(target, @cache_path)
    runner = ->(_argv, timeout:) { success }

    selected = new_selector(runner: runner).select

    assert_equal 'direct_seed', selected[:kind]
    assert File.symlink?(@cache_path)
    assert_equal target_bytes, File.read(target)
  end

  def test_unsafe_cache_permissions_and_hardlinks_are_not_overwritten
    write_cache(addresses: ['45.83.223.197:443'], last_success: nil, mode: 0o644)
    original = File.binread(@cache_path)
    runner = ->(_argv, timeout:) { success }

    new_selector(runner: runner).select
    assert_equal original, File.binread(@cache_path)
    assert_equal 0o644, File.stat(@cache_path).mode & 0o777

    File.unlink(@cache_path)
    write_cache(addresses: ['45.83.223.197:443'], last_success: nil)
    original = File.binread(@cache_path)
    duplicate = File.join(@directory, 'duplicate.json')
    File.link(@cache_path, duplicate)
    new_selector(runner: runner).select
    assert_equal original, File.binread(@cache_path)
    assert_equal original, File.binread(duplicate)
  end

  def test_oversized_cache_is_not_read_or_overwritten
    original = 'x' * (AccountApiRoutes::MAX_CACHE_BYTES + 1)
    File.write(@cache_path, original, mode: 'w', perm: 0o600)
    runner = ->(_argv, timeout:) { success }

    selected = new_selector(runner: runner).select

    assert_equal 'direct_seed', selected[:kind]
    assert_equal original, File.binread(@cache_path)
  end

  def test_bounds_direct_candidates_per_selection
    addresses = (197..210).map { |last| "45.83.223.#{last}:443" }
    write_cache(addresses: addresses, last_success: '45.83.223.196:443')
    captured = []
    runner = lambda do |argv, timeout:|
      captured << argv
      failure
    end

    assert_raises(AccountApiRoutes::Error) do
      new_selector(proxy: 'http://127.0.0.1:7890', runner: runner).select
    end

    direct = captured.map { |argv| route(argv) }.select { |kind, _| kind == :direct }
    assert_equal AccountApiRoutes::MAX_DIRECT_CANDIDATES, direct.length
    assert_equal :system_https, route(captured.last).first
  end

  def test_total_and_per_attempt_budgets_are_bounded
    write_cache(addresses: ['45.83.223.197:443', '45.83.223.198:443'], last_success: '45.83.223.199:443')
    clock_value = 0.0
    clock = -> { clock_value }
    timeouts = []
    runner = lambda do |argv, timeout:|
      timeouts << timeout
      clock_value += timeout
      failure
    end

    assert_raises(AccountApiRoutes::Error) do
      new_selector(proxy: 'http://127.0.0.1:7890', runner: runner, clock: clock).select
    end

    assert_operator timeouts.length, :<=, 5 # four pinned addresses plus proxy, bounded by the shared deadline
    assert_operator timeouts.max, :<=, AccountApiRoutes::MAX_ATTEMPT_SECONDS
    assert_operator clock_value, :<=, AccountApiRoutes::MAX_TOTAL_SECONDS
  end

  def test_cache_write_failure_does_not_invalidate_discovery
    missing_parent = File.join(@directory, 'absent', 'api-addresses.json')
    runner = ->(_argv, timeout:) { success }

    selected = AccountApiRoutes.new(proxy: nil, cache_path: missing_parent, runner: runner).select

    assert_equal 'direct_seed', selected[:kind]
    refute File.exist?(File.dirname(missing_parent))
  end
end
