# frozen_string_literal: true
require_relative 'minitest_dependencies'
require 'tmpdir'
require_relative 'mullvad_adapter'

class MullvadAccountOnboardingTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('mullvad-onboarding')
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def test_clean_state_starts_only_the_account_control_api_without_engines
    adapter = MullvadAdapter.new(state_dir: @dir)
    called = []
    adapter.define_singleton_method(:trap_signals) {}
    adapter.define_singleton_method(:start_api_server) { called << :api; @stop_requested = true }
    %i[ensure_front load_cached_metadata start_connection_monitor start_local_network_monitor
       start_control_plane_monitor start_active_health_monitor start_runtime_supervisor start_city_maintenance].each do |name|
      adapter.define_singleton_method(name) { raise "unexpected first-run operation: #{name}" }
    end
    adapter.define_singleton_method(:shutdown) { called << :shutdown }
    adapter.run
    assert_equal [:api, :shutdown], called
    state = adapter.send(:snapshot)
    assert_equal 'needs_setup', state[:service_readiness]
    refute state[:front][:ready]
    assert_empty state[:workers]
    assert_nil state[:active_relay]
    refute File.exist?(adapter.send(:template_path))
    assert_equal ['--proxy', '', '--noproxy', '*'], adapter.send(:bootstrap_proxy_args)
    assert_nil adapter.instance_variable_get(:@options)[:profile]
    assert_nil adapter.instance_variable_get(:@options)[:default_relay]
  end

  def test_explicit_missing_profile_fails_instead_of_becoming_account_only
    adapter = MullvadAdapter.new(state_dir: @dir, profile: File.join(@dir, 'missing.yaml'))
    assert_raises(Errno::ENOENT) { adapter.send(:load_template) }
  end

  def test_explicit_invalid_proxy_is_not_replaced_with_system_https
    adapter = MullvadAdapter.new(state_dir: @dir, bootstrap_proxy: 'http://example.invalid:8080')
    assert_raises(RuntimeError) { adapter.send(:bootstrap_proxy_args) }
  end

  def test_cached_identity_keeps_historical_local_defaults_unless_explicitly_overridden
    File.write(File.join(@dir, 'wireguard-template.json'), '{}')
    legacy = MullvadAdapter.new(state_dir: @dir)
    assert_equal ['--proxy', 'http://127.0.0.1:17893'], legacy.send(:bootstrap_proxy_args)
    assert_equal 'us-sea-wg-401', legacy.instance_variable_get(:@options)[:default_relay]
    assert_equal 'legacy_local_default', legacy.instance_variable_get(:@api_route_source)
    explicit = MullvadAdapter.new(state_dir: @dir, bootstrap_proxy: '', default_relay: 'example-relay')
    assert_equal ['--proxy', '', '--noproxy', '*'], explicit.send(:bootstrap_proxy_args)
    assert_equal 'example-relay', explicit.instance_variable_get(:@options)[:default_relay]
    assert_equal 'explicit_option', explicit.instance_variable_get(:@api_route_source)
  end

  def test_new_state_does_not_inherit_legacy_defaults_when_an_identity_is_added_later
    File.write(File.join(@dir, 'bootstrap-defaults.json'), JSON.generate(schema: 1, source: 'system_default'))
    File.chmod(0o600, File.join(@dir, 'bootstrap-defaults.json'))
    File.write(File.join(@dir, 'wireguard-template.json'), '{}')
    adapter = MullvadAdapter.new(state_dir: @dir)
    assert_equal ['--proxy', '', '--noproxy', '*'], adapter.send(:bootstrap_proxy_args)
    assert_nil adapter.instance_variable_get(:@options)[:default_relay]
    assert_equal 'system_default', adapter.instance_variable_get(:@api_route_source)
  end

  def test_corrupt_default_provenance_cannot_silently_restore_legacy_proxy
    File.write(File.join(@dir, 'bootstrap-defaults.json'), JSON.generate(schema: 1, source: 'unknown'))
    assert_raises(RuntimeError) { MullvadAdapter.new(state_dir: @dir) }
  end

  def test_system_https_does_not_claim_clash_entry_validation
    adapter = MullvadAdapter.new(state_dir: @dir)
    adapter.send(:check_clash_global_path)
    assert_equal 'external', adapter.send(:snapshot).dig(:dns, :clash_global, :status)
  end

  def defaults_pair
    path = File.join(@dir, 'bootstrap-defaults.json')
    pending = path + '.pending'
    File.write(pending, JSON.generate(schema: 1, source: 'system_default'), mode: 'w', perm: 0o600)
    File.link(pending, path)
    [path, pending]
  end

  def test_constructor_recovers_exact_defaults_link_pair_before_private_read
    path, pending = defaults_pair
    assert_equal 2, File.stat(path).nlink
    adapter = MullvadAdapter.new(state_dir: @dir)
    assert_equal 'system_default', adapter.instance_variable_get(:@api_route_source)
    assert_equal 1, File.stat(path).nlink
    refute File.exist?(pending)
    assert_equal ['--proxy', '', '--noproxy', '*'], adapter.send(:bootstrap_proxy_args)
  end

  def test_constructor_never_unlinks_a_conflicting_defaults_pending_record
    path, pending = defaults_pair
    File.unlink(pending)
    File.write(pending, 'conflicting record', mode: 'w', perm: 0o600)
    assert_raises(RuntimeError) { MullvadAdapter.new(state_dir: @dir) }
    assert_equal 'conflicting record', File.read(pending)
    assert_equal 'system_default', JSON.parse(File.read(path))['source']
  end

  def test_constructor_rejects_extra_hardlinks_or_public_defaults_pair
    path, pending = defaults_pair
    third = File.join(@dir, 'unexpected-third-link')
    File.link(path, third)
    assert_raises(RuntimeError) { MullvadAdapter.new(state_dir: @dir) }
    assert_equal 3, File.stat(path).nlink
    assert File.exist?(pending)
    File.unlink(third)
    File.chmod(0o644, path)
    assert_raises(RuntimeError) { MullvadAdapter.new(state_dir: @dir) }
    assert_equal 2, File.stat(path).nlink
    assert File.exist?(pending)
  end
end
