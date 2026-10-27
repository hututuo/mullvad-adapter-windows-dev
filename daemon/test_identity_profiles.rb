# frozen_string_literal: true
require_relative 'test_account'

class MullvadIdentityProfilesTest < MullvadAccountTest
  SECOND_NUMBER = '1234567890123478'
  SECOND_KEY = Base64.strict_encode64(['5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'].pack('H*'))

  def setup
    super
    first_template = @adapter.instance_variable_get(:@template).merge('ipv6' => 'fc00::2')
    @adapter.instance_variable_set(:@template, first_template)
    @first = @adapter.send(:identity_profile_record, number: NUMBER, template: first_template)
    second_template = { 'ip' => '10.64.0.3', 'ipv6' => 'fc00::3', 'private-key' => SECOND_KEY }
    @second = @adapter.send(:identity_profile_record, number: SECOND_NUMBER, template: second_template,
      device: { 'id' => OTHER, 'name' => 'fixture animal', 'pubkey' => @adapter.send(:template_public_key, SECOND_KEY),
                'ipv4_address' => '10.64.0.3/32', 'ipv6_address' => 'fc00::3/128' })
    @adapter.send(:write_identity_profiles, { 'schema' => 1, 'revision' => 0, 'active_id' => nil, 'profiles' => [@first, @second] })
  end

  def selection
    { 'id' => @second['id'], 'expected_active_id' => @first['id'] }
  end

  def test_list_has_no_private_key_or_complete_account_and_marks_unknown_name
    code, data, raw = request('/account')
    assert_equal 200, code
    assert_equal 2, data['saved_identities'].length
    assert_equal @first['id'], data['active_identity_id']
    assert_nil data['saved_identities'].first['device_name']
    assert_equal 'not_verified', data['saved_identities'].first['name_source']
    [NUMBER, SECOND_NUMBER, SECOND_KEY, @first['template']['private-key']].each { |secret| refute_includes raw, secret }
    assert_equal 0o600, File.stat(@adapter.send(:identity_profiles_path)).mode & 0o777
  end

  def test_switch_stops_every_worker_before_committing_and_resets_observations
    workers = @adapter.instance_variable_get(:@workers)
    workers['a'] = { pid: 1 }; workers['b'] = { pid: 2 }
    trace = []
    adapter = @adapter
    @adapter.define_singleton_method(:stop_worker) do |slot|
      trace << [:stop, slot, active_saved_identity&.fetch('id')]
      @workers.delete(slot)
    end
    @adapter.instance_variable_set(:@account_token, { value: 'old-token' })
    @adapter.instance_variable_set(:@last_network_path, { relay: 'old' })
    @adapter.instance_variable_get(:@inner_dns_observations) << { relay: 'old' }
    generation = @adapter.send(:snapshot)[:generation]
    assert @adapter.send(:switch_saved_identity, selection, '', 'auto')
    assert_equal [[:stop, 'a', nil], [:stop, 'b', nil]], trace
    assert_empty workers
    assert_equal @second['id'], @adapter.send(:active_saved_identity)['id']
    assert_equal SECOND_KEY, @adapter.instance_variable_get(:@template)['private-key']
    assert_nil @adapter.instance_variable_get(:@account_token)
    assert_nil @adapter.instance_variable_get(:@last_network_path)
    assert_empty @adapter.instance_variable_get(:@inner_dns_observations)
    assert_operator @adapter.send(:snapshot)[:generation], :>, generation
    refute File.exist?(File.join(@dir, 'account.json')) # No mixed two-file commit.
    refute File.exist?(@adapter.send(:template_path))
    fresh = MullvadAdapter.new(state_dir: @dir)
    fresh.send(:load_template); fresh.send(:load_account_manager)
    assert_equal SECOND_NUMBER, fresh.instance_variable_get(:@account_number)
    assert_equal SECOND_KEY, fresh.instance_variable_get(:@template)['private-key']
  end

  def test_cleanup_failure_does_not_select_new_identity
    @adapter.instance_variable_get(:@workers)['a'] = { pid: 1 }
    @adapter.define_singleton_method(:stop_worker) { |_| raise MullvadAdapter::LocalProbeTimeout, 'worker-stop' }
    assert_raises(MullvadAdapter::LocalProbeTimeout) { @adapter.send(:switch_saved_identity, selection, '', 'auto') }
    assert_nil @adapter.send(:active_saved_identity)
    assert_equal @first['template']['private-key'], @adapter.instance_variable_get(:@template)['private-key']
  end

  def test_stale_selection_cannot_change_identity_or_start_an_engine
    error = assert_raises(MullvadAdapter::AccountError) { @adapter.send(:switch_saved_identity, selection.merge('expected_active_id' => 'stale'), '', 'auto') }
    assert_equal 'identity_changed', error.code
    assert_empty @adapter.instance_variable_get(:@workers)
    assert_nil @adapter.send(:active_saved_identity)
  end

  def test_switch_requires_local_authorization_and_confirmation
    assert_equal 403, request('/account/identities/switch', selection, authorized: false).first
    assert_equal 'confirmation_required', request('/account/identities/switch', selection)[1]['code']
    assert_empty @calls
  end

  def test_real_http_admission_hands_over_account_lock_before_the_switch
    code, receipt = request('/account/identities/switch', selection.merge('confirm' => true))
    assert_equal 202, code
    Timeout.timeout(3) { sleep 0.01 while @adapter.send(:action_pending?) }
    operation = @adapter.send(:operation_snapshot, receipt['id'])
    assert_equal 'succeeded', operation[:state], operation[:error]
    assert_includes operation[:message], '尚未验证联网'
    assert_equal @second['id'], @adapter.send(:active_saved_identity)['id']
    assert_empty @calls
  end

  def test_directory_sync_failure_after_atomic_commit_keeps_memory_and_disk_on_same_identity
    @adapter.define_singleton_method(:sync_identity_directory) { |_| raise Errno::EIO }
    assert @adapter.send(:switch_saved_identity, selection, '', 'auto')
    assert_equal @second['id'], @adapter.send(:active_saved_identity)['id']
    assert_equal SECOND_KEY, @adapter.instance_variable_get(:@template)['private-key']
  end

  def test_corrupt_or_symlinked_store_fails_closed_without_legacy_fallback
    path = @adapter.send(:identity_profiles_path)
    File.write(path, '{bad')
    assert_raises(MullvadAdapter::AccountError) { @adapter.send(:load_template) }
    File.unlink(path); File.symlink(File.join(@dir, 'account-capability'), path)
    assert_raises(MullvadAdapter::AccountError) { @adapter.send(:identity_profiles_document) }
  end

  def test_modified_template_cannot_import_a_dialer_or_mismatched_key
    path = @adapter.send(:identity_profiles_path)
    data = JSON.parse(File.read(path))
    data['profiles'].last['template']['dialer-proxy'] = 'untrusted'
    File.write(path, JSON.generate(data))
    assert_raises(MullvadAdapter::AccountError) { @adapter.send(:identity_profiles_document) }
  end

  def test_official_device_must_match_private_key_and_assigned_addresses
    assert_raises(MullvadAdapter::AccountError) do
      @adapter.send(:identity_profile_record, number: SECOND_NUMBER, template: @second['template'],
        device: { 'name' => 'wrong', 'pubkey' => @first['public_key'], 'ipv4_address' => '10.64.0.3/32', 'ipv6_address' => 'fc00::3/128' })
    end
  end

  def test_failed_network_activation_does_not_claim_new_identity_is_connected
    @adapter.instance_variable_set(:@metadata, {})
    @adapter.define_singleton_method(:activate) { |*, **| false }
    refute @adapter.send(:switch_saved_identity, selection, 'fixture-relay', 'auto')
    assert_equal @second['id'], @adapter.send(:active_saved_identity)['id']
    assert_nil @adapter.send(:snapshot)[:active_slot]
    refute_equal 'ready', @adapter.send(:snapshot)[:service_readiness]
  end

  def test_logout_of_saved_identity_stays_logged_out_after_backend_restart
    @adapter.send(:switch_saved_identity, selection, '', 'auto')
    assert_equal 200, request('/account/logout', {}).first
    fresh = MullvadAdapter.new(state_dir: @dir)
    fresh.send(:load_template); fresh.send(:load_account_manager)
    assert_nil fresh.instance_variable_get(:@account_number)
    assert_equal SECOND_KEY, fresh.instance_variable_get(:@template)['private-key']
  end

  def test_same_selected_identity_is_an_idempotent_read_without_worker_restart
    @adapter.send(:switch_saved_identity, selection, '', 'auto')
    @adapter.define_singleton_method(:stop_worker) { |_| flunk 'must not touch a worker' }
    before = File.binread(@adapter.send(:identity_profiles_path))
    assert @adapter.send(:switch_saved_identity, { 'id' => @second['id'], 'expected_active_id' => @second['id'] }, '', 'auto')
    assert_equal before, File.binread(@adapter.send(:identity_profiles_path))
  end
end
