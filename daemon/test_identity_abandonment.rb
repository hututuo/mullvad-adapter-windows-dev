# frozen_string_literal: true
require_relative 'test_first_identity'

class MullvadIdentityAbandonmentTest < Minitest::Test
  def setup
    @fixture = MullvadFirstIdentityTest.new(:test_precommit_failure_preserves_setup_and_can_retry_the_exact_identity)
    @fixture.setup
    @adapter = @fixture.instance_variable_get(:@adapter)
    @dir = @fixture.instance_variable_get(:@dir)
    target = @adapter.send(:template_path)
    @adapter.define_singleton_method(:write_private_identity_once) do |path, bytes|
      if path == target
        File.open(path + '.pending', File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(bytes); file.flush; file.fsync }
        raise IOError, 'injected template precommit failure'
      end
      super(path, bytes)
    end
    assert_equal 422, @fixture.request.first
    @adapter.singleton_class.remove_method(:write_private_identity_once)
    @metadata_path = File.join(@dir, 'identity-installation.json')
    @pending_path = target + '.pending'
    @metadata = File.binread(@metadata_path)
    @pending = File.binread(@pending_path)
    @hash = Digest::SHA256.hexdigest(@metadata)
    @fixture.instance_variable_get(:@reads).clear
  end

  def teardown
    @fixture.teardown
  end

  def payload
    { 'confirm' => true, 'account_fingerprint' => Digest::SHA256.hexdigest(@adapter.instance_variable_get(:@account_number)),
      'expected_installation_account_fingerprint' => Digest::SHA256.hexdigest(MullvadFirstIdentityTest::NUMBER), 'expected_metadata_sha256' => @hash }
  end

  def cancel(values = payload)
    @fixture.request(values, action: 'identity/abandon')
  end

  def status
    @fixture.request({ 'account_fingerprint' => Digest::SHA256.hexdigest(@adapter.instance_variable_get(:@account_number)),
      'public_key' => MullvadFirstIdentityTest::PUBLIC, 'device_id' => MullvadFirstIdentityTest::DEVICE }, action: 'identity/abandonment-status')
  end

  def archive
    File.join(@dir, 'retired-installations', @hash)
  end

  def assert_preserved_archives
    assert_equal @metadata, File.binread(File.join(archive, 'metadata.json'))
    assert_equal @pending, File.binread(File.join(archive, 'template-pending.json'))
    assert_equal 0o600, File.stat(File.join(archive, 'template-pending.json')).mode & 0o777
    assert_equal 1, File.stat(File.join(archive, 'template-pending.json')).nlink
    refute File.exist?(@metadata_path)
    refute File.exist?(@pending_path)
    refute File.exist?(@adapter.send(:template_path))
  end

  def test_cancel_copies_exact_bytes_and_proves_abandonment_without_official_api
    code, snapshot, raw = cancel
    assert_equal 200, code
    assert_nil snapshot['pending_identity_installation']
    refute snapshot['identity_configured']
    assert_preserved_archives
    assert_empty @fixture.instance_variable_get(:@reads)
    code, reply = status
    assert_equal 200, code
    assert_equal @hash, reply.dig('receipt', 'metadata_sha256')
    refute_includes raw, MullvadFirstIdentityTest::PRIVATE
    assert_equal 200, cancel.first
    assert_preserved_archives
  end

  def test_cross_account_dual_binding_releases_old_intent_for_valid_new_identity
    @adapter.instance_variable_set(:@account_number, '9999999999999999')
    assert_equal 200, cancel.first
    assert_empty @fixture.instance_variable_get(:@reads)
    key = Base64.strict_encode64(['5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'].pack('H*'))
    pubkey = @adapter.send(:template_public_key, key)
    device = { 'id' => '44444444-4444-4444-4444-444444444444', 'name' => 'second bird', 'pubkey' => pubkey, 'ipv4_address' => '10.64.0.3/32', 'ipv6_address' => 'fc00::3/128' }
    @fixture.instance_variable_get(:@devices).replace([device])
    @adapter.send(:save_registration_receipt, device)
    code, snapshot = @fixture.request({ 'confirm' => true, 'account_fingerprint' => payload['account_fingerprint'],
      'device_id' => device['id'], 'public_key' => pubkey, 'private_key' => key, 'ipv4_address' => device['ipv4_address'], 'ipv6_address' => device['ipv6_address'] })
    assert_equal 200, code
    assert_equal pubkey, snapshot['activated_draft_public_key']
    @adapter.instance_variable_set(:@account_number, MullvadFirstIdentityTest::NUMBER)
    assert_equal @hash, status[1].dig('receipt', 'metadata_sha256')
    assert_equal key, JSON.parse(File.read(@adapter.send(:template_path)))['private-key']
  end

  def test_revoked_original_can_be_abandoned_but_retired_key_cannot_be_reinstalled
    @fixture.instance_variable_get(:@devices).clear
    assert_equal 200, cancel.first
    assert_equal @hash, status[1].dig('receipt', 'metadata_sha256')
    assert_empty @fixture.instance_variable_get(:@reads)
    assert_equal 'identity_abandoned', @fixture.request[1]['code']
    refute File.exist?(@adapter.send(:template_path))
  end

  def test_current_account_old_account_and_metadata_hash_are_all_bound
    assert_equal 'account_changed', cancel(payload.merge('account_fingerprint' => 'b' * 64))[1]['code']
    assert_equal 'installation_changed', cancel(payload.merge('expected_installation_account_fingerprint' => 'b' * 64))[1]['code']
    assert_equal 'installation_changed', cancel(payload.merge('expected_metadata_sha256' => 'b' * 64))[1]['code']
    assert_equal 'confirmation_required', cancel(payload.merge('confirm' => false))[1]['code']
    assert_equal @metadata, File.binread(@metadata_path)
    assert_equal @pending, File.binread(@pending_path)
    refute File.exist?(archive)
  end

  def test_archives_are_read_back_before_source_unlink
    @adapter.define_singleton_method(:verify_abandonment_archives!) { |*| raise IOError, 'injected readback failure' }
    assert_equal 'identity_abandonment_unknown', cancel[1]['code']
    assert_equal @metadata, File.binread(@metadata_path)
    assert_equal @pending, File.binread(@pending_path)
    refute File.exist?(File.join(@dir, 'identity-abandonment.json'))
  end

  def test_symlink_or_extra_hardlink_pending_template_is_never_followed_or_deleted
    other = File.join(@dir, 'outside-record')
    File.rename(@pending_path, other)
    File.symlink(other, @pending_path)
    assert_equal 422, cancel.first
    assert_equal @pending, File.binread(other)
    File.unlink(@pending_path)
    File.link(other, @pending_path)
    assert_equal 422, cancel.first
    assert_equal @pending, File.binread(other)
    assert_equal @metadata, File.binread(@metadata_path)
  end

  def test_template_appearing_at_cleanup_boundary_blocks_all_cleanup
    target = @adapter.send(:template_path)
    @adapter.define_singleton_method(:check_abandonment_sources!) do |plan|
      File.write(target, 'new occupied identity', mode: 'w', perm: 0o600) unless File.exist?(target)
      super(plan)
    end
    assert_equal 'identity_exists', cancel[1]['code']
    assert_equal 'new occupied identity', File.read(target)
    assert_equal @metadata, File.binread(@metadata_path)
    assert_equal @pending, File.binread(@pending_path)
  end

  def test_archive_count_limit_stops_before_any_source_is_unlinked
    root = File.join(@dir, 'retired-installations')
    Dir.mkdir(root, 0o700)
    64.times { |index| Dir.mkdir(File.join(root, format('%064x', index)), 0o700) }
    assert_equal 'identity_abandonment_unknown', cancel[1]['code']
    assert_equal @metadata, File.binread(@metadata_path)
    assert_equal @pending, File.binread(@pending_path)
  end

  def test_locks_and_port_reservation_cover_every_source_cleanup
    adapter, source_paths = @adapter, [@metadata_path, @pending_path]
    ports = @fixture.instance_variable_get(:@ports)
    ports.clear
    hook = Module.new do
      define_method(:unlink) do |path|
        if source_paths.include?(path)
          raise 'account lock missing' unless adapter.instance_variable_get(:@account_mutex).locked?
          raise 'operation lock missing' unless adapter.instance_variable_get(:@switch_mutex).locked?
          raise 'port reservation missing' unless ports == [:reserved]
        end
        super(path)
      end
    end
    # This singleton hook is inert outside these exact disposable fixture paths.
    File.singleton_class.prepend(hook)
    assert_equal 200, cancel.first
    assert_equal [:reserved, :released], ports
    assert_preserved_archives
  end

  def test_engine_or_account_concurrency_cannot_clear_an_installation
    @adapter.instance_variable_set(:@front_pid, 123)
    assert_equal 'engine_running', cancel[1]['code']
    @adapter.instance_variable_set(:@front_pid, nil)
    lock = @adapter.instance_variable_get(:@switch_mutex)
    lock.lock
    assert_equal 'identity_busy', cancel[1]['code']
    lock.unlock
    lock = @adapter.instance_variable_get(:@account_mutex)
    lock.lock
    assert_equal 'account_busy', cancel[1]['code']
    lock.unlock
    assert_equal @metadata, File.binread(@metadata_path)
    assert_equal @pending, File.binread(@pending_path)
    assert_empty @fixture.instance_variable_get(:@reads)
  end

  def test_restart_after_source_removal_finishes_from_durable_journal_only
    pid = fork do
      original = @metadata_path
      File.singleton_class.prepend(Module.new do
        define_method(:unlink) do |path|
          result = super(path)
          Process.exit!(77) if path == original
          result
        end
      end)
      cancel
      Process.exit!(78)
    end
    Process.wait(pid)
    assert_equal 77, $?.exitstatus
    replacement = MullvadAdapter.new(state_dir: @dir)
    replacement.send(:prepare_state_dir)
    replacement.send(:load_account_manager)
    replacement.instance_variable_set(:@account_number, MullvadFirstIdentityTest::NUMBER)
    replacement.instance_variable_set(:@account_only_mode, true)
    replacement.define_singleton_method(:reserve_identity_install_ports) { |&block| block.call }
    replacement.define_singleton_method(:account_refresh) { |*| raise 'unexpected official API request' }
    @adapter = replacement
    @fixture.instance_variable_set(:@adapter, replacement)
    assert replacement.send(:pending_identity_installation)[:cancellation_pending]
    assert_equal 'identity_abandonment_pending', @fixture.request[1]['code']
    assert_equal 200, cancel.first
    assert_preserved_archives
  end

  def test_every_durable_write_boundary_resumes_without_losing_source_key
    boundaries = %w[metadata.json template-pending.json plan.json identity-abandonment.json completed.json index]
    boundaries.each_with_index do |boundary, index|
      if index.positive?
        teardown
        setup
      end
      pid = fork do
        @adapter.define_singleton_method(:write_abandonment_record_once) do |path, bytes|
          result = super(path, bytes)
          matched = boundary == 'index' ? path.include?('/abandoned-device-drafts/') : File.basename(path) == boundary
          Process.exit!(71) if matched
          result
        end
        cancel
        Process.exit!(72)
      end
      Process.wait(pid)
      assert_equal 71, $?.exitstatus, boundary
      if %w[completed.json index].include?(boundary)
        assert_equal @hash, status[1].dig('receipt', 'metadata_sha256'), boundary
      end
      assert_equal 200, cancel.first, boundary
      assert_preserved_archives
    end
  end

  def test_process_exit_during_each_archive_journal_and_receipt_write_is_recoverable
    boundaries = %w[metadata.json template-pending.json plan.json identity-abandonment.json completed.json index]
    cases = boundaries.product(%w[empty partial written linked])
    cases.each_with_index do |(boundary, point), index|
      if index.positive?
        teardown
        setup
      end
      pid = fork do
        armed = false
        @adapter.define_singleton_method(:write_abandonment_record_once) do |path, bytes|
          matched = boundary == 'index' ? path.include?('/abandoned-device-drafts/') : File.basename(path) == boundary
          if matched && !armed
            armed = true
            prefix = File.join(@state_dir, 'identity-abandonment-staging', Digest::SHA256.hexdigest(path) + '-')
            File.prepend(Module.new do
              define_method(:write) do |content|
                if self.path.start_with?(prefix)
                  Process.exit!(75) if point == 'empty'
                  if point == 'partial'
                    super(content.byteslice(0, 5))
                    Process.exit!(75)
                  end
                  result = super(content)
                  Process.exit!(75) if point == 'written'
                  result
                else
                  super(content)
                end
              end
            end)
            File.singleton_class.prepend(Module.new do
              define_method(:link) do |source, target|
                result = super(source, target)
                Process.exit!(75) if source.start_with?(prefix) && point == 'linked'
                result
              end
            end)
          end
          super(path, bytes)
        end
        cancel
        Process.exit!(76)
      end
      Process.wait(pid)
      assert_equal 75, $?.exitstatus, [boundary, point].join(':')
      assert_equal 200, cancel.first, [boundary, point].join(':')
      assert_preserved_archives
      stages = Dir.children(File.join(@dir, 'identity-abandonment-staging'))
      assert_operator stages.length, :<=, 1
      stages.each { |name| assert_equal 1, File.lstat(File.join(@dir, 'identity-abandonment-staging', name)).nlink }
    end
  end

  def test_foreign_staging_link_and_staging_capacity_preserve_source_records
    directory = File.join(@dir, 'identity-abandonment-staging')
    Dir.mkdir(directory, 0o700)
    target = File.join(archive, 'metadata.json')
    stage = File.join(directory, Digest::SHA256.hexdigest(target) + '-' + ('a' * 16))
    File.symlink(@metadata_path, stage)
    assert_equal 422, cancel.first
    assert_equal @metadata, File.binread(@metadata_path)
    File.unlink(stage)
    File.link(@metadata_path, stage)
    assert_equal 422, cancel.first
    assert_equal @metadata, File.binread(@metadata_path)
    File.unlink(stage)
    64.times { |index| File.write(File.join(directory, format('%064x-%016x', index, index)), '', mode: 'w', perm: 0o600) }
    assert_equal 422, cancel.first
    assert_equal @metadata, File.binread(@metadata_path)
    assert_equal @pending, File.binread(@pending_path)
  end

  def test_each_source_or_journal_unlink_boundary_resumes_idempotently
    [@pending_path, @metadata_path, File.join(@dir, 'identity-abandonment.json')].each_with_index do |path, index|
      if index.positive?
        teardown
        setup
        path = index == 1 ? @metadata_path : File.join(@dir, 'identity-abandonment.json')
      end
      pid = fork do
        hook = Module.new do
          define_method(:unlink) do |target|
            result = super(target)
            Process.exit!(73) if target == path
            result
          end
        end
        File.singleton_class.prepend(hook)
        cancel
        Process.exit!(74)
      end
      Process.wait(pid)
      assert_equal 73, $?.exitstatus
      assert_equal 200, cancel.first
      assert_preserved_archives
    end
  end

  def test_untouched_registration_device_is_not_replayed_or_removed
    before = Marshal.dump(@fixture.instance_variable_get(:@devices))
    assert_equal 200, cancel.first
    assert_equal before, Marshal.dump(@fixture.instance_variable_get(:@devices))
    assert_empty @fixture.instance_variable_get(:@reads)
  end
end
