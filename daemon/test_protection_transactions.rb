# frozen_string_literal: true

require_relative 'test_reliability'

class MullvadProtectionTransactionTest < Minitest::Test
  PLAIN = { multihop: false, entry_city: nil, post_quantum: false }.freeze
  PQ = PLAIN.merge(post_quantum: true).freeze

  def setup
    @dir = Dir.mktmpdir('mullvad-protection-transaction')
    @adapter = ReliabilityAdapter.new(@dir)
    @adapter.define_singleton_method(:ensure_pq_available!) { |_profile| true }
    original = @adapter.method(:start_worker)
    @adapter.define_singleton_method(:start_worker) do |*args, **kwargs|
      original.call(*args, **kwargs).tap { |worker| worker[:protection_profile] = protection_profile }
    end
    @path = File.join(@dir, 'protection.json')
  end

  def teardown
    %i[adapter_network_epoch adapter_protection_profile adapter_operation_id adapter_attempt_id].each { |key| Thread.current[key] = nil }
    FileUtils.remove_entry(@dir)
  end

  def seed(profile)
    File.write(@path, JSON.generate(profile))
    @adapter.send(:load_protection_profile)
    @adapter.seed_active
    @adapter.events.clear
  end

  def committed_events
    path = File.join(@dir, 'logs', 'events.jsonl')
    File.readlines(path).map { |line| JSON.parse(line) }.select { |event| event['event'] == 'switch-committed' }
  end

  def rollback_with(profile, failure)
    seed(profile)
    @adapter.fail_mode = 'ipv4'
    @adapter.define_singleton_method(:run_readiness_canary) do |_slot|
      good_canary.tap { |canary| canary[failure] = { status: 'fail' } if failure }
    end
    refute @adapter.send(:activate, 'one', reason: 'reconnect', transport_preference: 'ipv4')
  end

  def test_pq_rollback_rejects_dns_degraded_worker_before_front_selection
    rollback_with(PQ, :inner_dns)
    assert_empty @adapter.events.select { |event| event.first == :select }
    assert_empty @adapter.instance_variable_get(:@workers)
    assert_equal 1, committed_events.length
    assert_equal PQ, @adapter.send(:protection_profile)
  end

  def test_pq_rollback_rejects_https_degraded_worker_before_front_selection
    rollback_with(PQ, :https_data)
    assert_empty @adapter.events.select { |event| event.first == :select }
    assert_empty @adapter.instance_variable_get(:@workers)
    assert_equal 1, committed_events.length
  end

  def test_pq_rollback_commits_only_a_fully_ready_worker_and_keeps_policy
    rollback_with(PQ, nil)
    assert_equal [[:select, 'a']], @adapter.events.select { |event| event.first == :select }
    assert_equal 'reconnect-rollback', @adapter.send(:snapshot)[:switch_reason]
    assert_equal PQ, @adapter.send(:protection_profile)
    assert_equal PQ, JSON.parse(File.read(@path), symbolize_names: true)
    assert_equal 2, committed_events.length
  end

  def test_non_pq_original_path_can_still_be_preserved_when_dns_is_degraded
    rollback_with(PLAIN, :inner_dns)
    assert_equal [[:select, 'a']], @adapter.events.select { |event| event.first == :select }
    assert_equal 'degraded_dns', @adapter.send(:snapshot)[:service_readiness]
  end

  def interrupted_policy_change(old_profile, requested_profile)
    seed(old_profile)
    old_bytes = File.binread(@path)
    writes = @adapter.method(:atomic_account_file)
    injected = false
    @adapter.define_singleton_method(:atomic_account_file) do |path, content|
      writes.call(path, content)
      if !injected && File.basename(path).start_with?('protection') && JSON.parse(content, symbolize_names: true) == requested_profile
        injected = true
        apply_local_network_observation(status: 'unavailable', source: 'controlled-test', detail: 'during policy preparation')
      end
    end
    refute @adapter.send(:activate, 'one', reason: 'protection-change', protection_profile: requested_profile)
    assert injected, 'the failure was injected after a real policy write/fsync'
    assert_equal old_bytes, File.binread(@path)
    assert_equal old_profile, @adapter.send(:protection_profile)
    assert_empty @adapter.instance_variable_get(:@workers)
    assert_equal 1, committed_events.length, 'no successful commit receipt for the rejected policy'
    assert_equal 'waiting_network', @adapter.send(:snapshot)[:service_readiness]
    assert_empty Dir.glob(File.join(@dir, 'protection.json.pending-*'))

    # Recovery must use the previous committed policy, including required PQ.
    @adapter.instance_variable_get(:@options)[:local_network_settle] = 0
    @adapter.send(:apply_local_network_observation, status: 'available', source: 'controlled-test', detail: 'returned')
    assert @adapter.send(:activate, 'one', reason: 'network-resume')
    worker = @adapter.instance_variable_get(:@workers).values.first
    assert_equal old_profile, worker[:protection_profile]
    assert_equal old_bytes, File.binread(@path)
  end

  def test_interrupted_pq_enable_does_not_save_or_adopt_uncommitted_policy
    interrupted_policy_change(PLAIN, PQ)
  end

  def test_interrupted_pq_disable_does_not_save_or_adopt_uncommitted_policy
    interrupted_policy_change(PQ, PLAIN)
  end

  def test_process_death_after_staged_write_keeps_previous_policy_on_restart
    skip 'requires fork for abrupt process-death injection' unless Process.respond_to?(:fork)
    seed(PQ)
    pid = fork do
      writes = @adapter.method(:atomic_account_file)
      @adapter.define_singleton_method(:atomic_account_file) do |path, content|
        writes.call(path, content)
        Process.exit!(71) if File.basename(path).start_with?('protection')
      end
      @adapter.send(:activate, 'one', reason: 'protection-change', protection_profile: PLAIN)
      Process.exit!(72)
    end
    _, status = Process.wait2(pid)
    assert_equal 71, status.exitstatus
    reopened = MullvadAdapter.new(state_dir: @dir)
    reopened.send(:load_protection_profile)
    assert_equal PQ, reopened.send(:protection_profile)
    assert_equal PQ, JSON.parse(File.read(@path), symbolize_names: true)
  end

  def test_final_rename_failure_keeps_old_policy_and_rebuilds_original_path
    seed(PQ)
    original = File.method(:rename)
    File.stub(:rename, ->(from, to) {
      raise IOError, 'injected final rename failure' if from.include?('protection.json.pending-') && to == @path
      original.call(from, to)
    }) do
      refute @adapter.send(:activate, 'one', reason: 'protection-change', protection_profile: PLAIN)
    end
    assert_equal PQ, @adapter.send(:protection_profile)
    assert_equal PQ, JSON.parse(File.read(@path), symbolize_names: true)
    assert_equal 'reconnect-rollback', @adapter.send(:snapshot)[:switch_reason]
    assert_empty Dir.glob(File.join(@dir, 'protection.json.pending-*'))
  end

  def test_process_death_after_commit_point_recovers_the_committed_policy
    skip 'requires fork for abrupt process-death injection' unless Process.respond_to?(:fork)
    seed(PLAIN)
    pid = fork do
      original = File.method(:rename)
      File.stub(:rename, ->(from, to) {
        original.call(from, to)
        Process.exit!(73) if from.include?('protection.json.pending-') && to == @path
      }) do
        @adapter.send(:activate, 'one', reason: 'protection-change', protection_profile: PQ)
      end
      Process.exit!(74)
    end
    _, status = Process.wait2(pid)
    assert_equal 73, status.exitstatus
    reopened = MullvadAdapter.new(state_dir: @dir)
    reopened.send(:load_protection_profile)
    assert_equal PQ, reopened.send(:protection_profile)
  end

  def test_epoch_change_during_preparation_rejects_even_after_link_returns
    seed(PQ)
    @adapter.instance_variable_get(:@options)[:local_network_settle] = 0
    writes = @adapter.method(:atomic_account_file)
    injected = false
    @adapter.define_singleton_method(:atomic_account_file) do |path, content|
      writes.call(path, content)
      if !injected && File.basename(path).start_with?('protection')
        injected = true
        Thread.new do
          apply_local_network_observation(status: 'unavailable', source: 'thread-test', detail: 'lost')
          apply_local_network_observation(status: 'available', source: 'thread-test', detail: 'returned')
        end.value
      end
    end
    refute @adapter.send(:activate, 'one', reason: 'protection-change', protection_profile: PLAIN)
    refute @adapter.send(:snapshot).dig(:local_network, :paused)
    assert_equal PQ, @adapter.send(:protection_profile)
    assert_equal PQ, JSON.parse(File.read(@path), symbolize_names: true)
    assert_empty @adapter.instance_variable_get(:@workers)
    assert_equal 1, committed_events.length
  end

  def test_outage_during_final_rename_is_ordered_after_policy_commit
    seed(PLAIN)
    original = File.method(:rename)
    observer = nil
    observed = Queue.new
    locked = false
    File.stub(:rename, ->(from, to) {
      if from.include?('protection.json.pending-') && to == @path
        locked = @adapter.instance_variable_get(:@mutex).owned?
        observer = Thread.new do
          observed << :started
          @adapter.send(:apply_local_network_observation, status: 'unavailable', source: 'thread-test', detail: 'after commit')
          observed << :finished
        end
        assert_equal :started, observed.pop
        assert_raises(ThreadError, 'observer cannot pass the commit mutex') { observed.pop(true) }
      end
      original.call(from, to)
    }) do
      assert @adapter.send(:activate, 'one', reason: 'protection-change', protection_profile: PQ)
    end
    observer.value
    assert locked, 'final rename runs under the network observer mutex'
    assert_equal :finished, observed.pop
    assert_equal PQ, @adapter.send(:protection_profile)
    assert_equal PQ, JSON.parse(File.read(@path), symbolize_names: true)
    assert @adapter.send(:snapshot).dig(:local_network, :paused)
    assert_equal 2, committed_events.length
  ensure
    observer&.join
  end

  def test_outage_during_pq_rollback_cleans_worker_before_selection
    seed(PQ)
    @adapter.fail_mode = 'ipv4'
    @adapter.define_singleton_method(:run_readiness_canary) do |_slot|
      Thread.new do
        apply_local_network_observation(status: 'unavailable', source: 'thread-test', detail: 'during rollback')
      end.value
      good_canary
    end
    refute @adapter.send(:activate, 'one', reason: 'reconnect', transport_preference: 'ipv4')
    assert_empty @adapter.events.select { |event| event.first == :select }
    assert_empty @adapter.instance_variable_get(:@workers)
    assert_equal 1, committed_events.length
    assert_equal PQ, @adapter.send(:protection_profile)
  end

end
