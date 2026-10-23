# frozen_string_literal: true

require_relative 'minitest_dependencies'
require 'tmpdir'
require 'fileutils'
require_relative '../scripts/mac-launch-agent-policy'

class MullvadLaunchAgentPolicyTest < Minitest::Test
  def setup
    skip 'real plist round-trip requires macOS plutil' unless RUBY_PLATFORM.include?('darwin')
    @dir = Dir.mktmpdir('adapter-launch-policy')
    @path = File.join(@dir, 'agent.plist')
    @config = { 'Label' => 'local.mullvad.adapter', 'ProcessType' => 'Background',
                'ProgramArguments' => ['/fixture/ruby', '/fixture/mullvad-local-adapter', '--fixture'],
                'KeepAlive' => true, 'RunAtLoad' => true,
                'EnvironmentVariables' => { 'FIXTURE_ONLY' => 'preserve-me' } }
    File.write(@path, JSON.generate(@config), mode: 'w', perm: 0o600)
  end

  def teardown
    FileUtils.remove_entry(@dir) if @dir
  end

  def test_only_scheduling_class_changes_in_real_plist_round_trip
    original = File.binread(@path)
    assert MullvadLaunchAgentPolicy.apply(@path)
    output, _error, result = Open3.capture3('/usr/bin/plutil', '-convert', 'json', '-o', '-', @path)
    assert result.success?
    updated = JSON.parse(output)
    assert_equal @config.merge('ProcessType' => 'Interactive'), updated
    assert_equal 0o600, File.stat(@path).mode & 0o777
    refute_equal original, File.binread(@path)
    refute MullvadLaunchAgentPolicy.apply(@path), 'already-correct policy is idempotent'
    assert_empty Dir.glob("#{@path}.pending-*")
    # The installer keeps these exact original bytes for rollback.
    File.binwrite(@path, original)
    assert_equal 'Background', MullvadLaunchAgentPolicy.configuration(@path)['ProcessType']
  end

  def test_plist_specific_types_are_preserved_without_json_conversion
    xml = <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0"><dict>
      <key>Label</key><string>local.mullvad.adapter</string>
      <key>ProcessType</key><string>Background</string>
      <key>FixtureDate</key><date>2026-01-01T00:00:00Z</date>
      <key>FixtureData</key><data>Ynl0ZXM=</data>
      </dict></plist>
    XML
    File.write(@path, xml)
    before, _error, status = Open3.capture3('/usr/bin/plutil', '-convert', 'xml1', '-o', '-', @path)
    assert status.success?
    assert MullvadLaunchAgentPolicy.apply(@path)
    after, _error, status = Open3.capture3('/usr/bin/plutil', '-convert', 'xml1', '-o', '-', @path)
    assert status.success?
    assert_equal before.sub('<string>Background</string>', '<string>Interactive</string>'), after
  end

  def test_missing_or_unrelated_backup_is_rejected_before_an_upgrade
    missing = File.join(@dir, 'absent.plist')
    assert_raises(Errno::ENOENT) { MullvadLaunchAgentPolicy.validate_backup!(missing) }
    other = File.join(@dir, 'different.plist')
    File.write(other, JSON.generate(@config.merge('ProcessType' => 'Standard')))
    assert_raises(RuntimeError) { MullvadLaunchAgentPolicy.validate_backup!(other, current: @path) }
    assert MullvadLaunchAgentPolicy.validate_backup!(@path, current: @path)
    assert_equal @config, JSON.parse(File.read(@path))
  end

  def test_another_job_is_rejected_without_writing_it
    File.write(@path, JSON.generate(@config.merge('Label' => 'other.fixture')))
    before = File.binread(@path)
    assert_raises(RuntimeError) { MullvadLaunchAgentPolicy.apply(@path) }
    assert_equal before, File.binread(@path)
  end

  def test_symlink_is_rejected_without_changing_its_target
    target = File.join(@dir, 'target.plist')
    File.rename(@path, target)
    File.symlink(target, @path)
    before = File.binread(target)
    assert_raises(RuntimeError) { MullvadLaunchAgentPolicy.apply(@path) }
    assert_equal before, File.binread(target)
  end
end
