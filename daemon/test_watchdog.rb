# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require 'open3'

class MullvadWatchdogRegressionTest < Minitest::Test
  def test_disconnected_snapshot_needs_no_temporary_heredoc_and_bounds_log
    Dir.mktmpdir('mullvad-watchdog-test') do |dir|
      cli = File.join(dir, 'mock-cli')
      File.write(cli, "#!/bin/sh\nprintf '%s\\n' '{\"state\":\"disconnected\",\"details\":{\"locked_down\":false}}'\n")
      File.chmod(0o755, cli)
      log = File.join(dir, 'watchdog.log')
      File.write(log, "old error\n" * 600_000 + "recent evidence\n")
      env = {
        'MULLVAD_FAIL_OPEN_CLI' => cli,
        'MULLVAD_FAIL_OPEN_ARMED' => '0',
        'MULLVAD_FAIL_OPEN_MAX_POLLS' => '1',
        'MULLVAD_FAIL_OPEN_NO_SLEEP' => '1',
        'MULLVAD_FAIL_OPEN_LOG_PATH' => log
      }
      out, err, status = Open3.capture3(env, '/bin/sh', File.expand_path('../mullvad-fail-open-watchdog', __dir__))
      assert status.success?, err
      assert_empty err
      assert_includes out, 'class=state:disconnected'
      refute_includes out, 'disconnect_requested'
      assert_operator File.size(log), :<=, 256 * 1024
      assert File.read(log).end_with?("recent evidence\n")
    end
  end
end
