#!/usr/bin/env ruby
# frozen_string_literal: true

require 'fileutils'
require 'rbconfig'

# This build helper only stages repository-owned files and runs synthetic tests.
# It never invokes install-daemon.rb, a service command, or the real watchdog.
abort 'usage: stage-daemon-payload.rb OUTPUT_PAYLOAD_DIRECTORY' unless ARGV.length == 1 && !ARGV.first.empty?

root = File.realpath(File.join(__dir__, '..'))
output = File.expand_path(ARGV.first)
tests = Dir.glob('daemon/test_*.rb', base: root).sort
abort 'no daemon regression tests found' if tests.empty?

files = [
  'daemon/mullvad_adapter.rb',
  'mullvad-fail-open-watchdog', # test_watchdog.rb invokes it with a fake CLI, disarmed.
  'core/crates/probe/fixtures/dns-canary.json',
  'core/crates/catalogue/fixtures/relay-contract.json',
  'core/crates/history/fixtures/summary-contract.json'
] + tests

begin
  # Validate all inputs before producing an incomplete package. Do not copy an
  # entire source tree, runtime state, dotfiles, keys, logs or personal data.
  files.each do |relative|
    source = File.join(root, relative)
    raise "required payload source missing or not a regular file: #{relative}" unless File.file?(source) && !File.symlink?(source)
  end
  raise 'output must differ from the source repository' if output == root
  if File.exist?(output) || File.symlink?(output)
    raise 'output must be a nonsymlink directory' unless File.directory?(output) && !File.symlink?(output)
  end
  # A previously staged file is an error, not permission to overwrite it. An
  # existing app directory is allowed so the candidate assembly can add this
  # checked subset. The caller owns the output directory and its ancestors.
  files.each do |relative|
    destination = File.join(output, relative)
    raise "payload target already exists: #{relative}" if File.exist?(destination) || File.symlink?(destination)
    directory = File.dirname(destination)
    until directory == output
      if File.exist?(directory) || File.symlink?(directory)
        raise "payload parent is not a nonsymlink directory: #{relative}" unless File.directory?(directory) && !File.symlink?(directory)
      end
      directory = File.dirname(directory)
    end
  end

  files.each do |relative|
    destination = File.join(output, relative)
    FileUtils.mkdir_p(File.dirname(destination))
    FileUtils.cp(File.join(root, relative), destination, preserve: true)
  end
  abort 'staged daemon syntax check failed' unless system(RbConfig.ruby, '-c', 'daemon/mullvad_adapter.rb', chdir: output)
  abort 'staged daemon regression tests failed' unless system(
    RbConfig.ruby, '-I', '.', '-I', 'daemon', '-e',
    'ARGV.each { |file| require File.expand_path(file) }', *tests, chdir: output
  )
  puts "Staged and checked #{files.length} daemon payload files (#{tests.length} test files)."
rescue StandardError => e
  abort "daemon payload staging failed: #{e.message}"
end
