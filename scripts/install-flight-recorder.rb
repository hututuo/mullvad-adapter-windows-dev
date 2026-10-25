#!/usr/bin/env ruby
# frozen_string_literal: true
require 'json'
require 'digest'
require 'fileutils'
require 'open3'
require 'rbconfig'
require 'cgi'
require 'optparse'

# Only owns the independent recorder, never the adapter/core/Clash services.
opts = {}
OptionParser.new do |p|
  p.on('--install') { opts[:install] = true }
  p.on('--backup-dir PATH') { |v| opts[:backup] = File.expand_path(v) }
  p.on('--rollback PATH') { |v| opts[:rollback] = File.expand_path(v) }
end.parse!
abort 'use --install --backup-dir NEW_DIRECTORY or --rollback DIRECTORY' unless
  (opts[:install] && opts[:backup] && !opts[:rollback]) || (opts[:rollback] && !opts[:install])

label = 'local.mullvad.adapter.flight-recorder'
domain = "gui/#{Process.uid}"
service = "#{domain}/#{label}"
targets = { 'script' => File.expand_path('~/.local/libexec/mullvad-flight-recorder.rb'),
            'plist' => File.expand_path("~/Library/LaunchAgents/#{label}.plist") }
def stop_recorder(service)
  _, _, present = Open3.capture3('/bin/launchctl', 'print', service)
  return unless present.success?
  _, _, stopped = Open3.capture3('/bin/launchctl', 'bootout', service)
  raise 'recorder service could not stop' unless stopped.success?
end
def install_file(bytes, path, mode)
  raise 'unsafe target' if File.symlink?(path) || File.symlink?(File.dirname(path))
  FileUtils.mkdir_p(File.dirname(path), mode: 0o700)
  tmp = "#{path}.#{Process.pid}.tmp"
  File.open(tmp, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, mode) { |f| f.write(bytes) }
  File.rename(tmp, path)
end

if opts[:rollback]
  dir = opts[:rollback]
  receipt = JSON.parse(File.read(File.join(dir, 'receipt.json')))
  abort 'rollback owner/targets differ' unless receipt['uid'] == Process.uid && receipt['targets'] == targets
  targets.each do |name, path|
    abort 'installed recorder changed; preserve it for manual review' unless File.file?(path) && !File.symlink?(path) && Digest::SHA256.file(path).hexdigest == receipt['new_hashes'][name]
  end
  stop_recorder(service)
  targets.each do |name, path|
    original = receipt.fetch('originals')[name]
    if original
      bytes = File.binread(File.join(dir, name))
      abort 'backup hash differs' unless Digest::SHA256.hexdigest(bytes) == original['sha256']
      install_file(bytes, path, original['mode'])
    else
      File.unlink(path)
    end
  end
  if receipt['was_loaded']
    abort 'old recorder bootstrap failed' unless system('/bin/launchctl', 'bootstrap', domain, targets['plist'])
  end
  puts 'Recorder rollback complete; adapter and network untouched. Logs retained.'
  exit
end

dir = opts[:backup]
abort 'backup directory already exists' if File.exist?(dir)
FileUtils.mkdir_p(dir, mode: 0o700)
_, _, loaded = Open3.capture3('/bin/launchctl', 'print', service)
receipt = { uid: Process.uid, targets: targets, was_loaded: loaded.success?, originals: {}, new_hashes: {} }
targets.each do |name, path|
  abort 'unsafe existing recorder file' if File.symlink?(path)
  if File.exist?(path)
    abort 'existing recorder is not an owned regular file' unless File.file?(path) && File.stat(path).uid == Process.uid
    FileUtils.cp(path, File.join(dir, name), preserve: true)
    receipt[:originals][name] = { sha256: Digest::SHA256.file(path).hexdigest, mode: File.stat(path).mode & 0o777 }
  else
    receipt[:originals][name] = nil
  end
end
script = File.binread(File.join(__dir__, 'diagnostics/offline_flight_recorder.rb'))
plist = <<~XML
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0"><dict>
    <key>Label</key><string>#{label}</string>
    <key>ProgramArguments</key><array><string>#{CGI.escapeHTML(RbConfig.ruby)}</string><string>#{CGI.escapeHTML(targets['script'])}</string></array>
    <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
    <key>ThrottleInterval</key><integer>30</integer>
    <key>ProcessType</key><string>Interactive</string>
    <key>StandardOutPath</key><string>/dev/null</string>
    <key>StandardErrorPath</key><string>/dev/null</string>
  </dict></plist>
XML
payload = { 'script' => script, 'plist' => plist }
payload.each { |name, bytes| receipt[:new_hashes][name] = Digest::SHA256.hexdigest(bytes) }
File.write(File.join(dir, 'receipt.json'), JSON.pretty_generate(receipt), mode: 'w', perm: 0o600)
stop_recorder(service)
payload.each { |name, bytes| install_file(bytes, targets[name], name == 'script' ? 0o700 : 0o600) }
abort "recorder bootstrap failed; receipt retained at #{dir}" unless system('/bin/launchctl', 'bootstrap', domain, targets['plist'])
puts JSON.generate(status: 'recorder-installed', backup: dir, script_sha256: receipt[:new_hashes]['script'])
