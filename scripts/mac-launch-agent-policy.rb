# frozen_string_literal: true

require 'json'
require 'open3'
require 'securerandom'
require 'digest'

# The local HTTP/status service and its proxy children serve foreground traffic.
# Adaptive is not appropriate: this service uses TCP, not XPC transactions.
# This helper only prepares/updates the existing owned job; it never restarts it.
module MullvadLaunchAgentPolicy
  LABEL = 'local.mullvad.adapter'
  PROCESS_TYPE = 'Interactive'

  def self.configuration(path)
    stat = File.lstat(path)
    raise 'unsafe adapter launch agent' unless stat.file? && stat.uid == Process.uid && stat.nlink == 1
    label, _error, status = Open3.capture3('/usr/bin/plutil', '-extract', 'Label', 'raw', '-o', '-', path)
    raise 'unexpected launch agent label' unless status.success? && label.strip == LABEL
    type, _error, result = Open3.capture3('/usr/bin/plutil', '-extract', 'ProcessType', 'raw', '-o', '-', path)
    { 'Label' => LABEL, 'ProcessType' => result.success? ? type.strip : nil }
  end

  def self.validate_backup!(backup, current: nil)
    configuration(backup)
    if current && Digest::SHA256.file(backup).hexdigest != Digest::SHA256.file(current).hexdigest
      raise 'backup launch agent does not match current baseline'
    end
    true
  end

  def self.apply(path)
    config = configuration(path)
    return false if config['ProcessType'] == PROCESS_TYPE
    pending = "#{path}.pending-#{SecureRandom.hex(8)}"
    begin
      File.open(pending, File::WRONLY | File::CREAT | File::EXCL, File.stat(path).mode & 0o777) do |file|
        File.open(path, 'rb') { |original| IO.copy_stream(original, file) }
        file.flush
      end
      # Mutate the property in the copied plist directly. JSON round-tripping
      # would lose plist-specific Date/Data types in otherwise unrelated keys.
      _output, _error, status = Open3.capture3('/usr/bin/plutil', '-replace', 'ProcessType', '-string', PROCESS_TYPE, pending)
      raise 'launch agent policy update failed' unless status.success?
      File.open(pending, 'r+') { |file| file.fsync }
      File.rename(pending, path)
    ensure
      File.unlink(pending) if File.exist?(pending)
    end
    true
  end
end
