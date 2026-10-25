#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'yaml'
require 'optparse'
require 'open3'
require 'timeout'
require_relative 'ss_wg_observer'

# Explicit, bounded diagnostic only. No HTTP probes, packet transmission,
# privilege escalation, packet files or daemon configuration changes.
module PassiveSSCapture
  def self.run(argv)
    options = { seconds: 30 }
    parser = OptionParser.new do |p|
      p.banner = 'Usage: observe_ss_wg.rb --config SLOT_CONFIG (--interface en0 | --pcap FILE) [--seconds 30]'
      p.on('--config PATH') { |v| options[:config] = v }
      p.on('--interface NAME') { |v| options[:interface] = v }
      p.on('--pcap PATH') { |v| options[:pcap] = v }
      p.on('--seconds N', Integer) { |v| options[:seconds] = v }
    end
    parser.parse!(argv)
    raise ArgumentError unless argv.empty? && options[:config] && options[:seconds].between?(1, 120)
    raise ArgumentError unless !!options[:interface] ^ !!options[:pcap]
    raise ArgumentError if options[:interface] && !options[:interface].match?(/\A[a-zA-Z][a-zA-Z0-9]{0,15}\z/)

    # Bounded file read; the entire config and all secrets stay local in memory.
    raw = File.binread(options[:config], 2_097_153)
    raise ArgumentError if raw.bytesize > 2_097_152
    config = YAML.safe_load(raw, aliases: false)
    inlet = Array(config.fetch('proxies')).find { |p| p['name'] == 'SS-INLET' }
    raise ArgumentError unless inlet && inlet['type'] == 'ss' && inlet['cipher'] == 'aes-256-gcm'
    observer = SSObservations.new(password: inlet.fetch('password'), endpoint_ip: inlet.fetch('server'),
                                  endpoint_port: Integer(inlet.fetch('port')))
    outcome = 'completed'
    if options[:pcap]
      Timeout.timeout(options[:seconds]) do
        File.open(options[:pcap], 'rb') { |input| observer.consume_pcap(input) }
      end
    else
      # Literal validated endpoint, argv execution, exact capture filter.
      command = ['/usr/sbin/tcpdump', '-n', '-U', '-s', '65535', '-i', options[:interface],
                 '-w', '-', 'udp', 'and', 'host', inlet.fetch('server'), 'and', 'port', inlet.fetch('port').to_s]
      Open3.popen3(*command) do |stdin, stdout, stderr, waiter|
        stdin.close
        # Drain without retaining stderr (may contain local identifiers).
        drainer = Thread.new do
          begin
            loop { stderr.readpartial(4096) }
          rescue EOFError, IOError
            nil
          end
        end
        begin
          Timeout.timeout(options[:seconds]) { observer.consume_pcap(stdout) }
          outcome = waiter.value.success? ? 'completed' : 'capture-failed-check-local-capture-permission'
        rescue Timeout::Error
          outcome = 'duration-complete'
        ensure
          # Signal only our unreaped child; never select processes by name.
          [['INT', 1], ['TERM', 1], ['KILL', 1]].each do |signal, wait|
            break unless waiter.alive?
            begin
              Process.kill(signal, waiter.pid)
            rescue Errno::ESRCH
              break
            end
            waiter.join(wait)
          end
          stdout.close unless stdout.closed?
          stderr.close unless stderr.closed?
          drainer.join(1)
        end
      end
    end
    { status: outcome, counters: observer.summary,
      limitation: 'Observed packet shapes are not proof of an accepted WireGuard handshake or application availability.' }
  rescue Timeout::Error
    { status: 'input-time-limit', counters: observer&.summary }
  rescue StandardError => e
    # No exception messages: configuration or packet content must not escape.
    { status: 'unavailable', error_class: e.class.name }
  ensure
    observer&.close
    raw&.replace("\0" * raw.bytesize)
    password = inlet&.dig('password')
    password.replace('') if password.is_a?(String)
  end
end

if $PROGRAM_NAME == __FILE__
  result = PassiveSSCapture.run(ARGV)
  puts JSON.pretty_generate(result)
  exit(%w[completed duration-complete].include?(result[:status]) ? 0 : 1)
end
