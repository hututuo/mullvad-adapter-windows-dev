#!/usr/bin/env ruby
# frozen_string_literal: true
# Controlled fake-process output only. Never points at a running adapter.
require_relative '../daemon/test_reliability'

out = File.expand_path('../core/crates/protocol/fixtures/legacy', __dir__)
FileUtils.mkdir_p(out)
Dir.mktmpdir('adapter-contract') do |dir|
  adapter = ReliabilityAdapter.new(dir)
  adapter.seed_active
  adapter.define_singleton_method(:template_public_key) { 'fixture-public-key-not-a-real-identity' }
  fixtures = {
    'status' => adapter.send(:snapshot),
    'cities' => adapter.send(:city_workspace_snapshot),
    'relays' => adapter.send(:safe_relays, nil),
    'protection' => adapter.send(:protection_snapshot),
    'account' => adapter.send(:account_snapshot),
    'operation' => { id: 'fixture-operation', kind: 'select', relay: 'one', state: 'succeeded', stage: 'finished',
                     message: 'controlled example', result: { ok: true } }
  }
  normalize = lambda do |value, key = nil|
    case value
    when Hash
      value.to_h { |k, v| [k, normalize.call(v, k.to_s)] }
    when Array
      value.map { |v| normalize.call(v, key) }
    when String
      if key == 'source_sha256' then '0' * 64
      elsif value.match?(/\A\d{4}-\d{2}-\d{2}T/) then '2026-01-01T00:00:00Z'
      elsif value.include?(dir) then value.gsub(dir, '<fixture-state>')
      else value end
    when Numeric
      %w[uptime_seconds age_seconds].include?(key) ? 0 : value
    else value
    end
  end
  fixtures.each { |name, data| File.write(File.join(out, "#{name}.json"), JSON.pretty_generate(normalize.call(data)) + "\n") }
end
