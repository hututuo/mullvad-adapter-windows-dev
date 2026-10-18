# frozen_string_literal: true
require_relative '../daemon/test_reliability'

class MullvadSharedContractTest < Minitest::Test
  def test_shared_canary_contract_matches_ruby_for_every_input_combination
    Dir.mktmpdir('mullvad-shared-contract') do |dir|
      adapter = ReliabilityAdapter.new(dir)
      path = File.expand_path('../core/crates/protocol/fixtures/canary-cases.json', __dir__)
      JSON.parse(File.read(path), symbolize_names: true).each do |row|
        canary = { ip_data: { status: row[:ip] ? 'pass' : 'fail' }, inner_dns: { status: row[:dns] ? 'pass' : 'fail' }, https_data: { status: row[:https] ? 'pass' : 'fail' } }
        classified = adapter.send(:classify_canary, canary)
        assert_equal row[:alive], classified[:relay_liveness] == 'pass'
        assert_equal row[:readiness], classified[:service_readiness]
        assert_equal row[:accept], adapter.send(:candidate_acceptable?, classified, profile: { post_quantum: row[:pq] }, require_ready: row[:require_ready])
      end
    end
  end
end
