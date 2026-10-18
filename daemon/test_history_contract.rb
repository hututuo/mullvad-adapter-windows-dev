# frozen_string_literal: true
require 'minitest/autorun'
require 'json'
require_relative 'mullvad_adapter'

class HistoryContractTest < Minitest::Test
  def cases
    @cases ||= JSON.parse(File.read(File.expand_path('../core/crates/history/fixtures/summary-contract.json', __dir__))).fetch('cases')
  end

  def adapter_with_synthetic_history
    adapter = MullvadAdapter.allocate
    adapter.instance_variable_set(:@history_mutex, Mutex.new)
    entries = cases.reverse.to_h do |entry|
      summary = entry.fetch('summary').reject { |key, _| key == 'readiness_rate' }
      raw = adapter.send(:symbolize_json_object, summary)
      raw[:last_result] = { synthetic_marker: 'must-not-enter-public-summary' }
      [entry.fetch('id'), raw]
    end
    adapter.instance_variable_set(:@relay_history, entries)
    adapter
  end

  def test_actual_public_snapshot_recomputes_rates_sorts_and_removes_last_result
    adapter = adapter_with_synthetic_history
    before = Marshal.dump(adapter.instance_variable_get(:@relay_history))
    snapshot = JSON.parse(JSON.generate(adapter.send(:relay_history_snapshot)))
    expected = cases.map do |entry|
      entry.fetch('summary').merge('readiness_rate' => entry.fetch('expected_rate'))
    end.sort_by { |row| [row.fetch('relay'), row.fetch('transport_mode')] }
    assert_equal expected, snapshot
    assert_equal 3, snapshot.count { |row| row['relay'] == 'us-aaa-wg-003' }
    refute_includes JSON.generate(snapshot), 'must-not-enter-public-summary'
    refute_includes JSON.generate(snapshot), 'last_result'
    assert_equal before, Marshal.dump(adapter.instance_variable_get(:@relay_history))
    zero = snapshot.find { |row| row['samples'].zero? }
    assert_nil zero.fetch('readiness_rate')
  end

  def test_actual_wilson_score_matches_shared_values_and_penalty_cap
    adapter = adapter_with_synthetic_history
    scores = cases.to_h do |entry|
      raw = adapter.send(:symbolize_json_object, entry.fetch('summary'))
      score = adapter.send(:history_confidence_score, raw)
      assert_in_delta entry.fetch('expected_score'), score, 1e-12, entry.fetch('name')
      [entry.fetch('name'), score]
    end
    assert_operator scores.fetch('stable_twenty'), :>, scores.fetch('one_success')
    assert_equal scores.fetch('three_failures'), scores.fetch('five_failures')
    assert_equal(-1.0, scores.fetch('zero_unknown'))
  end

  def test_public_snapshot_is_detached_and_has_no_file_or_network_dependency
    adapter = adapter_with_synthetic_history
    public_rows = adapter.send(:relay_history_snapshot)
    public_rows.first[:source_counts][:synthetic] = 999
    public_rows.first[:relay].replace('changed-fixture')
    refute_equal public_rows.first, adapter.send(:relay_history_snapshot).first
    assert_nil adapter.instance_variable_get(:@state_dir)
    assert_nil adapter.instance_variable_get(:@metadata)
  end
end
