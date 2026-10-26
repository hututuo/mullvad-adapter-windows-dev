# frozen_string_literal: true

require_relative 'minitest_dependencies'
require 'digest'
require_relative 'mullvad_adapter'

class CatalogueChangesTest < Minitest::Test
  CHECKED_AT = '2026-10-26T00:00:00Z'

  def setup
    # These tests exercise only a pure comparison helper and its catalogue
    # candidate counter; allocating avoids starting daemon threads or I/O.
    @adapter = MullvadAdapter.allocate
  end

  def test_unchanged_catalogue_ignores_hash_node_and_extra_address_order
    previous = metadata(
      relays: [relay('relay-one', extras: %w[192.0.2.11 192.0.2.12 192.0.2.11]), relay('relay-two')]
    )
    current = reverse_hash_keys(previous)
    current['wireguard']['relays'].reverse!
    first = current['wireguard']['relays'].find { |row| row['hostname'] == 'relay-one' }
    first['shadowsocks_extra_addr_in'] = %w[192.0.2.12 192.0.2.11 192.0.2.12]

    result = compare(previous, current)

    assert result[:baseline_available]
    refute result[:catalogue_changed]
    assert_equal [0, 0, 0], %i[added_count removed_count changed_count].map { |key| result.fetch(key) }
    assert_empty result[:shared_changes]
    assert_empty result[:changed_relays]
    assert_equal 'unchanged', result.dig(:current_relay, :state)
  end

  def test_change_to_another_relay_does_not_mark_current_relay_changed
    previous = metadata(relays: [relay('relay-one'), relay('relay-two')])
    current = metadata(relays: [relay('relay-one'), relay('relay-two', location: 'us-lax')])

    result = compare(previous, current)

    assert result[:catalogue_changed]
    assert_equal 1, result[:changed_count]
    assert_equal 'unchanged', result.dig(:current_relay, :state)
    assert_empty result.dig(:current_relay, :fields)
    assert_equal ['relay-two'], result[:changed_relays].map { |entry| entry.fetch(:relay) }
  end

  def test_current_primary_and_dedicated_ss_addresses_report_additions_and_removals
    previous = metadata(relays: [relay('relay-one', ip: '192.0.2.10', extras: %w[192.0.2.20 192.0.2.21])])
    current = metadata(relays: [relay('relay-one', ip: '192.0.2.12', extras: %w[192.0.2.21 192.0.2.22])])

    result = compare(previous, current)
    fields = result.dig(:current_relay, :fields)
    ip_field = find_field(fields, 'ipv4_addr_in')
    ss_field = find_field(fields, 'shadowsocks_extra_addr_in')

    assert_equal 'changed', result.dig(:current_relay, :state)
    assert_equal '192.0.2.10', ip_field.fetch(:before)
    assert_equal '192.0.2.12', ip_field.fetch(:after)
    assert_includes ss_field.fetch(:added), '192.0.2.22'
    assert_includes ss_field.fetch(:removed), '192.0.2.20'
    assert_equal 1, ss_field.fetch(:added_count)
    assert_equal 1, ss_field.fetch(:removed_count)
    assert fields.all? { |field| field.fetch(:label).match?(/\p{Han}/) }, 'field labels should be Chinese'
  end

  def test_public_key_changes_are_reported_only_as_sha256_prefixes
    old_key = 'raw-secret-public-key-before'
    new_key = 'raw-secret-public-key-after'
    previous = metadata(relays: [relay('relay-one', public_key: old_key)])
    current = metadata(relays: [relay('relay-one', public_key: new_key)])

    result = compare(previous, current)
    field = find_field(result.dig(:current_relay, :fields), 'public_key')

    assert_includes field.fetch(:before), Digest::SHA256.hexdigest(old_key)[0, 12]
    assert_includes field.fetch(:after), Digest::SHA256.hexdigest(new_key)[0, 12]
    refute_includes result.inspect, old_key
    refute_includes result.inspect, new_key
  end

  def test_shared_ss_port_change_marks_current_state_and_recounts_candidates
    previous = metadata(
      relays: [relay('relay-one', extras: ['192.0.2.20'])],
      ss_ranges: [[20_484, 20_486]]
    )
    current = metadata(
      relays: [relay('relay-one', extras: ['192.0.2.20'])],
      ss_ranges: [[20_484, 20_488]]
    )

    result = compare(previous, current)

    assert result[:catalogue_changed]
    assert_equal 'changed', result.dig(:current_relay, :state)
    assert_equal 4, result.dig(:current_relay, :ss_before_count)
    assert_equal 6, result.dig(:current_relay, :ss_after_count)
    assert_includes result[:shared_changes].map { |field| field.fetch(:key) }, 'shadowsocks_port_ranges'
  end

  def test_missing_baseline_is_not_reported_as_every_relay_being_added
    current = metadata(relays: [relay('relay-one'), relay('relay-two')])

    result = compare(nil, current)

    refute result[:baseline_available]
    assert_nil result[:catalogue_changed]
    assert_equal [0, 0, 0], %i[added_count removed_count changed_count].map { |key| result.fetch(key) }
    assert_empty result[:changed_relays]
    assert_equal 'no_baseline', result.dig(:current_relay, :state)
  end

  def test_deleted_current_relay_is_reported_as_removed
    previous = metadata(relays: [relay('relay-one'), relay('relay-two')])
    current = metadata(relays: [relay('relay-two')])

    result = compare(previous, current)

    assert_equal 1, result[:removed_count]
    assert_equal 'removed', result.dig(:current_relay, :state)
    assert_operator result.dig(:current_relay, :ss_before_count), :>, 0
    assert_equal 0, result.dig(:current_relay, :ss_after_count)
  end

  def test_changed_relay_list_is_capped_and_keeps_current_relay_first
    previous_relays = 25.times.map { |index| relay("relay-#{index}") }
    current_relays = previous_relays.map { |row| row.merge('active' => false) }
    previous = metadata(relays: previous_relays)
    current = metadata(relays: current_relays)

    result = compare(previous, current, current_relay: 'relay-24')
    relays = result.fetch(:changed_relays)

    assert_equal 25, result[:changed_count]
    assert_equal 20, relays.length
    assert_equal 'relay-24', relays.first.fetch(:relay)
    assert_equal 5, result[:truncated_count]
  end

  private

  def compare(previous, current, current_relay: 'relay-one')
    @adapter.instance_variable_set(:@metadata, current)
    @adapter.send(
      :catalogue_change_summary,
      previous,
      current,
      current_relay: current_relay,
      checked_at: CHECKED_AT
    )
  end

  def find_field(fields, key)
    fields.find { |field| field.fetch(:key) == key } || flunk("missing catalogue field #{key}")
  end

  def metadata(relays:, ss_ranges: [[20_484, 20_486]])
    {
      'wireguard' => {
        'port_ranges' => [[33_431, 51_820]],
        'shadowsocks_port_ranges' => ss_ranges,
        'relays' => relays
      }
    }
  end

  def relay(hostname, ip: '192.0.2.10', extras: [], public_key: "key-#{hostname}", location: 'us-sjc')
    {
      'hostname' => hostname,
      'active' => true,
      'location' => location,
      'public_key' => public_key,
      'ipv4_addr_in' => ip,
      'ipv6_addr_in' => '2001:db8::10',
      'shadowsocks_extra_addr_in' => extras
    }
  end

  def reverse_hash_keys(value)
    case value
    when Hash
      value.to_a.reverse.to_h.transform_values { |item| reverse_hash_keys(item) }
    when Array
      value.map { |item| reverse_hash_keys(item) }
    else
      value
    end
  end
end
