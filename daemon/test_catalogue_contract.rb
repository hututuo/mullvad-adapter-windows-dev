# frozen_string_literal: true
require 'minitest/autorun'
require 'json'
require_relative 'mullvad_adapter'

class CatalogueContractTest < Minitest::Test
  def test_shared_public_metadata_corpus
    path = File.expand_path('../core/crates/catalogue/fixtures/relay-contract.json', __dir__)
    JSON.parse(File.read(path)).each do |entry|
      adapter = MullvadAdapter.allocate
      payload = entry.fetch('payload')
      if entry.fetch('accepted')
        validated = adapter.send(:validate_metadata_payload, payload)
        adapter.instance_variable_set(:@metadata, validated)
        rows = validated.fetch('wireguard').fetch('relays')
        assert_equal entry.fetch('hostnames'), rows.map { |row| row.fetch('hostname') }, entry.fetch('name')
        assert_equal entry.fetch('rejected'), adapter.instance_variable_get(:@last_metadata_validation_warnings).length
        modes = rows.map { |row| row['active'] ? adapter.send(:available_transport_modes, row) : [] }
        assert_equal entry.fetch('transports'), modes
      else
        assert_raises(RuntimeError, entry.fetch('name')) { adapter.send(:validate_metadata_payload, payload) }
      end
    end
  end
end
