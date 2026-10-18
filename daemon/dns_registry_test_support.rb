# frozen_string_literal: true

# Detect response-driven growth with both Resolv's old Hash registry and its
# newer constant-backed registry; do not call get_class while taking a snapshot.
module DnsRegistryTestSupport
  def resource_registry_snapshot
    registry = Resolv::DNS::Resource::ClassHash
    [registry.is_a?(Hash) ? registry.dup : nil,
     Resolv::DNS::Resource.constants(false).sort,
     Resolv::DNS::Resource::Generic.constants(false).sort]
  end
end
