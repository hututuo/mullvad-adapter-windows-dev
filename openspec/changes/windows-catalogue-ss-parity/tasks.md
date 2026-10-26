# Validation checklist

- Implement and test WIN-PARITY-01 canonical comparison and API/cache outcomes.
- Implement and test WIN-PARITY-02 complete candidate pool and bounded ordering.
- Implement and test WIN-PARITY-03 restart, common tuples, key changes, legacy
  scores, cancellation and nonrefundable per-round budget.
- Implement and test WIN-PARITY-04 worker/front config boundaries and pinned
  engine parser contracts; real network/PMTU acceptance remains separate.
- Verify WIN-PARITY-05 TypeScript, readable event vocabulary, changed/unchanged
  synthetic UI and shared-report privacy.
- Run the existing tests-only GitHub workflow on Windows and other supported
  check hosts. Bind exact results to the source SHA in private project evidence.
- Do not create an installer or replace an installed app in this stage.
