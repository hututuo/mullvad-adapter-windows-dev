# Acceptance map

| Requirement | Implementation | Evidence gate |
| --- | --- | --- |
| CC-1, CC-6 | desktop/src/clash-page.tsx, style.css | TypeScript/build, renderer interaction/visual review, native UI |
| CC-2 | clash-integration crate, native bridge | Transformation/loop tests, pinned isolated core apply/readback |
| CC-3 | snapshot/delta guards | stale preview, rule/name conflicts, live divergence regression |
| CC-4 | private record and Outcome | failed validation/reload and recoverable undo regression |
| CC-5 | undo and record discovery | later edits/choices, repeated apply/undo, profile switching |
| CC-8 | independent bootstrap button + native activation gate | first-use bootstrap available disconnected; routing activation requires a connected front |
| CC-7 | endpoint selection, platform local pipe, pinned HTTP transport | blank/nonlocal distinction, bounded native pipe tests, isolated official core pipe apply/undo, real-client read-only detection |

Per-run PASS/FAIL/NOT_RUN and actual installed source SHA are maintained in private
project context. This map is not a claim that native end-to-end acceptance passed.
