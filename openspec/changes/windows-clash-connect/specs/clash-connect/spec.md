# Clash connection contract

- CC-1: WHEN the page opens, THEN detect a supported local client and show current
  profile, available manual groups, independent ordinary exits and distinct saved,
  selector and tunnel states. Unsupported clients offer a safe local-node export.
- CC-2: WHEN the user applies, THEN use the backend front port, preview/hash guard,
  private backup and engine validation; change only the current profile's managed
  extension, reload and read back the selected group. Do not enable TUN, change
  global mode, DNS or system proxy. Account API traffic has an independent route.
- CC-3: WHEN the preview is stale, names/routes conflict, or live routing diverges
  from the generated file, THEN stop with a specific error and preserve evidence.
- CC-4: WHEN apply is uncertain, THEN keep recoverable backups and report saved
  separately from active. Do not silently claim success or blindly retry writes.
- CC-5: WHEN undo is requested, THEN verify the owned script, remove only managed
  deltas, preserve later user edits/choices, retain backups and keep the adapter
  tunnel running. Other profile records must remain discoverable.
- CC-6: All controls use full button hit areas; feedback has reserved height.
  User-facing operation errors never expose controller secrets or config bodies.
  No automated sleep or physical-network interruption is part of these tests.
- CC-7: WHEN the detected Windows client already exposes a local named pipe,
  THEN use it without enabling HTTP or changing the client's controller settings.
  Do not send the HTTP secret over the pipe. Remote or ambiguous pipe paths are
  refused, failed pipes do not silently fall back, and control I/O has a bounded
  total lifetime. An empty HTTP address without a pipe reports a missing control
  interface, not an unsafe remote address.

- CC-8: WHEN first-use account access needs the existing local Clash, THEN allow
  saving its detected mixed port as the adapter bootstrap before account login or
  tunnel connection, without modifying Clash files or selectors. Activating a
  traffic group still requires an already connected adapter.
