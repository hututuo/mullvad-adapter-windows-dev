# Design

Use monotonically increasing request IDs and a completion fence for every status read, including city-generation reconciliation. Cancelled reads do not advance the fence or consume failure evidence. Only three consecutive transport failures spanning at least ten seconds permit the unavailable-control-state label; HTTP/decoding failures remain separate. Retain the prior snapshot with explicit age, never display it as fresh successful evidence during a failed read. No UI read failure can initiate tunnel recovery.

Use an asynchronous serial JSONL writer, two 256-KiB owner-readable regular files. Only typed fields (event, request ID, duration, failure category/code, count, age, UI version and session) are allowed; no arbitrary error text, body or URL. Log startup, failures, cancellations, discarded responses, recovery and slow success, not every healthy poll. Include both files in diagnostic export. Failed disk writes cannot stop polling.

Deployment changes only the signed UI bundle. The current Ruby daemon and all engine processes remain running; no network/identity mutation or physical fault injection is part of acceptance.
