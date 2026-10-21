# Lightweight local status reads

Local status reads must not queue behind control commits, history, city lists or account operations. Preserve authoritative connection transactions and expose freshness honestly. This change is source/tests only; no package or deployment.
