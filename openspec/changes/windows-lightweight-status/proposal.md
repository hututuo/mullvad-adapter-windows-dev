# Independent Windows status reads

Status reads currently compete with control requests and depend on owner dispatch. Give public state a separate authenticated read-only channel, preserve freshness and classify local observation errors separately from tunnel failures. Source/tests only; no installer, deployment or live network mutation.
