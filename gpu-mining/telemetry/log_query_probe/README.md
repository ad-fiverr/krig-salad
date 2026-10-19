# Salad organization log-query contract probe

This package is a bounded diagnostic for the exact read-only log-query route:

    POST https://api.salad.com/api/public/organizations/{organization_name}/log-entries

The HTTP method is POST, but this exact route is classified as READ_LOG_QUERY.
The implementation grants no general POST permission. It does not use alert
normalization, a durable cursor, an alert ledger, Firebase, or Telegram.

## Current state

- Default mode is OFFLINE_SYNTHETIC. It uses an in-memory responder and opens
  no socket.
- LIVE_MANUAL is closed unless the operator chooses that mode, supplies the
  existing exact live-read gate, runs in an interactive terminal, and enters a
  Salad key through the existing hidden InteractiveSecretProvider.
- Codex does not run the live mode. A separate C2C REVIEW: PASS and explicit
  operator authorization are required before an operator may use it.
- PRODUCTION_CAUSE_UNKNOWN. A synthetic fixture does not establish Salad
  provider semantics or resolve a production watcher incident.
- The probe performs at most six requests in one experiment. It does not retry,
  paginate, recurse beyond one split, persist provider data, or advance a
  cursor.

## Reproducible offline run

From gpu-mining/telemetry, run:

    $env:PYTHONDONTWRITEBYTECODE = '1'
    python -m log_query_probe.cli --mode offline-synthetic --operation experiment --organization synthetic-org --start-time 2026-10-14T20:00:00Z --end-time 2026-10-14T20:30:00Z --query '(resource.type = "container" or resource.type = "instance_controller")' --repeat-parent

Every result from that command is labelled SYNTHETIC/UNVERIFIED. It is only a
check of local parsing, bounded subdivision, and sanitized reporting.

An offline single-query check accepts page sizes 1 through 100 and either
asc or desc:

    python -m log_query_probe.cli --mode offline-synthetic --operation single --organization synthetic-org --start-time 2026-10-14T20:00:00Z --end-time 2026-10-14T20:01:00Z --page-size 99 --sort-order desc --query '(resource.type = "container" or resource.type = "instance_controller")'

No live request has been made as part of implementation or QA. Do not run
LIVE_MANUAL based on this implementation alone. Its use remains a separate
operational gate.

## Experiment semantics

The experiment issues:

1. Parent query with page_size=100.
2. Same window, query, and order with page_size=99.
3. An optional repeated parent request.
4. Two direct children only when the parent returned exactly 100 entries.
5. An optional user-selected left or right half of the parent, without
   descendants. Other subintervals are rejected before any request.

For `--operation experiment`, the configured `--page-size` must be exactly
100. The experiment rejects another value before making any request; page
sizes 1 through 100 remain available for `--operation single`.

The logical window is limited to one hour. Child split uses the logical midpoint
floored to a whole UTC second; both children share that boundary. HTTP start is
floored and end is ceiled to UTC milliseconds so the serialized interval covers
the logical interval. A collapsed or invalid interval fails before its request.
Responses are limited to 5 MB total, six requests, 100 entries per request, and
600 entries across an experiment.

The output contains only an allowlisted set of request metadata, counts,
monotonicity, timestamp format classes, temporal relations, and rounded/capped
time deltas. Organization/query values are omitted. Provider timestamps are
never emitted verbatim. Log bodies, labels, resource identifiers, credentials,
URLs containing organization names, and exception text are not emitted.

The following conclusions remain explicitly unknown:

- A count of 100 does not prove truncation.
- A count below the limit does not prove completeness.
- Child counts adding to the parent count do not prove completeness.
- Repeated timestamps do not prove that entries represent the same event.
- Observed ordering does not prove the provider's ordering contract.
- Empty results and missing page bounds do not establish pagination semantics.
- Synthetic responses are never provider evidence.

Pagination completeness and provider semantics remain UNKNOWN until Salad's
current contract is independently verified. This probe does not relax or modify
the production watcher, adapter, cursor, overlap, or deduplication behavior.
