# Rediver Go SDK

Implement one `Scanner` interface: receive a **batch of targets** and emit typed
SDK result sets. The SDK handles registration, polling, target assignment,
uploads, heartbeats, retries and job completion. The NetworkAgent token determines
the scanner type on the backend; scanner code does not select an enum or a
scanner-specific constructor.

Scanner projects use one import, `github.com/redivers/sdk-go`, for the agent,
native inputs, results and configuration. Backend protocol types stay internal.

This breaking update uses the `networkscan` contract from the backend's
`network-scan` implementation.

```sh
go get github.com/redivers/sdk-go
```

Use a revision containing this migration. The module path remains
`github.com/redivers/sdk-go`; this change does not publish a release.
Deploy the backend realtime migration and implementation before upgrading scanners.

## Quick start

```go
package main

import (
    "context"
    "errors"
    "log"
    "net"
    "os"
    "os/signal"

    rediver "github.com/redivers/sdk-go"
)

func scan(ctx context.Context, targets []rediver.Target, emitter rediver.Emitter) error {
    for _, target := range targets {
        ips, err := net.DefaultResolver.LookupHost(ctx, target.Domain)
        if err != nil {
            var dnsErr *net.DNSError
            if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
                continue
            }
            return err
        }
        if err := emitter.EmitDomains(rediver.DNSResult{
            Target: target,
            Items: []rediver.DNSRecord{{Domain: target.Domain, IPs: ips}},
        }); err != nil {
            return err
        }
    }
    return nil
}

func main() {
    agent, err := rediver.NewAgent(os.Getenv("REDIVER_TOKEN"), rediver.ScanFunc(scan))
    if err != nil {
        log.Fatal(err)
    }
    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
    defer cancel()
    if err := agent.Run(ctx); err != nil {
        log.Fatal(err)
    }
}
```

Use a token configured for subdomain scanning to run this DNS example. Set
`REDIVER_URL` to your backend origin, for example `http://localhost:5152`.
The default is `https://api.rediver.ai`.

## One scanner interface

```go
type Scanner interface {
    Scan(context.Context, []Target, Emitter) error
}

type Emitter interface {
    EmitDomains(...DNSResult) error
    EmitServices(...ServiceResult) error
    EmitFindings(...FindingResult) error
}
```

The SDK calls `Scan` once with **all unfinished targets in one assigned job**.
This is a batch supplied by the backend, not the entire global scan queue. Pass
the list to a bulk engine in one invocation, or schedule individual targets
inside your scanner. The SDK does not force one engine invocation per target.

Implement the interface on your own type to keep engine configuration and
resources together:

```go
type DNSScanner struct{}

var _ rediver.Scanner = (*DNSScanner)(nil)

func (*DNSScanner) Scan(ctx context.Context, targets []rediver.Target, emitter rediver.Emitter) error {
    return scan(ctx, targets, emitter)
}

func newDNSAgent(token string) (*rediver.Agent, error) {
    return rediver.NewAgent(token, &DNSScanner{})
}
```

This example reuses `scan` from the quick start. A plain function uses
`rediver.ScanFunc(scan)` instead. Both forms share the same runtime and require no
job IDs, run IDs, scanner enum, or reporter.

`Target` contains ordinary Go fields populated for the assignment:

| Scan input | Fields used by the scanning logic |
|---|---|
| Domain | `Domain string` |
| Service discovery | `Host string`, `Ports []int`, `Rate int` |
| Vulnerability | `Host string`, `Port int`, `URL string` when available |

Service discovery receives validated, sorted, unique ports. `Rate` is one probe
budget for the **whole job batch**, repeated on its targets. Pass it once to your
bulk engine or share one limiter across workers; do not allocate that full budget
to every target. See [serviceprobe](examples/serviceprobe). The SDK cannot meter
requests made inside an external scanning engine.

Each input also carries a private SDK reference. Set each result set's `Target`
to the original input or a copy of it; keep it alongside each engine input when
correlating results. Constructing a new `Target` from a hostname loses the
assignment reference. The SDK retains the original backend target, including
optional field presence, so scan code never constructs transport identifiers.

## Emit observations

Use the method matching the scanner kind configured in your token. Each result
set pairs one assigned target with a slice of native observations:

| Method | Result set |
|---|---|
| `EmitDomains` | `DNSResult{Target: target, Items: []DNSRecord{...}}` |
| `EmitServices` | `ServiceResult{Target: target, Items: []Service{...}}` |
| `EmitFindings` | `FindingResult{Target: target, Items: []Finding{...}}` |

These names are aliases of the shared `Result[T]` type:

```go
type Result[T any] struct {
    Target       Target
    ErrorMessage *string
    Items        []T
}

type DNSResult = Result[DNSRecord]
type ServiceResult = Result[Service]
type FindingResult = Result[Finding]
```

Use either spelling, including slices such as `[]Result[Finding]` passed to
`EmitFindings(results...)`. All result types store observations in `Items`.

All three result types also have an optional `ErrorMessage *string` for a scan
error on that target, including when partial observations are available. Leave
it `nil` when absent, or set it with `rediver.Ptr("scan timed out")`.
`rediver.Ptr("")` represents an explicitly present empty message.

This field is reserved for upcoming protocol support: the current SDK transport
does not upload it or use it to change job status. A result containing only
`ErrorMessage` remains a no-op after target validation. Return an error from
`Scan` when the whole job should fail.

Emit one result set as soon as its observations are available:

```go
oneResult := rediver.FindingResult{
    Target: target,
    Items: []rediver.Finding{{
        Name: "Observed vulnerability",
        Severity: rediver.SeverityHigh,
        RuleID: "my-rule",
    }},
}
if err := emitter.EmitFindings(oneResult); err != nil {
    return err
}
```

An engine can also return a list spanning multiple assigned targets. For example,
with findings already collected for two targets:

```go
results := []rediver.FindingResult{
    {Target: targets[0], Items: firstTargetFindings},
    {Target: targets[1], Items: secondTargetFindings},
}
return emitter.EmitFindings(results...)
```

Each inner `Items` slice may contain multiple findings for its target. The same
single-result and batch forms work with `EmitDomains` and `EmitServices`; see the
[runnable examples](#examples-and-development).

All three methods belong to one `Emitter`. Calling a method incompatible with the
assigned job returns an error, even with zero arguments. Unknown payload types
cannot be passed to these typed methods. For the matching method, zero arguments
or an expanded nil/empty result slice is a valid no-op. A result set with no inner
observations is also a no-op, but its `Target` must still belong to the assignment.
Return emission errors from your scanner; the SDK remembers them so ignoring one
cannot silently complete the batch.

`Emitter` supports concurrent calls and snapshots accepted observations before
returning. Finish all your goroutines before `Scan` returns and honor `ctx`.
The emitter closes when scanning finishes; late emissions fail.

**Each `Emit*` call with observations uploads immediately and waits for backend acknowledgement.** You
can emit several chunks for the same target while scanning continues. Calls are
serialized within a job to provide backpressure. Each call accepts at most
100,000 observations and 64 MiB of encoded payload; there is no cumulative job
result limit. Split larger output across calls. These limits exclude Go object
overhead.

| Scanner outcome | Meaning |
|---|---|
| `Emit*` returns `nil` | Backend acknowledged this chunk, or the call was an empty no-op. |
| `Scan` returns `nil` | Finish every assigned target and complete the job. |
| No emissions for a target, with successful `Scan` | Finish that target with no observations. |
| `Scan` errors, panics, or is canceled | Report failure; already accepted observations remain stored. |
| An emit error occurs | Fail the job even if the scanner ignores it and returns `nil`. |

DNS records may describe the assigned domain or strict descendants; direct
subdomain targets may only report themselves. The own-domain record is optional.
The SDK never fabricates DNS metadata. Successful DNS completion still lets the
backend schedule the assigned hostname for the next enabled stage. Each emitted
DNS/service observation is a complete record: later observations replace its
scanner-owned metadata. For services, an empty `Host` uses the assigned host.

The SDK gives each push a fresh idempotency key and reuses it on transport retries
within the current job run. A lost acknowledgement therefore does not repeat that
push's projection. A later `Emit*` call is a new push, even with identical data.
If a job attempt fails, backend may scan its unfinished targets again; accepted
partial results remain available. Return emission errors promptly and honor
cancellation.

Result models use plain strings and integers for ordinary fields. Optional values
that need explicit presence use pointers, such as `DNSRecord.TTL`,
`Finding.CVSSScore`, and `Certificate.Wildcard`; `rediver.Ptr(value)` is available.
Certificate validity dates use `time.Time`. See the
[model definitions](internal/contract/models.go) for all fields; the root SDK
exposes these same types through aliases. Findings require a name and one of
`SeverityInfo`, `SeverityLow`, `SeverityMedium`, `SeverityHigh`, or
`SeverityCritical`. Include both raw request
and response when adding `RawHTTPRequest` evidence.

## Run the agent

`agent.Run(ctx)` polls continuously. `agent.RunOnce(ctx)` polls and handles one
job, returning `ErrNoJobAvailable` if none is available. An Agent supports one
lifecycle invocation; create another Agent to run it again.

`WithMaxConcurrency(n)` controls concurrent **jobs**, each with its own batch and
rate budget. The default is one. Your scanner controls concurrency within each
batch and must support concurrent `Scan` calls when job concurrency exceeds one.

On cancellation, `Run` stops polling and lets active jobs drain until the shutdown
timeout. `Stop()` cancels polling and active work immediately. The SDK maintains
heartbeats during scanning and uploads, including the drain period. `Run` logs
individual job errors and continues; authentication or malformed-assignment
errors stop the agent. `RunOnce` returns execution errors to the caller.

| Option | Purpose |
|---|---|
| `WithServerURL(url)` | Override the backend origin. |
| `WithMaxConcurrency(n)` | Bound concurrent jobs; default 1. |
| `WithPollInterval(d)` | Delay between empty or failed polls; default 5 seconds. |
| `WithRequestTimeout(d)` | Bound RPCs; default 60 seconds. Allow headroom above backend long polling, which defaults to 30 seconds. |
| `WithShutdownTimeout(d)` | Grace period for active jobs; default 30 seconds. Bounded terminal cleanup may follow. |
| `WithLogger(logger)` | Use a `*slog.Logger`. |
| `WithRetryDefault()`, `WithRetryAggressive()`, `WithNoRetry()` | Choose a retry preset. |

See [options.go](options.go) for heartbeat intervals, runner metadata, custom HTTP
clients and retry policies. Claiming polls and terminal callbacks are not
transparently retried, because a lost response may already have changed backend
state. Transient polling failures resume in the next `Run` polling cycle.

Use `errors.Is` with `ErrNoJobAvailable`, `ErrInvalidConfig`, `ErrInvalidJob` or
`ErrAlreadyRunning` for SDK control flow. Wrapped failures preserve diagnostic
context and underlying causes.

The SDK uses the published Buf Connect and protobuf modules. See
[go.mod](go.mod) for dependency versions.

## Examples and development

- [subdomain](examples/subdomain): a custom `Scanner` implementation for DNS.
- [serviceprobe](examples/serviceprobe): batch TCP probes sharing one rate limiter.
- [vulnscan](examples/vulnscan): emit a list of expired-certificate result sets across targets.
- [task](examples/task): one polled job using `ScanFunc`.

Use `snake_case` for Go filenames. Group tests by their implementation file:
`file.go` pairs with `file_test.go`. Keep scenario tests and shared test helpers
in the matching implementation's test file.

```sh
go build ./...
go vet ./...
go test -race ./...
```

## License

Proprietary — Calif Engineering
