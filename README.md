# Rediver Go SDK

Build a Rediver network scanner by implementing one batch interface. The SDK
registers the agent, polls for work, maintains heartbeats, uploads results, and
reports job completion. The NetworkAgent token determines the scanner kind;
scanner code does not select a scanner enum or use a kind-specific constructor.

```sh
go get github.com/redivers/sdk-go
```

Scanner projects use the root `github.com/redivers/sdk-go` package for the
agent, inputs, results, and configuration.

## Quick start

This DNS scanner reports one final result for every assigned target:

```go
package main

import (
    "context"
    "errors"
    "fmt"
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
                if emitErr := emitter.EmitDomains(rediver.DNSResult{
                    Target:       target,
                    ErrorMessage: rediver.Ptr(dnsErr.Error()),
                }); emitErr != nil {
                    return emitErr
                }
                continue
            }
            return fmt.Errorf("resolve %s: %w", target.Domain, err)
        }
        if err := emitter.EmitDomains(rediver.DNSResult{
            Target: target,
            Items:  []rediver.DNSRecord{{Domain: target.Domain, IPs: ips}},
        }); err != nil {
            return err
        }
    }
    return nil
}

func main() {
    agent, err := rediver.NewAgent(
        os.Getenv("REDIVER_TOKEN"),
        rediver.ScanFunc(scan),
    )
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

Use a token configured for subdomain scanning with this example. Set
`REDIVER_URL` to the backend origin when needed; the default is
`https://api.rediver.ai`.

## Scanner inputs

```go
type Scanner interface {
    Scan(context.Context, []Target, Emitter) error
}
```

The SDK calls `Scan` once with all unfinished targets in one assigned job. This
is one backend-supplied batch, not the global scan queue. A scanner can pass the
batch to a bulk engine or schedule its targets internally. Implement `Scanner`
on a type when the engine owns configuration or resources; use `ScanFunc` for a
plain function.

Each `Target` contains the input for its scanner kind:

| Input | Fields |
|---|---|
| Domain | `Domain string` |
| Service discovery | `Host string`, `Ports []int`, `Rate int` |
| Vulnerability | `Host string`, `Port int`, and `URL string` when available |

Service discovery receives validated, sorted, unique ports. `Rate` is one probe
budget for the whole job batch and is repeated on its targets. Pass it once to a
bulk engine or share one limiter across workers.

A target also contains a private assignment reference. Put the original target,
or a copy of it, in every emitted result. Constructing a new `Target` from its
visible fields loses that reference.

## Emit final results

```go
type Emitter interface {
    EmitDomains(...DNSResult) error
    EmitServices(...ServiceResult) error
    EmitFindings(...FindingResult) error
}

type Result[T any] struct {
    Target       Target
    ErrorMessage *string
    Items        []T
}

type DNSResult = Result[DNSRecord]
type ServiceResult = Result[Service]
type FindingResult = Result[Finding]
```

Use the emitter method that matches the scanner kind configured for the token.
Calling another method returns an error, even with zero arguments. On the
matching method, zero arguments or an expanded nil or empty result slice is a
valid no-op and sends no RPC.

Every supplied result is the complete, final outcome for its target:

- Non-empty `Items` reports one or more observations.
- Empty `Items` with a nil `ErrorMessage` reports a successful scan with no
  observations. The target-only result is still uploaded.
- A non-nil `ErrorMessage` reports a final failure for that target. It cannot
  accompany non-empty `Items`, including across multiple wrappers for the same
  target in one call. `rediver.Ptr("")` is an explicitly present empty message.
- An error returned from `Scan` reports transient whole-job trouble, such as a
  crashed external engine.

Return every emission error from the scanner. Emission errors are sticky, so an
ignored error still fails the job. A result must contain an original assigned
target; the backend decides whether its observations are valid.

For realtime reporting, emit each target once as soon as its scan finishes. A
call containing one or more results uploads immediately and waits for backend
acknowledgement. Calls within a job are serialized for backpressure. An engine
may emit a batch when several targets finish together:

```go
results := []rediver.FindingResult{
    {Target: targets[0], Items: firstTargetFindings},
    {Target: targets[1], Items: secondTargetFindings},
}
return emitter.EmitFindings(results...)
```

`Emitter` supports concurrent calls and snapshots accepted observations before
returning. Join every goroutine that uses it before `Scan` returns and honor the
provided context. The emitter closes when scanning finishes; late calls fail.

The backend's terminal target state provides replay safety. The first accepted
push terminalizes a target, and later pushes for that target are ignored. A lost
acknowledgement therefore cannot apply the same projection twice. If an attempt
fails, only unfinished targets can be assigned again; accepted outcomes remain.

| Scanner outcome | Behavior |
|---|---|
| `Emit*()` or an empty outer result slice | No-op; no RPC is sent. |
| `Emit*(Result{Target: target})` | Upload a final result with no observations or target error. |
| `Emit*` returns `nil` | The backend acknowledged the push. |
| `Scan` returns `nil` | Request completion after every assigned target emitted its final result. |
| An assigned target has no result | Completion is rejected while that target remains unfinished. |
| `Scan` errors, panics, or is canceled | Report job failure; already accepted target outcomes remain stored. |
| An emission fails | Fail the job even if the scanner later returns `nil`. |

Result models use strings and integers for ordinary fields. Values requiring
explicit presence use pointers, such as `DNSRecord.TTL`, `Finding.CVSSScore`,
and `Certificate.Wildcard`; `rediver.Ptr(value)` is available. Certificate dates
use `time.Time`. Findings require a name and a supported severity from
`SeverityInfo` through `SeverityCritical`.

## Run the agent

`agent.Run(ctx)` polls continuously. `agent.RunOnce(ctx)` handles at most one
job and returns `ErrNoJobAvailable` when none is assigned. An `Agent` supports
one lifecycle invocation; create another agent to run it again.

`Run` logs individual job failures and continues polling. Authentication and
malformed assignments stop it. On parent cancellation, `Run` stops polling and
lets active jobs drain until the shutdown timeout. `Stop()` immediately cancels
polling and active work.

Registration, heartbeats, and result uploads retry transient network,
resource-exhausted, unavailable, and backend deadline errors up to five total
attempts. Delays use exponential backoff from one second with up to 25% jitter.
Caller cancellation and the per-RPC timeout stop immediately. Job claims,
starts, and terminal callbacks are not replayed; `Run` resumes after a transient
poll error.

| Option | Purpose |
|---|---|
| `WithServerURL(url)` | Override `REDIVER_URL` and the default backend origin. |
| `WithHTTPClient(client)` | Supply the non-nil `*http.Client` used for RPCs. |
| `WithMaxConcurrency(n)` | Set the positive number of concurrent jobs; the default is one. |
| `WithShutdownTimeout(d)` | Set the positive grace period for active jobs during shutdown. |
| `WithRequestTimeout(d)` | Set the positive per-RPC timeout; allow headroom above backend long polling. |
| `WithLogger(logger)` | Supply a non-nil `*slog.Logger`. |

When job concurrency is greater than one, the scanner must support concurrent
`Scan` calls. Each call receives its own target batch and service-probe budget.
Use `errors.Is` with `ErrNoJobAvailable`, `ErrInvalidConfig`, `ErrInvalidJob`, or
`ErrAlreadyRunning` for SDK control flow.

## Examples and development

- [subdomain](examples/subdomain): a custom `Scanner` implementation for DNS.
- [serviceprobe](examples/serviceprobe): batch TCP probes sharing one rate limiter.
- [vulnscan](examples/vulnscan): one findings batch containing a final result for
  every assigned target.

Use `snake_case` for Go filenames. Pair each implementation and test as
`file.go` and `file_test.go`; keep scenario tests and shared helpers with the
matching implementation test.

```sh
go build ./...
go vet ./...
go test -race ./...
```

## License

Proprietary — Calif Engineering
