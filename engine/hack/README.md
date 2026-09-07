# hack

Development and test tooling. **Nothing here is part of the product.** No
kapkan binary builds, links or runs any of it, and none of it is packaged: `make
build` and `go build ./...` in `engine/` do not even see the Go module in
`h3probe/`.

- [`h3probe/`](h3probe) — an HTTP/3 test client that reports what the QUIC
  handshake did. Its own Go module.
- [`h3client/`](h3client) — stock Debian `curl`, in a container, as the
  ordinary-client half of the same tests.
- [`kernel-matrix/`](kernel-matrix) — boots real Linux kernels under QEMU and
  runs the data-plane suite on each. Has its own README.

## The two HTTP/3 clients

Milestone E5 of the edge track (`engine/docs/edge-spec.md` §8) puts HTTP/3 into
the nginx/Angie configuration Kapkan renders. Proving that needs two different
clients, for two different reasons.

`h3client` is the honest one: distribution curl, unmodified, exactly what a
visitor's browser stands in for. If it fetches a page over h3 from a rendered
terminator, h3 works. What it cannot do is see inside the handshake — curl will
not tell you whether the server sent a **Retry**, and it cannot be made to offer
a session ticket issued by a *different* node.

`h3probe` is the instrumented one, for those two facts: it reports `retry_seen`
from the connection's own qlog trace, and under `-resume` it makes a second
connection sharing one TLS session cache and reports whether that connection
resumed. Those are the assertions behind E5's Retry arm (`quic_retry on`) and
its shared-ticket-key arm (a session issued by edge-1, resumed on edge-2).

### Why h3probe is a separate Go module

Decision **D10** of the E5 plan: the product carries no QUIC dependency. Kapkan
orchestrates a terminator and never terminates QUIC itself — that is the whole
shape of the edge track (edge-spec, *"Shape: orchestrate over own-proxy"*), and
a QUIC stack in `engine/go.mod` would land in the kapkan binary's module graph
and its CVE surface for the sake of a test client.

So `h3probe/` has its own `go.mod`. Go tooling does not descend into nested
modules, so `go build ./...`, `go test ./...`, `go list -m all` and the release
build in `engine/` are all untouched by it. The rule is enforced, not merely
documented: `internal/edge/render/deps_guard_test.go` fails if a `quic-go`
requirement ever appears in `engine/go.mod` — and fails, too, if `h3probe`
stops requiring one, so the guard can never pass vacuously.

## h3probe

```sh
cd engine
make h3probe            # builds bin/h3probe
```

```sh
bin/h3probe get -url https://edge-1.example:443/ -ca lab-ca.pem
bin/h3probe get -url https://edge-1.example/ -sni shop.example -insecure
bin/h3probe get -url https://edge-1.example/ -ca lab-ca.pem \
  -resume-url https://edge-2.example/          # ticket from edge-1, offered to edge-2
```

It prints **one JSON object** on stdout and exits 0 even when the request
failed, so a shell arm can parse a refusal as readily as a success. Only a
usage error exits non-zero (2), and prints nothing on stdout.

```json
{"status":200,"alpn":"h3","proto":"HTTP/3.0","alt_svc":"h3=\":443\"; ma=86400","retry_seen":true,"resumed":false,"error":""}
```

| field | meaning |
| --- | --- |
| `status` | HTTP status of the first response; `0` when the request failed |
| `alpn` | ALPN negotiated on the first connection; `h3` when h3 is served |
| `proto` | response protocol; `HTTP/3.0` on a served h3 request |
| `alt_svc` | the response's `Alt-Svc` header; omitted when the header is absent |
| `retry_seen` | the **first** connection received a QUIC Retry packet |
| `resumed` | the **second** connection resumed a TLS session (`-resume` only) |
| `resume_status` | HTTP status of the second response; present only with `-resume` |
| `error` | why the run failed; empty on success |

Flags: `-url` (required, https), `-sni`, `-ca`, `-insecure`, `-timeout` (the
budget for the whole run, both connections, default 5s), `-resume`,
`-resume-url` (implies `-resume`). `-sni` also fixes the TLS session cache key,
which is what lets a ticket issued by one node be offered to another.

Its own tests are hermetic — an in-process quic-go server on a random loopback
UDP port, a throwaway certificate — and cover both directions of every claim:
`retry_seen` true against a server whose transport validates source addresses
and false against one that does not, `resumed` true under `-resume` and false
without it.

```sh
cd engine/hack/h3probe && go test ./...
```

## h3client

```sh
cd engine/hack/h3client
docker build -t kapkan-h3client .
docker run --rm kapkan-h3client -V | grep HTTP3
docker run --rm kapkan-h3client --http3-only -sv https://edge-1.example/
```

`ENTRYPOINT` is `curl`, so the container takes curl's own arguments. Debian 13's
curl 8.14.1 is built against OpenSSL 3.5 with nghttp3 and speaks HTTP/3 with no
extra packages; the image installs nothing but `curl` and `ca-certificates`.

The build ends with `curl -V | grep -q HTTP3`. That line is the point of the
image being pinned to a distribution: `curl --http3` *falls back* to HTTP/2
rather than failing, so a point release that dropped HTTP/3 would leave every h3
arm passing over the wrong protocol. This way the image build fails instead.
