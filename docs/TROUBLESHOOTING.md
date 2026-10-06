# Troubleshooting

Failure signatures seen against a real ADSS staging estate, and what each one
turned out to mean. Every entry here was diagnosed from evidence on the wire or
in a log, not inferred from the symptom — several of them look like something
they are not.

## The orchestrator reports 1001, internal server error

`1001` means an exception this product did not classify. The HTTP response
deliberately carries no detail; the stack trace is in the log:

```
awk '/PAdES signing failed/{n=NR} {a[NR]=$0} END{for(i=n;i<n+14&&i<=NR;i++) print a[i]}' \
  /var/log/twokeyok-orchestrator/orchestrator.log
```

### `The signature field 'Signature1' does not exist`

```
at ASC_PdfBoxSignerService.getHash
at PdfSigningRequest.computePdfHashIfRequired
```

`local_hash: true` makes the SDK hash the PDF here, which requires the document
to already contain the empty signature field named by `signature_field_name`.
Either embed the field first or set `local_hash: false` and let ADSS create it.

`compute_hash` is **not** this switch, despite the name it shares with the
Ascertia Orchestrator's own `compute_hash`. Here it maps to `setSignatureHash`,
which only asks ADSS to return the hash.

### `ASC_SOAPEnvelope.getBody() is null`

Not a fault in this product, and it is now reported as `1115`. In DSS request
mode ADSS reports a refusal in the *response headers* with `Content-Length: 0`:

```
RESPONSE_STATUS: FAILED
ERROR_CODE: 41003
MESSAGE: [Error-41003] Failed to process request - Signing service is stopped
```

The SDK's parser expects a SOAP envelope, finds no body and throws, so ADSS's
own words never reach the application. Read them off the wire — see
**Reading what ADSS actually said** below. `41003` is a stopped Signing Service;
`41004` is an internal ADSS error whose detail is only in ADSS's debug log.

## A setting in orchestrator.yml appears to be ignored

Environment variables outrank every config file in Spring's precedence, and a
stray one is invisible in the YAML. A deployment here ran for hours with
`local_hash` resolving to `true` from a `SIGNING_DSS_SIGNATURE_LOCAL_HASH` left
in systemd's *manager* environment — absent from the unit file, from
`orchestrator.env`, and from every file on disk.

Ask the running JVM which source won:

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,env
```

```
curl -su '<client>:<secret>' \
  'http://localhost:9443/orchestrator/actuator/env/signing.dss.signature.local-hash'
```

The answer names every property source that defines the key. Remove the
exposure afterwards. To clear a manager-environment variable:
`systemctl unset-environment SIGNING_DSS_SIGNATURE_LOCAL_HASH`.

Note that `--check-adss` prints the configured **defaults**, while the backend
logs the **resolved** values after `defaults → client → signer → request`. When
the two disagree, an override or an environment variable is responsible.

## HTTP 500 with an HTML body, and no ADSS headers

ADSS answers its own protocol in headers (`RESPONSE_STATUS`, `ERROR_CODE`,
`MESSAGE`). An HTML body instead means the request never reached the signing
handler. Three different causes presented identically here:

| Body | Cause |
|---|---|
| ~455 bytes, Tomcat's default page | the Signing Service was stopped |
| ~39 KB, branded "Web Page Blocked!" with an Attack ID | a **WAF** blocked the request |
| ADSS's own error page | the request reached ADSS and it refused |

Strip the tags before concluding anything — the WAF page names the blocked URL,
the client IP and an Attack ID to quote at whoever runs the firewall.

### When a WAF blocks the signing request

Observed against one staging estate: every request the ADSS Client SDK sent to
`/adss/signing/hdsi` was blocked, while every hand-built equivalent passed. Each
of these was sent from the same host to the same URL and **allowed**:

| Sent with curl | Result |
|---|---|
| a plain `multipart/form-data` POST | allowed |
| the same, with a PDF as a second part | allowed |
| the real `HTTPRequestParameters` JSON the SDK sends | allowed |
| `Content-Type: RequestParameters` on that part (the SDK's non-standard value) | allowed |
| `multipart/form-data;charset=UTF-8 boundary=…` (the SDK's non-conformant header) | allowed |

And both of these, from the orchestrator, were **blocked**:

| Sent by the SDK | Result |
|---|---|
| full-document signing (`local_hash: false`) | blocked |
| hash signing (`local_hash: true`) — digest only, no document | blocked |

So the payload is irrelevant: a request carrying nothing but a hash is blocked
too. Do not spend time narrowing it from outside, as was done here — the WAF's
own log, looked up by the Message ID on the block page, names the matched rule
directly. Collect two or three Message IDs and the elimination table above, and
ask for an exemption for `POST /adss/signing/hdsi` from the orchestrator's
source address.

Note for anyone reaching for hash signing as a way round a firewall: it is not
one. It also cannot produce a visible signature, because ADSS never sees the
page.

## Reading what ADSS actually said

Over plaintext, capture it directly:

```
tcpdump -i any -s0 -A 'host <adss-host> and tcp port <port>'
```

Over TLS, terminate it on loopback, point `signing.gateway.url` at the relay and
read one exchange. `deploy/tls-relay.py` does this with the standard library —
no extra packages, nothing leaves the host that was not already going there.

## Endpoints that look required but are not

Only `signing.gateway.url` is dialled by this process. The verification,
timestamp, OCSP and RAS addresses are handed to ADSS, which reaches them from
its own network, so a timeout from the orchestrator host says nothing about
whether signing will work. `--check-adss` reports them and gates its exit code
on the gateway alone.

## Known SDK notes

- **8.1.0 needs iText 7** for PDF signature generation. **8.2 and later use
  Apache PDFBox**; this product targets 8.3.7 and ships no iText. Never call
  `setITextVersion`.
- 8.1.x needs the javax XML stack, 8.3.x the jakarta one. The `sdk-javax` and
  `sdk-jakarta` Maven profiles cover JAXB, JAX-WS, xmlsec, jdom and mail.
- `ClientHttpRequest` in 8.3.7 emits
  `multipart/form-data;charset=UTF-8 boundary=…` — a space where RFC 2045 wants
  a semicolon. Observed, but not seen to cause a failure: every HTTP-mode
  failure here had another explanation. Noted so it is not mistaken for a cause.

## Storing an appearance fails with 1127

`1127 Signature appearance template [...] could not be stored`, while reading
templates from the same directory works.

The systemd unit runs with `ProtectSystem=strict`, which makes the entire
filesystem read-only to the service apart from the paths it declares. Moving the
store elsewhere does not help - `/etc`, `/var/lib` and everywhere else are
equally read-only until the unit says otherwise.

The unit declares a state directory for exactly this:

```ini
StateDirectory=twokeyok-orchestrator
Environment="ORCHESTRATOR_STATE_DIR=/var/lib/twokeyok-orchestrator"
```

systemd creates it owned by `User=` and adds it to the writable set, and the
packaged default puts the appearance store inside it. Point `store-path` there:

```yaml
signing:
  dss:
    signature:
      appearance:
        store-path: /var/lib/twokeyok-orchestrator/appearances
```

After changing the unit, `systemctl daemon-reload` before restarting - editing
the file alone has no effect.

Appearance templates created through the API are application state, not
configuration, which is why they belong there rather than beside
`orchestrator.yml`. Templates declared in `orchestrator.yml` stay read-only
through the API regardless.
