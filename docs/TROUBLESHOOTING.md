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
the client IP and an Attack ID to quote at whoever runs the firewall. A
multipart POST carrying a PDF is the kind of request a WAF blocks by default.

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
