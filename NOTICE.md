# Third-party notices

## Ascertia ADSS Client SDK — not included in this repository

This project is built against the **Ascertia ADSS Client SDK**
(`adss_client_api.jar`), which is licensed commercial software. It is
**deliberately not part of this repository**, and must not be committed to it:
the SDK licence requires it to be kept in confidence and not disclosed to third
parties.

Nothing in this repository contains Ascertia source code, the SDK jar, the SDK
documentation or the SDK sample data. What it does contain is *this project's*
own code, which calls the SDK's public API.

To build, install your own licensed copy of the SDK into your local Maven
repository first:

```bash
./deploy/install-adss-sdk.sh /path/to/your/JAVAsdk
```

The script reads `API/lib/adss_client_api.jar` from the SDK directory you
already hold a licence for, verifies its shipped SHA-256 checksum, and installs
it as `com.ascertia:adss-client-api`. `.gitignore` blocks the jar, `lib/`,
`API/` and `Docs/` so it cannot be committed by accident.

## Other dependencies

Every other dependency resolves from Maven Central and is pinned in `pom.xml` to
the exact version shipped with the SDK, so the runtime matches the set Ascertia
tested against. Principal ones:

| Component | Licence |
|---|---|
| Spring Boot | Apache-2.0 |
| Bouncy Castle | MIT-style (Bouncy Castle Licence) |
| Apache PDFBox / FontBox | Apache-2.0 |
| Apache HttpComponents | Apache-2.0 |
| Apache Santuario (xmlsec) | Apache-2.0 |
| dom4j | BSD-style |
| JDOM | Apache-style (JDOM Licence) |
| Nimbus JOSE+JWT | Apache-2.0 |
| Jasypt Spring Boot | Apache-2.0 |

## Configuration in this repository

The committed configuration uses **placeholder hostnames**
(`adss-*.internal.example`) and empty secrets. Real endpoints, credentials and
key material belong in `/etc/twokeyok/orchestrator/orchestrator.env` on the
deployment host, which is never committed.
