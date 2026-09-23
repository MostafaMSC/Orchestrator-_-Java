# TwoKeyOk MiddleWare Orchestrator

A middleware that lets a business application sign documents through the ADSS
RAS / SAM platform with one REST call, for both **organisation e-seals** and
**natural persons** (remote authorised signing).

The REST surface follows the TwoKeyOk MiddleWare API guide at
<https://api-middle.twokeyok.iq/>. This release implements the two endpoints the
integration needs first:

| Method | Path | Guide page |
|---|---|---|
| `POST` | `/orchestrator/service/sign` | Signing PDF (PAdES) |
| `GET` | `/orchestrator/service/signing/appearances/list` | List Signature Appearances |

Everything else in the guide — XAdES/CAdES signing, verification, the appearance
CRUD endpoints and the CSC v1 surface — is deliberately out of scope for now; the
code is laid out so those land beside the existing ones rather than through them
(see [Extending](#extending)).

---

## How it works

```
Business application            TwoKeyOk Orchestrator                ADSS
------------------------        ---------------------------          ------------------
POST /service/sign         →    authenticate caller                   
  Authorization: Basic/Bearer   resolve signer (e-seal | person)
  input_files, signer_id,       merge signature appearance
  pin, signature_appearance     build ADSS request  ────────────→    /adss/signing/hdsi
                                                                      │
                            e-seal:  signed PDF returned  ←───────────┘
                            person:  PENDING + transaction id
                                     poll status  ───────────────→    signer approves
                                     embed signature ←──────────────  on their device
     signed PDF / zip      ←    package (NONE | ASiC-S | ASiC-E)
```

The signing engine is the **ADSS Client SDK** (`adss_client_api.jar` from
`JAVAsdk/API/lib`), driven through `PdfSigningRequest` / `StatusRequest` exactly
as the SDK samples do — `AuthorisedSignPdfWithLocalHash.java` for the remote
authorised flow and `SignPDF.java` for the direct one.

### The two signing modes

|  | e-Seal | Natural person |
|---|---|---|
| Configured as | `type: ESEAL` | `type: NATURAL_PERSON` |
| Who approves | nobody — unattended | the signer, on their device |
| Sent to ADSS | profile + certificate alias | profile + alias + **RAS user id** + **PIN** |
| Response | signed document immediately | `PENDING` + transaction id, then polling |
| PIN | optional static credential password | supplied per request, never stored |

---

## Build

Requirements: **JDK 17 or 21**, **Maven 3.9+**, and the ADSS Client SDK.

```bash
# 1. Install the licensed SDK jar into the local Maven repository (once).
#    With no argument it searches the usual locations, including the deployed
#    Ascertia installations under /appdata/ascertia. It reads the version from
#    the jar's own manifest when the SDK ships no version file.
./deploy/install-adss-sdk.sh                       # or pass a path:
./deploy/install-adss-sdk.sh /appdata/ascertia/orchestrator
./deploy/install-adss-sdk.sh /path/to/JAVAsdk      # Windows: .\deploy\install-adss-sdk.ps1

# 2. Build.
mvn -B clean package
```

The build defaults to SDK **8.1.0**, the version shipped in the deployed ADSS
installations. For a different SDK, point the build at it without editing
anything:

```bash
mvn -B -Dadss.sdk.version=8.3.7 clean package
```

Both 8.1.0 and 8.3.7 compile and pass the full suite.

The result is `target/twokeyok-orchestrator.jar`, a self-contained Spring Boot
application.

> The SDK jar is licensed software and is not on Maven Central, which is why it
> is installed locally instead of being declared as a normal remote dependency.
> Every other dependency is pinned to the exact version shipped in
> `JAVAsdk/API/lib`, so the runtime matches the SDK's tested set.

## Install on Linux

```bash
sudo ./deploy/install.sh
```

This creates the `twokeyok` service account, lays out `/opt/twokeyok/orchestrator`,
`/etc/twokeyok/orchestrator` and `/var/log/twokeyok-orchestrator`, installs the
hardened systemd unit and the logrotate policy, and never overwrites an existing
configuration. Full walkthrough: [`docs/INSTALL-LINUX.md`](docs/INSTALL-LINUX.md).

A container build is available too — see [`docker/Dockerfile`](docker/Dockerfile).

## Configure

Two files, both under `/etc/twokeyok/orchestrator`:

| File | Holds |
|---|---|
| `orchestrator.yml` | ADSS endpoints, signature defaults, appearances, signers, registered clients |
| `orchestrator.env` | secrets and per-host values referenced as `${VAR}` from the YAML |

**The key names match the deployed Ascertia Orchestrator configuration**
(`signing.gateway.*`, `signing.dss.signature.*`, `signing.ras.*`,
`csc-config.registered-clients`), so an existing working `application.yml` can be
copied across for the parts this product implements. That is not a claim on
paper: `src/test/resources/reference-application.yml` is a real (redacted) file
and `ReferenceConfigurationCompatibilityTest` binds it and checks the values
arrive intact. Keys for features this product does not implement — one-time
signing, the DSS revocation tuning, XAdES/CAdES — are ignored rather than
half-honoured; [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) has the full
honoured/ignored table.

On top of that shape it adds `signing.signers.<id>` — the per-identity
configuration that lets one deployment serve several e-seals and natural
persons, layered **defaults → client → signer → request**.

Client secrets are stored as BCrypt hashes (`ENC(...)` from the reference form is
also accepted):

```bash
java -jar /opt/twokeyok/orchestrator/twokeyok-orchestrator.jar --hash-secret 'my-secret'
```

Before the first signing attempt on a new host, check what it can actually reach:

```bash
java -jar /opt/twokeyok/orchestrator/twokeyok-orchestrator.jar --check-adss
```

## Use

```bash
# e-Seal, business application authenticating with its own credentials
curl -sk -X POST https://orchestrator.internal.example/orchestrator/service/sign \
  -u 'hr_portal:my-secret' \
  -F 'input_files=@invoice.pdf' \
  -F 'signer_id=ministry_eseal' \
  -F 'container_type=NONE' \
  -o invoice-signed.pdf

# Natural person, signer presenting their own IAM access token
curl -sk -X POST https://orchestrator.internal.example/orchestrator/service/sign \
  -H "Authorization: Bearer $TOKEN" \
  -F 'input_files=@contract.pdf' \
  -F 'pin=12345678' \
  -F 'signature_appearance={"template_id":"default_signature_appearance","reason":{"label":"Reason: ","include_label":true,"value":"I approve this contract"}}' \
  -o contract-signed.pdf

# Appearance catalogue
curl -sk https://orchestrator.internal.example/orchestrator/service/signing/appearances/list \
  -u 'hr_portal:my-secret' | jq
```

Endpoint reference, parameters and error codes: [`docs/API.md`](docs/API.md).

## Operate

```bash
systemctl status twokeyok-orchestrator
journalctl -u twokeyok-orchestrator -f
curl -sk https://localhost/orchestrator/actuator/health
```

Two log files under `/var/log/twokeyok-orchestrator`:

* `orchestrator.log` — application log
* `audit.log` — one line per signing attempt (request id, client, signer, profile,
  credential, document count, ADSS transaction id, outcome). It never contains a
  PIN, a token, a document or a signature, and is kept for two years by default.

## Layout

```
twokeyok-orchestrator/
├── pom.xml
├── config/                      configuration shipped to /etc/twokeyok/orchestrator
│   ├── orchestrator.yml
│   └── appearances/*.json       signature appearance templates
├── deploy/
│   ├── install.sh               Linux installer (systemd)
│   ├── uninstall.sh
│   ├── install-adss-sdk.sh|ps1  installs the licensed SDK jar into ~/.m2
│   ├── systemd/                 hardened unit file
│   ├── env/                     orchestrator.env template
│   └── logrotate/
├── docker/                      Dockerfile + compose
├── docs/                        API, configuration and install guides
└── src/main/java/iq/twokeyok/orchestrator/
    ├── web/                     REST layer (controllers, DTOs, error mapping)
    ├── security/                Basic client auth + IAM bearer token validation
    ├── service/                 the /service/sign workflow and the audit trail
    ├── signing/                 signer resolution, backend SPI, ADSS backend, containers
    ├── appearance/              template store, merge, ADSS appearance XML writer
    ├── config/                  configuration model
    └── error/                   error codes
```

## Extending

* **Another endpoint from the guide** (verify, XAdES/CAdES, appearance CRUD) —
  add a controller under `web/`; the signer resolution, appearance and audit
  pieces are already reusable.
* **Talking CSC REST to RAS instead of the SDK** — implement
  `signing.SigningBackend` and register it instead of `AdssSigningBackend`.
  Nothing above that interface knows which transport is in use.
* **Another appearance field** — add it to `AppearanceTemplate.Fields`, map it in
  `AppearanceXmlWriter.ADSS_FIELD_NAMES`, and merge it in `AppearanceService`.

## Licensing

The ADSS Client SDK, its documentation and Go>Sign components in the parent
`JAVAsdk` directory are licensed by Ascertia; see `JAVAsdk/license.txt`. They are
neither redistributed nor vendored by this project — the build reads the jar from
the SDK installation you already hold a licence for.
