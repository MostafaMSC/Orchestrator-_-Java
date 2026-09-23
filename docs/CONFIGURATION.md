# Configuration reference

The key names mirror the **deployed Ascertia Orchestrator** configuration, so an
existing working `application.yml` can be copied across for the parts this
product implements. `src/test/resources/reference-application.yml` holds a real
(redacted) file and `ReferenceConfigurationCompatibilityTest` asserts that it
binds — so the compatibility claim on this page is tested, not asserted.

Files under `${ORCHESTRATOR_CONFIG_DIR}` (default `/etc/twokeyok/orchestrator`):

| File | Purpose | Mode |
|---|---|---|
| `orchestrator.yml` | ADSS endpoints, signature defaults, appearances, signers, clients | `0640 root:twokeyok` |
| `orchestrator.env` | secrets and per-host values, referenced as `${VAR}` | `0640 root:twokeyok` |
| `appearances/` | optional JSON templates and appearance images | `0640 root:twokeyok` |

Any value may be written as `${ENV_VAR}` / `${ENV_VAR:default}`, or as
`ENC(...)` — Jasypt decrypts those using `JASYPT_ENCRYPTOR_PASSWORD`.

Changing configuration needs a restart. The exception is appearance templates,
re-read on every call when `appearance.reload-always: true`.

Spring's relaxed binding accepts the snake_case spellings from the reference file
(`pdf_profile_id`, `default_credential_strategy`) and kebab-case equally.

---

## What is honoured, and what is ignored

The reference file configures a product that also does XAdES/CAdES, one-time
signing and its own DSS-library signature building. This orchestrator signs PDFs
through the ADSS Client SDK. Keys for the rest are **ignored, not
half-implemented** — binding succeeds, nothing reads them.

| Reference key | Status |
|---|---|
| `signing.gateway.*` | **honoured** — `url`, `client_id`, `pdf_profile_id` |
| `signing.verification.*` | **honoured** — used for LT/LTA upgrades |
| `signing.ras.keystore_path` / `keystore_password` | **honoured** — client certificate for mutual TLS |
| `signing.ras.url` / `client_id` / `client_secret` / `profile_id` / `device_id` | bound and reported by the preflight; the SDK path reaches RAS through the gateway, so they are not sent directly |
| `signing.truststore_path` / `truststore_password` | **honoured** |
| `signing.default_credential_strategy` | **honoured** — `NONE` / `LATEST` |
| `signing.dss.tsa.*` | **honoured** |
| `signing.dss.signature.hash_algorithm`, `dictionary_size`, `compute_hash`, `signature_level` | **honoured** |
| `signing.dss.signature.appearance.*` | **honoured** — see [Appearances](#appearances) |
| `signing.dss.ocsp.*` | bound and reported by the preflight; revocation is fetched by ADSS, not here |
| `signing.dss.signature.revocation_*`, `timestamp_retries`, `annotation_overlapping`, `packaging` | ignored — the DSS library does not build the signature here |
| `signing.dss.signature.xml_*`, `cms_*` | ignored — this release signs PDFs only |
| `signing.one_time_signing.*`, `signing.certification.*` | ignored — no certificate issuance |
| `signing.authorization.*` | ignored — SAD keys are held by ADSS/RAS in this design |
| `signing.match-subject-dn`, `authorization_text` | ignored |
| `csc-config.registered-clients[]` | **honoured** |
| `csc-config.csc-v1-info.*`, `cache-expiry` | bound; the CSC endpoints themselves are not implemented yet |
| `spring.datasource`, `spring.jpa`, `spring.hazelcast` | not needed — this service is stateless |

---

## Precedence

Every signing setting resolves through four layers, most specific last:

```
signing.dss.signature.*                     (defaults)
        ↓  overridden by
csc-config.registered-clients[].overrides   (the calling application)
        ↓  overridden by
signing.signers.<id>.overrides              (the identity)
        ↓  overridden by
the request — only where the layers above allow it
```

The last step is what makes this safe to expose to several applications: a client
that may not repaint an organisation seal has `allow-request-appearance: false`,
and a `signature_appearance` in its request is refused with `1107` rather than
quietly ignored.

---

## `signing` — the signing platform

| Key | Default | Notes |
|---|---|---|
| `gateway.url` | `http://localhost:8777/adss/signing/hdsi` | Use the **hdsi** interface; remote authorised signing needs it. On an ADSS host this really is `localhost`. |
| `gateway.client_id` | `Orchestrator-Signing` | ADSS originator id. |
| `gateway.pdf_profile_id` | — | Default signing profile; a signer entry may override it. |
| `gateway.request_mode` | `HTTP` | `HTTP` or `DSS`. Remote authorised signing requires `HTTP`. |
| `gateway.timeout_ms` / `retries` | `120000` / `1` | Per ADSS call. |
| `gateway.tls_protocol` | — | e.g. `TLSv1.2`. |
| `gateway.proxy.host` / `port` | — | Outbound proxy; ignored when the host is empty. |
| `gateway.status_polling.interval_ms` | `3000` | How often a pending transaction is polled. |
| `gateway.status_polling.max_attempts` | `60` | `interval × attempts` is how long a signer has to approve. Default 3 minutes. |
| `verification.url` / `profile_id` / `client_id` | — | Required for LT/LTA. |
| `ras.keystore_path` / `keystore_password` | — | Client certificate presented to ADSS and RAS. |
| `truststore_path` / `truststore_password` | — | Trust for the ADSS server certificates. JKS or PKCS12. |
| `dss.tsa.url` / `policy_id` | — | Required for LT/LTA. |
| `default_credential_strategy` | `LATEST` | See below. |
| `debug-mode` | `false` | Turns on verbose SDK HTTP logging. Never in production. |

> `status_polling` is the first thing to tune in production. A signing call holds
> a request thread while it waits, so the budget must stay comfortably below the
> caller's own HTTP timeout, and `limits.max-concurrent-signing-requests` bounds
> how many may wait at once.

### `default_credential_strategy`

What happens when neither the signer entry nor the request names a credential:

* `NONE` — refuse the request with `1122`. Use when every signer must be pinned.
* `LATEST` — send no certificate alias and let the ADSS signing profile select
  the signer's current certificate. This is the reference default.

A credential named in the request is only accepted when the signer entry leaves
`certificate-alias` and `credential-id` unset; otherwise it must match, or the
request is refused with `1029`.

## `signing.dss.signature` — defaults

| Key | Default | Notes |
|---|---|---|
| `hash_algorithm` | `SHA256` | `SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, `SHA3-224/256/384/512`. |
| `dictionary_size` | `12000` | Raise for long certificate chains or LTV data. |
| `compute_hash` | `true` | Ask ADSS to compute the final hash at signing time. |
| `local_hash` | `false` | Hash the PDF here and send only the digest. Use when documents must not leave the network. |
| `signature_level` | `PAdES_BASELINE_B` | ETSI spelling; mapped onto the SDK's PAdES types — see below. |
| `signature_field_name` | `Signature1` | |
| `signing_page` | `1` | Used when no appearance box says otherwise. |
| `container_type` | `NONE` | `NONE`, `ASiC-S`, `ASiC-E`. |
| `data_to_be_displayed` | *(a prompt)* | Shown to a natural person on their authorisation device. |

### `signature_level`

The SDK exposes three upgrade types, so the configured ETSI level maps like this:

| Configured | Sent to ADSS | Needs verification + TSA |
|---|---|---|
| `PAdES_BASELINE_B`, `PAdES_BASELINE_T`, `PKCS7_B`, `PKCS7_T` | *(nothing — the ADSS signing profile produces the level)* | no |
| `PAdES_BASELINE_LT`, `PKCS7_LT` | `PAdES-LT` | yes |
| `PAdES_BASELINE_LTA`, `PKCS7_LTA` | `PAdES-B-LTA` | yes |
| `PAdES_LTV` | `PAdES-LTV` | yes |
| anything else | refused at start-up with `1120` | — |

## `signing.limits`

| Key | Default |
|---|---|
| `max-files-per-request` | `20` |
| `max-file-size-bytes` | `26214400` (25 MB) |
| `max-total-request-bytes` | `104857600` (100 MB) |
| `max-concurrent-signing-requests` | `8` |

Raise `spring.servlet.multipart.max-file-size` / `max-request-size` alongside
them — Tomcat rejects an oversized upload before this service sees it.

## `signing.signers.<signer_id>`

The identity a signature is created for. The key is the `signer_id` callers send;
wrap it in brackets if it contains a dot: `"[john.doe]"`.

| Key | Applies to | Notes |
|---|---|---|
| `enabled` | both | `false` → `1103`. |
| `type` | both | `ESEAL` or `NATURAL_PERSON`. |
| `display-name` | both | Also the fallback for the appearance's "signed by". |
| `profile-id` | both | Falls back to `signing.gateway.pdf_profile_id`. |
| `certificate-alias` | e-seal | ADSS certificate alias. |
| `credential-id` | natural person | CSC credential id; used as the alias when no alias is set. |
| `user-id` | natural person | ADSS/RAS user id. Defaults to the signer key. |
| `credential-password` | e-seal | Static credential password for unattended sealing. Put it in `orchestrator.env`. |
| `require-pin` | natural person | `true` (default) rejects a request without `pin` as `1105`. |
| `overrides` | both | See below. |

> Never give a natural person a `credential-password`. The PIN arrives with the
> request, is used once, and is never written to configuration, to the audit
> trail or to the logs.

### Overrides

Available under both `registered-clients[].overrides` and
`signers.<id>.overrides`. An unset key means "inherit".

| Key | Effect |
|---|---|
| `hash-algorithm`, `signature-level`, `dictionary-size`, `signature-field-name`, `signing-page`, `local-hash`, `compute-hash`, `container-type`, `data-to-be-displayed` | As in the defaults. |
| `appearance-template` | Which template this client or signer uses. |
| `signed-by`, `signer-role`, `signing-reason`, `signing-location`, `contact-info` | Fixed appearance values. |
| `allow-request-appearance` | May the request change appearance values? Default `true`. |
| `allow-request-appearance-template` | May the request pick another template? Default `true`. |
| `allow-request-container-type` | May the request choose the container? Default `true`. |

---

## Appearances

Two sources, merged. Configuration wins on a clash.

### 1. In `orchestrator.yml` (the reference shape)

```yaml
signing:
  dss:
    signature:
      appearance:
        enabled: true          # false = sign, but draw nothing
        use_default: true      # fall back to the first enabled template
        store-path: /etc/twokeyok/orchestrator/appearances
        appearances:
          - template_id: eseal_signature_appearance
            enabled: true
            signature_text_position: RIGHT     # TOP | BOTTOM | LEFT | RIGHT
            signed_by:    { include_label: false, label: "Sealed By: ", value: "Ministry" }
            signing_date: { include_label: true,  label: "Date: ", value: "yyyy.MM.dd HH:mm:ss ZZ" }
            reason:       { include_label: true,  label: "Reason: ", value: "Officially sealed" }
            text_font:
              name: Helvetica
              size: 6
              color: { r: 0, g: 0, b: 0, a: 1.0 }
            text_background_color: { r: 255, g: 255, b: 255, a: 0.5 }
            signature_field: { page_no: 1, x: 10, y: 650, width: 240, height: 90 }
            company_logo: { value: "images/company-seal.png" }
```

* Field names are the same vocabulary as the `signature_appearance` JSON a caller
  may send, so what is configured and what is requested line up.
* `signing_date.value` is a date **pattern**, not a date.
* `company_logo.value` is a **file path** here (resolved against `store-path`,
  read once at start-up); in a request it is Base64. A path that cannot be read
  is logged as an ERROR and the signature is produced without the image.
* Text is laid out automatically: the configured lines are stacked in reading
  order and the image sits above, below or beside them per
  `signature_text_position`.
* `signer_role` is accepted but never drawn — the ADSS appearance document has no
  role field, so the value becomes the signature's signer role instead.

### 2. JSON files in `store-path`

For pixel-exact placement, a template may instead be a JSON file carrying a box
per field and embedded Base64 images. Same field keys, plus `position` on each
field and an explicit `width`/`height`. The two templates bundled in the jar are
in this form and are used when neither source yields anything, so a fresh install
still answers `appearances/list`.

---

## `csc-config` — who may call

```yaml
csc-config:
  require-authentication: true
  registered-clients:
    - client-id: hr_portal
      secret-hash: ${HR_PORTAL_SECRET_HASH}   # preferred
      # client-secret: ENC(...)               # reference form, also accepted
      authorities: [ROLE_CLIENT_CREDENTIALS]
      default-signer-id: ministry_eseal
      allowed-signer-ids: [ministry_eseal]
      overrides:
        allow-request-appearance: false
  bearer:
    enabled: true
    issuer: https://iam.internal.example/realms/twokeyok
    jwks-uri: https://iam.internal.example/realms/twokeyok/protocol/openid-connect/certs
    audiences: [twokeyok-orchestrator]
    signer-id-claim: preferred_username
    credential-id-claim: credential_id
    client-id-claim: azp
```

`secret-hash` is preferred over `client-secret`: a BCrypt hash stays useless to
anyone who reads the file, whereas `ENC(...)` is reversible to whoever holds the
Jasypt password. Generate one with:

```bash
java -jar twokeyok-orchestrator.jar --hash-secret '<secret>'
```

Bearer tokens accept RS/PS/ES algorithms only. Symmetric (`HS*`) tokens are
refused — a shared secret is not an adequate basis for authorising a signature.

---

## Preflight

Before the first signing attempt on a new host:

```bash
java -jar /opt/twokeyok/orchestrator/twokeyok-orchestrator.jar --check-adss
```

It reports reachability of the gateway, verification, TSA, OCSP and RAS
endpoints, whether the keystore and truststore exist and are readable, and the
effective signature settings. It opens TCP connections and stats files only — it
never signs and never sends a credential.
