# API reference

Base URL: `https://<server>:<port>/orchestrator`

The paths, parameter names and error body follow the TwoKeyOk MiddleWare API
guide (<https://api-middle.twokeyok.iq/>). Anything this release adds on top is
marked **(orchestrator extension)**.

## Authentication

Both schemes of the guide are accepted on every endpoint.

| Scheme | Header | Who it identifies |
|---|---|---|
| Client credentials | `Authorization: Basic base64(client_id:client_secret)` | a business application; it must say which signer it acts for |
| Signer access token | `Authorization: Bearer <access-token>` | the signer; the identity comes from the token |

A bearer token is validated against the JWKS of the customer IAM (issuer,
audience, signature and expiry). The signer identity is read from the claim named
in `orchestrator.security.bearer.signer-id-claim`.

A token holder **cannot** sign as someone else: if `signer_id` is present and
differs from the token's signer, the request is rejected with `1104`.

`/orchestrator/actuator/health` is open so a load balancer can probe the service.

---

## POST /service/sign — Signing PDF (PAdES)

`Content-Type: multipart/form-data`

| Parameter | Presence | Description |
|---|---|---|
| `input_files` | mandatory | One or more PDF documents. |
| `signer_id` | conditional | Required with Basic authentication unless the client has a `default-signer-id`. Ignored (and validated) with Bearer. |
| `pin` | conditional | Signer PIN. Required for a natural person whose signer entry has `require-pin: true` and no static credential password. |
| `credential_id` | optional | CSC credential id. Accepted only when the signer entry does not pin one; otherwise it must match. |
| `container_type` | optional | `NONE` (default), `ASiC-S`, `ASiC-E`. See [Containers](#containers). |
| `signature_appearance` | optional | JSON, see below. |
| `hash_algo` | optional | `SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, `SHA3-224`, `SHA3-256`, `SHA3-384`, `SHA3-512`. Overrides the configured digest. Spelling is flexible (`SHA-256`, `sha256`). |
| `hashes`, `compute_hash` | — | Not enabled in this release; a request carrying `hashes` is rejected with `1118`. |

### Response

| Input | Container | Response |
|---|---|---|
| one document | `NONE` | `application/pdf`, the signed document |
| several documents | `NONE` | `application/zip` |
| any | `ASiC-S` / `ASiC-E` | `application/vnd.etsi.asic-{s,e}+zip` |

A `Content-Disposition` header carries the file name. Failures return
`{"error_code": …, "error_description": …}` with the status from the table at the
bottom of this page.

### `signature_appearance`

```json
{
  "template_id": "default_signature_appearance",
  "signed_by":    { "label": "Signed By: ",   "include_label": true, "value": "John Doe" },
  "signer_role":  { "label": "Role: ",        "include_label": true, "value": "Approver" },
  "signing_date": { "label": "Signed Date: ", "include_label": true, "value": "dd MMM yyyy HH:mm:ss zz" },
  "reason":       { "label": "Reason: ",      "include_label": true, "value": "Document is approved" },
  "location":     { "label": "Location: ",    "include_label": true, "value": "Baghdad, Iraq" },
  "contact_info": { "label": "Email: ",       "include_label": true, "value": "info@twokeyok.iq" },
  "signature_field": { "x": 200, "y": 450, "width": 200, "height": 80, "page_no": 1 },
  "company_logo":  { "value": "<base64 image>" },
  "hand_signature": { "value": "<base64 image>" }
}
```

Notes:

* Every member is optional. A missing value falls back to the signer/client
  configuration, then to the template.
* `template_id` picks one of the templates from
  `GET /service/signing/appearances/list`.
* `signature_field` is in PDF points from the bottom-left of the page.
* `hand_signature` is an **orchestrator extension**; the ADSS appearance supports
  it and the guide's example simply does not show it.
* `signer_role` is applied to the signature itself (the ADSS signer role), not to
  the visible appearance box, because the ADSS appearance document has no role
  field.
* `text_font` and `background_color` are accepted but ignored: fonts and colours
  come from the template, so that a customer's signatures look the same whichever
  application produced them. Change them in the template instead.
* Whether a caller may change any of this at all is governed by
  `allow-request-appearance` and `allow-request-appearance-template` — see
  [CONFIGURATION.md](CONFIGURATION.md).

### Containers

`NONE` is the behaviour described in the guide. `ASiC-S` and `ASiC-E` wrap the
signed documents in an ETSI EN 319 162 container with `mimetype` as the first,
uncompressed entry; the signature itself remains the PAdES signature inside each
PDF. `ASiC-S/T` and `ASiC-E/T` need a container-level timestamp token and are
rejected with `1109` rather than silently downgraded.

---

## GET /service/signing/appearances/list — List Signature Appearances

Returns the appearance templates available to the caller.

```json
[
  {
    "template_id": "default_signature_appearance",
    "name": "Default signature appearance",
    "description": "Natural person visible signature…",
    "width": 463,
    "height": 250,
    "signature_field": { "x": 200, "y": 450, "width": 200, "height": 80, "page_no": 1 },
    "fields": {
      "signed_by":    { "include": true, "label": "Signed By", "show_label": true,
                        "position": { "x": 14, "y": 5, "width": 197, "height": 18 } },
      "company_logo": { "include": false, "label": "Company Logo", "show_label": false,
                        "has_image": false,
                        "position": { "x": 274, "y": 80, "width": 180, "height": 163 } }
    }
  }
]
```

Image fields report `has_image` instead of their Base64 payload: a default logo
can be hundreds of kilobytes and nothing in a picker needs it.

---

## Error codes

Body: `{"error_code": <int>, "error_description": "<text>"}`.

### From the reference guide

These are returned for the conditions the orchestrator can determine itself. A
failure raised inside ADSS surfaces as `1115` carrying the ADSS error code and
message, because the orchestrator does not reinterpret the signing platform's
diagnostics.

| Code | HTTP | Meaning |
|---|---|---|
| 1001 | 500 | Internal server error |
| 1002 | 400 | `signer_id` not provided |
| 1003 | 400 | Request exceeds the maximum permitted file size |
| 1005 | 401 | Invalid `client_id` |
| 1009 | 401 | Invalid `client_id` or `client_secret` |
| 1013 | 401 | Invalid or expired token |
| 1026 | 401 | The access token is missing a required claim |
| 1029 | 400 | No signer certificate for that signer / credential |
| 1030 | 400 | No file or hash provided |
| 1031 | 401 | Invalid signer PIN |
| 1034 | 400 | Invalid or corrupted document |

### Orchestrator extensions

| Code | HTTP | Meaning |
|---|---|---|
| 1100 | 400 | Too many input files |
| 1101 | 400 | Input is not a PDF |
| 1102 | 400 | Signer is not configured |
| 1103 | 403 | Signer is disabled |
| 1104 | 403 | This client may not sign as that signer |
| 1105 | 400 | The signer requires a PIN |
| 1106 | 400 | Appearance template not found |
| 1107 | 403 | This client may not override the appearance |
| 1108 | 400 | `signature_appearance` is not valid JSON, or an image is not valid Base64 |
| 1109 | 400 | Container type not supported |
| 1110 | 403 | This client may not choose the container type |
| 1111 | 500 | The signer entry has no `profile-id` |
| 1112 | 504 | The signer did not authorise in time |
| 1113 | 403 | The signer declined |
| 1114 | 502 | ADSS is not reachable |
| 1115 | 502 | ADSS rejected the request |
| 1116 | 503 | Too many concurrent signing requests |
| 1117 | 401 | `Authorization` header missing |
| 1118 | 400 | Signing pre-computed hashes is not enabled |
| 1119 | 400 | Unsupported hash algorithm |
| 1120 | 500 | Configured `signature_level` is not a PDF level this orchestrator supports |
| 1121 | 500 | An appearance image could not be read |
| 1122 | 400 | No credential supplied and `default_credential_strategy` is `NONE` |
