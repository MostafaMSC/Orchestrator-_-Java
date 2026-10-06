# API reference

Base URL: `https://<server>:<port>/orchestrator`

The paths, parameter names and error body follow the TwoKeyOk MiddleWare API
guide (<https://api-middle.twokeyok.iq/>). Anything this release adds on top is
marked **(orchestrator extension)**.

## Authentication

Every endpoint accepts all three schemes. What `Basic` **means** is set by
`signing.basic_auth_type`.

| Scheme | `basic_auth_type` | Header | Who it identifies |
|---|---|---|---|
| Implicit | `implicit` (default) | `Authorization: Basic base64(signer_id:credential_password)` | the signer; no `signer_id` or `pin` field is needed |
| Client credentials | `client_credentials` | `Authorization: Basic base64(client_id:client_secret)` | a business application; it must say which signer it acts for |
| Signer access token | either | `Authorization: Bearer <access-token>` | the signer; the identity comes from the token |

`implicit` is the scheme the deployed Ascertia Orchestrator uses, so a caller
written against that API works here unchanged:

```bash
curl -X POST https://<host>/orchestrator/service/sign \
  -H 'Authorization: Basic base64(signer@example.com:password)' \
  -F 'input_files=@document.pdf' \
  -F 'signature_appearance={"template_id":"my_template"};type=application/json'
```

The Basic password becomes the credential password sent to ADSS. A `pin` field,
if present, takes precedence over it. Because the signer is not named in
configuration, `implicit` normally runs with `signing.dynamic-signer.enabled:
true` so the identity in the header resolves; a signer listed under
`signing.signers` still wins and keeps its configured profile and credential.

Under `client_credentials` the registered clients in `csc-config` are
authenticated instead, and `allowed-signer-ids` applies as usual.

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

## Signature appearance management

The appearance catalogue is managed through the API as well as the configuration
file. `template_id` from any of these is what `/service/sign` accepts in
`signature_appearance`.

| Operation | Method | Path | Success |
|---|---|---|---|
| List | `GET` | `/service/signing/appearances/list` | 200, array |
| Get by id | `GET` | `/service/signing/appearances/{template_id}` | 200 |
| Create | `POST` | `/service/signing/appearances` | **201** |
| Update | `POST` (or `PUT`) | `/service/signing/appearances` | **200** |
| Delete | `DELETE` | `/service/signing/appearances/{template_id}` | 204 |

Create and update are one operation taking the template the caller wants to
exist; the status code distinguishes them.

```bash
curl -u 'client:secret' -X POST https://<host>/orchestrator/service/signing/appearances \
  -H 'Content-Type: application/json' -d '{
    "template_id": "ministry_seal",
    "name": "Ministry e-seal",
    "enabled": true,
    "width": 400, "height": 120,
    "signature_field": { "x": 200, "y": 200, "width": 100, "height": 100, "page_no": 1 },
    "text_font": { "name": "Arial", "size": 12, "color": { "r": 0, "g": 0, "b": 0 } },
    "background_color": { "r": 255, "g": 255, "b": 255, "a": 0.5 },
    "fields": {
      "signed_by":     { "include": true, "label": "Sealed By", "show_label": true },
      "signing_date":  { "include": true, "label": "Date", "show_label": true,
                         "value": "yyyy.MM.dd HH:mm:ss ZZ" },
      "reason":        { "include": true, "label": "Reason", "show_label": true },
      "company_logo":  { "include": true, "image_name": "seal.png",
                         "position": { "x": 300, "y": 20, "width": 90, "height": 90 } }
    }
  }'
```

Then sign with it:

```bash
curl -u 'client:secret' -F 'input_files=@document.pdf' \
  -F 'signature_appearance={"template_id":"ministry_seal"};type=application/json' \
  -o signed.pdf -X POST https://<host>/orchestrator/service/sign
```

### Where templates live, and which can be changed

Managed templates are JSON files in `signing.dss.signature.appearance.store-path`,
one per `template_id` - the API and the directory are the same store, so an
operator can inspect, back up and hand-edit what callers create. Without a
`store-path` the management endpoints return `1126`.

Templates declared in `orchestrator.yml` are listed and usable but **cannot be
changed or deleted through the API** (`1125`): that file belongs to whoever
operates the service, and a write here would be undone at the next restart.

`template_id` must match `[A-Za-z0-9._-]{1,64}`, so it cannot escape the
store directory or collide on a case-insensitive filesystem (`1123`).

### Visible appearances and hash signing

A visible appearance works with `local_hash: true`. ADSS never sees the
document in that mode, so the appearance is rendered from the inline appearance
document the SDK builds - which means **`server_side_id` must not be set**.
With it set, the request only names an ADSS-side appearance that nothing will
draw. The vendor's own PDF signature guide pairs `SetLocalHash(true)` with
`SetSignatureAppearance(...)` for exactly this reason.

`user_info` is accepted and stored for compatibility with the API guide, but
it is never drawn: ADSS's appearance document has no user-info element. The
overridable fields are signed by, reason, location, contact info, company logo
and hand signature. `signer_role` is likewise carried but not drawn - it
becomes the signature's signer role instead.

### Images in an appearance

An image field carries the image as Base64 in its `value`, and `image_name`
is the file name recorded in the appearance document:

```json
"fields": {
  "company_logo": {
    "include": true,
    "image_name": "logo.png",
    "value": "<base64 of the PNG>",
    "position": { "x": 290, "y": 15, "width": 90, "height": 90 }
  }
}
```

`company_logo` and `hand_signature` are the two image fields. A caller can
also supply either per request instead of baking it into the template, which
suits a per-tenant logo:

```bash
-F 'signature_appearance={"template_id":"eseal_v1","company_logo":"<base64>"};type=application/json'
```

Give positions explicitly once a template mixes text and an image: the automatic
layout puts the image on the right and stacks text on the left, but it cannot
know the image's aspect ratio. An image the SDK cannot decode is reported as
`1121`, not as a signing failure.

Both spellings of an image are accepted. The API guide's top-level form:

```json
{ "template_id": "ministry_seal", "company_logo": "<base64>" }
```

is folded into `fields.company_logo`, so it is equivalent to the nested form
and reaches the appearance the same way. Send the nested form when you also want
a position, label or image name; if both are present, the nested value wins.
`hand_signature` behaves identically.
