# Installing on Linux

Tested on RHEL / Rocky 8–9, Ubuntu 20.04–24.04 and Debian 11–12. Any systemd
distribution with a JDK 17 or 21 package works.

## 1. Requirements

| | |
|---|---|
| CPU / RAM | 2 vCPU, 2 GB (4 GB when signing large PDFs concurrently) |
| Disk | 2 GB for the application, plus room for the audit trail |
| Java | JRE/JDK **17 or 21** on the target host |
| Network | outbound HTTPS to the ADSS Signing / Verification / TSA services, and to the IAM JWKS endpoint if bearer tokens are enabled |
| Ports | inbound 443 (or whatever `ORCHESTRATOR_PORT` says) |

```bash
# RHEL / Rocky
sudo dnf install -y java-21-openjdk-headless

# Debian / Ubuntu
sudo apt-get install -y openjdk-21-jre-headless
```

## 2. Build the artefact

The build happens on a workstation or a CI runner that holds the ADSS Client SDK
licence — not necessarily on the target server. It needs **Maven 3.9+**.

```bash
cd JAVAsdk/twokeyok-orchestrator
./deploy/install-adss-sdk.sh          # installs adss_client_api.jar into ~/.m2
mvn -B clean package
```

Ship `target/twokeyok-orchestrator.jar` together with the `config/` and `deploy/`
directories to the server.

## 3. Install

```bash
sudo ./deploy/install.sh
```

The installer:

* creates the `twokeyok` system account (no login shell);
* lays out `/opt/twokeyok/orchestrator`, `/etc/twokeyok/orchestrator{,/appearances,/tls}`
  and `/var/log/twokeyok-orchestrator`;
* installs the jar, the configuration, the appearance templates, the logrotate
  policy and the systemd unit, and enables the service;
* **never overwrites an existing configuration** — a changed packaged file is
  dropped next to it as `*.new` so you can diff and merge.

Re-run it to upgrade: it stops the service, replaces the jar and the unit, and
starts it again.

## 4. Configure

### 4.1 TLS material

```bash
sudo cp server.p12                 /etc/twokeyok/orchestrator/tls/
sudo cp orchestrator-client.pfx    /etc/twokeyok/orchestrator/tls/
sudo cp adss-truststore.p12        /etc/twokeyok/orchestrator/tls/
sudo chown twokeyok:twokeyok /etc/twokeyok/orchestrator/tls/*
sudo chmod 0640 /etc/twokeyok/orchestrator/tls/*
```

* `server.p12` — the certificate this service presents to business applications.
* `orchestrator-client.pfx` — the client certificate ADSS expects from it.
* `adss-truststore.p12` — trust for the ADSS server certificate or its CA.

Behind a TLS-terminating reverse proxy, set `ORCHESTRATOR_TLS_ENABLED=false` and
bind to a loopback port instead.

### 4.2 Secrets

```bash
# One hash per registered business application.
java -jar /opt/twokeyok/orchestrator/twokeyok-orchestrator.jar --hash-secret 'hr-portal-secret'
```

Paste the output into `/etc/twokeyok/orchestrator/orchestrator.env`:

```ini
HR_PORTAL_SECRET_HASH=$2a$12$....
ORCHESTRATOR_TLS_KEYSTORE_PASSWORD=...
ADSS_CLIENT_PFX_PASSWORD=...
ADSS_TRUSTSTORE_PASSWORD=...
MINISTRY_ESEAL_PASSWORD=...
```

```bash
sudo chown root:twokeyok /etc/twokeyok/orchestrator/orchestrator.env
sudo chmod 0640 /etc/twokeyok/orchestrator/orchestrator.env
```

### 4.3 ADSS endpoints, clients and signers

Edit `/etc/twokeyok/orchestrator/orchestrator.yml` — every key is documented in
[CONFIGURATION.md](CONFIGURATION.md). At minimum:

* `orchestrator.adss.signing-url` — the **hdsi** endpoint of your ADSS server;
* one entry under `orchestrator.security.clients`;
* one entry under `orchestrator.signers` per e-seal and per natural person.

## 5. Start and verify

```bash
sudo systemctl start twokeyok-orchestrator
systemctl status twokeyok-orchestrator
sudo journalctl -u twokeyok-orchestrator -f
```

A healthy start-up logs the loaded clients, signers and appearance templates.

```bash
# Liveness (no credentials needed)
curl -sk https://localhost/orchestrator/actuator/health

# Appearance catalogue
curl -sk -u 'hr_portal:hr-portal-secret' \
  https://localhost/orchestrator/service/signing/appearances/list

# End-to-end e-seal
curl -sk -u 'hr_portal:hr-portal-secret' \
  -F 'input_files=@/tmp/test.pdf' -F 'signer_id=ministry_eseal' \
  -o /tmp/test-signed.pdf \
  https://localhost/orchestrator/service/sign
```

Confirm the signature in the produced PDF, and confirm the audit line:

```bash
sudo tail -n 5 /var/log/twokeyok-orchestrator/audit.log
```

## 6. Firewall

```bash
# firewalld
sudo firewall-cmd --permanent --add-port=443/tcp && sudo firewall-cmd --reload

# ufw
sudo ufw allow 443/tcp
```

## 7. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Permission denied` binding port 443 | The unit grants `CAP_NET_BIND_SERVICE`; check it was installed with `systemctl cat twokeyok-orchestrator`. |
| Start-up fails on `jwks-uri is not configured` | `bearer.enabled: true` without `jwks-uri`. Set it, or disable bearer authentication. |
| Every call returns `1009` | The secret does not match the hash. Re-run `--hash-secret` and copy the whole `$2a$…` string, unquoted. |
| Every call returns `1114` | ADSS unreachable: check `signing-url`, the truststore and any proxy settings. |
| `1115` with an ADSS message | ADSS rejected the request — usually a wrong `profile-id`, an unknown certificate alias, or the client certificate not being authorised on that profile. |
| `1112` on natural-person signing | The signer did not approve in time. Raise `adss.status-polling.max-attempts` and the caller's own HTTP timeout together. |
| Service cannot read its config under SELinux | `sudo semanage fcontext -a -t etc_t '/etc/twokeyok/orchestrator(/.*)?' && sudo restorecon -R /etc/twokeyok/orchestrator` |

## 8. Uninstall

```bash
sudo ./deploy/uninstall.sh            # keeps configuration, logs and the account
sudo ./deploy/uninstall.sh --purge    # removes them too, after a typed confirmation
```

The audit trail is signing evidence — take a copy before purging.
