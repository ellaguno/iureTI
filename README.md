[Leer en español](README.es.md)

<p align="center">
  <h1 align="center">iureTI Discovery</h1>
  <p align="center">Find every PC, server, switch, printer and access point on your network and send them to the Iurefficient inventory, classified and ready to review.</p>
  <p align="center">
    <a href="https://github.com/ellaguno/iureTI/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/ellaguno/iureTI"></a>
    <a href="https://github.com/ellaguno/iureTI/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/ellaguno/iureTI/total"></a>
    <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/ellaguno/iureTI"></a>
    <img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20(amd64%20%7C%20arm64)-informational">
    <a href="https://github.com/ellaguno/iureTI/pkgs/container/iureti"><img alt="Docker image" src="https://img.shields.io/badge/docker-ghcr.io%2Fellaguno%2Fiureti-blue?logo=docker&logoColor=white"></a>
    <a href="https://github.com/ellaguno/iureTI/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/ellaguno/iureTI/actions/workflows/ci.yml/badge.svg"></a>
  </p>
  <p align="center"><b><a href="#install-a-probe-service">Install on Linux (Debian · Ubuntu · Raspberry Pi OS · Docker)</a></b> · <a href="https://github.com/ellaguno/iureTI/releases/latest">Latest release</a></p>
</p>

<p align="center">
  <img src="docs/media/hero-es.gif" width="860" alt="A scan of two networks in progress in the iureTI Discovery web interface, ending on the list of classified assets">
</p>

> The web interface is currently in Spanish only, so the screenshots are in Spanish. The documentation in
> [docs/](docs/README.md) is in Spanish too.

> **Use this tool only on networks you are expressly authorized to scan.**

## Why iureTI Discovery

- **An inventory that builds itself.** It sweeps your ranges and identifies each device from what it already
  announces (SNMP, mDNS, UPnP, NetBIOS, its own web page, the MAC vendor), instead of someone filling in a
  spreadsheet by hand.
- **Classified, not just listed.** Each asset gets a type (PC, laptop, server, switch, firewall, printer,
  access point, UPS, NAS…), a confidence score and the reasons behind it.
- **You stay in control.** The probe sends everything it sees to the **Discovered** tray of the Iurefficient
  inventory; approving, linking to existing assets or ignoring happens there.
- **Read-only and local.** Read-only SNMP credentials, a web interface that listens only on `127.0.0.1`, and
  credentials that never leave the probe.
- **Runs anywhere Linux runs.** A `.deb` with its own Python for amd64 and arm64 (a Raspberry Pi is enough),
  or a Docker image.

## Screenshots

<table>
  <tr>
    <td width="50%"><img src="docs/media/scan-es.png" alt="Scan tab: ranges, the probe's networks, progress and history"><br><sub>Pick the ranges (or click the probe's own networks) and follow the scan phase by phase.</sub></td>
    <td width="50%"><img src="docs/media/assets-es.png" alt="Asset list with type, confidence, vendor, model, serial, MAC, ports and Iurefficient status"><br><sub>The classified inventory, with its status in Iurefficient after sending it.</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/media/detail-es.png" alt="Asset detail with the product identified online, specs, SNMP data and classification reasons"><br><sub>Asset detail: product identified online (optional), SNMP data and why it was classified that way.</sub></td>
    <td width="50%"><img src="docs/media/settings-es.png" alt="Settings in dark mode: probe, Iurefficient URL and token, scheduled scans, SNMP credentials"><br><sub>Settings (dark mode): Iurefficient connection, scheduled scans and read-only SNMP credentials.</sub></td>
  </tr>
</table>

<sub>All data in the screenshots and the GIF is fictional.</sub>

## Features

- **Discovery:** ping/TCP sweep and ARP, open ports, SNMP v2c/v3 (read-only, each credential can be limited
  to its subnets), mDNS, UPnP/SSDP, NetBIOS, the device's own web page and the IEEE OUI vendor database.
- **Classification and deduplication:** device type with confidence and reasons; the same device seen by
  several sources (serial, MAC, hostname) becomes one asset.
- **Local web interface** (`iureti-discovery serve`, `http://127.0.0.1:8765/`) and a **CLI** for scanning,
  exporting and sending.
- **Iurefficient integration:** send to the inventory's ingest API, or export a CSV for
  *Inventario › Importar* or JSON with the API contract.
- **Service mode** (`serve --agent`, what the package installs): heartbeat with Iurefficient, remote
  configuration, scheduled scans within a time window, automatic sending after each scan.
- **Online product identification (optional, off by default):** an AI model with web search (OpenRouter or
  Anthropic) finds the commercial name, description, specs and photo of each product model.

## Install a probe (service)

Debian / Ubuntu / Raspberry Pi OS, amd64 or arm64:

```bash
curl -fsSL https://github.com/ellaguno/iureTI/releases/latest/download/install.sh | sudo sh -s -- \
  --url https://cliente.iurefficient.com --token iurprobe_xxxxx --site "Matriz"
```

Or with Docker (host network): `docker run -d --name iureti --network host --restart unless-stopped -v iureti-data:/data ghcr.io/ellaguno/iureti:latest`.

`install.sh` downloads the `.deb` from the latest release, **verifies its SHA-256**, installs it with `apt`
and enrolls the probe when `--url`/`--token` are given; running it again updates. Details (Docker Compose
next to an on-premise Iurefficient, updates, where to place the probe) in
[docs/07](docs/07-distribucion.md).

The probe has to be **inside** the network it discovers, and it only makes outgoing connections. It does
not run on Windows or WSL2 (no access to the office network); for Windows-only sites use a Raspberry Pi
or a small Linux VM.

## Quick start (development)

Requires Linux, Python 3.11+ and [uv](https://docs.astral.sh/uv/). Does not require root.

```bash
git clone https://github.com/ellaguno/iureTI.git && cd iureTI
uv sync
uv run iureti-discovery oui-update          # MAC vendor database (IEEE)
uv run iureti-discovery serve --open        # web interface at http://127.0.0.1:8765/
```

From the terminal:

```bash
uv run iureti-discovery networks                          # this machine's networks
uv run iureti-discovery scan 192.168.1.0/24 --community public
uv run iureti-discovery export --format csv -o activos.csv # for Inventario › Importar
export OPENROUTER_API_KEY=sk-or-...                        # or ANTHROPIC_API_KEY with --provider anthropic
uv run iureti-discovery enrich --enable                     # identify products online (AI + web search)
uv run iureti-discovery enrich --model deepseek/deepseek-v4-flash   # change model
uv run iureti-discovery sync                               # send to Iurefficient (URL and token in the settings)
```

The interface listens only on `127.0.0.1`. On a server without a desktop, use an SSH tunnel
(`ssh -L 8765:127.0.0.1:8765 server`) instead of exposing it on the network.

## Security and privacy

Summary of [docs/05 — Seguridad y operación](docs/05-seguridad.md):

- **The web interface listens only on `127.0.0.1:8765`.** The API checks the `Host` header (DNS rebinding),
  requires its own header on every request (CSRF) and sends a strict CSP. If you expose it with
  `--host 0.0.0.0`, a mandatory interface token is generated; an SSH tunnel is still the recommended way.
- **What goes to Iurefficient, and when:** only if you configure its URL and probe token. The discovered
  assets (type, hostname, IPs, MACs, vendor, model, serial, OS, ports, location, SNMP description and
  contact, classification reasons and the product summary) are sent when you press *Enviar a iurefficient*,
  run `sync`, or after each scheduled scan with automatic sending on. In service mode the probe also sends a
  heartbeat every 5 minutes by default (probe name, version, site, hostname, OS, scan and sync status, its
  networks). SNMP credentials and AI keys are never sent.
- **Ranges are clamped:** ranges must fall within private networks plus the probe's own (or the list you
  set), so a compromised Iurefficient cannot make the probe scan the internet.
- **Online identification is off by default.** When you enable it, only **product** data goes to OpenRouter
  (and the chosen model's provider; the probe asks for providers that do not store or train on the data) or
  to Anthropic: brand, model, OS/firmware, what the device announces via SNMP/UPnP/mDNS/web, and its open
  ports. Never IPs, MACs, hostnames, serial numbers, locations or user-given names; they are also scrubbed
  from every text field before sending.
- **Other connections:** the IEEE OUI download when you request it. No telemetry.
- The service runs as the unprivileged `iureti` user under systemd hardening; the local database has `600`
  permissions. Releases carry build provenance attestations (`gh attestation verify …`).

## Documentation

In Spanish:

- [Vision and feasibility](docs/01-vision-factibilidad.md)
- [Discovery sources](docs/02-fuentes-descubrimiento.md)
- [Architecture](docs/03-arquitectura.md)
- [Ingest API contract](docs/04-api-ingesta.md)
- [Security and operation](docs/05-seguridad.md)
- [Roadmap](docs/06-roadmap.md)
- [Distribution and installation](docs/07-distribucion.md)
- [Integration with Iurefficient](docs/08-integracion-iurefficient.md)

## Part of the Iurefficient suite

| App | What it does |
|---|---|
| [IureTranscribe](https://github.com/ellaguno/iuretranscribe) | Local Whisper transcription, live recording with who-spoke, summaries and minutes. |
| [IureEditor](https://github.com/ellaguno/iureditor) | WYSIWYG Markdown editor with Mermaid, LaTeX and PDF/DOCX export. |
| [IureDav](https://github.com/ellaguno/iuredav) | Mount a WebDAV server (or Iurefficient) as a drive. |
| [IureOCR](https://github.com/ellaguno/iureocr) | Local OCR that turns scans into searchable PDFs. |
| **iureTI** | IT asset discovery probe for the Iurefficient inventory. |

## Contributing

Issues and pull requests are welcome. Good first contributions: bug reports with the service log
(`journalctl -u iureti-discovery`) or the command output, better classification rules for devices that end
up with the wrong type, translations (the interface is Spanish-only today) and documentation. See
[Development](#development) to run the tests.

Only run the probe, and any test you do with it, on networks you are authorized to scan.

## Development

```bash
uv run pytest
```

<details>
<summary>Build, releases and regenerating the README media</summary>

- Build the `.deb` locally: `docker run --rm -v "$PWD":/src -w /src debian:12 bash packaging/build-deb.sh` (→ `dist/`).
- Releases: a `vX.Y.Z` tag runs `.github/workflows/release.yml`: tests → `.deb` for amd64 and arm64 (built on
  `debian:12`, tested on clean Ubuntu 22.04/24.04) → multi-arch image on `ghcr.io/ellaguno/iureti` → GitHub
  release with the `.deb` files, their `.sha256`, `SHA256SUMS` and `install.sh`. Provenance attestations for
  the `.deb` and the image.
- Where it stores things: `~/.local/share/iureti-discovery/iureti.db` and `~/.cache/iureti-discovery/` when run
  by hand; `/var/lib/iureti/` and `/var/cache/iureti/` as a service; `/data` in Docker.
- README GIF and screenshots: `scripts/readme-media/run.sh` (real web interface, fictional data, no network
  scan). See [scripts/readme-media/README.md](scripts/readme-media/README.md).

</details>

## License

[Apache License 2.0](LICENSE). See also [NOTICE](NOTICE): the license grants no rights to the names
«iureTI» and «iurefficient».
