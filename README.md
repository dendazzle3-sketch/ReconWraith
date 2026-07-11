# ReconWraith — Usage Guide

ReconWraith is a single-file, dependency-light, automated reconnaissance tool
for Linux. It chains together WHOIS, DNS enumeration, subdomain discovery,
HTTP header/technology fingerprinting, and port scanning into one command,
then writes a clean `.txt` and/or `.json` report.

> **Use only against systems you own or have explicit written authorization to test.**
> The tool prompts for an authorization confirmation every run unless you pass `-y`.

---

## 1. Requirements

- Linux (tested on Ubuntu/Debian; works on most distros)
- Python 3.8+
- Internet access (for subdomain lookups via crt.sh and live HTTP checks)

### Optional but recommended system tools

ReconWraith auto-detects these and uses them if present; otherwise it falls
back to a built-in pure-Python equivalent.

| Tool | Used for | Install (Debian/Ubuntu) |
|------|----------|--------------------------|
| `nmap` | Service/version-accurate port scanning | `sudo apt install nmap` |
| `whois` | WHOIS registration lookup | `sudo apt install whois` |
| `dig`   | Full DNS record enumeration | `sudo apt install dnsutils` |

Install all three at once:

```bash
sudo apt update && sudo apt install -y nmap whois dnsutils
```

---

## 2. Installation

```bash
# 1. Copy reconwraith.py to a folder of your choice
mkdir -p ~/tools/reconwraith
cp reconwraith.py ~/tools/reconwraith/
cd ~/tools/reconwraith

# 2. Make it executable
chmod +x reconwraith.py

# 3. (Optional) Put it on your PATH so you can run it from anywhere
sudo cp reconwraith.py /usr/local/bin/reconwraith
sudo chmod +x /usr/local/bin/reconwraith
```

After step 3 you can simply type `reconwraith` from any directory.

---

## 3. Basic Usage

```bash
python3 reconwraith.py <target>
```

or, if installed to PATH:

```bash
reconwraith <target>
```

`<target>` can be a domain (`example.com`) or an IP address (`10.0.0.15`).

On every run you'll be asked to confirm authorization:

```
Type 'yes' to confirm you are authorized to scan 'example.com':
```

---

## 4. Command Reference

```
usage: reconwraith [-h] [-o OUTPUT] [--format {txt,json,both}] [--skip-whois]
                    [--skip-dns] [--skip-ports] [--skip-subdomains]
                    [--skip-http] [--ports PORTS] [--wordlist WORDLIST]
                    [--full] [-y] [-v]
                    target
```

| Flag | Description |
|------|-------------|
| `target` | Domain or IP address to scan (required, positional) |
| `-o`, `--output` | Output file prefix. Default: `reconwraith_<target>_<timestamp>` |
| `--format {txt,json,both}` | Report format to write. Default: `both` |
| `--skip-whois` | Skip the WHOIS module |
| `--skip-dns` | Skip the DNS enumeration module |
| `--skip-ports` | Skip the port scanning module |
| `--skip-subdomains` | Skip subdomain enumeration (crt.sh + brute force) |
| `--skip-http` | Skip HTTP header grabbing + tech fingerprinting |
| `--ports 22,80,443` | Scan a custom, comma-separated port list instead of the default top-20 |
| `--wordlist FILE` | Use your own subdomain wordlist instead of the built-in list |
| `--full` | Also run extra modules (robots.txt / sitemap.xml discovery) |
| `-y`, `--yes` | Skip the interactive authorization prompt (for scripts/CI — only use on pre-approved targets) |
| `-v`, `--version` | Print the tool version and exit |
| `-h`, `--help` | Show help text |

---

## 5. Example Commands

**Full default scan (WHOIS, DNS, HTTP, ports, subdomains):**
```bash
python3 reconwraith.py example.com
```

**Scan an internal IP, skip WHOIS/subdomains (not applicable to IPs anyway):**
```bash
python3 reconwraith.py 10.0.0.15 --skip-whois
```

**Only do a quick port scan against specific ports:**
```bash
python3 reconwraith.py example.com --skip-whois --skip-dns --skip-subdomains --skip-http --ports 21,22,80,443,8080
```

**Full recon, including robots.txt/sitemap discovery, JSON-only report, custom filename:**
```bash
python3 reconwraith.py example.com --full --format json -o client_acme_scan
```

**Non-interactive run for automation/CI (pre-authorized target only):**
```bash
python3 reconwraith.py example.com -y --format both
```

**Subdomain enumeration with your own wordlist:**
```bash
python3 reconwraith.py example.com --skip-ports --skip-http --wordlist my_subs.txt
```

---

## 6. Understanding the Report

Every scan produces one or both of:

- `reconwraith_<target>_<timestamp>.txt` — human-readable, section-by-section report
- `reconwraith_<target>_<timestamp>.json` — machine-readable, same data, for feeding into other tools/scripts

Report sections:

1. **TARGET / RESOLVED_IP** — the input target and the IP it resolved to
2. **WHOIS** — domain registration data (registrar, dates, name servers)
3. **DNS** — A, AAAA, MX, NS, TXT, SOA, CNAME records
4. **HTTP** — status code + response headers for ports 80 and 443
5. **TECH_FINGERPRINT** — `Server` / `X-Powered-By` header values, when present
6. **PORT_SCAN** — open ports and detected services (nmap output if available, otherwise built-in scanner results)
7. **SUBDOMAINS** — live subdomains discovered via crt.sh certificate transparency logs and brute force, with resolved IPs
8. **ROBOTS_SITEMAP** *(only with `--full`)* — contents of `robots.txt` / `sitemap.xml` if reachable

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `whois binary not found` in report | `sudo apt install whois` |
| DNS section only shows an `A` record | `sudo apt install dnsutils` (installs `dig`) |
| Port scan is slow | Install `nmap` for a faster/more accurate scan, or narrow the list with `--ports` |
| No subdomains found | Some domains have no CT log entries and don't match the built-in wordlist — try `--wordlist` with a larger list (e.g., SecLists) |
| `Could not resolve target` | Check spelling/DNS connectivity; confirm the domain is registered and resolvable |

---

## 8. Uninstall

```bash
sudo rm -f /usr/local/bin/reconwraith
rm -rf ~/tools/reconwraith
```
