#!/usr/bin/env python3
"""
ReconWraith - Automated Reconnaissance Tool for Linux
=======================================================
A modular, automated OSINT & network reconnaissance tool intended for
authorized security assessments, bug bounty engagements, and CTF practice
against targets you own or have explicit written permission to test.

Author : ReconWraith Project
License: MIT
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

# --------------------------------------------------------------------------- #
#  Globals / constants
# --------------------------------------------------------------------------- #

VERSION = "1.0.0"
BANNER = r"""
 ____                     __        __           _ _   _
|  _ \ ___  ___ ___  _ __ \ \      / / __ __ _ (_) |_| |__
| |_) / _ \/ __/ _ \| '_ \ \ \ /\ / / '__/ _` || | __| '_ \
|  _ <  __/ (_| (_) | | | | \ V  V /| | | (_| || | |_| | | |
|_| \_\___|\___\___/|_| |_|  \_/\_/ |_|  \__,_|/ |\__|_| |_|
                                             |__/
        Automated Reconnaissance Tool  |  v{version}
""".format(version=VERSION)

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

COMMON_SUBS = ["www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
               "cpanel", "whm", "autodiscover", "autoconfig", "m", "shop",
               "blog", "dev", "test", "staging", "api", "vpn", "remote",
               "portal", "admin", "cdn", "cloud", "app", "secure", "beta"]

DEFAULT_TIMEOUT = 4

# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #

class Colors:
    HEADER = "\033[95m"
    OK = "\033[92m"
    INFO = "\033[94m"
    WARN = "\033[93m"
    FAIL = "\033[91m"
    END = "\033[0m"
    BOLD = "\033[1m"


def log(msg, level="INFO"):
    color = {
        "INFO": Colors.INFO,
        "OK": Colors.OK,
        "WARN": Colors.WARN,
        "FAIL": Colors.FAIL,
    }.get(level, Colors.INFO)
    stamp = datetime.now().strftime("%H:%M:%S")
    print(f"{color}[{stamp}] [{level}]{Colors.END} {msg}")


def which_or_none(binary):
    return shutil.which(binary)


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def run_cmd(cmd, timeout=30):
    """Run a shell command list and return stdout text (or None on failure)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return None


# --------------------------------------------------------------------------- #
#  Recon modules
# --------------------------------------------------------------------------- #

def resolve_target(target):
    """Resolve a domain to its IP address (or confirm an IP)."""
    if is_ip(target):
        return target
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def module_whois(target, results):
    log("Running WHOIS lookup...", "INFO")
    if which_or_none("whois"):
        out = run_cmd(["whois", target], timeout=20)
        results["whois"] = out if out else "No WHOIS data returned."
    else:
        results["whois"] = "whois binary not found on this system (sudo apt install whois)."
    log("WHOIS lookup complete.", "OK")


def module_dns(target, results):
    log("Enumerating DNS records...", "INFO")
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    if which_or_none("dig"):
        for rtype in record_types:
            out = run_cmd(["dig", "+short", target, rtype], timeout=10)
            records[rtype] = out.splitlines() if out else []
    else:
        try:
            records["A"] = [socket.gethostbyname(target)]
        except socket.gaierror:
            records["A"] = []
        results["dns_note"] = "dig not found; limited to basic A record (sudo apt install dnsutils)."
    results["dns"] = records
    log("DNS enumeration complete.", "OK")


def _http_head(host, port, use_ssl, timeout=DEFAULT_TIMEOUT):
    """Grab basic HTTP response headers without external deps."""
    try:
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{host}:{port}/"
        req = urllib.request.Request(url, method="GET",
                                      headers={"User-Agent": "ReconWraith/%s" % VERSION})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx if use_ssl else None) as resp:
            headers = dict(resp.getheaders())
            return {"status": resp.status, "headers": headers}
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, ValueError, OSError) as exc:
        if isinstance(exc, urllib.error.HTTPError):
            return {"status": exc.code, "headers": dict(exc.headers or {})}
        return None


def module_http_headers(target, results):
    log("Grabbing HTTP/HTTPS banners & headers...", "INFO")
    http_info = {}
    for port, use_ssl in [(80, False), (443, True)]:
        info = _http_head(target, port, use_ssl)
        if info:
            http_info[f"port_{port}"] = info
    results["http"] = http_info if http_info else "No HTTP(S) service responded."
    log("HTTP header grab complete.", "OK")


def _scan_port(ip, port, timeout=1.2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                return port, service
    except socket.error:
        pass
    return None


def module_port_scan(ip, results, ports=None, use_nmap_if_available=True):
    ports = ports or COMMON_PORTS
    if use_nmap_if_available and which_or_none("nmap"):
        log("nmap found - running nmap service/version scan...", "INFO")
        port_str = ",".join(str(p) for p in ports)
        out = run_cmd(["nmap", "-sV", "-Pn", "-p", port_str, ip], timeout=120)
        results["port_scan"] = {"engine": "nmap", "raw_output": out or "nmap returned no output."}
        log("nmap scan complete.", "OK")
        return

    log(f"nmap not found - using built-in socket scanner on {len(ports)} ports...", "INFO")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(_scan_port, ip, p) for p in ports]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append({"port": res[0], "service": res[1]})
    open_ports.sort(key=lambda x: x["port"])
    results["port_scan"] = {"engine": "builtin-socket", "open_ports": open_ports}
    log(f"Socket scan complete - {len(open_ports)} open port(s) found.", "OK")


def _check_subdomain(sub, domain):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except socket.gaierror:
        return None


def module_subdomain_enum(domain, results, wordlist_path=None):
    log("Enumerating subdomains (crt.sh + brute force)...", "INFO")
    found = {}

    # --- Certificate Transparency lookup (crt.sh) ---
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "ReconWraith/%s" % VERSION})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            names = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name and not name.startswith("*"):
                        names.add(name)
            for name in names:
                ip = resolve_target(name)
                if ip:
                    found[name] = ip
        log(f"crt.sh returned {len(names)} unique candidate names.", "OK")
    except Exception as exc:
        log(f"crt.sh lookup failed or timed out: {exc}", "WARN")

    # --- Brute force common subdomain list (and/or user wordlist) ---
    wordlist = COMMON_SUBS
    if wordlist_path and os.path.isfile(wordlist_path):
        with open(wordlist_path) as fh:
            wordlist = [line.strip() for line in fh if line.strip()]

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(_check_subdomain, sub, domain) for sub in wordlist]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                found[res[0]] = res[1]

    results["subdomains"] = found
    log(f"Subdomain enumeration complete - {len(found)} live subdomain(s) found.", "OK")


def module_tech_fingerprint(target, results):
    log("Fingerprinting web technologies...", "INFO")
    fingerprint = {}
    http_data = results.get("http", {})
    if isinstance(http_data, dict):
        for port_key, info in http_data.items():
            headers = info.get("headers", {})
            server = headers.get("Server")
            powered_by = headers.get("X-Powered-By")
            if server:
                fingerprint.setdefault(port_key, {})["server"] = server
            if powered_by:
                fingerprint.setdefault(port_key, {})["x_powered_by"] = powered_by
    results["tech_fingerprint"] = fingerprint if fingerprint else "No identifying headers found."
    log("Technology fingerprinting complete.", "OK")


def module_robots_sitemap(target, results):
    log("Checking robots.txt and sitemap.xml...", "INFO")
    findings = {}
    for scheme in ["http", "https"]:
        for path in ["robots.txt", "sitemap.xml"]:
            try:
                url = f"{scheme}://{target}/{path}"
                req = urllib.request.Request(url, headers={"User-Agent": "ReconWraith/%s" % VERSION})
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT,
                                             context=ctx if scheme == "https" else None) as resp:
                    if resp.status == 200:
                        body = resp.read(2000).decode("utf-8", errors="ignore")
                        findings[f"{scheme}_{path}"] = body
            except Exception:
                continue
    results["robots_sitemap"] = findings if findings else "robots.txt / sitemap.xml not accessible."
    log("robots.txt / sitemap.xml check complete.", "OK")


# --------------------------------------------------------------------------- #
#  Report writers
# --------------------------------------------------------------------------- #

def write_json_report(results, out_path):
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2, default=str)


def write_txt_report(results, out_path, target):
    lines = []
    lines.append("=" * 70)
    lines.append(f" ReconWraith Report - Target: {target}")
    lines.append(f" Generated: {datetime.now().isoformat()}")
    lines.append("=" * 70)

    def section(title, content):
        lines.append("\n" + "-" * 70)
        lines.append(f" {title}")
        lines.append("-" * 70)
        if isinstance(content, dict):
            lines.append(json.dumps(content, indent=2, default=str))
        elif isinstance(content, list):
            for item in content:
                lines.append(f"  - {item}")
        else:
            lines.append(str(content))

    for key, value in results.items():
        section(key.upper(), value)

    with open(out_path, "w") as fh:
        fh.write("\n".join(lines))


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #

def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="reconwraith",
        description="ReconWraith - Automated Reconnaissance Tool for authorized security testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Target domain or IP address (e.g. example.com or 10.0.0.5)")
    parser.add_argument("-o", "--output", default=None,
                         help="Output file prefix (default: reconwraith_<target>_<timestamp>)")
    parser.add_argument("--format", choices=["txt", "json", "both"], default="both",
                         help="Report format (default: both)")
    parser.add_argument("--skip-whois", action="store_true", help="Skip WHOIS lookup")
    parser.add_argument("--skip-dns", action="store_true", help="Skip DNS enumeration")
    parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-subdomains", action="store_true", help="Skip subdomain enumeration")
    parser.add_argument("--skip-http", action="store_true", help="Skip HTTP header grabbing")
    parser.add_argument("--ports", default=None,
                         help="Comma-separated custom port list, e.g. 22,80,443")
    parser.add_argument("--wordlist", default=None,
                         help="Path to a custom subdomain wordlist file")
    parser.add_argument("--full", action="store_true",
                         help="Run every module (equivalent to not skipping anything, plus tech-fingerprint & robots)")
    parser.add_argument("-y", "--yes", action="store_true",
                         help="Skip the authorization confirmation prompt (use in automated/CI contexts only)")
    parser.add_argument("-v", "--version", action="version", version=f"ReconWraith {VERSION}")
    return parser


def confirm_authorization(target):
    print(Colors.WARN + Colors.BOLD +
          "\nLEGAL / AUTHORIZATION NOTICE" + Colors.END)
    print(Colors.WARN +
          "Only run ReconWraith against systems you own or are explicitly\n"
          "authorized in writing to test. Unauthorized scanning may be illegal\n"
          f"in your jurisdiction.\n" + Colors.END)
    answer = input(f"Type 'yes' to confirm you are authorized to scan '{target}': ").strip().lower()
    return answer == "yes"


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    print(Colors.HEADER + BANNER + Colors.END)

    if not args.yes:
        if not confirm_authorization(args.target):
            log("Authorization not confirmed. Exiting.", "FAIL")
            sys.exit(1)

    target = args.target
    ip = resolve_target(target)
    if not ip:
        log(f"Could not resolve target '{target}'. Check the hostname/IP and your network connection.", "FAIL")
        sys.exit(1)

    log(f"Target: {target}  |  Resolved IP: {ip}", "INFO")

    results = {
        "target": target,
        "resolved_ip": ip,
        "scan_started": datetime.now().isoformat(),
    }

    if not args.skip_whois:
        module_whois(target, results)
    if not args.skip_dns:
        module_dns(target, results)
    if not args.skip_http:
        module_http_headers(target, results)
        module_tech_fingerprint(target, results)
    if not args.skip_ports:
        custom_ports = None
        if args.ports:
            try:
                custom_ports = [int(p.strip()) for p in args.ports.split(",")]
            except ValueError:
                log("Invalid --ports value; falling back to default port list.", "WARN")
        module_port_scan(ip, results, ports=custom_ports)
    if not args.skip_subdomains and not is_ip(target):
        module_subdomain_enum(target, results, wordlist_path=args.wordlist)
    if args.full:
        module_robots_sitemap(target, results)

    results["scan_finished"] = datetime.now().isoformat()

    prefix = args.output or f"reconwraith_{target.replace('/', '_')}_{int(time.time())}"

    if args.format in ("txt", "both"):
        txt_path = f"{prefix}.txt"
        write_txt_report(results, txt_path, target)
        log(f"Text report saved to {txt_path}", "OK")
    if args.format in ("json", "both"):
        json_path = f"{prefix}.json"
        write_json_report(results, json_path)
        log(f"JSON report saved to {json_path}", "OK")

    log("Scan complete.", "OK")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.FAIL}Interrupted by user. Exiting.{Colors.END}")
        sys.exit(130)
