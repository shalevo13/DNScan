#!/usr/bin/env python3
"""
dns_lab_check.py
Light DNS misconfiguration scanner for the local lab.
Points DNS queries to 127.0.0.1 (your local bind lab).
Requires: dnspython, rich
"""

import dns.resolver, dns.query, dns.zone, dns.exception, dns.name
import random, sys, socket, time
from rich import print
from rich.table import Table

# target: take from argv or default to vulnerable.test
domain = sys.argv[1] if len(sys.argv) > 1 else "vulnerable.test"
nameserver = "127.0.0.1"

# Configure resolver to use our local bind
resolver = dns.resolver.Resolver(configure=False)
resolver.timeout = 3.0
resolver.lifetime = 6.0
resolver.nameservers = [nameserver]

def get_ns(domain):
    try:
        ans = resolver.resolve(domain, 'NS')
        return [str(r.target).rstrip('.') for r in ans]
    except Exception as e:
        print(f"[red]Could not resolve NS for {domain}: {e}[/red]")
        return []

def check_axfr(domain):
    discovered = []
    ns = get_ns(domain)
    for n in ns:
        try:
            # perform AXFR against nameserver address
            xfr = dns.query.xfr(nameserver, domain, timeout=5)
            z = dns.zone.from_xfr(xfr)
            if z:
                nodes = list(z.nodes)
                print(f"[bold red]AXFR allowed! Nameserver {n} (via {nameserver}) returned {len(nodes)} records[/bold red]")
                discovered.append((n, len(nodes)))
        except Exception as e:
            # usually this will timeout/raise if not allowed
            pass
    if not discovered:
        print("[green]AXFR not allowed (good)[/green]")
    return discovered

def check_spf_dmarc(domain):
    spf = False
    dmarc = False
    try:
        for r in resolver.resolve(domain, 'TXT'):
            txt = b"".join(r.strings).decode(errors='ignore')
            if "v=spf1" in txt.lower():
                spf = True
    except Exception:
        pass
    try:
        for r in resolver.resolve("_dmarc." + domain, 'TXT'):
            txt = b"".join(r.strings).decode(errors='ignore')
            if "v=dmarc1" in txt.lower():
                dmarc = True
    except Exception:
        pass
    print(f"SPF: {'[green]present[/green]' if spf else '[red]missing[/red]'}")
    print(f"DMARC: {'[green]present[/green]' if dmarc else '[red]missing[/red]'}")
    return spf, dmarc

def check_wildcard(domain):
    rnd = str(random.randint(100000, 999999))
    test = f"{rnd}.test.{domain}"
    try:
        resolver.resolve(test, 'A')
        print(f"[yellow]Wildcard likely detected — {test} resolved via {nameserver}[/yellow]")
        return True
    except dns.resolver.NXDOMAIN:
        print("[green]No wildcard detected[/green]")
    except Exception:
        print("[green]No wildcard detected or query blocked[/green]")
    return False

def check_mx(domain):
    try:
        mxs = resolver.resolve(domain, 'MX')
        problems = []
        for m in mxs:
            exchange = str(m.exchange).rstrip('.')
            try:
                resolver.resolve(exchange, 'A')
            except Exception:
                problems.append(exchange)
        if problems:
            print(f"[red]MX points to non-resolving hosts: {problems}[/red]")
        else:
            print("[green]MX targets resolve[/green]")
    except Exception:
        print("[yellow]No MX records found or query failed[/yellow]")

def check_cname_takeover(domain):
    # very basic: find CNAMEs and flag external-looking ones
    try:
        # brute force some common names
        candidates = ["oldservice."+domain, "dev."+domain, "staging."+domain]
        issues = []
        for c in candidates:
            try:
                ans = resolver.resolve(c, 'CNAME')
                target = str(ans[0].target).rstrip('.')
                # If the target looks like an external service (heuristic), warn
                if "." in target and not target.endswith(domain):
                    issues.append((c, target))
            except Exception:
                pass
        if issues:
            print(f"[yellow]Potential CNAME external targets (review for takeover): {issues}[/yellow]")
        else:
            print("[green]No obvious risky CNAMEs found among sample names[/green]")
    except Exception as e:
        print(f"[yellow]CNAME check aborted: {e}[/yellow]")

def check_ns_health(domain):
    ns = get_ns(domain)
    for n in ns:
        try:
            # resolve NS A record by querying our local server for that name
            a = resolver.resolve(n, 'A')
            print(f"NS {n} -> {a[0]}")
        except Exception as e:
            print(f"[red]NS {n} not resolving locally: {e}[/red]")

if __name__ == "__main__":
    print(f"[bold]Running DNS lab scan for [cyan]{domain}[/cyan] via [cyan]{nameserver}[/cyan][/bold]\n")
    check_axfr(domain)
    print()
    check_spf_dmarc(domain)
    print()
    check_wildcard(domain)
    print()
    check_mx(domain)
    print()
    check_cname_takeover(domain)
    print()
    check_ns_health(domain)
