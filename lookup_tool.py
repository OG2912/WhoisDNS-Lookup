#!/usr/bin/env python3

import whois
import dns.resolver
import argparse
import sys

def whois_lookup(domain):
    print(f"\n[WHOIS] {domain}")
    try:
        w = whois.whois(domain)
        for key, value in w.items():
            print(f"{key}: {value}")
    except Exception as e:
        print(f"[-] WHOIS Lookup failed: {e}")

def dns_lookup(domain, record_type):
    print(f"\n[DNS - {record_type}] {domain}")
    try:
        answers = dns.resolver.resolve(domain, record_type)
        for rdata in answers:
            print(f"{record_type} Record: {rdata.to_text()}")
    except dns.resolver.NoAnswer:
        print(f"[-] No {record_type} record found.")
    except Exception as e:
        print(f"[-] DNS Lookup failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Whois & DNS Lookup Tool")
    parser.add_argument("domain", help="Target domain to lookup")
    parser.add_argument("-a", "--all", action="store_true", help="Run WHOIS and all DNS lookups")
    parser.add_argument("-w", "--whois", action="store_true", help="Run WHOIS only")
    parser.add_argument("-d", "--dns", nargs='*', help="Run specific DNS record lookups (e.g., A MX NS TXT CNAME)")

    args = parser.parse_args()

    if not any([args.whois, args.dns, args.all]):
        parser.error("Please specify at least one lookup option (--whois, --dns, or --all).")

    if args.whois or args.all:
        whois_lookup(args.domain)

    if args.dns:
        for rtype in args.dns:
            dns_lookup(args.domain, rtype.upper())
    elif args.all:
        for rtype in ['A', 'MX', 'NS', 'TXT', 'CNAME']:
            dns_lookup(args.domain, rtype)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupted by user.")
