import requests
import dns.resolver
import whois

# -----------------------------
# Subdomain Enumeration
# -----------------------------
def get_subdomains(domain):
    subdomains = set()

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    # -------------------------
    # 1. crt.sh (Primary)
    # -------------------------
    url = f"https://crt.sh/?q={domain}&output=json"

    for attempt in range(2):
        try:
            print(f"[+] Trying crt.sh (attempt {attempt+1})...")
            response = requests.get(url, headers=headers, timeout=20)

            if response.status_code == 200:
                data = response.json()

                for entry in data:
                    name = entry.get("name_value")
                    if name:
                        for sub in name.split("\n"):
                            if domain in sub:
                                sub = sub.strip()

                                # Filter unwanted entries
                                if (
                                    "@" not in sub and
                                    not sub.startswith("*.") and
                                    not sub.startswith("http")
                                ):
                                    subdomains.add(sub)

                if subdomains:
                    print(f"[+] crt.sh found {len(subdomains)} subdomains")
                    return list(subdomains)

        except Exception:
            print("[!] crt.sh failed, using backup source...")

    # -------------------------
    # 2. HackerTarget (Backup)
    # -------------------------
    try:
        print("[+] Trying HackerTarget API...")
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=15)

        if response.status_code == 200:
            for line in response.text.splitlines():
                sub = line.split(",")[0]

                if (
                    domain in sub and
                    "@" not in sub and
                    not sub.startswith("http")
                ):
                    subdomains.add(sub.strip())

            print(f"[+] HackerTarget found {len(subdomains)} subdomains")

    except Exception:
        print("[!] HackerTarget failed, continuing without it...")

    return list(subdomains)


# -----------------------------
# WHOIS Information
# -----------------------------
def get_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "emails": w.emails
        }
    except Exception as e:
        print(f"[!] WHOIS error: {e}")
        return {}


# -----------------------------
# DNS Resolution
# -----------------------------
def resolve_dns(domain):
    records = []
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            records.append(rdata.to_text())
    except Exception:
        pass
    return records


# -----------------------------
# Main Passive Recon Function
# -----------------------------
def passive_recon(domain):
    return {
        "domain": domain,
        "subdomains": get_subdomains(domain),
        "whois": get_whois(domain),
        "ip_addresses": resolve_dns(domain),
        "osint": {}
    }


# -----------------------------
# Testing
# -----------------------------
if __name__ == "__main__":
    target = "github.com"

    print(f"[+] Starting passive recon for {target}")
    data = passive_recon(target)

    import json
    print(json.dumps(data, indent=4))
