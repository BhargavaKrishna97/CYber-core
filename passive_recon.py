import requests
import dns.resolver
import whois

def get_subdomains(domain):
    subdomains = []
    try:
        # Query certificate transparency logs via crt.sh
        url = f"https://crt.sh/?q={domain}&output=json"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                name = entry.get("name_value")
                if name and domain in name:
                    subdomains.append(name.strip())
    except Exception as e:
        print(f"[!] Error fetching subdomains: {e}")
    return list(set(subdomains))

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

def passive_recon(domain):
    results = {
        "domain": domain,
        "subdomains": get_subdomains(domain),
        "whois": get_whois(domain),
        "osint": {}  # placeholder for future OSINT integrations
    }
    return results

if __name__ == "__main__":
    target = "example.com"
    data = passive_recon(target)
    print(data)
