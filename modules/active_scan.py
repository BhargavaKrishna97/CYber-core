import nmap
import json
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from html.parser import HTMLParser

DEBUG = False

# ----------------------------------------
# HTML Title Parser
# ----------------------------------------
class TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.capture = False
        self.title = ""

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self.capture = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.capture = False

    def handle_data(self, data):
        if self.capture:
            self.title += data.strip()


# ----------------------------------------
# Get IP Address
# ----------------------------------------
def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unavailable"


# ----------------------------------------
# Banner Grabbing (Improved)
# ----------------------------------------
def banner_grab(host, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((host, port))

        # HTTP ports
        if port in [80, 8080, 8000]:
            s.send(f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())

        # HTTPS port
        elif port == 443:
            context = ssl.create_default_context()
            secure = context.wrap_socket(s, server_hostname=host)
            secure.send(f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            data = secure.recv(1024).decode(errors="ignore")
            secure.close()
            return data.strip()

        data = s.recv(1024).decode(errors="ignore")
        s.close()

        return data.strip() if data else "No Banner"

    except:
        return "Unavailable"


# ----------------------------------------
# HTTP Detection 
# ----------------------------------------
def get_http_info(host):
    for proto in ["https://", "http://"]:
        url = proto + host
        try:
            req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            res = urlopen(req, timeout=4)

            html = res.read(2048).decode(errors="ignore")

            parser = TitleParser()
            parser.feed(html)

            return {
                "url": url,
                "status": res.getcode(),
                "title": parser.title or "No Title",
                "server": res.headers.get("Server", "Unknown")
            }

        except HTTPError as e:
            return {
                "url": url,
                "status": e.code,
                "title": "Blocked / Error",
                "server": "Unknown"
            }

        except:
            continue

    return {
        "url": None,
        "status": None,
        "title": None,
        "server": None
    }


# ----------------------------------------
# Risk Detection
# ----------------------------------------
def get_risk(port):
    if port in [21, 22, 23, 25, 3389]:
        return "HIGH"
    elif port in [80, 443, 8080, 3306]:
        return "MEDIUM"
    return "LOW"


# ----------------------------------------
# Scan Target 
# ----------------------------------------
def scan_target(target, scan_type="fast"):
    scanner = nmap.PortScanner()
    results = []

    # Scan mode
    arguments = "-F -T4 --host-timeout 30s"
    if scan_type == "full":
        arguments = "-sV -T4 --host-timeout 60s"
    elif scan_type == "vuln":
        arguments = "-sV --script vuln -T4 --host-timeout 90s"

    try:
        print(f"[+] Scanning {target} ({scan_type})...")

        scanner.scan(target, arguments=arguments)

        ip = get_ip(target) or get_ip(host)

        # 🔥 ALWAYS run HTTP detection
        web_info = get_http_info(target)

        seen_ports = set()

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                for port in scanner[host][proto].keys():

                    if port in seen_ports:
                        continue
                    seen_ports.add(port)

                    service = scanner[host][proto][port]

                    if service.get("state") == "open":

                        results.append({
                            "host": host,
                            "ip": ip,
                            "port": port,
                            "service": service.get("name", "unknown"),
                            "state": "open",
                            "banner": banner_grab(host, port),
                            "risk": get_risk(port),
                            "status": "scanned"
                        })

        # 🔥 If NO ports → still return web info
        if not results:
            results.append({
                "host": target,
                "ip": ip,
                "message": "No open ports (likely filtered)",
                "web_info": web_info,
                "risk": "INFO",
                "status": "scanned"
            })

        # 🔥 Attach web info to all results
        for r in results:
            r["web_info"] = web_info

       
        if DEBUG:
            print(f"[DEBUG] {target} → {len(results)} result(s)")

    except Exception as e:
        print(f"[!] Error: {e}")
        results.append({
            "host": target,
            "ip": get_ip(target),
            "message": str(e),
            "status": "failed"
        })

    return results


# ----------------------------------------
# Multi-thread Scan
# ----------------------------------------
def active_scan(targets, scan_type="fast"):
    all_results = {}

    def worker(target):
        clean = target.replace("*.", "").replace("*", "").strip()

        if not clean or "@" in clean or clean.startswith("http"):
            return None

        return clean, scan_target(clean, scan_type)

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(worker, targets)

    for res in results:
        if res:
            k, v = res
            all_results[k] = v

    return all_results


# ----------------------------------------
# Save Report
# ----------------------------------------
def save_report(data):
    with open("final_report.json", "w") as f:
        json.dump(data, f, indent=4)
    print("[+] Full report saved to final_report.json")


# ----------------------------------------
# MAIN
# ----------------------------------------
if __name__ == "__main__":
    targets = ["scanme.nmap.org"]

    result = active_scan(targets, scan_type="fast")

    print(json.dumps(result, indent=4))

    save_report(result)
