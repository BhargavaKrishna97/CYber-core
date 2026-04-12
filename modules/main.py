from modules.active_scan import active_scan
from modules.passive_recon import passive_recon
import json

def run_tool(target):
    print(f"[+] Starting full recon on {target}")

    passive_data = passive_recon(target)
    active_data = active_scan(target)

    final_output = {
        "target": target,
        "passive": passive_data,
        "active": active_data
    }

    with open("final_report.json", "w") as f:
        json.dump(final_output, f, indent=4)

    print("[+] Full report saved to final_report.json")


if __name__ == "__main__":
    target = "scanme.nmap.org"
    run_tool(target)
