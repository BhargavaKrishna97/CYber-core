from modules.active_scan import active_scan
from modules.passive_recon import passive_recon
import json
import sys
import time

# ----------------------------------------
#DEBUG MODE (Trun off before github push)
# ----------------------------------------
DEBUG = False


# ----------------------------------------
# Main Tool Runner
# ----------------------------------------
def run_tool(target, mode="fast"):
    start_time = time.time()

    print(f"[+] Starting full recon on {target}")
    print(f"[+] Scan mode: {mode}")

    try:
        # ----------------------------------------
        # Step 1: Passive Recon
        # ----------------------------------------
        passive_data = passive_recon(target)

	# DEBUG HERE (Safe Controlled)
        if DEBUG:
            print(f"[DEBUG] Passive keys: {list(passive_data.keys())}")

        # ----------------------------------------
        # Step 2: Prepare Targets
        # ----------------------------------------
        subdomains = passive_data.get("subdomains", [])
        
        subdomains = sorted(subdomains)

        MAX_TARGETS = 10

        if len(subdomains) > MAX_TARGETS:
            print(f"[!] Limiting scan to first {MAX_TARGETS} targets")
            subdomains = subdomains[:MAX_TARGETS]

        if not subdomains:
            subdomains = [target]

        print(f"[+] Total targets for scanning: {len(subdomains)}")

        # ----------------------------------------
        # Step 3: Active Scan
        # ----------------------------------------
        active_data = active_scan(subdomains, mode)

	#DEBUG Active Results
        if DEBUG:
            for host, results in active_data.items():
                print(f"[DEBUG] {host} -> {len(results)} result(s)")
       
        # ----------------------------------------
	# Step 4: RISK COUNTER 
        # ---------------------------------------
        high = 0 
        medium = 0
        low = 0

        for host, results in active_data.items():
            for r in results:
                risk = r.get("risk", "LOW")
                if risk == "HIGH":
                    high += 1
                elif risk == "MEDIUM":
                    medium += 1
                else:
                    low += 1

        # ----------------------------------------
        # Step 5: Combine Results
        # ----------------------------------------
        final_output = {
            "target": target,
            "scan_type": mode,
            "total_targets": len(subdomains),
            "passive": passive_data,
            "active": active_data,

            # Additions for 3rd person
            "summary": {
                "total_subdomains": len(subdomains),
                "scan_mode": mode
            },
            "risk_summary": {
                "high": high,
                "medium": medium,
                "low": low
            },
            "status": "success"

        }

        # ----------------------------------------
        # Step 6: Save Report
        # ----------------------------------------
        with open("final_report.json", "w") as f:
            json.dump(final_output, f, indent=4)

        print("[+] Full report saved to final_report.json")

        end_time = time.time()
        print(f"[+] Completed in {round(end_time - start_time, 2)} seconds")

    except Exception as e:
        print(f"[!] Error: {e}")


# ----------------------------------------
# CLI Handling (IMPORTANT FIX)
# ----------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <target> [fast|full|vuln]")
        sys.exit(1)

    target = sys.argv[1]

    # Default scan mode
    mode = "fast"

    if len(sys.argv) >= 3:
        mode = sys.argv[2].lower()

        if mode not in ["fast", "full", "vuln"]:
            print("[!] Invalid mode. Use: fast, full, vuln")
            sys.exit(1)

    run_tool(target, mode)
