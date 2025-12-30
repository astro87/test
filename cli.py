import argparse
import sys
import time
import json
import httpx

def main():
    parser = argparse.ArgumentParser(description="VULNERA-MAP CLI")
    parser.add_argument("--file", required=True, help="Path to SBOM file")
    parser.add_argument("--url", default="http://localhost:8000", help="API URL")
    parser.add_argument("--fail-on", default="CRITICAL", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Fail pipeline on this severity or higher")
    args = parser.parse_args()

    print(f"Uploading {args.file} to {args.url}...")
    
    try:
        with open(args.file, "rb") as f:
            files = {"file": f}
            res = httpx.post(f"{args.url}/api/upload", files=files)
            
        if res.status_code != 200:
            print(f"Error: {res.text}")
            sys.exit(1)
            
        job_id = res.json()["job_id"]
        print(f"Job ID: {job_id}. Waiting for analysis...")
        
        # Poll for completion (Simple polling for CLI is fine vs SSE)
        while True:
            res = httpx.get(f"{args.url}/api/results/{job_id}")
            data = res.json()
            status = data.get("status")
            
            if status == "completed":
                print("Analysis Complete.")
                process_results(data, args.fail_on)
                break
            elif status == "failed":
                print(f"Analysis Failed: {data.get('error')}")
                sys.exit(1)
            else:
                print(f"Status: {status} - Progress: {data.get('progress')}%")
                time.sleep(1)
                
    except Exception as e:
        print(f"CLI Error: {e}")
        sys.exit(1)

def process_results(data, fail_threshold):
    stats = data["data"]["stats"]["risk_distribution"]
    print("\n=== Risk Summary ===")
    print(json.dumps(stats, indent=2))
    
    thresholds = {
        "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4
    }
    
    fail_level = thresholds[fail_threshold]
    
    max_severity = 0
    if stats.get("CRITICAL", 0) > 0: max_severity = 4
    elif stats.get("HIGH", 0) > 0: max_severity = 3
    elif stats.get("MEDIUM", 0) > 0: max_severity = 2
    elif stats.get("LOW", 0) > 0: max_severity = 1
    
    if max_severity >= fail_level:
        print(f"\n[FAIL] System has vulnerabilities of severity {fail_threshold} or higher.")
        sys.exit(1)
    else:
        print("\n[PASS] No threshold violations.")
        sys.exit(0)

if __name__ == "__main__":
    main()
