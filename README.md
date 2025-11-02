# Brustcraft 🚀

**Brustcraft** is a lightweight, concurrent HTTP burst sender.  
Use it for controlled load testing, API behavior testing, or security testing (in authorized environments only).

---

## Features
- Read raw HTTP request files (Burp-style `req.txt` or just a request body).
- Supports a `%s` placeholder in headers and body which is replaced from a wordlist (one word per line).
- Send requests in concurrent bursts (threadpool).
- Optionally route traffic through an HTTP proxy (e.g., Burp, mitmproxy).
- Simple result classification from response body: `Applied`, `Already`, `Invalid`, `Other`.
- Preserves request headers (e.g., `User-Agent`, `Referer`, `Origin`) and sets cookies into the session if `Cookie` header is 
present.
- Removes hop-by-hop headers (e.g., `Connection`, `Content-Length`) so requests play nicely with `requests`.

> ⚠️ Use this tool only against systems you own or have explicit permission to test.

---

## Requirements
- Python 3.8+
- `requests` library

Install requirements:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Quick start / Usage

### Basic usage
```bash
python burst_sender_wordlist.py   --url "https://target.example.com/cart/coupon"   --rawfile req.txt   --wordlist words.txt   
--burst-size 5   --burst-count 1   --timeout 15
```

### Example `req.txt` (Burp-style)
```
POST /cart/coupon HTTP/2
Host: target.example.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0
Referer: https://target.example.com/cart
Cookie: session=abcd1234; other=xyz
Content-Type: application/x-www-form-urlencoded

csrf=7MrY7ScnX7prbRi0NwS38vgAreCkR8GF&coupon=%s
```

If the file above contains `%s` anywhere (headers or body), each line from `words.txt` will replace `%s` in turn.

### Wordlist file (`words.txt`) example
```
PROMO1
PROMO2
PROMO20
```

### Using a proxy (intercept / debug)
```bash
python burst_sender_wordlist.py   --url "https://target.example.com/cart/coupon"   --rawfile req.txt   --wordlist words.txt   
--burst-size 10   --burst-count 2   --proxy http://127.0.0.1:8080
```
This will route requests through `http://127.0.0.1:8080` (useful for Burp or mitmproxy).

---

## Command-line options
- `--url` (required) — target URL (full URL, e.g. `https://target/...`)
- `--rawfile, -r` (required) — raw request file (headers + body or only body)
- `--wordlist, -w` (required) — file with replacement words, one per line (used to substitute `%s`)
- `--burst-size` (required) — number of concurrent requests per burst
- `--burst-count` — number of bursts to run per word (default `1`)
- `--timeout` — request timeout seconds (default `15`)
- `--proxy` — optional proxy URL (e.g., `http://127.0.0.1:8080`)

---

## Behavior notes & tips
- If your `req.txt` contains only a body (no headers), the tool will treat the whole file as the POST body.
- The script sets cookies into `requests.Session()` when a `Cookie` header is present. It performs a simple `key=value; 
key2=value2` parse — complex cookie attributes are not parsed.
- Hop-by-hop headers (like `Connection`, `Transfer-Encoding`, `Content-Length`, `Host`) are omitted before sending so `requests` 
can manage them properly.
- `requests` uses HTTP/1.1 by default. If you require HTTP/2 for the actual transport, consider using `httpx` with HTTP/2 support 
or another HTTP/2-capable client (not included by default).
- The response classification is naive string matching (`"invalid"`, `"already applied"`, `"applied"`). Adjust the detection logic 
if the target returns different messages or uses localized text.

---

## Output / Reporting
- The script prints per-burst summaries like:
```
[burst 1] sent 10 reqs in 0.85s; summary: Applied:3, Invalid:6, Other:1
```
- At the end it prints a grand summary of all outcomes.

---

## Extending / Customization ideas
- Write responses to a CSV/JSON log with timestamps, word, status code, and response length.
- Add rate-limiting/delays between bursts to avoid accidental DoS.
- Add support for different HTTP methods by parsing the request line (GET/PUT/DELETE).
- Add more robust cookie parsing and support for signed cookies or CSRF token auto-extraction.
- Replace `requests` with `httpx` (with HTTP/2) if you need real HTTP/2 transport.

---

## License
Add your preferred license (e.g., MIT) here.

