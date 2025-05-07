import aiohttp
import asyncio
import hashlib
import math
import re
import json
import os
import time
import signal
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from collections import defaultdict, Counter

# --- CONFIGURATION ---
MAX_AGENTS = 5
CONCURRENT_REQUESTS = 10
DEPTH_LIMIT = 5
KEYWORDS = ["admin", "login", "token", "key", "secret", "api"]
WEIGHTS = {"entropy": 2.0, "keyword": 3.0, "leak": 5.0, "form": 2.0, "js": 1.0}

# Globals
ALLOWED_DOMAIN = None
shared = {
    "visited_urls": set(),
    "url_scores": {},
    "leaks_found": [],
    "scores_history": defaultdict(list),
    "domains": set(),
}
agent_semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS)

# --- MEMORY SYSTEM ---
INTEL_DIR = "intel"
KNOWN_JS_PATHS_FILE = os.path.join(INTEL_DIR, "known-js-paths.json")
API_HINTS_FILE = os.path.join(INTEL_DIR, "api-hints.json")

os.makedirs(INTEL_DIR, exist_ok=True)


def load_json(path):
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump({}, f)
    with open(path, "r") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


known_js_paths = load_json(KNOWN_JS_PATHS_FILE)
api_hints = load_json(API_HINTS_FILE)


# --- UTILS ---
def shannon_entropy(s):
    freq = Counter(s)
    total = len(s)
    return (
        -sum((f / total) * math.log2(f / total) for f in freq.values())
        if total
        else 0.0
    )


def entropy_drift(e1, e2):
    return abs(e2 - e1)


def scan_secrets(text, source_url=None):
    leaks = []
    patterns = {
        "AWS": r"AKIA[0-9A-Z]{16}",
        "GoogleAPI": r"AIza[0-9A-Za-z-_]{35}",
        "JWT": r"eyJ[\w-]+\.[\w-]+\.[\w-]+",
        "Bearer": r"Bearer\s+[A-Za-z0-9\-_.=]+",
        "GenericAPI": r"(api[_-]?key|secret|token)[\"'\s:=]{1,5}[a-z0-9-_]{8,40}",
    }
    for name, pat in patterns.items():
        for match in re.findall(pat, text, re.I):
            leaks.append((name, match))
            if source_url:
                api_hints.setdefault(name, [])
                if source_url not in api_hints[name]:
                    api_hints[name].append(source_url)
    return leaks


def scan_json_keys(text):
    try:
        obj = json.loads(text)
    except:
        return []
    keys = []

    def traverse(o):
        if isinstance(o, dict):
            for k, v in o.items():
                keys.append(k)
                traverse(v)
        elif isinstance(o, list):
            for i in o:
                traverse(i)

    traverse(obj)
    return [k for k in keys if k.lower() in ("password", "secret", "token", "apikey")]


def extract_links(html, base):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all(["a", "script", "link", "iframe"]):
        attr = tag.get("href") or tag.get("src")
        if attr:
            u = urljoin(base, attr)
            parsed = urlparse(u)
            shared["domains"].add(parsed.netloc)
            if ALLOWED_DOMAIN and parsed.netloc.endswith(ALLOWED_DOMAIN):
                links.add(f"{parsed.scheme}://{parsed.netloc}{parsed.path}")

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            full_url = urljoin(base, src)
            if ALLOWED_DOMAIN in full_url:
                known_js_paths.setdefault(ALLOWED_DOMAIN, [])
                if full_url not in known_js_paths[ALLOWED_DOMAIN]:
                    known_js_paths[ALLOWED_DOMAIN].append(full_url)

    return links


def compute_score(parent_e, html, leaks):
    e_child = shannon_entropy(html)
    drift = entropy_drift(parent_e, e_child)
    kcount = sum(html.lower().count(k) for k in KEYWORDS)
    js_files = html.count(".js")
    forms = html.count("<form")
    score = (
        WEIGHTS["entropy"] * drift
        + WEIGHTS["keyword"] * kcount
        + WEIGHTS["leak"] * len(leaks)
        + WEIGHTS["form"] * forms
        + WEIGHTS["js"] * js_files
    )
    shared["scores_history"][parent_e].append(score)
    return score, e_child


async def fetch_page(session, url):
    async with agent_semaphore:
        try:
            async with session.get(url, timeout=10) as resp:
                text = await resp.text(errors="ignore")
                return resp.status, text, resp.headers
        except:
            return None, "", {}


async def recon_agent(name, start_urls, max_depth):
    queue = [(u, 0, shannon_entropy("")) for u in start_urls]
    async with aiohttp.ClientSession() as session:
        while queue:
            url, depth, parent_e = queue.pop(0)
            if depth > max_depth or url in shared["visited_urls"]:
                continue
            shared["visited_urls"].add(url)
            status, html, headers = await fetch_page(session, url)
            if status != 200 or not html:
                continue

            leaks = scan_secrets(html, url)
            keys = scan_json_keys(html)
            for k in keys:
                leaks.append(("JSONKey", k))

            score, e_child = compute_score(parent_e, html, leaks)
            shared["url_scores"][url] = max(shared["url_scores"].get(url, 0), score)

            for lname, val in leaks:
                shared["leaks_found"].append((url, lname, val))

            print(f"[{name}] D{depth} | {url} | S:{score:.1f} | leaks:{len(leaks)}")

            links = extract_links(html, url)
            for l in links:
                queue.append((l, depth + 1, e_child))


def save_output(domain_dir):
    os.makedirs(domain_dir, exist_ok=True)
    with open(os.path.join(domain_dir, "urls.txt"), "w") as f:
        for u in shared["url_scores"]:
            f.write(u + "\n")

    with open(os.path.join(domain_dir, "domains.txt"), "w") as f:
        for d in shared["domains"]:
            f.write(d + "\n")

    with open(os.path.join(domain_dir, f"leaks-{ALLOWED_DOMAIN}.txt"), "w") as f:
        for url, name, val in shared["leaks_found"]:
            f.write(f"{url} -> [{name}] {val}\n")

    with open(os.path.join(domain_dir, "api-tokens.json"), "w") as f:
        json.dump(shared["url_scores"], f)


def sig_handler(sig, frame):
    print("\n✋ Ctrl+C caught — saving output...")
    domain_dir = os.path.join("output", ALLOWED_DOMAIN)
    save_output(domain_dir)
    save_json(KNOWN_JS_PATHS_FILE, known_js_paths)
    save_json(API_HINTS_FILE, api_hints)
    exit(0)


signal.signal(signal.SIGINT, sig_handler)
signal.signal(signal.SIGTERM, sig_handler)


async def main(target, num_agents, depth):
    global ALLOWED_DOMAIN
    if not target.startswith("http"):
        target = "https://" + target
    ALLOWED_DOMAIN = urlparse(target).netloc
    domain_dir = os.path.join("output", ALLOWED_DOMAIN)

    # Replay known JS
    js_urls = known_js_paths.get(ALLOWED_DOMAIN, [])
    print(f"[i] Loaded {len(js_urls)} known JS paths from memory")
    for js_url in js_urls:
        shared["visited_urls"].add(js_url)

    try:
        await asyncio.gather(
            *[recon_agent(f"A{i+1}", {target}, depth) for i in range(num_agents)]
        )
    finally:
        save_output(domain_dir)
        save_json(KNOWN_JS_PATHS_FILE, known_js_paths)
        save_json(API_HINTS_FILE, api_hints)
        print(f"\n✅ Recon finished. Output in: {domain_dir}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="⚔️ Infotaxis++ Async Recon")
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("--agents", type=int, default=MAX_AGENTS)
    parser.add_argument("--depth", type=int, default=DEPTH_LIMIT)
    args = parser.parse_args()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main(args.target, args.agents, args.depth))
