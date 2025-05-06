import aiohttp
import asyncio
import hashlib
import math
import re
import json
import random
import argparse
import os
import time
import csv
import matplotlib.pyplot as plt
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from datetime import datetime, timezone
from collections import defaultdict, Counter

## Basic part of  Scanner with Infotaxis Agent for Monitoring Large Industrial based Web Applications
##  Major Feauteres are still missing :))



#CONFIGURATION Just for testing purposes in internal network thing's would be different
OUTPUT_DIR = "output"
MAX_AGENTS = 5
CONCURRENT_REQUESTS = 10
DEPTH_LIMIT = 5
FUZZ_PAYLOADS = [
    "<script>alert(1)</script>",
    "' OR '1'='1;--",
    "../../../../etc/passwd",
    "../.env",
    "<img src=x onerror=alert(1)>",
    "?debug=true",
    "?admin=1",
]
KEYWORDS = ["admin", "login", "token", "key", "secret", "api"]
WEIGHTS = {
    "entropy": 2.0,
    "keyword": 3.0,
    "leak": 5.0,
    "form": 2.0,
    "js": 1.0,
    "fuzz": 4.0,
}
FUZZ_LENGTH_THRESHOLD = 50  # bytes difference to count as real fuzz hit as it's still not the great method :) for simplicty i did it

#  globals 
ALLOWED_DOMAIN = None
os.makedirs(OUTPUT_DIR, exist_ok=True)
agent_semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS)
shared = {
    "visited_urls": set(),
    "url_scores": {},
    "leaks_found": [],
    "fuzz_success": Counter(),
    "domains": set(),
    "fuzzed_urls": set(),
}

# --- UTILS ---
def shannon_entropy(s: str) -> float:
    freq = Counter(s)
    total = len(s)
    return (
        -sum((f / total) * math.log2(f / total) for f in freq.values())
        if total
        else 0.0
    )

# --- SCANNERS ---  swarns  !!!!! 
def scan_secrets(text: str):
    leaks = []
    patterns = {
        "AWS": r"AKIA[0-9A-Z]{16}",
        "GoogleAPI": r"AIza[0-9A-Za-z-_]{35}",
        "JWT": r"eyJ[\w-]+\.[\w-]+\.[\w-]+",
        "Bearer": r"Bearer\s+[A-Za-z0-9\-_.=]+",
    }
    for name, pat in patterns.items():
        for m in re.findall(pat, text):
            leaks.append((name, m))
    return leaks

# json strcutues 
def scan_json_structure(text: str):
    try:
        o = json.loads(text)
    except:
        return False
    keys = []

    def traverse(x):
        if isinstance(x, dict):
            for k, v in x.items():
                keys.append(k)
                traverse(v)
        elif isinstance(x, list):
            for e in x:
                traverse(e)

    traverse(o)
    return any(k.lower() in ("password", "secret", "token", "apikey") for k in keys)


# link in csv
def extract_links(html: str, base: str):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all(["a", "script", "link", "iframe"]):
        href = tag.get("href") or tag.get("src")
        if not href:
            continue
        u = urljoin(base, href)
        p = urlparse(u)
        shared["domains"].add(p.netloc)
        if ALLOWED_DOMAIN and not p.netloc.endswith(ALLOWED_DOMAIN):
            continue
        links.add(f"{p.scheme}://{p.netloc}{p.path}")
    return links


# --- FETCH ---
async def fetch(session, url: str):
    async with agent_semaphore:
        start = time.time()
        try:
            r = await session.get(url, timeout=10)
            text = await r.text(errors="ignore")
            return r.status, text, r.headers, time.time() - start
        except:
            return None, "", {}, 0


#RECON AGENT lmo 
async def agent(name: str, start: str, depth_limit: int):
    queue = [(start, 0)]
    async with aiohttp.ClientSession() as ses:
        while queue:
            url, depth = queue.pop(0)
            if depth > depth_limit or url in shared["visited_urls"]:
                continue
            shared["visited_urls"].add(url)

            status, body, hdrs, lat = await fetch(ses, url)
            if status != 200 or not body:
                continue

            #  scanning 
            #  Belo2 scanning features are not the best and still need to be improved esp for large corp. 
            leaks = scan_secrets(body)
            if scan_json_structure(body):
                leaks.append(("JSON", "struct"))

            # Fuzz GET params
            fuzz_hits = 0
            fuzz_details = []
            if url not in shared["fuzzed_urls"]:
                p = urlparse(url)
                qs = parse_qs(p.query)
                for k in qs:
                    pl = random.choice(FUZZ_PAYLOADS)
                    mutated = p._replace(query=urlencode({k: pl}, doseq=True)).geturl()
                    st2, b2, _, _ = await fetch(ses, mutated)
                    if st2 == 200 and abs(len(b2) - len(body)) > FUZZ_LENGTH_THRESHOLD:
                        fuzz_hits += 1
                        shared["fuzz_success"][pl] += 1
                        fuzz_details.append((k, pl))
                        print(f"[FUZZ-GET] {mutated}")
                shared["fuzzed_urls"].add(url)

            # Fuzz POST forms
            soup = BeautifulSoup(body, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action") or url
                action = urljoin(url, action)
                method = form.get("method", "get").lower()
                inputs = [
                    inp.get("name") for inp in form.find_all("input") if inp.get("name")
                ]
                for inp_name in inputs:
                    for pl in FUZZ_PAYLOADS:
                        if method == "post":
                            r2 = await ses.post(action, data={inp_name: pl})
                        else:
                            r2 = await ses.get(action, params={inp_name: pl})
                        t2 = await r2.text(errors="ignore")
                        if (
                            r2.status == 200
                            and abs(len(t2) - len(body)) > FUZZ_LENGTH_THRESHOLD
                        ):
                            fuzz_hits += 1
                            shared["fuzz_success"][pl] += 1
                            fuzz_details.append((f"form:{inp_name}", pl))
                            print(f"[FUZZ-POST] {action} {inp_name}={pl}")

            # Scoring
            e = shannon_entropy(body)
            drift = abs(e - shannon_entropy(""))
            score = (
                drift * WEIGHTS["entropy"]
                + len(leaks) * WEIGHTS["leak"]
                + sum(body.lower().count(k) for k in KEYWORDS) * WEIGHTS["keyword"]
                + body.count("<form") * WEIGHTS["form"]
                + body.count(".js") * WEIGHTS["js"]
                + fuzz_hits * WEIGHTS["fuzz"]
            )
            shared["url_scores"][url] = max(shared["url_scores"].get(url, 0), score)

            # Record leaks
            for ln, val in leaks:
                if (url, ln, val) not in shared["leaks_found"]:
                    shared["leaks_found"].append((url, ln, val))

            # Save JSON per-domain
            d = urlparse(url).netloc
            od = os.path.join(OUTPUT_DIR, d)
            os.makedirs(od, exist_ok=True)
            fn = hashlib.sha1(url.encode()).hexdigest()[:8] + ".json"
            with open(os.path.join(od, fn), "w") as f:
                json.dump(
                    {
                        "url": url,
                        "score": score,
                        "leaks": leaks,
                        "fuzz_hits": fuzz_details,
                        "time": lat,
                    },
                    f,
                    indent=2,
                )

            print(
                f"[{name}] D{depth}|{url}|S:{score:.1f}|L:{len(leaks)}|F:{fuzz_hits}|t:{lat:.2f}s"
            )

            # Enqueue children
            for link in extract_links(body, url):
                queue.append((link, depth + 1))


async def main(tgt: str, agents: int, depth: int):
    global ALLOWED_DOMAIN
    if not tgt.startswith("http"):
        tgt = "http://" + tgt
    ALLOWED_DOMAIN = urlparse(tgt).netloc
    await asyncio.gather(*[agent(f"A{i+1}", tgt, depth) for i in range(agents)])

    # SummaryCSV  urls is here grep for further processing
    csvf = os.path.join(OUTPUT_DIR, "summary.csv")
    with open(csvf, "w", newline="") as cf:
        w = csv.writer(cf)
        w.writerow(["url", "score", "leaks", "fuzz_hits"])
        for u, sc in shared["url_scores"].items():
            ls = [f"{ln}:{v}" for (uu, ln, v) in shared["leaks_found"] if uu == u]
            fs = [f"{k}({c})" for k, c in shared["fuzz_success"].items()]
            w.writerow([u, sc, ";".join(ls), ";".join(fs)])
    print("CSV->", csvf)

    # Heatmap for URLs ,
    segs = defaultdict(list)
    for u, sc in shared["url_scores"].items():
        parts = urlparse(u).path.split("/")
        seg = parts[1] if len(parts) > 1 and parts[1] else "root"
        segs[seg].append(sc)
    keys = list(segs.keys())
    vals = [sum(v) / len(v) for v in segs.values()]
    plt.figure()
    plt.bar(keys, vals)
    plt.xticks(rotation=45)
    plt.tight_layout()
    hp = os.path.join(OUTPUT_DIR, "heatmap.png")
    plt.savefig(hp)
    print("Heatmap->", hp)

    # Domains
    domf = os.path.join(OUTPUT_DIR, "domains.txt")
    with open(domf, "w") as df:
        for d in sorted(shared["domains"]):
            df.write(d + "\n")
    print("Domains->", domf)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("--agents", type=int, default=MAX_AGENTS)
    p.add_argument("--depth", type=int, default=DEPTH_LIMIT)
    a = p.parse_args()
    asyncio.run(main(a.target, a.agents, a.depth))

## Todo 
# 1. Refactor the code to make it more modular and readable as well remove recurring Fuzzing