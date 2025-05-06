import aiohttp
import asyncio
import hashlib
import re
import math
import json
import argparse
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime

visited = set()
entropy_map = {}
OUTPUT_DIR = "output"

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

## For further development, please refer to the following: You can PR to the repo,
## Here I just provided the basic working principle of  infotaxis algorithm  and How it can be benefical for Large Industrial Purpose.

# --- ENTROPY ---
def shannon_entropy(s):
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return (
        -sum((f / total) * math.log2(f / total) for f in freq.values()) if total else 0
    )

def calc_entropy_gain(data):
    h = hashlib.sha256(data.encode()).hexdigest()
    if h in entropy_map:
        return 0
    e = shannon_entropy(data)
    entropy_map[h] = e
    return e

# --- LEAK SCANNER --- I just used simple regex for the demo purpose, in real indutrial purpose,
# If you are taking this and developing for your own Industry i would suggest to use  ML based approach to detect the leaks acc to service used.
def scan_for_secrets(text):
    leaks = []
    regexes = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
        "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "Stripe Key": r"sk_live_[0-9a-zA-Z]{24}",
        "Bearer Token": r"Bearer\s+[A-Za-z0-9\-_.=]+",
        "JWT": r"eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+",
        "Basic Auth": r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]+",
        "Generic token": r"token\s*[:=]\s*['\"][a-zA-Z0-9\-_\.]{10,}['\"]",
    }
    for name, pattern in regexes.items():
        found = [str(x) for x in re.findall(pattern, text)]
        if found:
            leaks.append((name, found))
    return leaks

# --- FORM SCANNER ---
def scan_for_forms(html):
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    results = []
    for f in forms:
        action = f.get("action", "")
        method = f.get("method", "GET")
        inputs = [inp.get("name", "") for inp in f.find_all("input")]
        results.append({"action": action, "method": method, "inputs": inputs})
    return results

# --- API SCANNER ---
def scan_for_json_api(text, url):
    return (
        url.endswith(".json")
        or "application/json" in text
        or bool(re.search(r'{\s*".+?"\s*:', text))
    )

# --- LINK EXTRACT -
def extract_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all(["a", "script", "link", "iframe"]):
        href = tag.get("href") or tag.get("src")
        if href:
            link = urljoin(base_url, href)
            parsed = urlparse(link)
            clean = parsed.scheme + "://" + parsed.netloc + parsed.path
            if clean not in visited:
                links.add(clean)
    return links

# --- FETCH PAGE ---
async def fetch(session, url):
    try:
        async with session.get(url, timeout=10) as r:
            content_type = r.headers.get("Content-Type", "")
            text = await r.text(errors="ignore")
            return text, content_type
    except Exception as e:
        print(f"[!] Failed to fetch {url} :: {e}")
        return "", ""

# --- SAVE ---
# I am quit lazy to format it, so i just used the basic json format,
# In real world, you can use the database to store the data and then use it for analysis.
def save_output(url, leaks, entropy, forms, is_api):
    ts = datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_url = url.replace("://", "_").replace("/", "_").replace("?", "_")
    file_path = os.path.join(OUTPUT_DIR, f"{ts}_{safe_url}.json")
    try:
        json.dump(
            {
                "url": url,
                "entropy": entropy,
                "leaks": leaks,
                "forms": forms,
                "api": is_api,
            },
            open(file_path, "w"),
            indent=2,
        )
    except Exception as e:
        print(f"[!] JSON write failed for {url}: {e}")

# --- SWARM (Infotaxis) ---
async def infotaxis_smart_recon(start_url, max_depth=5):
    frontier = {start_url}
    async with aiohttp.ClientSession() as session:
        for depth in range(max_depth):
            print(f"\n🔥 Depth {depth} | Targets: {len(frontier)}")
            scored = []

            for url in list(frontier):
                if url in visited:
                    continue
                visited.add(url)

                html, content_type = await fetch(session, url)
                gain = calc_entropy_gain(html)

                leaks = scan_for_secrets(html)
                if leaks:
                    print(f"🚨 LEAKS FOUND @ {url}")
                    for ltype, vals in leaks:
                        print(f"   - {ltype}: {vals}")

                forms = scan_for_forms(html)
                if forms:
                    print(f"[+] {len(forms)} forms found @ {url}")

                is_api = scan_for_json_api(html, url)
                if is_api:
                    print(f"[+] API detected @ {url}")

                save_output(url, leaks, gain, forms, is_api)
                links = extract_links(html, url)

                scored.append((gain, links, url))

            scored.sort(reverse=True, key=lambda x: x[0])  # infotaxis priority
            frontier = set()
            for gain, links, src_url in scored[:5]:
                print(f"[~] Entropy: {gain:.2f} :: {src_url}")
                frontier.update(links)

            if not frontier:
                print("[-] No more links. Swarm complete.")
                break

# --- LEARNING SCORING ENGINE ---Randomly added the score's Adjust plz:)
learning_db = {
    "tags": {
        "aws-key": 6,
        "token": 5,
        "secrets-exposed": 7,
        "api-key": 4,
        "form-zone": 3,
        "api-endpoint": 5,
        "high-entropy": 2,
        "js-payload-zone": 4,
    },
    "boost_patterns": {
        "/admin": 3,
        "/reset": 2,
        "/callback": 2,
        "/token": 2,
        ".env": 5,
    },
}


def run_infotaxis_analyzer(output_dir="output"):
    from collections import defaultdict
    import matplotlib.pyplot as plt

    cluster = defaultdict(list)
    scores = []

    for root, dirs, files in os.walk(output_dir):
        for f in files:
            if not f.endswith(".json"):
                continue

            path = os.path.join(root, f)
            try:
                with open(path) as jf:
                    data = json.load(jf)

                url = data.get("url", "unknown")
                entropy = data.get("entropy", 0)
                leaks = data.get("leaks", [])
                forms = data.get("forms", [])
                is_api = data.get("api", False)

                tags = []

                if leaks:
                    for l in leaks:
                        ltype = l[0].lower()
                        if "aws" in ltype:
                            tags.append("aws-key")
                        if "bearer" in ltype:
                            tags.append("token")
                        if "secret" in ltype:
                            tags.append("secrets-exposed")
                        if "api" in ltype:
                            tags.append("api-key")

                if forms:
                    tags.append("form-zone")
                if is_api:
                    tags.append("api-endpoint")
                if entropy > 5:
                    tags.append("high-entropy")
                if any("callback" in ltype or "token" in ltype for ltype, _ in leaks):
                    tags.append("js-payload-zone")

                score = sum(learning_db["tags"].get(tag, 0) for tag in tags)

                for pattern, boost in learning_db["boost_patterns"].items():
                    if pattern in url:
                        score += boost
                        tags.append(f"boost:{pattern}")

                scores.append((score, url, tags))
                base = url.split("/")[3] if len(url.split("/")) > 3 else "/"
                cluster[base].append(score)

            except Exception as e:
                print(f"[!] Failed to process {path}: {e}")

    scores.sort(reverse=True, key=lambda x: x[0])

    print("\n💥 ADVANCED INFOTAXIS OUTPUT ANALYSIS 💥")
    for score, url, tags in scores:
        print(f"[{score:02d}] {url} :: {' | '.join(tags)}")

    # CLUSTER VISUALIZATION
    try:
        plt.figure(figsize=(12, 5))
        keys = list(cluster.keys())
        vals = [sum(v) / len(v) for v in cluster.values()]
        plt.bar(keys, vals)
        plt.xticks(rotation=45, ha="right")
        plt.title("🔥 Recon Heatmap: Endpoint Clusters by Average Score")
        plt.tight_layout()
        heatmap_file = os.path.join(output_dir, "heatmap.png")
        plt.savefig(heatmap_file)
        print(f"\n[+] Heatmap saved to {heatmap_file}")
    except Exception as e:
        print(f"[!] Heatmap failed: {e}")


# --- CLI ENTRY ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🔥 Infotaxis Recon")
    parser.add_argument(
        "--analyze-only", action="store_true", help="Run analysis only on saved output"
    )
    parser.add_argument("--depth", type=int, default=5, help="Set depth for crawling")
    args = parser.parse_args()

    if args.analyze_only:
        print("🔍 Analyzing existing output folder only...")
        run_infotaxis_analyzer(OUTPUT_DIR)
        exit(0)

    print("Swarm Recon Tool Demo For Industrial Purpose using Infotaxis based Algorithm")
    target = input("Enter target URL (e.g. https://example.com): ").strip()
    if not target.startswith("http"):
        target = "https://" + target
    asyncio.run(infotaxis_smart_recon(target, max_depth=args.depth))
    print("\n🔎 Running final output analysis...")
    run_infotaxis_analyzer(OUTPUT_DIR)
