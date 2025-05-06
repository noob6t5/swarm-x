# swarm-x
Demo tool of Next-Gen Intelligence Swarm highly focused for Large Huge Infrastructure ,**That I am working on **

**Insp :::** 
Ever Thought of  swarm of AI-infused agents doing parallel recon, entropy-based leak detection, and parameter fuzzing — all while mapping app structure and identifying vuln-prone areas .   Amazing Right??
---

### **About This Repository**
This repository showcases a **custom asynchronous reconnaissance and fuzzing scanner** that I am designing to **monitor and fuzz at scale**,
which  **learns**, **evolves**, and **adapts** based on the real-time feedback it gets from the system. 
It’s like having a **self-tuning weapon** that gets smarter after every scan, **AI-powered fuzzing** evolve and morph, testing payloads dynamically based on the system’s responses.
It doesn’t just **scan**; it **learns** from its results. This self-optimization means that as it scans more targets, it gets better at recognizing patterns, detecting vulnerabilities, and evading defensive measures

 It incorporates features like:
- **Entropy scoring**
- **Leak detection**
- **Form abuse detection**
- **Parameter mutation**

> **Note:** This repository is part of my learning journey. I’ve uploaded it to gather feedback and contributions from others working on similar prototypes. While it’s currently a work in progress, it’s designed with scalability and long-term infrastructure security in mind.

---
### **Key Features**
#### 🕵️ RECON AGENTS
-   Each `agent()` starts crawling from a given URL, up to a max depth.
-   Extracts links, forms, JS references, etc.
-   Avoids re-visiting URLs (keeps global set).
#### 🧬 LEAK DETECTION:
-   Regex hunt for **API keys, JWTs, Bearer tokens, AWS creds**.
-   JSON structure traversal: finds embedded secrets like `"apikey":`, `"token":`, `"password"`.
#### ⚖️ ENTROPY SCORING:
-   `shannon_entropy()` scores responses.
-   High entropy changes from baseline? It flags the content as **likely dynamic / interesting** (e.g. secrets, encoded blobs, token dumps).
#### 💉 PARAM & FORM FUZZING:
-   GET param fuzzing (querystring injection).
-   POST form fuzzing (input injection via HTML forms).
-   Uses classic payloads (`XSS`, `LFI`, `debug toggles`, etc.).
-   Tracks hits where content-length shift > threshold → indicates impact.
#### 📊 HEATMAP VISUALIZATION:
-   URLs are bucketed into segments (`/admin/`, `/api/`, etc.).
-   Averages scores, builds bar chart heatmap (with `matplotlib`).
-   Surfaces hot zones visually for triage.
#### 📝 OUTPUT:
-   **Per-URL JSONs** with score, fuzz hits, and leaks.   
-   **CSV summary** for automation/pipelining.
-   **Domain list** aggregation.
-   **PNG heatmap** for analyst overview.

**Usage :** 
```bash python3 swarm_wb.py http://testphp.vulnweb.com --agents 5 --depth 5
```
---
### **Future Enhancements**
This repository is a simplified version of the industrial-grade tool I’m building. It currently lacks advanced features like:
- Persistent memory core
- Deep entropy gradients
- Scoring engine
- Visual attack surface mapping
- Self-tuning heuristics

Contributions are welcome! Feel free to submit a pull request if you’d like to help enhance this project.
---

### **Contact**
If you are a company or individual looking to secure your infrastructure with cutting-edge AI-powered reconnaissance and fuzzing tools, I’d love to collaborate. Swarm-X is designed for large-scale, long-term infrastructure security. 

For inquiries, contracts, or partnerships, please contact me directly. Let’s work together to build a more secure future!
