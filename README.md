# Pickle Bomb Detector

**Finds Remote Code Execution (RCE) vulnerabilities in ML training infrastructure before attackers do.**

## ✅ Proven Track Record

- **2 RCEs Found & Patched** in production ML systems
- Focus: Pickle deserialization vulnerabilities in AI/ML pipelines

### Case Studies

| Project | Vulnerability | Status |
|---------|--------------|--------|
| PerkunasAI Training Platform | Unsafe pickle in KV cache NVMe layer | ✅ Patched (Issue #93) |
| TriAgent | `pickle.load` in `paging.py:137` | ✅ Fixed |

### Screenshots

See `/screenshots/` directory for vulnerability proofs.

---

### Why This Matters
`torch.load('model.pkl')` = arbitrary code execution if the .pkl is user-controlled.
Most ML teams don't know this. Attackers do. I found 2 cases in production AI infra.
This scanner finds the pattern before you get popped.

## 🚀 Quick Start

```bash
# Clone and scan a target
git clone https://github.com/Perfex-3437/pickle-bomb-detector.git
cd pickle-bomb-detector

# Install dependencies
pip install -r requirements.txt

# Run scanner
python scanner.py --help
python scanner.py --target https://github.com/example/repo
```

🔍 Features
- Scans Python repositories for dangerous deserialization patterns
- Targets pickle, torch.load, joblib.load, yaml.load, eval(), exec()
- Filters for high-value paths (model loading, inference, etc.)
- Generates JSON reports with actionable findings
📊 Output
- raw_results.json - Full semgrep scan output
- high_value_findings.json - Filtered, actionable vulnerabilities
- scan_log.txt - Execution history
🤝 Consulting
Professional security audits available. See CONSULTING.md