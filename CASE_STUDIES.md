
---

# Case Studies: Pickle RCE Vulnerabilities

## Case Study 1: PerkunasAI Training Platform

**Vulnerability:** Unsafe pickle deserialization in KV cache NVMe layer  
**Severity:** Critical (RCE)  
**Status:** ✅ Patched (Issue #93)  
**Bounty:** Confidential  

### Technical Details

The PerkunasAI training platform used pickle serialization for caching model weights in their NVMe-based key-value store. The deserialization occurred without any safety checks, allowing arbitrary code execution.

**Vulnerable Code Pattern:**
```python
# In kv_cache/nvme_layer.py
cache_data = nvme_read(offset, length)
data = pickle.loads(cache_data)
```
  # UNSAFE

Impact:
- Remote code execution on training nodes
- Access to model weights and training data
- Potential for data poisoning attacks
Timeline:
- Discovered: May 2026
- Reported: May 2026
- Patched: May 2026
- Disclosed: June 2026


Case Study 2: Triagent
Vulnerability: pickle.load in paging.py:137
Severity: Critical (RCE)
Status: ✅ Fixed
Bounty: Confidential
Technical Details
TriAgent's memory paging system used pickle to serialize and deserialize model state between CPU and GPU memory. The deserialization at line 137 of paging.py was reachable with user-controlled input.
Vulnerable Code:
# paging.py:137
def load_page(page_id):
    data = storage.read(page_id)
    return pickle.load(data)  # UNSAFE - user-controlled page_id
Exploit Vector:
 1. Attacker uploads malicious pickle payload as a "page"
 2. System loads page via pickle.load()
 3. Arbitrary code execution achieved
Impact:
- Full compromise of inference endpoints
- Access to all loaded models
- Data exfiltration from memory
Timeline:
- Discovered: April 2026
- Reported: April 2026
- Fixed: May 2026
- Disclosed: June 2026
Methodology
Both vulnerabilities were discovered using automated scanning with custom semgrep rules targeting:
- pickle.load() / pickle.loads()
- torch.load() with pickle_module
- joblib.load()
- yaml.load() with Loader not specified
Followed by manual verification of:
 1. User-controlled input reachability
 2. Lack of allowlist/blocklist validation
 3. Impact assessment
Lessons Learned
 1. Never use pickle for untrusted data - Use JSON, msgpack, or other safe formats
 2. Validate all deserialization - Even "internal" data can be attacker-controlled
 3. Defense in depth - Sandbox loading operations, use seccomp filters
 4. Monitor for anomalies - Unexpected pickle operations in logs
