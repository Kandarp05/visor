# Visor Phishing Detection Extension

Visor is a Chrome Manifest V3 browser extension for client-side passive detection of Browser-in-the-Middle (BiTB), Adversary-in-the-Middle (AiTM), Clickjacking, and Homograph attacks.

**v1 status:** the feature-extraction layer is complete and produces the full final
feature set. The AiTM classifier is a **trained model**
(`models/aitm_model.js`, generated from the v2 corpus). BiTB, homograph and
clickjacking remain placeholder heuristics.

> **The allowlist is the contract.** `lib/model_feature_allowlist.js` is the single
> source of truth for what a model may see. `models/interface.js` projects the
> vector onto it before any model runs, so a lab-specific, kit-specific,
> origin-specific or capture-specific feature cannot reach a classifier — by
> construction, not by discipline. See [FEATURE_CONTRACT.md](FEATURE_CONTRACT.md) §0.

---

## Architecture Overview

```
                      ┌───────────────────────────────────────┐
                      │          Browser Core (Chrome)        │
                      └──────────────────┬────────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │                                               │
                 ▼                                               ▼
     ┌───────────────────────┐                       ┌───────────────────────┐
     │  Background Worker    │                       │    Content Scripts    │
     │  (Tier 1 - Network)   │                       │    (Tier 2 - DOM)     │
     ├───────────────────────┤                       ├───────────────────────┤
     │ webRequest            │                       │ DOM Credential Scans  │
     │ webNavigation         │                       │ Iframe Overlays       │
     │ chrome.cookies        │                       │ Navigation Timings    │
     │ Session State Vector  │                       │ Identity Consistency  │
     └───────────┬───────────┘                       └───────────┬───────────┘
                 │                                               │
                 │                 chrome.runtime                │
                 └───────────────────────┬───────────────────────┘
                                         │
                                         ▼
                             ┌───────────────────────┐
                             │  Allowlist Projection │
                             │  (interface.js)      │
                             └───────────┬───────────┘
                                         │
                                         ▼
                             ┌───────────────────────┐
                             │    Model Interface    │
                             │ (Passive Evaluators)  │
                             └───────────────────────┘
```

---

## Vector Scopes & Serialization

Features are stored memory-only in `chrome.storage.session` using per-tab keys (`visor:tab:{tabId}`).
Updates are strictly serialized through an async queue (`enqueue(tabId, fn)`) and applied using atomic mutations (`mutateVector(tabId, fn)`).

### Scopes
1. **Navigation Scope**: Features specific to the active document:
   - **Origin-identity leakage (class-generic, the load-bearing signal)**: `identity_host_mismatch_header`, `n_identity_mismatch_header`, `identity_match_ratio_header`, `n_foreign_origin_headers`.
   - Network & Redirect: `nav_redirect_hop_count`, `cross_origin_hop_count`.
   - Entry path: `has_referer`, `entry_path`.
   - Request Stream: `n_requests`, per-type counters (`n_document`, `n_script`, `n_stylesheet`, `n_image`, `n_font`, `n_xhr`, `n_other`), `n_hosts`, `third_party_ratio`, `same_host_ratio`, `n_cached`, `cache_ratio`, `n_failed`.
   - Cookie Jar: `cookie_domain_mismatch`, `n_cookies`, `n_host_only_cookies`.
   - DOM & Credential Gating: `has_password_field`, `n_password_fields`, `n_forms`, `form_action_mismatch`, `script_src_is_opaque_root_path`, `n_opaque_root_scripts`, iframe overlays, identity mismatch, storage keys, navigation timings.
   - Cleared upon `onBeforeNavigate` to a new document URL.
2. **Session Scope**: Features accumulated across navigations within the tab — `session_redirect_hop_count`, `session_cross_origin_hop_count`, `ever_saw_cross_origin_hop`, and **`ever_saw_identity_mismatch_header`**. The last one matters: the credential page may not carry the leaking header, but an earlier page in the same tab did. Maintained until the tab is closed.

### Merge Invariants
- **Sticky Booleans**: Critical detection flags (`cookie_domain_mismatch`, `iframe_overlap_viewport`, `has_password_field`, `ever_saw_cross_origin_hop`, `ever_saw_identity_mismatch_header`) once set to `true` cannot be overwritten by `false`.
- **Monotonic Counts**: Max-accumulated within a page view to avoid regressions from partial re-scans.
- **Null Safety**: Undefined and null values never wipe existing non-null evidence. A measured zero is `0`, never `null`.

---

## Shared Feature Contract

See [FEATURE_CONTRACT.md](FEATURE_CONTRACT.md) for the exact specification of all features
extracted across both `visor` and `aitm-harness`, and the final feature set in
[`../aitm_final_feature_set.md`](../aitm_final_feature_set.md).

