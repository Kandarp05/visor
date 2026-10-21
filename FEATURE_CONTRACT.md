# Visor Phishing Detector — Shared Feature Contract

This document specifies the exact contract between:
1. **Dataset Feature Extractor** (`aitm-harness/crawler/extract.py`), which derives features from raw crawler traces (`data-v2/raw/`).
2. **Live Extension Extractor** (`visor/feature_extractor/*`), which extracts browser-observable signals in real time inside Chrome MV3.

---

## 0. v2 — the allowlist is the contract

> **The single source of truth for what a model may see is
> `visor/lib/model_feature_allowlist.js`.**
> The final feature set is specified in `../aitm_final_feature_set.md`.
> The generalizability evidence is in `../aitm-harness/data-v2/GENERALIZABILITY.md`.

Three mechanisms enforce it, so a lab-specific feature cannot reach a model even by
accident:

1. `crawler/extract.py` reads the allowlist and **refuses to write** a non-allowlisted
   column into the training table (`data-v2/features/visits.jsonl`). Everything else
   goes to `data-v2/features/analysis.jsonl`, which is for stratification and QA only.
2. `models/interface.js` **projects** the vector onto the allowlist before any model
   sees it.
3. `model/test_serving.py` asserts that injecting `remote_ip`, `server`, `ua`,
   `page_host`, `title`, `protocol` and `hdr_hsts` changes the score by exactly zero.

### The v2 table split

| file | contents | trainable? |
|---|---|---|
| `data-v2/features/visits.jsonl` | allowlist + neutral scaffolding | **yes** |
| `data-v2/features/analysis.jsonl` | environment axes, origin literals, kit/deployment/capture features | **no** |
| `data-v2/features/snapshots.jsonl` | per-snapshot rows (dcl / load / settle) | no (not used for v1 training) |

### Features added in v2

| feature | scope | source (both sides) |
|---|---|---|
| `identity_host_mismatch_header` | navigation | `Link` response header, identity-bearing relations only |
| `n_identity_mismatch_header` | navigation | count of foreign origin hosts in that header |
| `identity_match_ratio_header` | navigation | matched / total identity hosts; null when the set is empty |
| `n_foreign_origin_headers` | navigation | foreign hosts named by `link` / `location` / `content-location` / `x-pingback` |
| `ever_saw_identity_mismatch_header` | **session, sticky** | true if any response in this tab's session named a foreign origin |
| `has_referer` | navigation | the main document request carried a `Referer` |
| `entry_path` | navigation | `redirect_entry` / `direct` / `link_internal` / `link_referrer` |
| `script_src_is_opaque_root_path` | navigation | a script whose path matches `/[0-9a-f]{32,64}\.js$` |
| `n_opaque_root_scripts` | navigation | how many such scripts |
| `nav_failed` | navigation | the navigation failed — not an observation of the page; dropped before training |

### Two helpers that must stay identical

These are the only places the dataset and the extension may diverge. They are duplicated
verbatim in `crawler/extract.py` and `feature_extractor/tier1_network.js`:

1. **eTLD+1** — last two labels, leading `www.` stripped. Used for third-party
   classification and for cross-origin hop counting.
2. **Identity-bearing `Link` relations** — `canonical`, `shortlink`,
   `https://api.w.org/`, `alternate`, `edituri`, `hub`. **`rel="profile"` is NOT
   identity-bearing** — excluding it is what keeps `gmpg.org` from flagging every
   benign page.

---

## 1. Vector Scopes and Lifecycle

A tab in Visor maintains two distinct scopes of features:

- **Navigation Scope** (`nav_*`): Reset to baseline values upon `webNavigation.onBeforeNavigate` for each new document. Reflects the active page view.
- **Session Scope** (`session_*`): Persisted across navigations within the lifetime of a browser tab. Accumulates history across the sequence of visits until tab closure (`chrome.tabs.onRemoved`).

| Scope | Vector Fields | Reset Condition |
| :--- | :--- | :--- |
| **Navigation** | `url`, `protocol`, `has_hsts`, `has_csp`, `cookie_domain_mismatch`, `n_cookies`, `is_gzipped`, `is_chunked`, `has_content_length`, `resp_connection_header`, `resp_connection_close`, `n_new_connections`, `connection_reuse_ratio`, `n_requests`, `n_hosts`, `third_party_ratio`, `same_host_ratio`, `n_cached`, `cache_ratio`, `n_failed`, `nav_redirect_hop_count` (`redirect_hop_count`), `nav_cross_origin_hop_count` (`cross_origin_hop_count`), DOM & timing features | `webNavigation.onBeforeNavigate` (different URL) |
| **Session** | `session_id`, `session_start_time`, `visits_in_session`, `session_redirect_hop_count`, `session_cross_origin_hop_count`, `ever_saw_cross_origin_hop` | Tab close (`chrome.tabs.onRemoved`) |

---

## 2. Null Semantics Convention (Null vs. Zero vs. Absent)

To prevent models from mistaking uncaptured fields for genuine signals or fabricating spurious splits on missing-value masks, the following strict convention applies across both the dataset and extension:

1. **Measured and Absent**: Emitted as `0`, `0.0`, `False`, or `""` (empty string). Never null.
   - Examples: `error: ""` (no error occurred), `content_encoding: ""` (no compression header sent), `transfer_encoding: ""` (no chunked header sent), `n_cached: 0`.
2. **Pooled / Reused Connection Phases (CDP `-1` / Performance API `0`)**: Emitted as `0.0` ms.
   - Chrome's CDP `Network.ResourceTiming` reports `-1` when a handshake phase did not occur because the request was multiplexed over an existing pooled connection.
   - W3C Navigation and Resource Timing APIs report `0` for these unexecuted phases.
   - Both the dataset extractor and extension treat `-1` and `0` as a measured fact: the connection was already established, requiring `0.0` ms of additional handshake delay.
   - Emitting `null` here would create a spurious split (84% benign null vs 0% AiTM null in un-pooled proxy setups).
3. **Never Captured**: Omitted from the dataset entirely.
   - Examples: `text_length`, `dom_node_count`, and `device_memory` were never captured by the recorder and are excluded from the dataset output.
4. **Not Applicable (`null`)**: Allowed **only** when a feature fundamentally cannot exist for that visit:
   - `lure_status`: null for benign visits (no lure request was executed; 10,687 / 12,708 rows).
   - `form_same_origin`: null when the document contains 0 HTML forms (10,212 / 12,708 rows).
   - `secure_cookie_ratio`, `samesite_none_ratio`, `host_only_ratio`, `parent_domain_ratio`: null when the document has 0 cookies (division by zero / no cookies present; 6,402 / 12,708 rows).
   - `identity_match_ratio`: null when the document contains 0 identity tags (canonical, OG, JSON-LD; 5,095 / 12,708 rows).
   - `resource_duration_mean_ms`, `resource_duration_p95_ms`: null when 0 subresource performance entries exist (2,544 / 12,708 rows).
   - `warmup`: null for initial cold-start sessions where the profile was unthrottled baseline (64 / 12,708 rows).
   - `ssl_ms`: null **only** for plain HTTP requests (TLS negotiation was never attempted). For HTTPS over pooled connections, `ssl_ms` is `0.0`.

---

## 3. Generality Tiers & Attack Surface Taxonomy

Features are classified into four distinct generality tiers to guide model training and prevent overfitting to lab artifacts:

1. **`class-generic`**: Fundamental, intrinsic properties of the attack class that generalize across arbitrary implementations and target origins.
   - Examples: `cookie_domain_mismatch`, `form_action_mismatch`, `has_password_field`, `iframe_overlap_viewport`, `identity_host_mismatch`, `has_autocomplete_current_password`.
2. **`proxy-implementation-specific`**: Artifacts arising from specific reverse-proxy architectures, web server implementations, or runtime defaults (e.g. Evilginx written in Go).
   - Examples: `resp_connection_header`, `resp_connection_close`, `n_new_connections`, `connection_reuse_ratio`, `is_chunked`, `is_gzipped`.
   > [!IMPORTANT]
   > `Connection: close` and zero connection reuse are **proxy-implementation-specific**, NOT class-generic AiTM properties.
   > In our testbed, Evilginx re-serializes responses and does not keep connections alive (`Connection: close`), forcing a fresh TLS handshake for every subresource (AiTM mean 10.08 new connections vs benign 0.20).
   > However, an AiTM proxy engineered with connection pooling, keep-alive, or HTTP/2 multiplexing would not exhibit this artifact. Classifiers relying on this signal alone would fail against advanced proxies.
3. **`origin-specific`**: Artifacts tied to the specific target origin or server stack (e.g., WordPress configuration, hosting provider).
   - Examples: `hdr_hsts`, `has_redirect_to`, `character_set`, `viewport_w`, `viewport_h`.
4. **`capture-artifact`**: Artifacts produced by crawler instrumentation, synthetic session harness, or capture protocols.
   - Examples: `warmup`, `session_id`, `lure_status`, `transition_type`.

---

## 4. Feature Specification Matrix

### 4.1 Identity & Navigation Features

| Feature Name | Generality Tier | Type | Semantics | Dataset Source | Extension Source | Null Condition |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `url` | `origin-specific` | `string` | Full URL of the page | `d["final_url"]` | `details.url` | Unset before initial navigation |
| `status` | `class-generic` | `int` | Main document HTTP status | `d["status"]` | `details.statusCode` | Unset before headers received |
| `protocol` | `proxy-implementation-specific` | `string \| null` | HTTP protocol version (`"h2" \| "http/1.1" \| "h3"`) | `main_req["protocol"]` | Regex token match on `statusLine` (`/^HTTP\/2\b/`, `/^HTTP\/1\.1\b/`, `/^HTTP\/3\b/`) | Inconclusive / outside vocabulary |
| `redirect_hop_count` | `class-generic` | `int` | Honest observed HTTP redirect hops for document | Count of `reqs` with `redirect_response` | Main frame `onBeforeRedirect` increments | Always int (`0` if no redirects) |
| `cross_origin_hop_count` | `class-generic` | `int` | Redirects where eTLD+1 changed | `registrable(target) != registrable(source)` | `onBeforeRedirect` with `registrableDomain` | Always int (`0` if no cross-origin hops) |
| `session_redirect_hop_count` | `class-generic` | `int` | Cumulative redirects across session | Sum of `redirect_hop_count` in session | Tab session accumulator | Always int (`0` default) |
| `session_cross_origin_hop_count` | `class-generic` | `int` | Cumulative cross-origin redirects in session | Sum of cross-origin hops in session | Tab session accumulator | Always int (`0` default) |
| `ever_saw_cross_origin_hop` | `class-generic` | `bool` | True if any redirect crossed eTLD+1 in session | Any cross-origin hop in session | Sticky boolean in `session_state.js` | Always bool (`false` default) |
| `transition_type` | `capture-artifact` | `string \| null` | Navigation transition type | `null` (crawler synthetic) | `webNavigation.onCommitted` | Not committed |
| `url_query_keys` | `origin-specific` | `list[str]` | Query parameter keys in final URL | `urlparse(d["final_url"]).query` | `URL(details.url).searchParams.keys()` | Empty list `[]` |
| `has_redirect_to` | `origin-specific` | `bool` | True if `redirect_to` is a query parameter | `"redirect_to" in query` | `"redirect_to" in searchParams` | Always bool (`false` default) |
| `error` | `class-generic` | `string` | Error string if navigation failed | `d.get("error") or ""` | `details.error` in `onErrorOccurred` | Always string (`""` default) |

---

### 4.2 Request Stream & Connection Reuse Signals

First-party vs. third-party requests are determined using `registrableDomain(host)`: the last two labels of the hostname, stripping leading `www.`.
A request is first-party if `registrableDomain(req_host) === registrableDomain(page_host)`.

> [!NOTE]
> In the current testbed corpus, `third_party_ratio == 0.0` and `n_hosts == 1` for all 12,708 visits because the benign WordPress site and Evilginx twin serve no external third-party assets. The feature is implemented according to the general specification.

| Feature Name | Generality Tier | Type | Semantics | Dataset Source | Extension Source | Null Condition |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `n_requests` | `proxy-implementation-specific` | `int` | Total HTTP requests in navigation | `len(reqs)` | `onBeforeRequest` counter | Always int (`0` default) |
| `n_document` | `class-generic` | `int` | Document requests (main and sub frames) | `type == "Document"` | `type in ("main_frame", "sub_frame")` | Always int (`0` default) |
| `n_script` | `origin-specific` | `int` | JavaScript requests | `type == "Script"` | `type == "script"` | Always int (`0` default) |
| `n_stylesheet` | `origin-specific` | `int` | CSS stylesheet requests | `type == "Stylesheet"` | `type == "stylesheet"` | Always int (`0` default) |
| `n_image` | `origin-specific` | `int` | Image asset requests | `type == "Image"` | `type == "image"` | Always int (`0` default) |
| `n_font` | `origin-specific` | `int` | Webfont requests | `type == "Font"` | `type == "font"` | Always int (`0` default) |
| `n_xhr` | `origin-specific` | `int` | Asynchronous fetch / XHR / ping requests | `type in ("XHR", "Fetch")` | `type in ("xmlhttprequest", "ping")` | Always int (`0` default) |
| `n_other` | `origin-specific` | `int` | Other requests (media, websocket, etc.) | Other types | Other types | Always int (`0` default) |
| `n_hosts` | `class-generic` | `int` | Number of unique hostnames requested | `len(set(req_hosts))` | Size of `req_hosts` set in vector | Always int (`0` default) |
| `n_third_party_requests` | `class-generic` | `int` | Requests to different registrable domain | Count where `registrable != page_base` | Count where `registrable != page_base` | Always int (`0` default) |
| `third_party_ratio` | `class-generic` | `float` | `n_third_party_requests / n_requests` | Computed ratio | Computed ratio | `0.0` if `n_requests == 0` |
| `same_host_ratio` | `class-generic` | `float` | `same_host_requests / n_requests` | Computed ratio | Computed ratio | `1.0` if `n_requests == 0` |
| `n_cached` | `origin-specific` | `int` | Requests fulfilled from browser cache | `from_cache == True` | `onCompleted` with `details.fromCache` | Always int (`0` default) |
| `cache_ratio` | `origin-specific` | `float` | `n_cached / n_requests` | Computed ratio | Computed ratio | `0.0` if `n_requests == 0` |
| `n_failed` | `class-generic` | `int` | Requests that failed | `failed == True` | `onErrorOccurred` counter | Always int (`0` default) |
| `n_new_connections` | `proxy-implementation-specific` | `int` | Count of requests initiating a fresh TCP/TLS handshake | Count where `timing.dnsStart >= 0` | Performance API entries where `connectEnd > 0 && (domainLookupEnd > domainLookupStart \|\| connectEnd > connectStart)` | Always int (`0` default) |
| `connection_reuse_ratio` | `proxy-implementation-specific` | `float` | Ratio of pooled requests (`1.0 - n_new / n_reqs`) | `1.0 - (n_new_connections / n_requests)` | Computed from Performance Resource Timings | Always float (`0.0` default) |

---

### 4.3 Security & Response Headers

Headers are evaluated **case-insensitively**:

| Feature Name | Generality Tier | Type | Semantics | Dataset Source | Extension Source | Null Condition |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `hdr_hsts` (`has_hsts`) | `origin-specific` | `bool` | `Strict-Transport-Security` present | `raw_resp_headers["strict-transport-security"]` | Case-insensitive lookup in `onHeadersReceived` | `null` prior to headers |
| `hdr_csp` (`has_csp`) | `origin-specific` | `bool` | `Content-Security-Policy` present | `raw_resp_headers["content-security-policy"]` | Case-insensitive lookup in `onHeadersReceived` | `null` prior to headers |
| `hdr_xfo` | `origin-specific` | `bool` | `X-Frame-Options` present | `raw_resp_headers["x-frame-options"]` | Case-insensitive lookup in `onHeadersReceived` | `null` prior to headers |
| `hdr_xcto` | `origin-specific` | `bool` | `X-Content-Type-Options` present | `raw_resp_headers["x-content-type-options"]` | Case-insensitive lookup in `onHeadersReceived` | `null` prior to headers |
| `hdr_referrer` | `origin-specific` | `bool` | `Referrer-Policy` present | `raw_resp_headers["referrer-policy"]` | Case-insensitive lookup in `onHeadersReceived` | `null` prior to headers |
| `hdr_permissions` | `origin-specific` | `bool` | `Permissions-Policy` present | `raw_resp_headers["permissions-policy"]` | Case-insensitive lookup in `onHeadersReceived` | `null` prior to headers |
| `hdr_coop` | `origin-specific` | `bool` | `Cross-Origin-Opener-Policy` present | `raw_resp_headers["cross-origin-opener-policy"]` | Case-insensitive lookup in `onHeadersReceived` | `null` prior to headers |
| `hdr_coep` | `origin-specific` | `bool` | `Cross-Origin-Embedder-Policy` present | `raw_resp_headers["cross-origin-embedder-policy"]` | Case-insensitive lookup in `onHeadersReceived` | `null` prior to headers |
| `hdr_corp` | `origin-specific` | `bool` | `Cross-Origin-Resource-Policy` present | `raw_resp_headers["cross-origin-resource-policy"]` | Case-insensitive lookup in `onHeadersReceived` | `null` prior to headers |
| `header_score` | `origin-specific` | `int` | Count of present security headers (`0..6`) | Sum of `(hsts, csp, xfo, xcto, referrer, permissions)` | Calculated in `onHeadersReceived` | Always int (`0` default) |
| `resp_connection_header` | `proxy-implementation-specific` | `bool` | Response carries a `Connection` header | `"connection" in raw_resp_headers` | `"connection" in headerMap` in `onHeadersReceived` | Always bool (`false` default) |
| `resp_connection_close` | `proxy-implementation-specific` | `bool` | Response `Connection` header contains `close` | `"close" in raw_resp_headers.get("connection", "").lower()` | `headerMap["connection"].toLowerCase().includes("close")` | Always bool (`false` default) |

---

### 4.4 Compression & Encoding Signals

`is_gzipped` and `is_chunked` serve as independent compression signals (benign: 9,303 gzip / 31 chunked vs. AiTM: 0 gzip / 2,021 chunked).
`has_content_length` is byte-identical with `is_gzipped` across all 12,708 visits in this corpus (HTTP/2 omits `Content-Length` on streamed responses) and is **redundant** — not to be used as an independent model feature.

| Feature Name | Generality Tier | Type | Semantics | Dataset Source | Extension Source | Null Condition |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `is_gzipped` | `proxy-implementation-specific` | `bool` | `Content-Encoding` contains `gzip` | `raw_resp_headers["content-encoding"]` | Header in `onHeadersReceived` | Always bool (`false` default) |
| `is_chunked` | `proxy-implementation-specific` | `bool` | `Transfer-Encoding` contains `chunked` | `raw_resp_headers["transfer-encoding"]` | Header in `onHeadersReceived` | Always bool (`false` default) |
| `has_content_length` | `proxy-implementation-specific` | `bool` | `Content-Length` header present (redundant with `is_gzipped`) | `"content-length" in raw_resp_headers` | Header in `onHeadersReceived` | Always bool (`false` default) |
| `content_encoding` | `proxy-implementation-specific` | `string` | Raw `Content-Encoding` header value | `raw_resp_headers.get("content-encoding") or ""` | Header in `onHeadersReceived` | Always string (`""` default) |
| `transfer_encoding` | `proxy-implementation-specific` | `string` | Raw `Transfer-Encoding` header value | `raw_resp_headers.get("transfer-encoding") or ""` | Header in `onHeadersReceived` | Always string (`""` default) |

---

### 4.5 Cookie Jar Features

The extension queries `chrome.cookies.getAll({ url: pageUrl })` because Chrome's `domain:` filter restricts to exact match or subdomains, which excludes parent-domain cookies (`.phish.kandarpjindal.in` on `wordpress.phish.kandarpjindal.in`). The `url:` filter retrieves all cookies that would match a request to this URL.

Cookie classification follows the **strict leading-dot contract**:
- **Host-only**: cookie domain has **no leading dot** and strictly equals `page_host`.
- **Parent/domain-scoped**: cookie domain **starts with a leading dot** (`.`) or differs from `page_host`.
- **Mismatch (`cookie_domain_mismatch = true`)**: any cookie visible to the page is parent/domain-scoped.

| Feature Name | Generality Tier | Type | Semantics | Dataset Source | Extension Source | Null Condition |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `cookie_domain_mismatch` | `class-generic` | `bool` | Any cookie domain starts with dot or != page host | Derived from `settle.cookies` | `chrome.cookies.getAll({ url })` inspection | Always bool (`false` default) |
| `set_cookie_domain_mismatch` | `class-generic` | `bool` | Any `Set-Cookie` header domain != page host | `null` (absent from raw CDP captures) | `onHeadersReceived` inspection (all requests) | Always bool (`false` default) |
| `n_cookies` | `class-generic` | `int` | Total cookies visible to page | `len(settle["cookies"])` | `chrome.cookies.getAll({ url })` length | Always int (`0` default) |
| `n_host_only_cookies` | `class-generic` | `int` | Cookies matching host without leading dot | Leading-dot check | Leading-dot check | Always int (`0` default) |
| `n_parent_domain_cookies` | `class-generic` | `int` | Cookies with leading dot or broad domain | Leading-dot check | Leading-dot check | Always int (`0` default) |
| `parent_domain_ratio` | `class-generic` | `float \| null` | `n_parent_domain_cookies / n_cookies` | `pct(n_parent, n_cookies)` | Computed ratio | `null` if `n_cookies == 0` |
| `host_only_ratio` | `class-generic` | `float \| null` | `n_host_only_cookies / n_cookies` | `pct(n_host_only, n_cookies)` | Computed ratio | `null` if `n_cookies == 0` |
| `secure_cookie_ratio` | `origin-specific` | `float \| null` | `n_secure_cookies / n_cookies` | `pct(n_secure, n_cookies)` | Computed ratio | `null` if `n_cookies == 0` |
| `samesite_none_ratio` | `origin-specific` | `float \| null` | `n_samesite_none / n_cookies` | `pct(n_none, n_cookies)` | Computed ratio | `null` if `n_cookies == 0` |

---

### 4.6 DOM & Credential Form Gating

Form interception and submission gating in Visor are strictly scoped to **credential-bearing forms** containing visible human-typed input fields:
1. Input element must not be `type="hidden"`.
2. Input element must be visible (`offsetParent !== null || getClientRects().length > 0`).
3. Input `type` must be one of `password | text | email | tel | number`.
4. Matching criteria:
   - Password: `type="password"` or `autocomplete*="password"`.
   - Email: `type="email"`, `autocomplete*="email"`, or `name*="email"`.
   - Username: `autocomplete*="username"`, `name in ("username", "user", "login", "user_login")`, `id in ("username", "user", "login")`.
   - 2FA/Auth: `autocomplete*="one-time-code"`, `name*="auth"`, `name*="otp"`.
   - *Exclusions*: Wildcards `name*="token"` and `name*="user"` are excluded to prevent intercepting CSRF tokens, OAuth tokens, and hidden user identifiers.
5. `has_password_field` is an independent DOM-scan feature evaluated strictly on `input[type="password"]` and `input[autocomplete*="password" i]`.

| Feature Name | Generality Tier | Type | Semantics | Dataset Source | Extension Source | Null Condition |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `has_password_field` | `class-generic` | `bool` | Document contains password input | `n_password_fields > 0` | `input[type="password"] \| autocomplete*="password"` | `null` before scan |
| `n_password_fields` | `class-generic` | `int` | Count of password inputs | Count in DOM | Length of password field query | Always int (`0` default) |
| `has_autocomplete_current_password` | `class-generic` | `bool` | Password input has `autocomplete="current-password"` | Checked on password inputs | Checked on password inputs | Always bool (`false` default) |
| `n_forms` | `origin-specific` | `int` | Total HTML forms in document | `len(dom["forms"])` | `document.forms.length` | Always int (`0` default) |
| `form_same_origin` | `class-generic` | `int \| null` | Count of forms whose action matches page origin | Count where `action_host == page_host` | Count where `action_host == page_host` | `null` if `n_forms == 0` |
| `form_action_mismatch` | `class-generic` | `bool` | Any credential form submits to different origin | `form_same_origin < n_forms` | Credential form `action` host != page host | Always bool (`false` default) |
| `has_iframe` | `class-generic` | `bool` | Page embeds at least one iframe | Count of iframe elements | `document.querySelectorAll("iframe").length > 0` | `null` before scan |
| `iframe_overlap_viewport` | `class-generic` | `bool` | Iframe covers $\ge 50\%$ viewport with high z-index / low opacity | DOM iframe geometric evaluation | `coversViewport(iframe)` in `tier2_dom.js` | `null` before scan |
| `identity_host_mismatch` | `class-generic` | `bool` | Canonical, OG, or JSON-LD identity host != page host | `id_mismatch > 0` | Canonical/OG/JSON-LD host comparison | `null` before scan |
| `identity_match_ratio` | `class-generic` | `float \| null` | Ratio of matching identity hosts | `pct(id_match, len(all_identity_hosts))` | `id_match / total_identity_hosts` | `null` if 0 identity tags |
| `localStorage_keys` | `origin-specific` | `list[str]` | Keys stored in `localStorage` | `dom["storage"]["local"]` keys | `Object.keys(localStorage)` | Empty list `[]` |
| `sessionStorage_keys` | `origin-specific` | `list[str]` | Keys stored in `sessionStorage` | `dom["storage"]["session"]` keys | `Object.keys(sessionStorage)` | Empty list `[]` |
| `ls_keys` / `ss_keys` | `origin-specific` | `int` | Count of storage keys | Count in storage | Length of storage keys | Always int (`0` default) |
| `n_idb` / `n_sw` / `n_caches` | `origin-specific` | `int` | Count of IndexedDB, service workers, caches | Count in storage snapshot | Evaluated in storage | Always int (`0` default) |

---

### 4.7 Timing Phase Breakdown

Values in milliseconds extracted from Resource/Navigation Timing.
When connections are pooled or reused, CDP reports `-1` and Performance API reports `0`. In both dataset and extension, these phases took measured `0.0` ms of handshake delay, so they are emitted as `0.0`, eliminating spurious null splits.

| Feature Name | Generality Tier | Type | Semantics | Dataset Source | Extension Source | Null Condition |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `dns_ms` | `proxy-implementation-specific` | `float` | DNS resolution latency (ms) | `timing.dnsEnd - timing.dnsStart` (`0.0` if `-1`) | `nav.domainLookupEnd - nav.domainLookupStart` (`0.0` if `0`) | Unmeasured before navigation completes |
| `connect_ms` | `proxy-implementation-specific` | `float` | TCP connection establishment latency (ms) | `timing.connectEnd - timing.connectStart` (`0.0` if `-1`) | `nav.connectEnd - nav.connectStart` (`0.0` if `0`) | Unmeasured before navigation completes |
| `ssl_ms` | `proxy-implementation-specific` | `float \| null` | TLS negotiation latency (ms) | `timing.sslEnd - timing.sslStart` (`0.0` if `-1`) | `nav.connectEnd - nav.secureConnectionStart` (`0.0` if `0`) | `null` **only** for plain HTTP (TLS not applicable) |
| `ttfb_ms` | `proxy-implementation-specific` | `float` | Time to First Byte (ms) | `timing.receiveHeadersStart - timing.sendEnd` | `nav.responseStart - nav.requestStart` | Unmeasured before headers |
| `download_ms` | `origin-specific` | `float` | Response payload download duration (ms) | `timing.receiveHeadersEnd - timing.receiveHeadersStart` | `nav.responseEnd - nav.responseStart` | Unmeasured before download completes |
| `dom_interactive_ms` | `origin-specific` | `float` | Time to DOM interactive (ms) | `dom_timings.domInteractive` | `nav.domInteractive` | Unmeasured before event |
| `dom_content_loaded_ms` | `origin-specific` | `float` | Time to DOMContentLoaded end (ms) | `dom_timings.domContentLoadedEventEnd` | `nav.domContentLoadedEventEnd` | Unmeasured before event |
| `load_event_ms` | `origin-specific` | `float` | Time to Load event end (ms) | `dom_timings.loadEventEnd` | `nav.loadEventEnd` | Unmeasured before event |
