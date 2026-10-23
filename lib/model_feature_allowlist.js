// lib/model_feature_allowlist.js
// Single source of truth for what a model is allowed to see.
//
// The rule: a feature is admissible only if its benign/AiTM correlation follows from
// the attack being a proxy — not from our lab, our kit's implementation, our origin
// site's configuration, our deployment, or our capture protocol.
//
// See ../aitm_final_feature_set.md for the full rationale.

/**
 * The model-facing allowlist. Every feature here must be produced identically by
 * the dataset (aitm-harness/crawler/extract.py) and by the extension.
 */
export const MODEL_FEATURE_ALLOWLIST = [
  // ── Origin-identity leakage (the core class-generic signal) ──────────────
  'identity_host_mismatch_header',
  'n_identity_mismatch_header',
  'identity_match_ratio_header',
  'ever_saw_identity_mismatch_header',
  'identity_host_mismatch',
  'form_action_mismatch',
  'n_foreign_origin_headers',
  // The page's cookies are scoped to a different origin than the page itself.
  // NOTE: in our corpus this fires because the kit serves on a subdomain and scopes
  // its session cookie to the parent. The *form* is class-generic; treat it as a
  // supporting signal, never as sufficient on its own.
  'cookie_domain_mismatch',

  // ── Entry path ───────────────────────────────────────────────────────────
  'has_referer',
  'entry_path',
  'redirect_hop_count',
  'cross_origin_hop_count',

  // ── Proxy-shaped request stream ──────────────────────────────────────────
  'n_third_party_requests',
  'third_party_ratio',
  'script_src_is_opaque_root_path',
  'n_opaque_root_scripts',

  // ── Neutral scaffolding (no label information; lets the model condition) ─
  'n_requests',
  'n_document',
  'n_script',
  'n_stylesheet',
  'n_image',
  'n_font',
  'n_xhr',
  'n_other',
  'n_hosts',
  'same_host_ratio',
  'n_cached',
  'cache_ratio',
  'n_failed',
  'n_forms',
  'n_inputs',
  'n_hidden_inputs',
  'n_password_fields',
  'has_password_field',
  'has_autocomplete_current_password',
  'n_cookies',
  'n_host_only_cookies',
  'viewport_w',
  'viewport_h',
  'dpr',
  'character_set',
];

/**
 * The homograph module's allowlist.
 *
 * This module detects a different attack class — an IDN lookalike domain — so
 * its admissibility rule is different too. A homograph feature is admissible
 * when it is a property of the DOMAIN NAME alone: the attack is a registered
 * domain whose characters impersonate another, so anything derived purely from
 * the hostname's Unicode characters is class-generic by construction. Nothing
 * here can be a property of our lab, our kit, our origin site or our capture
 * protocol, because none of those touch the string.
 *
 * `homograph_impersonates` is the brand the reference list matched. It is a
 * display-only field (it names the target for the user); no model reads it.
 */
export const HOMOGRAPH_FEATURE_ALLOWLIST = [
  'is_punycode',
  'mixed_script_flag',
  'whole_script_confusable_violation',
  'confusable_char_ratio',
  'skeleton_exact_match',
  'skeleton_similarity',
];

/**
 * Everything the extension collects but no model may see.
 * `category`:
 *   lab-infrastructure  — our IPs, hosts, Caddy, Cloudflare account, Apache/PHP build,
 *                          site title, URL paths
 *   kit-implementation  — a property of this particular proxy build
 *   origin-config       — a property of how the legitimate site is configured
 *   deployment          — latency, caching and protocol choices of this deployment
 *   capture-artifact    — a property of our capture protocol
 */
export const FEATURE_QUARANTINE = {
  // lab-infrastructure
  remote_ip: 'lab-infrastructure',
  server: 'lab-infrastructure',
  x_powered_by: 'lab-infrastructure',
  via: 'lab-infrastructure',
  alt_svc: 'lab-infrastructure',
  etag: 'lab-infrastructure',
  last_modified: 'lab-infrastructure',
  date: 'lab-infrastructure',
  content_type: 'lab-infrastructure',
  page_host: 'lab-infrastructure',
  page_base: 'lab-infrastructure',
  session_entry_base: 'lab-infrastructure',
  ua: 'lab-infrastructure',
  title: 'lab-infrastructure',
  cookie_names: 'lab-infrastructure',
  canonical_hosts: 'lab-infrastructure',
  og_hosts: 'lab-infrastructure',
  twitter_hosts: 'lab-infrastructure',
  jsonld_hosts: 'lab-infrastructure',
  form_action_hosts: 'lab-infrastructure',
  redirect_urls: 'lab-infrastructure',
  url_query_keys: 'lab-infrastructure',
  page_type: 'lab-infrastructure',
  device: 'lab-infrastructure',
  network: 'lab-infrastructure',
  locale: 'lab-infrastructure',
  os: 'lab-infrastructure',
  effective_type: 'lab-infrastructure',
  referrer_origin: 'lab-infrastructure',
  link_header_identity_hosts: 'lab-infrastructure',
  req_hosts: 'lab-infrastructure',
  redirect_chain: 'lab-infrastructure',

  // kit-implementation
  protocol: 'kit-implementation',
  is_gzipped: 'kit-implementation',
  is_chunked: 'kit-implementation',
  has_content_length: 'kit-implementation',
  content_encoding: 'kit-implementation',
  transfer_encoding: 'kit-implementation',
  resp_connection_header: 'kit-implementation',
  resp_connection_close: 'kit-implementation',
  n_new_connections: 'kit-implementation',
  connection_reuse_ratio: 'kit-implementation',
  has_evilinx_style_cookie: 'kit-implementation',
  n_parent_domain_cookies: 'kit-implementation',
  parent_domain_ratio: 'kit-implementation',
  has_wordpress_logged_in: 'kit-implementation',
  n_secure_cookies: 'kit-implementation',
  n_samesite_none: 'kit-implementation',
  n_samesite_lax: 'kit-implementation',
  n_samesite_strict: 'kit-implementation',
  n_session_cookies: 'kit-implementation',
  n_http_only_cookies: 'kit-implementation',
  secure_cookie_ratio: 'kit-implementation',
  samesite_none_ratio: 'kit-implementation',
  host_only_ratio: 'kit-implementation',

  // origin-config
  hdr_hsts: 'origin-config',
  hdr_csp: 'origin-config',
  hdr_xfo: 'origin-config',
  hdr_xcto: 'origin-config',
  hdr_referrer: 'origin-config',
  hdr_permissions: 'origin-config',
  hdr_coop: 'origin-config',
  hdr_coep: 'origin-config',
  hdr_corp: 'origin-config',
  has_hsts: 'origin-config',
  has_csp: 'origin-config',
  header_score: 'origin-config',
  has_redirect_to: 'origin-config',
  n_identity_urls: 'origin-config',
  n_identity_mismatch: 'origin-config',
  identity_match_ratio: 'origin-config',
  form_same_origin: 'origin-config',
  has_cache_control: 'origin-config',
  has_age: 'origin-config',
  has_etag: 'origin-config',
  has_expires: 'origin-config',
  has_last_modified: 'origin-config',
  has_vary: 'origin-config',
  has_server: 'origin-config',
  has_x_powered_by: 'origin-config',
  set_cookie_count: 'origin-config',

  // deployment
  ttfb_ms: 'deployment',
  dcl_ms: 'deployment',
  load_ms: 'deployment',
  duration_ms: 'deployment',
  main_dns_ms: 'deployment',
  main_connect_ms: 'deployment',
  main_ssl_ms: 'deployment',
  main_ttfb_ms: 'deployment',
  main_download_ms: 'deployment',
  dns_ms: 'deployment',
  connect_ms: 'deployment',
  ssl_ms: 'deployment',
  download_ms: 'deployment',
  dns_ms_mean: 'deployment',
  dns_ms_p95: 'deployment',
  connect_ms_mean: 'deployment',
  connect_ms_p95: 'deployment',
  ssl_ms_mean: 'deployment',
  ssl_ms_p95: 'deployment',
  ttfb_ms_mean: 'deployment',
  ttfb_ms_p95: 'deployment',
  download_ms_mean: 'deployment',
  download_ms_p95: 'deployment',
  resource_duration_mean_ms: 'deployment',
  resource_duration_p95_ms: 'deployment',
  n_longtasks: 'deployment',
  n_resources: 'deployment',
  encoded_data_length_total: 'deployment',
  n_headers_total: 'deployment',
  n_remote_ips: 'deployment',

  // capture-artifact
  lure_status: 'capture-artifact',
  warmup: 'capture-artifact',
  cache_state: 'capture-artifact',
  http2_disabled: 'capture-artifact',
  extra_cookie_names: 'capture-artifact',
  started_at: 'capture-artifact',
  session_id: 'capture-artifact',
  navigation_id: 'capture-artifact',
  visit_id: 'capture-artifact',
  visit_index: 'capture-artifact',
  visits_in_session: 'capture-artifact',
  session_start_time: 'capture-artifact',
  createdAt: 'capture-artifact',
  transition_type: 'capture-artifact',
  transition_qualifiers: 'capture-artifact',
  n_console: 'capture-artifact',
  n_page_errors: 'capture-artifact',
  n_documents: 'capture-artifact',
  n_initiator_parser: 'capture-artifact',
  n_initiator_script: 'capture-artifact',
  n_initiator_other: 'capture-artifact',
  n_from_sw: 'capture-artifact',
  ls_key_names: 'capture-artifact',
  ss_key_names: 'capture-artifact',
  input_types: 'capture-artifact',
  input_names: 'capture-artifact',
  tabId: 'capture-artifact',
  url: 'capture-artifact',
};

const ALLOWLIST_SET = new Set(MODEL_FEATURE_ALLOWLIST);
const HOMOGRAPH_ALLOWLIST_SET = new Set(HOMOGRAPH_FEATURE_ALLOWLIST);

/**
 * Project a feature vector onto an allowlist.
 * A model physically cannot read a quarantined feature, whatever it asks for.
 *
 * `list` defaults to the AiTM allowlist. The homograph module has its own,
 * because the two modules detect different attack classes and their
 * admissibility rules differ.
 */
export function projectToAllowlist(fv, list = MODEL_FEATURE_ALLOWLIST) {
  if (!fv || typeof fv !== 'object') return {};
  const out = {};
  for (const k of list) {
    if (k in fv) out[k] = fv[k];
  }
  return out;
}

/** Names present in the vector but not on the allowlist (diagnostics only). */
export function quarantinedKeys(fv) {
  if (!fv || typeof fv !== 'object') return [];
  return Object.keys(fv).filter((k) => !ALLOWLIST_SET.has(k));
}

export { HOMOGRAPH_ALLOWLIST_SET };
