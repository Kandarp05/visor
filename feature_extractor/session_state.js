// feature_extractor/session_state.js
// Per-tab feature vector, stored in chrome.storage.session (memory-only,
// cleared on browser close — never written to disk).
//
// Key format:  "visor:tab:{tabId}"
// Lifecycle:   created on navigation start → updated incrementally
//              by Tier 1 and Tier 2 → read at gating moments → deleted
//              on tab close.

const PREFIX = 'visor:tab:';
const key = (tabId) => `${PREFIX}${tabId}`;

// In-memory queue to serialize async read-modify-write operations per tab.
const tabQueues = new Map();

function enqueue(tabId, fn) {
  const prev = tabQueues.get(tabId) || Promise.resolve();
  const next = prev.then(fn, fn); // continue queue even if previous rejected
  tabQueues.set(tabId, next);
  return next;
}

// Fields whose boolean true signal must NEVER be overwritten by false
const STICKY_BOOLEAN_FIELDS = new Set([
  'cookie_domain_mismatch',
  'set_cookie_domain_mismatch',
  'has_password_field',
  'form_action_mismatch',
  'has_iframe',
  'iframe_overlap_viewport',
  'identity_host_mismatch',
  'ever_saw_cross_origin_hop',
  'has_autocomplete_current_password',
  'has_redirect_to',
  'is_gzipped',
  'is_chunked',
  'has_content_length',
  'has_hsts',
  'has_csp',
  'hdr_hsts',
  'hdr_csp',
  'hdr_xfo',
  'hdr_xcto',
  'hdr_referrer',
  'hdr_permissions',
  'hdr_coop',
  'hdr_coep',
  'hdr_corp',
  'resp_connection_header',
  'resp_connection_close',
  'ever_saw_identity_mismatch_header',
]);

// Counts that must not regress within an active navigation/session
const MONOTONIC_MAX_FIELDS = new Set([
  'session_redirect_hop_count',
  'session_cross_origin_hop_count',
  'nav_redirect_hop_count',
  'redirect_hop_count',
  'nav_cross_origin_hop_count',
  'cross_origin_hop_count',
  'n_password_fields',
  'n_forms',
  'n_inputs',
  'n_hidden_inputs',
  'n_requests',
  'n_document',
  'n_script',
  'n_stylesheet',
  'n_image',
  'n_font',
  'n_xhr',
  'n_other',
  'n_hosts',
  'n_third_party_requests',
  'n_cached',
  'n_failed',
  'n_new_connections',
  'n_identity_mismatch_header',
  'n_foreign_origin_headers',
  'n_opaque_root_scripts',
]);

/**
 * Canonical feature vector shape.
 * Every field starts at null/0/false.
 * Fields are filled progressively — a null means "not yet computed",
 * NOT "false". Callers must tolerate partial vectors.
 */
export function emptyVector(tabId, url = '') {
  return {
    tabId,
    url,
    navigation_id: `nav_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    session_id: `sess_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    session_start_time: Date.now(),
    visits_in_session: 1,
    createdAt: Date.now(),

    // ── Tier 1: network & redirect features ───────────────────────────────
    // Navigation-scoped redirect metrics
    nav_redirect_hop_count: 0,
    redirect_hop_count: 0, // contract alias for nav_redirect_hop_count
    nav_cross_origin_hop_count: 0,
    cross_origin_hop_count: 0, // contract alias for nav_cross_origin_hop_count
    redirect_chain: [],

    // Session-scoped redirect metrics
    session_redirect_hop_count: 0,
    session_cross_origin_hop_count: 0,
    ever_saw_cross_origin_hop: false,

    // Cookie features
    cookie_domain_mismatch: false,
    set_cookie_domain_mismatch: false,
    n_cookies: 0,
    n_host_only_cookies: 0,
    n_parent_domain_cookies: 0,
    parent_domain_ratio: 0.0,

    // Protocol & compression
    protocol: null,
    is_gzipped: false,
    is_chunked: false,
    has_content_length: false,
    resp_connection_header: false,
    resp_connection_close: false,
    content_encoding: null,
    transfer_encoding: null,

    // Security headers (aligned with contract)
    has_hsts: null,
    has_csp: null,
    hdr_hsts: null,
    hdr_csp: null,
    hdr_xfo: null,
    hdr_xcto: null,
    hdr_referrer: null,
    hdr_permissions: null,
    hdr_coop: null,
    hdr_coep: null,
    hdr_corp: null,
    header_score: 0,

    // Navigation & transition
    transition_type: null,
    transition_qualifiers: [],
    url_query_keys: [],
    has_redirect_to: false,

    // ── Entry path (class-generic) ───────────────────────────────────────
    has_referer: null,
    entry_path: null,          // 'direct' | 'link_internal' | 'link_referrer'
    referrer_origin: null,

    // ── IDN homograph (a separate attack class, its own allowlist) ───────
    // Derived purely from the page's hostname, so they are class-generic for
    // the homograph module by construction.
    is_punycode: false,
    mixed_script_flag: false,
    whole_script_confusable_violation: false,
    confusable_char_ratio: 0.0,
    skeleton_exact_match: false,
    skeleton_similarity: 0.0,
    // Display-only: the brand the reference list matched. No model reads it.
    homograph_impersonates: null,
    homograph_bypassed: false,

    // ── Origin-identity leakage via response headers (class-generic) ──────
    identity_host_mismatch_header: null,
    n_identity_mismatch_header: 0,
    identity_match_ratio_header: null,
    link_header_identity_hosts: [],
    n_foreign_origin_headers: 0,
    // Session-scoped sticky: evidence seen on ANY page in this tab's session
    ever_saw_identity_mismatch_header: false,

    // ── Request stream metrics (D2) ───────────────────────────────────────
    n_requests: 0,
    n_document: 0,
    n_script: 0,
    n_stylesheet: 0,
    n_image: 0,
    n_font: 0,
    n_xhr: 0,
    n_other: 0,
    n_hosts: 0,
    req_hosts: [],
    n_third_party_requests: 0,
    third_party_ratio: 0.0,
    same_host_ratio: 1.0,
    n_cached: 0,
    cache_ratio: 0.0,
    n_failed: 0,

    // ── Tier 2: DOM & environment features ────────────────────────────────
    has_password_field: null,
    n_password_fields: 0,
    has_autocomplete_current_password: null,
    n_forms: 0,
    n_inputs: 0,
    n_hidden_inputs: 0,
    form_action_mismatch: null,
    has_iframe: null,
    iframe_overlap_viewport: null,
    identity_host_mismatch: null,
    script_src_is_opaque_root_path: null,
    n_opaque_root_scripts: 0,

    // Storage keys
    localStorage_keys: [],
    sessionStorage_keys: [],

    // Environment & timing
    character_set: null,
    viewport_w: null,
    viewport_h: null,
    dpr: null,
    n_new_connections: 0,
    connection_reuse_ratio: 0.0,
    dns_ms: null,
    connect_ms: null,
    ssl_ms: null,
    ttfb_ms: null,
    download_ms: null,
    dom_interactive_ms: null,
    dom_content_loaded_ms: null,
    load_event_ms: null,
  };
}

/**
 * Execute an atomic read-modify-write operation on the tab vector.
 * Guaranteed to be serialized through enqueue, eliminating race conditions.
 */
export function mutateVector(tabId, mutatorFn) {
  return enqueue(tabId, async () => {
    const k = key(tabId);
    const stored = await chrome.storage.session.get(k);
    const current = stored[k] || emptyVector(tabId, '');
    const updated = await mutatorFn(current);
    if (updated) {
      await chrome.storage.session.set({ [k]: updated });
    }
    return updated;
  });
}

/**
 * Create or reset the vector for a tab when navigation starts.
 * Navigation-scoped fields reset; session-accumulated fields persist.
 */
export function createVector(tabId, url) {
  return enqueue(tabId, async () => {
    const k = key(tabId);
    const stored = await chrome.storage.session.get(k);
    const existing = stored[k];

    // If navigating to the same URL or sub-resource in the same page,
    // preserve already computed features rather than wiping them.
    if (existing && existing.url === url) {
      return existing;
    }

    const v = emptyVector(tabId, url);

    // Carry over session-accumulated context across navigations
    if (existing) {
      v.session_id = existing.session_id || v.session_id;
      v.session_start_time = existing.session_start_time || v.session_start_time;
      v.session_redirect_hop_count = existing.session_redirect_hop_count || 0;
      v.session_cross_origin_hop_count = existing.session_cross_origin_hop_count || 0;
      v.ever_saw_cross_origin_hop = Boolean(existing.ever_saw_cross_origin_hop);
      v.ever_saw_identity_mismatch_header = Boolean(
        existing.ever_saw_identity_mismatch_header
      );
      v.visits_in_session = (existing.visits_in_session || 1) + 1;
    }

    await chrome.storage.session.set({ [k]: v });
    return v;
  });
}

/**
 * Merge a patch object into the existing vector.
 * Serialized per tabId via mutateVector, respecting sticky booleans and monotonic counts.
 */
export function updateVector(tabId, patch) {
  if (!patch || typeof patch !== 'object') return Promise.resolve(null);

  return mutateVector(tabId, (current) => {
    const updated = { ...current };

    for (const [k, v] of Object.entries(patch)) {
      if (v === undefined) continue;

      if (STICKY_BOOLEAN_FIELDS.has(k)) {
        // Sticky boolean: true never gets overwritten by false/null
        updated[k] = Boolean(current[k] || v);
      } else if (MONOTONIC_MAX_FIELDS.has(k) && typeof v === 'number') {
        // Monotonic counts within a view: non-regressive
        updated[k] = Math.max(current[k] ?? 0, v);
      } else if (v !== null || current[k] === null || current[k] === undefined) {
        // Only overwrite with non-null value, unless current was null
        updated[k] = v;
      }
    }

    // Keep aliases synced
    if ('nav_redirect_hop_count' in updated) {
      updated.redirect_hop_count = updated.nav_redirect_hop_count;
    }
    if ('nav_cross_origin_hop_count' in updated) {
      updated.cross_origin_hop_count = updated.nav_cross_origin_hop_count;
    }

    return updated;
  });
}

/** Read the current vector for a tab. Returns null if none exists. */
export async function getVector(tabId) {
  const stored = await chrome.storage.session.get(key(tabId));
  return stored[key(tabId)] ?? null;
}

/** Delete the vector for a tab (called on tab close). */
export function deleteVector(tabId) {
  tabQueues.delete(tabId);
  return chrome.storage.session.remove(key(tabId));
}
