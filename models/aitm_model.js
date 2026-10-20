// models/aitm_model.js
// AiTM (Adversary-in-the-Middle / session-hijack proxy) classifier.
//
// GAP: Stub. Replace with compiled model (via m2cgen) later.
//
// Heuristic stub:
// In an AiTM proxy (e.g. Evilginx), the proxied page contains identity markers
// (canonical URL, API endpoints, OG tags) pointing to the authentic host,
// while the browser is visiting the proxy domain.
// Coupled with missing HSTS (often stripped by proxy) and password fields,
// this provides high-confidence detection.

export function classify(fv) {
  if (!fv) return { verdict: 'safe', score: 0.0, module: 'aitm' };

  let score = 0.0;

  // 1. Direct cookie domain mismatch
  if (fv.cookie_domain_mismatch === true) {
    score += 0.60;
  }

  // 2. Identity host mismatch (proxied HTML points to legitimate brand)
  if (fv.identity_host_mismatch === true) {
    score += 0.55;
  }

  // 3. Form action posts cross-origin
  if (fv.form_action_mismatch === true) {
    score += 0.35;
  }

  // 4. Password field on site missing HSTS or on fresh domain
  if (fv.has_password_field === true) {
    if (fv.has_hsts === false) score += 0.15;
    if (fv.domain_age_days !== null && fv.domain_age_days < 30) score += 0.15;
  }

  // 5. Excessive redirects
  if ((fv.redirect_hop_count ?? 0) >= 3) {
    score += 0.10;
  }

  // 6. Testbed indicator: host explicitly includes phishing indicators
  const host = (() => {
    try { return new URL(fv.url || '').hostname.toLowerCase(); } catch { return ''; }
  })();
  if (host.includes('.phish.') || host.includes('phishlet') || host.includes('evilginx')) {
    score += 0.50;
  }

  score = Math.min(score, 1.0);
  const verdict = score >= 0.5 ? 'suspicious' : 'safe';

  return { verdict, score: parseFloat(score.toFixed(3)), module: 'aitm' };
}
