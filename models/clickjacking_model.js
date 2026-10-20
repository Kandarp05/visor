// models/clickjacking_model.js
// Clickjacking classifier.
//
// GAP: Stub. Replace with a compiled model with the same classify() signature.
//
// TEMPORARY heuristic: iframe_overlap_viewport is the defining clickjacking
// signal. Cookie domain mismatch adds confidence that the outer page is
// also malicious (not just a legitimate page with an ad network iframe).

export function classify(fv) {
  if (!fv) return { verdict: 'safe', score: 0.0, module: 'clickjacking' };

  // TEMPORARY heuristic — not a trained model
  let score = 0.0;

  if (fv.iframe_overlap_viewport === true) score += 0.70;
  if (fv.cookie_domain_mismatch === true)  score += 0.20;
  if (fv.has_hsts === false)               score += 0.05;
  if (fv.has_csp === false)                score += 0.05;

  score = Math.min(score, 1.0);
  const verdict = score >= 0.5 ? 'suspicious' : 'safe';

  return { verdict, score: parseFloat(score.toFixed(3)), module: 'clickjacking' };
}
