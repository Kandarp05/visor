// models/aitm_model.js
// AiTM (Adversary-in-the-Middle / session-hijack proxy) classifier.
//
// GAP: This is a stub. Replace with a compiled model (e.g. via m2cgen)
// that has the same classify(featureVector) signature.
//
// Heuristic stub (labeled TEMPORARY — not a real model result):
// Uses cookie_domain_mismatch and form_action_mismatch as strong signals,
// redirect chain depth as a weaker signal. This is intentionally simple
// so "it looks like it's doing something" during development. It will
// be replaced by a trained classifier before any evaluation.

export function classify(fv) {
  if (!fv) return { verdict: 'safe', score: 0.0, module: 'aitm' };

  // TEMPORARY heuristic — not a trained model
  let score = 0.0;

  if (fv.cookie_domain_mismatch === true)  score += 0.55;
  if (fv.form_action_mismatch === true)    score += 0.25;
  if ((fv.redirect_hop_count ?? 0) >= 3)  score += 0.10;
  if (fv.has_hsts === false)               score += 0.05;
  if (fv.domain_age_days !== null && fv.domain_age_days < 30) score += 0.05;

  score = Math.min(score, 1.0);
  const verdict = score >= 0.5 ? 'suspicious' : 'safe';

  return { verdict, score: parseFloat(score.toFixed(3)), module: 'aitm' };
}
