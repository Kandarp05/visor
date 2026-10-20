// models/homograph_model.js
// Homograph / unicode lookalike domain classifier.
//
// GAP: Stub. Replace with a compiled model with the same classify() signature.
//
// TEMPORARY heuristic: identity host mismatch is the primary homograph signal
// (the canonical/OG host is the "real" brand; the page host is the lookalike).
// Domain age is a strong secondary signal (fresh domains impersonating brands).

export function classify(fv) {
  if (!fv) return { verdict: 'safe', score: 0.0, module: 'homograph' };

  // TEMPORARY heuristic — not a trained model
  let score = 0.0;

  if (fv.identity_host_mismatch === true) score += 0.60;
  if (fv.domain_age_days !== null && fv.domain_age_days < 7)  score += 0.25;
  if (fv.domain_age_days !== null && fv.domain_age_days < 30) score += 0.10;
  if (fv.has_hsts === false)              score += 0.05;

  score = Math.min(score, 1.0);
  const verdict = score >= 0.5 ? 'suspicious' : 'safe';

  return { verdict, score: parseFloat(score.toFixed(3)), module: 'homograph' };
}
