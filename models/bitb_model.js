// models/bitb_model.js
// BiTB (Browser-in-the-Browser / fake popup) classifier.
//
// GAP: Stub. Replace with a compiled model with the same classify() signature.
//
// TEMPORARY heuristic: window.open from a page that already has cookie domain
// mismatch or form action mismatch is the strongest BiTB signal. We also
// weight identity host mismatch since BiTB pages often spoof the landing host.

export function classify(fv) {
  if (!fv) return { verdict: 'safe', score: 0.0, module: 'bitb' };

  // TEMPORARY heuristic — not a trained model
  let score = 0.0;

  if (fv.cookie_domain_mismatch === true)  score += 0.50;
  if (fv.identity_host_mismatch === true)  score += 0.30;
  if (fv.form_action_mismatch === true)    score += 0.15;

  score = Math.min(score, 1.0);
  const verdict = score >= 0.5 ? 'suspicious' : 'safe';

  return { verdict, score: parseFloat(score.toFixed(3)), module: 'bitb' };
}
