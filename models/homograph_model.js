// models/homograph_model.js
// Homograph / unicode lookalike domain classifier.
//
// GAP: Stub. Replace with a compiled model with the same classify() signature.
//
// TEMPORARY heuristic: identity host mismatch is the primary homograph signal
// (the canonical/OG host is the "real" brand; the page host is the lookalike).
//
// NOTE: the former domain-age term was removed — the feature was dropped from the
// extension (it leaked browsing history to crt.sh/rdap.org and collapsed subdomains
// to their parent) and is not on the model allowlist.
//
// The vector this receives has already been projected onto the allowlist by
// models/interface.js, so only allowlisted features are visible here.

export function classify(fv) {
  if (!fv) return { verdict: 'safe', score: 0.0, module: 'homograph' };

  // TEMPORARY heuristic — not a trained model
  let score = 0.0;

  if (fv.identity_host_mismatch === true) score += 0.60;
  if (fv.identity_host_mismatch_header === true) score += 0.20;
  if (fv.has_hsts === false)              score += 0.05;

  score = Math.min(score, 1.0);
  const verdict = score >= 0.5 ? 'suspicious' : 'safe';

  return { verdict, score: parseFloat(score.toFixed(3)), module: 'homograph' };
}
