// models/clickjacking_model.js
// Clickjacking classifier.
//
// GAP: no trained model. A placeholder must never produce a verdict that
// gates the page or raises an interstitial, so this always reports 'safe'.

export function classify(fv) {
  return { verdict: 'safe', score: 0.0, module: 'clickjacking' };
}