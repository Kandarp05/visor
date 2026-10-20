// models/interface.js
// Single public surface for all classifiers.
// background.js imports this; the four model files are the only things
// that change when real trained models are dropped in.
//
// Contract (every model file must satisfy):
//   Input:  featureVector object (may be partially null — tolerate it)
//   Output: { verdict: "safe" | "suspicious", score: number (0–1), module: string }

import { classify as classifyAitm }        from './aitm_model.js';
import { classify as classifyBitbModel }   from './bitb_model.js';
import { classify as classifyHomograph }   from './homograph_model.js';
import { classify as classifyCjModel }     from './clickjacking_model.js';

/**
 * Run all four classifiers against the feature vector.
 * Returns an array of four result objects (one per module), in priority order.
 * The gating logic uses the first suspicious result it finds.
 */
export function classifyAll(featureVector) {
  return [
    classifyAitm(featureVector),
    classifyBitbModel(featureVector),
    classifyHomograph(featureVector),
    classifyCjModel(featureVector),
  ];
}

/** Run only the BiTB classifier (called on window.open interception). */
export function classifyBitb(featureVector) {
  return classifyBitbModel(featureVector);
}

/** Run only the clickjacking classifier (called on iframe detection). */
export function classifyClickjacking(featureVector) {
  return classifyCjModel(featureVector);
}
