// models/interface.js
// Single public surface for all classifiers.
// background.js imports this; the four model files are the only things
// that change when real trained models are dropped in.
//
// Contract (every model file must satisfy):
//   Input:  featureVector object (may be partially null — tolerate it)
//   Output: { verdict: "safe" | "suspicious", score: number (0–1), module: string }
//
// IMPORTANT: the vector handed to a model is projected onto the allowlist first
// (lib/model_feature_allowlist.js). A model can never read a feature that is
// specific to our lab, our kit, our origin site, our deployment, or our capture
// protocol — regardless of what it asks for.

import { classify as classifyAitm }        from './aitm_model.js';
import { classify as classifyBitbModel }   from './bitb_model.js';
import { classify as classifyHomograph }   from './homograph_model.js';
import { classify as classifyCjModel }     from './clickjacking_model.js';
import {
  projectToAllowlist,
  MODEL_FEATURE_ALLOWLIST,
  HOMOGRAPH_FEATURE_ALLOWLIST,
} from '../lib/model_feature_allowlist.js';

/** Modules with a trained model behind them. Only these may produce a
 *  "suspicious" verdict that can gate the page or raise an interstitial. */
export const IMPLEMENTED_MODULES = ['aitm', 'homograph'];

/**
 * Run all four classifiers against the feature vector.
 * Returns an array of four result objects (one per module), in priority order.
 * The gating logic uses the first suspicious result it finds.
 *
 * Each module is projected onto ITS OWN allowlist. The AiTM and homograph
 * modules detect different attack classes, so their admissibility rules
 * differ; a shared projection would either hide a legitimate feature from one
 * module or expose one module's features to another.
 */
export function classifyAll(featureVector) {
  const aitmFv = projectToAllowlist(featureVector, MODEL_FEATURE_ALLOWLIST);
  const homographFv = projectToAllowlist(featureVector, HOMOGRAPH_FEATURE_ALLOWLIST);
  return [
    classifyAitm(aitmFv),
    classifyBitbModel(aitmFv),
    classifyHomograph(homographFv),
    classifyCjModel(aitmFv),
  ];
}

/** Run only the BiTB classifier (called on window.open interception). */
export function classifyBitb(featureVector) {
  return classifyBitbModel(projectToAllowlist(featureVector, MODEL_FEATURE_ALLOWLIST));
}

/** Run only the clickjacking classifier (called on iframe detection). */
export function classifyClickjacking(featureVector) {
  return classifyCjModel(projectToAllowlist(featureVector, MODEL_FEATURE_ALLOWLIST));
}
