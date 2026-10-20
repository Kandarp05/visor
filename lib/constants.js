// lib/constants.js — shared constants
// Imported by background.js and any other module that needs them.

export const VISOR_VERSION = '0.1.0';

// Message types used across background ↔ content script boundary.
// Add new types here as phases are built — single source of truth.
export const MSG = {
  // Phase 1
  PHASE1_PING: 'PHASE1_PING',

  // Phase 3 (content → background)
  TIER2_FEATURES: 'TIER2_FEATURES',
  BITB_WINDOW_OPEN: 'BITB_WINDOW_OPEN',
  FORM_SUBMIT: 'FORM_SUBMIT',
  IFRAME_SUSPICIOUS: 'IFRAME_SUSPICIOUS',

  // Phase 5 (background → content)
  SHOW_INTERSTITIAL: 'SHOW_INTERSTITIAL',
};
