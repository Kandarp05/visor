// models/aitm_model.js
// AiTM (Adversary-in-the-Middle / session-hijack proxy) classifier — GENERATED FILE.
//
// Trained on the v2 corpus (data-v2/features/visits.jsonl) using ONLY the features
// on the model allowlist (lib/model_feature_allowlist.js). Regenerate with:
//     python3 aitm-harness/model/train.py
//
// The feature vector handed to classify() is projected onto the allowlist by
// models/interface.js before it reaches this file, so this model cannot read a
// lab-specific, kit-specific, origin-specific or capture-specific feature.
//
// Model: lr
// Metrics on the time-based test split:
////   auc                      1.0000
//   fpr                      0.0000
//   tpr                      1.0000
//   tp                       253.0000
//   fp                       0.0000
//   fn                       0.0000
//   tn                       1320.0000

export const MODEL_FEATURES = [
  {
    "name": "cache_ratio",
    "kind": "num"
  },
  {
    "name": "character_set",
    "kind": "num"
  },
  {
    "name": "cookie_domain_mismatch",
    "kind": "bool"
  },
  {
    "name": "cross_origin_hop_count",
    "kind": "num"
  },
  {
    "name": "dpr",
    "kind": "num"
  },
  {
    "name": "entry_path==direct",
    "kind": "cat",
    "from": "entry_path",
    "value": "direct"
  },
  {
    "name": "entry_path==link_internal",
    "kind": "cat",
    "from": "entry_path",
    "value": "link_internal"
  },
  {
    "name": "entry_path==link_referrer",
    "kind": "cat",
    "from": "entry_path",
    "value": "link_referrer"
  },
  {
    "name": "entry_path==redirect_entry",
    "kind": "cat",
    "from": "entry_path",
    "value": "redirect_entry"
  },
  {
    "name": "ever_saw_identity_mismatch_header",
    "kind": "bool"
  },
  {
    "name": "form_action_mismatch",
    "kind": "bool"
  },
  {
    "name": "has_autocomplete_current_password",
    "kind": "bool"
  },
  {
    "name": "has_password_field",
    "kind": "bool"
  },
  {
    "name": "has_referer",
    "kind": "bool"
  },
  {
    "name": "identity_host_mismatch",
    "kind": "bool"
  },
  {
    "name": "identity_host_mismatch_header",
    "kind": "bool"
  },
  {
    "name": "identity_match_ratio_header",
    "kind": "num"
  },
  {
    "name": "n_cached",
    "kind": "num"
  },
  {
    "name": "n_cookies",
    "kind": "num"
  },
  {
    "name": "n_document",
    "kind": "num"
  },
  {
    "name": "n_failed",
    "kind": "num"
  },
  {
    "name": "n_font",
    "kind": "num"
  },
  {
    "name": "n_foreign_origin_headers",
    "kind": "num"
  },
  {
    "name": "n_forms",
    "kind": "num"
  },
  {
    "name": "n_hidden_inputs",
    "kind": "num"
  },
  {
    "name": "n_host_only_cookies",
    "kind": "num"
  },
  {
    "name": "n_hosts",
    "kind": "num"
  },
  {
    "name": "n_identity_mismatch_header",
    "kind": "num"
  },
  {
    "name": "n_image",
    "kind": "num"
  },
  {
    "name": "n_inputs",
    "kind": "num"
  },
  {
    "name": "n_opaque_root_scripts",
    "kind": "num"
  },
  {
    "name": "n_other",
    "kind": "num"
  },
  {
    "name": "n_password_fields",
    "kind": "num"
  },
  {
    "name": "n_requests",
    "kind": "num"
  },
  {
    "name": "n_script",
    "kind": "num"
  },
  {
    "name": "n_stylesheet",
    "kind": "num"
  },
  {
    "name": "n_third_party_requests",
    "kind": "num"
  },
  {
    "name": "n_xhr",
    "kind": "num"
  },
  {
    "name": "redirect_hop_count",
    "kind": "num"
  },
  {
    "name": "same_host_ratio",
    "kind": "num"
  },
  {
    "name": "script_src_is_opaque_root_path",
    "kind": "bool"
  },
  {
    "name": "third_party_ratio",
    "kind": "num"
  },
  {
    "name": "viewport_h",
    "kind": "num"
  },
  {
    "name": "viewport_w",
    "kind": "num"
  }
];

export const MODEL_META = {
  "n_rows": 11301,
  "n_features": 44,
  "split": "time-based 70/15/15 over the two training classes",
  "estimator": "lr",
  "params": {
    "n_estimators": 200,
    "max_depth": 3,
    "max_features": 0.4,
    "C": 1.0,
    "random_state": 42
  },
  "kind": "linear"
};

const MODEL_KIND = "linear";
const MODEL_INIT = 0.0;
const MODEL_BIAS = -0.20368100709895484;
const MODEL_WEIGHTS = [-0.00015093187823024106,0.0,1.695506608075695,0.0,-0.4110773573965212,-0.06953891721544735,0.051932957002996896,0.055650284466419876,-0.21379665879891394,2.4864505246671182,0.0,0.0,0.11654817871852881,-0.1062134173290624,0.0,1.9056696508743658,-2.1979701641338667,-0.0022465686964120973,0.45140125651740537,-0.1757523345450656,0.0,0.11654817871852881,1.9056696508743658,0.08826069256941566,0.0,-1.2441053515666036,-0.1757523345450656,1.9056696508743658,-0.6315604575411631,0.0,1.9407362887618522,0.0,0.11654817871852881,-0.388834575183459,0.9549690224828536,-0.6099333887806088,0.0,-0.043105595505145686,-0.180094125340595,-0.1757523345450656,1.9407362887618522,0.0,-0.00033385860805189776,-0.0015942080491732724];
const MODEL_TREES = [];

function coerceBool(v) { return v === true ? 1 : 0; }
function coerceNum(v) {
  if (v === null || v === undefined) return 0;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (typeof v === 'number') return Number.isFinite(v) ? v : 0;
  return 0;
}

/** Build the numeric vector from a raw feature vector, using MODEL_FEATURES. */
export function encodeFeatures(fv) {
  const out = new Array(MODEL_FEATURES.length);
  for (let i = 0; i < MODEL_FEATURES.length; i++) {
    const s = MODEL_FEATURES[i];
    if (s.kind === 'bool') out[i] = coerceBool(fv[s.name]);
    else if (s.kind === 'num') out[i] = coerceNum(fv[s.name]);
    else out[i] = fv[s.from] === s.value ? 1 : 0;
  }
  return out;
}

function scoreTree(nodes, x) {
  let i = 0;
  while (nodes[i].l !== -1) {
    i = x[nodes[i].f] <= nodes[i].t ? nodes[i].l : nodes[i].r;
  }
  return nodes[i].v;
}

function sigmoid(z) { return 1 / (1 + Math.exp(-z)); }

/** Probability that the page is AiTM-proxied. */
export function score(fv) {
  const x = encodeFeatures(fv);
  if (MODEL_KIND === 'linear') {
    let raw = MODEL_BIAS;
    for (let i = 0; i < MODEL_WEIGHTS.length; i++) raw += MODEL_WEIGHTS[i] * x[i];
    return sigmoid(raw);
  }
  if (MODEL_KIND === 'single') {
    return scoreTree(MODEL_TREES[0], x);
  }
  let acc = 0;
  for (const nodes of MODEL_TREES) acc += scoreTree(nodes, x);
  if (MODEL_KIND === 'mean') return acc / MODEL_TREES.length;
  return sigmoid(MODEL_INIT + acc);
}

/**
 * classify(fv) -> { verdict, score, module }
 */
export function classify(fv) {
  const s = Math.max(0, Math.min(1, score(fv)));
  return {
    verdict: s >= 0.5 ? 'suspicious' : 'safe',
    score: Math.round(s * 1000) / 1000,
    module: 'aitm',
  };
}
