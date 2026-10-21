// JS port of homograph/features.py (service-worker safe: no DOM, no network, pure string computation).
(function (root, factory) {
  const D = root.HomographData || (typeof require === 'function' ? require('./homograph_data.js') : null);
  const api = factory(D);
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.HomographFeatures = api;
})(typeof self !== 'undefined' ? self : globalThis, function (D) {
  'use strict';
  const FEATURE_ORDER = ['is_punycode', 'mixed_script_flag', 'whole_script_confusable_violation',
    'confusable_char_ratio', 'skeleton_exact_match', 'skeleton_edit_distance_min'];
  const NEUTRAL = new Set(D.NEUTRAL);
  const COMBOS = D.ALLOWED_COMBOS.map(c => new Set(c));
  const CONF = new Map(Object.entries(D.CONFUSABLES));
  const R = D.RANGES, EDIT_CAP = D.EDIT_CAP;
  const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'or', 'ne', 'go']);
  const cache = new Map();

  function scriptOf(ch) {
    let s = cache.get(ch);
    if (s !== undefined) return s;
    const cp = ch.codePointAt(0);
    let lo = 0, hi = R.length - 1, res = 'Unknown';
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (cp < R[mid][0]) hi = mid - 1;
      else if (cp > R[mid][1]) lo = mid + 1;
      else { res = R[mid][2]; break; }
    }
    cache.set(ch, res);
    return res;
  }

  // RFC 3492 Punycode decoder (label body, without the 'xn--' prefix). Throws on invalid input.
  function punycodeDecode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    const out = [];
    let basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) {
      if (input.charCodeAt(j) >= 0x80) throw new Error('bad input');
      out.push(input.charCodeAt(j));
    }
    const adapt = (delta, numPoints, first) => {
      let k = 0;
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
      return Math.floor(k + (base - tMin + 1) * delta / (delta + skew));
    };
    let n = 128, i = 0, bias = 72;
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const oldi = i;
      for (let w = 1, k = base; ; k += base) {
        if (idx >= input.length) throw new Error('bad input');
        const c = input.charCodeAt(idx++);
        const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
        if (digit >= base) throw new Error('bad input');
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
      }
      const len = out.length + 1;
      bias = adapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len);
      i %= len;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }

  const normalize = h => h.trim().replace(/\.+$/, '').normalize('NFKC').toLowerCase();

  function decodeLabels(host) {
    const labels = normalize(host).split('.');
    let pun = false;
    const out = labels.map(lab => {
      if (lab.startsWith('xn--')) {
        pun = true;
        if (/^[\x00-\x7f]*$/.test(lab)) { try { return punycodeDecode(lab.slice(4)); } catch (e) { /* keep raw */ } }
      }
      return lab;
    });
    return { labels: out, pun };
  }

  function registrable(labels) {
    if (labels.length <= 2) return labels.join('.');
    const n = labels.length;
    if (labels[n - 1].length === 2 && SECOND_LEVEL.has(labels[n - 2])) return labels.slice(-3).join('.');
    return labels.slice(-2).join('.');
  }
  const skeleton = s => Array.from(s.normalize('NFD').replace(/\p{M}/gu, '')).map(c => CONF.get(c) ?? c).join('');

  function levenshtein(a, b) {
    if (a === b) return 0;
    const A = Array.from(a), B = Array.from(b);
    let prev = Array.from({ length: B.length + 1 }, (_, i) => i);
    for (let i = 1; i <= A.length; i++) {
      const cur = [i];
      for (let j = 1; j <= B.length; j++)
        cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (A[i - 1] !== B[j - 1] ? 1 : 0)));
      prev = cur;
    }
    return prev[B.length];
  }

  const nonNeutral = label => Array.from(label).filter(c => !NEUTRAL.has(scriptOf(c)));
  function isMixed(scripts) {
    if (scripts.size <= 1) return false;
    return !COMBOS.some(combo => [...scripts].every(s => combo.has(s)));
  }
  function isWholeScriptConfusable(label) {
    if (/^[\x00-\x7f]*$/.test(label)) return false;
    const chars = nonNeutral(label);
    if (!chars.length) return false;
    const scripts = new Set(chars.map(scriptOf));
    return scripts.size === 1 && !scripts.has('Latin') && chars.every(c => CONF.has(c));
  }

  function makeReferenceList(domains, exclude) {
    const ex = exclude ? normalize(exclude) : null;
    return domains.map(normalize).filter(r => r !== ex).map(r => ({ raw: r, skel: skeleton(r) }));
  }
  const defaultRefs = () => makeReferenceList(D.REFERENCE_DOMAINS);

  function pyRound6(x) { return Math.round(x * 1e6) / 1e6; }

  function extract(host, refs) {
    const { labels, pun } = decodeLabels(host);
    let mixed = false, whole = false, ratio = 0;
    for (const lab of labels) {
      const chars = nonNeutral(lab);
      if (isMixed(new Set(chars.map(scriptOf)))) mixed = true;
      if (isWholeScriptConfusable(lab)) whole = true;
      if (chars.length) {
        let hits = 0;
        for (const c of chars) if (CONF.has(c) && scriptOf(c) !== scriptOf(CONF.get(c)[0])) hits++;
        ratio = Math.max(ratio, hits / chars.length);
      }
    }
    let exact = false, dist = EDIT_CAP, target = null;
    if (refs && refs.length) {
      const reg = registrable(labels), sk = skeleton(reg);
      const hit = refs.find(r => r.skel === sk && r.raw !== reg);
      if (hit) { exact = true; dist = 0; target = hit.raw; }
      else for (const r of refs) if (r.raw !== reg) dist = Math.min(dist, levenshtein(sk, r.skel));
    }
    return {
      features: {
        is_punycode: +pun, mixed_script_flag: +mixed, whole_script_confusable_violation: +whole,
        confusable_char_ratio: pyRound6(ratio), skeleton_exact_match: +exact, skeleton_edit_distance_min: dist
      },
      target, unicodeHost: labels.join('.')
    };
  }

  return { FEATURE_ORDER, extract, makeReferenceList, defaultRefs, punycodeDecode, decodeLabels, scriptOf, registrable, skeleton };
});

// Appended by sync_to_extension.sh: makes this an ES module in every
// runtime (node loads an ambiguous .js as CommonJS, Chrome does not).
export const HomographFeatures = globalThis.HomographFeatures;
