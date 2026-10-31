/* PTAF Detection Lab: a browser port of ptaf/sigma_lite.py plus a small YAML-subset parser.
 *
 * It lets an engineer paste a Sigma rule and an event and see, instantly and offline, whether the
 * rule matches and WHICH selection decided it. Nothing leaves the page.
 *
 * Parity with the Python engine is TESTED (tests/test_lab_parity.py runs both on the same vectors in
 * real Chrome), so the Lab does not drift from what the agent actually does.
 *
 * Differences, stated plainly:
 *  - regexes use JavaScript syntax here and Python syntax in the agent; simple patterns agree;
 *  - modifiers cidr/lt/lte/gt/gte are not available in the browser (reported, never silently wrong);
 *  - the YAML parser handles the subset Sigma uses (maps, lists, flow lists/maps, quoted scalars,
 *    block scalars, comments); anchors, tags and multi-document files are not supported.
 */
(function (root) {
  "use strict";

  var MAX_PATTERN_LEN = 1000, MAX_INPUT_LEN = 8192;
  var SUPPORTED = { contains: 1, startswith: 1, endswith: 1, all: 1, re: 1, windash: 1, exists: 1 };
  var UNAVAILABLE_HERE = { cidr: 1, lt: 1, lte: 1, gt: 1, gte: 1 };

  function LabError(msg) { this.message = msg; this.name = "LabError"; }
  LabError.prototype = Object.create(Error.prototype);

  /* ----------------------------- YAML subset ----------------------------- */
  function stripComment(line) {
    var q = null;
    for (var i = 0; i < line.length; i++) {
      var c = line[i];
      if (q) { if (c === q) { if (q === "'" && line[i + 1] === "'") { i++; } else { q = null; } } else if (q === '"' && c === "\\") { i++; } }
      else if (c === "'" || c === '"') { q = c; }
      else if (c === "#" && (i === 0 || /\s/.test(line[i - 1]))) { return line.slice(0, i); }
    }
    return line;
  }
  function scalar(t) {
    t = t.trim();
    if (t === "" || t === "~" || t === "null" || t === "Null" || t === "NULL") return null;
    if (t === "true" || t === "True" || t === "TRUE") return true;
    if (t === "false" || t === "False" || t === "FALSE") return false;
    if (/^[-+]?(0|[1-9][0-9]*)$/.test(t)) return parseInt(t, 10);
    if (/^[-+]?([0-9]+\.[0-9]*|\.[0-9]+)([eE][-+]?[0-9]+)?$/.test(t)) return parseFloat(t);
    return t;
  }
  var ESC = { n: "\n", t: "\t", r: "\r", "0": "\0", '"': '"', "\\": "\\", "/": "/" };
  function unquote(t) {
    if (t.length >= 2 && t[0] === "'" && t[t.length - 1] === "'") return t.slice(1, -1).replace(/''/g, "'");
    if (t.length >= 2 && t[0] === '"' && t[t.length - 1] === '"') {
      return t.slice(1, -1).replace(/\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|.)/g, function (_, e) {
        if (e[0] === "x" || e[0] === "u") return String.fromCharCode(parseInt(e.slice(1), 16));
        return Object.prototype.hasOwnProperty.call(ESC, e) ? ESC[e] : e;
      });
    }
    return null;
  }
  function value(t) { t = t.trim(); var u = unquote(t); return u !== null ? u : (t[0] === "[" || t[0] === "{") ? flow(t) : scalar(t); }

  function splitTop(s) {            // split on commas outside quotes/brackets
    var out = [], depth = 0, q = null, cur = "";
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (q) { cur += c; if (c === q) { if (q === "'" && s[i + 1] === "'") { cur += s[++i]; } else { q = null; } } else if (q === '"' && c === "\\") { cur += s[++i]; } continue; }
      if (c === "'" || c === '"') { q = c; cur += c; }
      else if (c === "[" || c === "{") { depth++; cur += c; }
      else if (c === "]" || c === "}") { depth--; cur += c; }
      else if (c === "," && depth === 0) { out.push(cur); cur = ""; }
      else cur += c;
    }
    if (cur.trim() !== "" || out.length) out.push(cur);
    return out;
  }
  function flow(t) {
    t = t.trim();
    var open = t[0], close = t[t.length - 1];
    if (!((open === "[" && close === "]") || (open === "{" && close === "}"))) throw new LabError("bad flow collection: " + t);
    var inner = t.slice(1, -1), parts = splitTop(inner).filter(function (x) { return x.trim() !== ""; });
    if (open === "[") return parts.map(value);
    var m = {};
    parts.forEach(function (p) { var kv = splitKey(p); m[kv[0]] = value(kv[1]); });
    return m;
  }
  function splitKey(text) {          // "key: value" -> [key, value]; respects a quoted key
    var i = 0, key;
    if (text[0] === "'" || text[0] === '"') {
      var q = text[0]; i = 1;
      while (i < text.length && !(text[i] === q && text[i + 1] !== q)) { i += (text[i] === q ? 2 : 1); }
      key = unquote(text.slice(0, i + 1)); i++;
      while (text[i] === " ") i++;
      if (text[i] !== ":") throw new LabError("expected ':' after key: " + text);
      return [key, text.slice(i + 1)];
    }
    var m = /^(.*?):(\s|$)/.exec(text);
    if (!m) throw new LabError("expected 'key: value', got: " + text);
    return [m[1].trim(), text.slice(m[0].length)];
  }
  function isKeyLine(t) { return /^("[^"]*"|'[^']*'|[^\s'"\[{][^:]*?):(\s|$)/.test(t); }

  function parseYaml(text) {
    var raw = String(text).replace(/\r\n?/g, "\n").replace(/\t/g, "  ").split("\n"), lines = [];
    for (var i = 0; i < raw.length; i++) {
      var body = stripComment(raw[i]);
      if (body.trim() === "" || body.trim() === "---") continue;
      lines.push({ indent: body.match(/^ */)[0].length, text: body.trim(), raw: raw[i], n: i });
    }
    var pos = 0;

    function parseBlock(indent) {
      if (pos >= lines.length) return null;
      var ln = lines[pos];
      return ln.text[0] === "-" && (ln.text.length === 1 || ln.text[1] === " ") ? parseList(ln.indent) : parseMap(ln.indent);
    }
    function nestedValue(parentIndent, rest) {
      rest = rest.trim();
      if (rest === "") {
        if (pos < lines.length && (lines[pos].indent > parentIndent || (lines[pos].indent === parentIndent && /^-( |$)/.test(lines[pos].text)))) return parseBlock(lines[pos].indent);
        return null;
      }
      if (/^[>|][-+]?$/.test(rest)) {        // block scalar: swallow deeper-indented raw lines
        var startN = lines[pos - 1].n, out = [];
        var k = startN + 1;
        while (k < raw.length) {
          var r = raw[k];
          if (r.trim() === "") { out.push(""); k++; continue; }
          if (r.match(/^ */)[0].length <= parentIndent) break;
          out.push(r.trim()); k++;
        }
        while (pos < lines.length && lines[pos].n < k) pos++;
        return out.join(rest[0] === ">" ? " " : "\n").trim();
      }
      // A plain (unquoted, non-flow) scalar may continue on deeper-indented lines; YAML folds them
      // into one line with single spaces.
      if (!/^["'\[{]/.test(rest)) {
        while (pos < lines.length && lines[pos].indent > parentIndent) { rest += " " + lines[pos].text; pos++; }
      }
      return value(rest);
    }
    function parseMap(indent) {
      var m = {};
      while (pos < lines.length && lines[pos].indent === indent && !/^-( |$)/.test(lines[pos].text)) {
        var ln = lines[pos++];
        if (!isKeyLine(ln.text)) throw new LabError("line " + (ln.n + 1) + ": expected 'key: value'");
        var kv = splitKey(ln.text);
        m[kv[0]] = nestedValue(indent, kv[1]);
      }
      return m;
    }
    function parseList(indent) {
      var arr = [];
      while (pos < lines.length && lines[pos].indent === indent && /^-( |$)/.test(lines[pos].text)) {
        var ln = lines[pos], rest = ln.text.slice(1).trim();
        if (rest === "") { pos++; arr.push(pos < lines.length && lines[pos].indent > indent ? parseBlock(lines[pos].indent) : null); continue; }
        if (isKeyLine(rest)) {
          // "- key: value" opens a map whose later keys sit at indent + 2
          lines[pos] = { indent: indent + 2, text: rest, raw: ln.raw, n: ln.n };
          arr.push(parseMap(indent + 2));
        } else { pos++; arr.push(nestedValue(indent, rest)); }
      }
      return arr;
    }
    if (!lines.length) return null;
    var result = parseBlock(lines[0].indent);
    if (pos < lines.length) throw new LabError("line " + (lines[pos].n + 1) + ": unexpected indentation");
    return result;
  }

  /* ------------------------------ Sigma-lite ------------------------------ */
  function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
  function glob(g) { var o = ""; for (var i = 0; i < g.length; i++) { var c = g[i]; o += c === "*" ? ".*" : c === "?" ? "." : esc(c); } return o; }
  var cache = {};
  function rx(pattern) {
    if (pattern.length > MAX_PATTERN_LEN) throw new LabError("regex longer than " + MAX_PATTERN_LEN + " characters");
    if (!cache[pattern]) { try { cache[pattern] = new RegExp(pattern, "is"); } catch (e) { throw new LabError("invalid regex: " + e.message); } }
    return cache[pattern];
  }
  function windash(v) { var sw = v.replace(/(^|\s)-/g, "$1/"); return sw === v ? [v] : [v, sw]; }

  function matchValue(actual, kind, expected) {
    if (expected === null) return actual === null || actual === undefined || actual === "";
    if (actual === null || actual === undefined) return false;
    var a = String(actual).slice(0, MAX_INPUT_LEN);
    if (kind === "re") return rx(String(expected)).test(a);
    var e = String(expected);
    if (e.indexOf("*") >= 0 || e.indexOf("?") >= 0) {
      var body = glob(e), p = kind === "contains" ? body : kind === "startswith" ? "^" + body : kind === "endswith" ? body + "$" : "^" + body + "$";
      return rx(p).test(a);
    }
    a = a.toLowerCase(); e = e.toLowerCase();
    if (kind === "contains") return a.indexOf(e) >= 0;
    if (kind === "startswith") return a.lastIndexOf(e, 0) === 0;
    if (kind === "endswith") return a.length >= e.length && a.indexOf(e, a.length - e.length) >= 0;
    return a === e;
  }
  function arr(v) { return Array.isArray(v) ? v : [v]; }

  function evalSelection(sel, ev) {
    if (Array.isArray(sel)) return sel.some(function (s) { return evalSelection(s, ev); });
    if ((typeof sel === "string" || typeof sel === "number")) {
      var needle = String(sel).replace(/\*/g, "").toLowerCase();
      return Object.keys(ev).some(function (k) { return typeof ev[k] === "string" && ev[k].toLowerCase().indexOf(needle) >= 0; });
    }
    if (sel === null || typeof sel !== "object") throw new LabError("unsupported selection shape");
    var keys = Object.keys(sel);
    for (var i = 0; i < keys.length; i++) {
      var parts = keys[i].split("|"), field = parts[0], mods = parts.slice(1), expected = sel[keys[i]];
      mods.forEach(function (m) {
        if (UNAVAILABLE_HERE[m]) throw new LabError("modifier '" + m + "' is not available in the browser Lab (the agent supports it)");
        if (!SUPPORTED[m]) throw new LabError("unsupported modifier(s): " + m);
      });
      if (mods.indexOf("exists") >= 0) {
        var present = ev[field] !== undefined && ev[field] !== null && ev[field] !== "";
        if (present !== !!expected) return false;
        continue;
      }
      var requireAll = mods.indexOf("all") >= 0;
      var kind = "equals";
      for (var j = 0; j < mods.length; j++) { if (mods[j] !== "all" && mods[j] !== "windash") { kind = mods[j]; break; } }
      var vals = arr(expected);
      if (mods.indexOf("windash") >= 0) { var wv = []; vals.forEach(function (v) { windash(String(v)).forEach(function (x) { wv.push(x); }); }); vals = wv; }
      var results = vals.map(function (v) { return matchValue(ev[field], kind, v); });
      if (!(requireAll ? results.every(Boolean) : results.some(Boolean))) return false;
    }
    return true;
  }

  function evalCondition(cond, sels) {
    var tokens = cond.match(/\(|\)|[^\s()]+/g) || [], pos = 0;
    function peek() { return pos < tokens.length ? tokens[pos].toLowerCase() : null; }
    function take() { return tokens[pos++]; }
    function quantified(kind) {
      take();
      var pat = take(), hits;
      if (pat.toLowerCase() === "them") hits = Object.keys(sels).map(function (k) { return sels[k]; });
      else { var re = new RegExp("^" + esc(pat).replace(/\\\*/g, ".*") + "$"); hits = Object.keys(sels).filter(function (k) { return re.test(k); }).map(function (k) { return sels[k]; }); }
      if (!hits.length) throw new LabError("'" + kind + " of " + pat + "' matches no selection");
      return kind === "all" ? hits.every(Boolean) : hits.some(Boolean);
    }
    function atom() {
      var t = peek();
      if (t === null) throw new LabError("unexpected end of condition");
      if (t === "not") { take(); return !atom(); }
      if (t === "(") { take(); var v = disj(); if (peek() !== ")") throw new LabError("unbalanced parentheses"); take(); return v; }
      var w = take();
      if ((w.toLowerCase() === "1" || w.toLowerCase() === "all") && peek() === "of") return quantified(w.toLowerCase() === "all" ? "all" : "1");
      if (!Object.prototype.hasOwnProperty.call(sels, w)) throw new LabError("condition references unknown selection '" + w + "'");
      return sels[w];
    }
    function conj() { var v = atom(); while (peek() === "and") { take(); var r = atom(); v = r && v; } return v; }
    function disj() { var v = conj(); while (peek() === "or") { take(); var r = conj(); v = r || v; } return v; }
    var out = disj();
    if (pos !== tokens.length) throw new LabError("unexpected token '" + tokens[pos] + "' in condition");
    return out;
  }

  /* Evaluate a rule (YAML text or parsed object) against one event. Never throws. */
  function evaluate(rule, event) {
    try {
      var r = typeof rule === "string" ? parseYaml(rule) : rule;
      if (!r || typeof r !== "object" || !r.detection) throw new LabError("not a Sigma rule: needs a 'detection:' section");
      var det = {}, cond = null;
      Object.keys(r.detection).forEach(function (k) { if (k === "condition") cond = r.detection[k]; else det[k] = r.detection[k]; });
      if (typeof cond !== "string") throw new LabError("only a single-string condition is supported");
      var sels = {};
      Object.keys(det).forEach(function (k) { sels[k] = evalSelection(det[k], event); });
      var tags = (r.tags || []).map(String), techniques = [];
      tags.forEach(function (t) { var m = /^attack\.(t\d{4}(\.\d{3})?)$/i.exec(t); if (m) techniques.push(m[1].toUpperCase()); });
      return { ok: true, matched: evalCondition(cond, sels), selections: sels, condition: cond, title: r.title || "untitled", level: r.level || "medium", techniques: techniques };
    } catch (e) {
      return { ok: false, error: e && e.message ? e.message : String(e) };
    }
  }

  root.PtafLab = { parseYaml: parseYaml, evaluate: evaluate, matchValue: matchValue };
})(typeof window !== "undefined" ? window : this);
