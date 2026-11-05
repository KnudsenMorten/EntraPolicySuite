// Entra Policy Suite web app (DESIGN §2). One same-origin script (the sign-in front's CSP: no inline script, no other origin).
// Rules kept here: every value a person reads goes through ONE number formatter (BRAND-2.6) and ONE time formatter
// (local time, BRAND-2.10); the DOM is built with textContent ONLY - directory values (object names, tag values someone
// else wrote) are attacker-controlled text and never become markup; a changing call sends X-EPS-Request: 1 + JSON (the
// server's anti-forgery check) and a reason for the audit trail.
'use strict';
(function () {
  var LOADED_VERSION = document.documentElement.getAttribute('data-version');
  // DOC-LINKS: the setting help links point at invardia.com/docs/eps, which is published only when the owner makes
  // Entra Policy Suite public there - until then the "Read more" link is not shown (a customer would get a 404)
  var DOCS_LIVE = false;
  var me = null;
  var store = {
    get: function (k, d) { try { var v = localStorage.getItem(k); return v === null ? d : v; } catch (e) { return d; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) { } }
  };

  // ---- formatters ------------------------------------------------------------------------------------------------
  function locale() { var l = store.get('eps.numbers', 'auto'); return l === 'auto' ? (navigator.language || 'en-US') : l; }
  function fmtNum(n) { if (n === null || n === undefined || n === '') return ''; var x = Number(n); return isNaN(x) ? String(n) : new Intl.NumberFormat(locale()).format(x); }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function fmtTime(iso) {
    if (!iso) return '';
    var d = new Date(iso); if (isNaN(d.getTime())) return String(iso);
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }

  // ---- DOM (textContent only) ------------------------------------------------------------------------------------
  function el(tag, attrs) {
    var e = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === 'text') e.textContent = String(v);
      else if (k === 'class') e.className = v;
      else if (k.indexOf('on') === 0) e.addEventListener(k.substring(2), v);
      else e.setAttribute(k, v === true ? '' : String(v));
    });
    for (var i = 2; i < arguments.length; i++) { var c = arguments[i]; if (c === null || c === undefined) continue; if (Array.isArray(c)) c.forEach(function (x) { if (x) e.appendChild(x); }); else e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); }
    return e;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); return n; }
  function timeEl(iso) { return el('time', { datetime: iso || '', title: iso ? 'UTC ' + iso : null, text: fmtTime(iso) }); }

  // ---- API ---------------------------------------------------------------------------------------------------------
  function api(method, path, body) {
    var opt = { method: method, credentials: 'same-origin', headers: { 'Accept': 'application/json' } };
    if (method !== 'GET') { opt.headers['X-EPS-Request'] = '1'; opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body || {}); }
    return fetch(path, opt).then(function (r) {
      if (r.status === 401) { document.getElementById('sessionBar').hidden = false; throw new Error('not signed in'); }
      var v = r.headers.get('X-EPS-Version'); if (v) checkVersion(v);
      return r.json().then(function (j) { if (!r.ok) { var e = new Error(j && j.error ? j.error : ('HTTP ' + r.status)); e.status = r.status; throw e; } return j; });
    });
  }
  function qs(o) { return Object.keys(o).filter(function (k) { return o[k] !== '' && o[k] !== null && o[k] !== undefined; }).map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(o[k]); }).join('&'); }
  function status(t) { document.getElementById('statusText').textContent = t || ''; }
  function isRole(r) { var rank = { Reader: 1, Admin: 2, SuperAdmin: 3 }; return me && rank[me.role] >= rank[r]; }

  // a changing action: the reason dialog, then the call
  // a configuration change is applied by the engine (SEC-AUDIT-1 S1): follow the request until it is done, then redraw
  // a notice people SEE (owner 2026-11-02: "when i click adopt, nothing happens" - it was applied a minute later, and
  // the only sign was the status line at the bottom): what was sent, then what the engine did
  var pendingReqs = {};
  function notice(t, kind) {
    var b = document.getElementById('noticeBar'); if (!b) { status(t); return; }
    document.getElementById('noticeText').textContent = t; b.className = 'bar ' + (kind === 'warn' ? 'bar-warn' : 'bar-info'); b.hidden = !t;
    document.getElementById('noticeClose').onclick = function () { b.hidden = true; };
    status(t);
  }
  // BULK-1 (owner 2026-11-02: "wording is wrong 'the engine applies them...'"): the engine takes changes at its next
  // check (every 5 minutes) - say so, show how many are applied, and follow them all with ONE call per round
  var pend = { total: 0, done: 0, failed: [], since: null, timer: null, rounds: 0, last: '' };
  var ENGINE_WAIT = 'The engine picks changes up at its next check (every 5 minutes) and applies them; this bar follows them.';
  function pendingText() {
    var left = Object.keys(pendingReqs).length; if (!left) return '';
    if (pend.total === 1) return 'Sent: ' + pendingReqs[Object.keys(pendingReqs)[0]] + '. ' + ENGINE_WAIT;
    return 'Sent ' + fmtNum(pend.total) + ' changes: ' + fmtNum(pend.done) + ' applied, ' + fmtNum(left) + ' waiting' + (pend.failed.length ? ', ' + fmtNum(pend.failed.length) + ' not applied' : '') + '. ' + ENGINE_WAIT;
  }
  function watchRequest(id, label, at) {
    if (!Object.keys(pendingReqs).length) { pend.total = 0; pend.done = 0; pend.failed = []; pend.rounds = 0; pend.since = new Date(Date.now() - 120000).toISOString(); }
    // a request taken up again after a reload is older: read from its own time
    if (at) { var t = new Date(new Date(at).getTime() - 60000); if (!isNaN(t) && t.toISOString() < pend.since) pend.since = t.toISOString(); }
    pendingReqs[String(id).toLowerCase()] = label || 'your change'; pend.total++;
    notice(pendingText());
    if (!pend.timer) pend.timer = setTimeout(pollRequests, 4000);
  }
  function pollRequests() {
    pend.timer = null;
    api('GET', '/api/requests/mine?since=' + encodeURIComponent(pend.since)).then(function (d) {
      (d.rows || []).forEach(function (q) {
        var id = String(q.RequestId).toLowerCase(); if (!pendingReqs[id]) return;
        if (q.Status === 'Done') { pend.done++; pend.last = q.StatusText || ''; delete pendingReqs[id]; }
        else if (q.Status === 'Refused' || q.Status === 'Failed') { pend.failed.push(pendingReqs[id] + ' - ' + q.Status.toLowerCase() + (q.StatusText ? ': ' + q.StatusText : '')); delete pendingReqs[id]; }
      });
      followUp();
    }).catch(followUp);
  }
  function followUp() {
    var left = Object.keys(pendingReqs).length;
    if (!left) {
      if (pend.failed.length) notice(fmtNum(pend.total - pend.failed.length) + ' of ' + fmtNum(pend.total) + ' applied; ' + fmtNum(pend.failed.length) + ' not: ' + pend.failed.slice(0, 3).join('; ') + (pend.failed.length > 3 ? ' ...' : ''), 'warn');
      else notice(pend.total === 1 ? 'Done - the engine applied it' + (pend.last ? ': ' + pend.last : '.') : 'Done - the engine applied all ' + fmtNum(pend.total) + ' changes.');
      render(); return;
    }
    notice(pendingText());
    if (++pend.rounds < 120) pend.timer = setTimeout(pollRequests, 10000);   // followed for 20 minutes
    else { notice(fmtNum(left) + ' change(s) still waiting for the engine - Jobs shows the requests.', 'warn'); pendingReqs = {}; }
  }
  function afterAction(r, label) {
    if (r && r.requestIds) {
      if (r.errors && r.errors.length) notice(r.errors.length + ' of ' + r.count + ' refused: ' + r.errors.slice(0, 3).join('; '), 'warn');
      r.requestIds.forEach(function (id) { watchRequest(id, label); });
      if (!r.requestIds.length && !(r.errors && r.errors.length)) { notice('Done.'); render(); }
      return;
    }
    if (r && r.queued && r.requestId) watchRequest(r.requestId, label);
    else { notice(r && r.text ? r.text : 'Done.'); render(); }
  }
  // CA-MONPEND (owner 2026-11-05: "it was not shown even though i refreshed the page ... no info"): a reload forgot the
  // changes this person sent and the engine had not applied yet - take them up again, so the bar keeps following them
  function resumeRequests() {
    api('GET', '/api/requests/mine?since=' + encodeURIComponent(new Date(Date.now() - 3600000).toISOString())).then(function (d) {
      (d.rows || []).forEach(function (q) {
        if (q.Job !== 'Config' || ['Pending', 'Dispatched', 'Running'].indexOf(q.Status) < 0) return;
        var mm = /^\/api\/ca\/monitors\/(.+)$/.exec(q.Path || '');
        watchRequest(q.RequestId, mm ? (q.Method === 'DELETE' ? 'Delete monitor ' : 'Save monitor ') + decodeURIComponent(mm[1]) : 'your change' + (q.Path ? ' (' + q.Method + ' ' + q.Path + ')' : ''), q.RequestedAtUtc);
      });
    }).catch(function () { /* the bar is a help, not a must */ });
  }
  function withReason(title, text, fn) {
    var d = document.getElementById('reasonDialog');
    document.getElementById('reasonTitle').textContent = title;
    document.getElementById('reasonText').textContent = text;
    var inp = document.getElementById('reasonInput'); inp.value = '';
    var form = document.getElementById('reasonForm');
    var done = function (ev) {
      ev.preventDefault(); var reason = inp.value.trim();   // optional (owner 2026-11-02)
      form.removeEventListener('submit', done); d.close();
      notice('Sending: ' + title + ' ...');
      fn(reason).then(function (r) { afterAction(r, title); }).catch(function (e) { notice('Refused: ' + e.message, 'warn'); });
    };
    form.addEventListener('submit', done);
    document.getElementById('reasonCancel').onclick = function () { form.removeEventListener('submit', done); d.close(); };
    d.showModal(); inp.focus();
  }

  // ---- tables (BRAND-2.7) ----------------------------------------------------------------------------------------
  // cols: [{ key, label, type: 'text'|'cat'|'num'|'date', render(row) -> node, wrap }]. Small tables: sort + filter here.
  var SEV_RANK = { Critical: 5, High: 4, Medium: 3, Normal: 2, Low: 2, Info: 1 };
  function table(rows, cols, opts) {
    // opts.bulk: [{ label, run(rows) -> Promise }] - a checkbox per row, "select all shown", and the actions on the
    // selection (owner 2026-11-02: "i also need multi-select options everywhere in the gui"). A 'cat' column filters
    // on SEVERAL values (a checklist), not one.
    opts = opts || {};
    var bulk = (opts.bulk || []).filter(function (b) { return !b.role || isRole(b.role); });
    var state = { sort: opts.sort || null, dir: opts.dir || -1, f: {}, q: '' };
    var sel = [], lastIdx = -1, shown = [];
    var host = el('div');
    var search = el('input', { type: 'search', placeholder: 'Search all columns', 'aria-label': 'Search' });
    var count = el('span', { class: 'count' });
    var clearBtn = el('button', { type: 'button', class: 'link', text: 'Clear filters' });
    var selInfo = el('span', { class: 'count' });
    var bulkBtns = bulk.map(function (b) {
      var btn = el('button', { type: 'button', class: 'secondary', text: b.label });
      btn.addEventListener('click', function () { var pick = shown.filter(function (r) { return sel.indexOf(r) >= 0; }); if (pick.length) b.run(pick); });
      return btn;
    });
    var tb = el('tbody');
    var head = el('tr'), filt = el('tr', { class: 'filters' });
    var allBox = null;
    if (bulk.length) {
      allBox = el('input', { type: 'checkbox', 'aria-label': 'Select all shown rows' });
      allBox.addEventListener('change', function () { sel = allBox.checked ? shown.slice() : []; draw(); });
      head.appendChild(el('th', { class: 'selcol' }, allBox)); filt.appendChild(el('th'));
    }
    cols.forEach(function (c) {
      var th = el('th', { class: c.type === 'num' ? 'num' : null, scope: 'col', text: c.label });
      th.addEventListener('click', function () { if (state.sort === c.key) state.dir = -state.dir; else { state.sort = c.key; state.dir = 1; } draw(); });
      head.appendChild(th);
      var fc = el('th');
      if (c.type === 'cat') {
        var vals = {}; rows.forEach(function (r) { catVals(r, c).forEach(function (v) { vals[v] = 1; }); });
        var sum = el('summary', { text: 'any' });
        var box = el('div', { class: 'msel-list' });
        var picked = {};
        var upd = function () {
          var on = Object.keys(picked).filter(function (k) { return picked[k]; });
          state.f[c.key] = on.length ? on : null;
          sum.textContent = !on.length ? 'any' : on.length === 1 ? (on[0] === '' ? '(empty)' : on[0]) : on.length + ' selected';
          draw();
        };
        Object.keys(vals).sort().forEach(function (v) {
          var cb = el('input', { type: 'checkbox' });
          cb.addEventListener('change', function () { picked[v] = cb.checked; upd(); });
          box.appendChild(el('label', { class: 'msel-item' }, cb, ' ', v === '' ? '(empty)' : v));
        });
        var dt = el('details', { class: 'msel', 'aria-label': 'Filter ' + c.label }, sum, box);
        dt._reset = function () { picked = {}; Array.prototype.forEach.call(box.querySelectorAll('input'), function (x) { x.checked = false; }); sum.textContent = 'any'; };
        fc.appendChild(dt);
      } else if (c.type !== 'num') {
        var i = el('input', { type: 'search', placeholder: c.type === 'date' ? 'contains (yyyy-mm-dd)' : 'contains', 'aria-label': 'Filter ' + c.label });
        i.addEventListener('input', function () { state.f[c.key] = i.value.toLowerCase(); draw(); }); fc.appendChild(i);
      }
      filt.appendChild(fc);
    });
    search.addEventListener('input', function () { state.q = search.value.toLowerCase(); draw(); });
    clearBtn.addEventListener('click', function () {
      state.f = {}; state.q = ''; search.value = '';
      Array.prototype.forEach.call(filt.querySelectorAll('input[type=search]'), function (x) { x.value = ''; });
      Array.prototype.forEach.call(filt.querySelectorAll('details.msel'), function (x) { x._reset(); x.open = false; });
      draw();
    });
    // a 'cat' column's values for one row: one value, or - with multi (a separator) - each part of a joined list, so a row
    // in two personas ("Users-Internal, Pilots") matches either (CA-LIMITS fix 3)
    function catVals(r, c) { var v = r[c.key] === null || r[c.key] === undefined ? '' : String(r[c.key]); return c.multi && v ? v.split(c.multi) : [v]; }
    function cellText(r, c) { var v = r[c.key]; if (c.type === 'date') return fmtTime(v).toLowerCase(); return v === null || v === undefined ? '' : String(v).toLowerCase(); }
    function draw() {
      var list = rows.filter(function (r) {
        for (var k in state.f) { if (!state.f[k] || (Array.isArray(state.f[k]) && !state.f[k].length)) continue; var c = cols.filter(function (x) { return x.key === k; })[0];
          if (c.type === 'cat') { var fv = state.f[k]; if (!catVals(r, c).some(function (v) { return fv.indexOf(v) >= 0; })) return false; } else if (cellText(r, c).indexOf(state.f[k]) < 0) return false; }
        if (state.q) { var hit = cols.some(function (c) { return cellText(r, c).indexOf(state.q) >= 0; }); if (!hit) return false; }
        return true;
      });
      if (state.sort) {
        var c = cols.filter(function (x) { return x.key === state.sort; })[0];
        list.sort(function (a, b) {
          var x = a[state.sort], y = b[state.sort];
          if (c && c.key === 'Severity') { x = SEV_RANK[x] || 0; y = SEV_RANK[y] || 0; }
          else if (c && c.type === 'num') { x = Number(x) || 0; y = Number(y) || 0; }
          else { x = x === null || x === undefined ? '' : String(x); y = y === null || y === undefined ? '' : String(y); }
          return (x < y ? -1 : x > y ? 1 : 0) * state.dir;
        });
      }
      shown = list;
      sel = sel.filter(function (r) { return list.indexOf(r) >= 0; });   // a filter drops what it hides from the selection
      var off = bulk.length ? 1 : 0;
      Array.prototype.forEach.call(head.children, function (th, i) { if (i < off) return; var k = cols[i - off].key; th.textContent = cols[i - off].label + (state.sort === k ? (state.dir > 0 ? ' ▲' : ' ▼') : ''); });
      clear(tb);
      list.forEach(function (r, idx) {
        var tr = el('tr', { class: sel.indexOf(r) >= 0 ? 'selected' : null });
        if (bulk.length) {
          var cb = el('input', { type: 'checkbox', 'aria-label': 'Select row' }); cb.checked = sel.indexOf(r) >= 0;
          cb.addEventListener('click', function (ev) {
            // shift-click selects the range from the last click
            var range = ev.shiftKey && lastIdx >= 0 ? list.slice(Math.min(lastIdx, idx), Math.max(lastIdx, idx) + 1) : [r];
            range.forEach(function (x) { var at = sel.indexOf(x); if (cb.checked && at < 0) sel.push(x); if (!cb.checked && at >= 0) sel.splice(at, 1); });
            lastIdx = idx; draw();
          });
          tr.appendChild(el('td', { class: 'selcol' }, cb));
        }
        cols.forEach(function (c) {
          var td = el('td', { class: (c.type === 'num' ? 'num ' : '') + (c.wrap ? 'wrap ' : '') + (c.cls ? c.cls(r) : '') });
          if (c.render) { var n = c.render(r); if (n) td.appendChild(typeof n === 'string' ? document.createTextNode(n) : n); }
          else if (c.type === 'date') td.appendChild(timeEl(r[c.key]));
          else if (c.type === 'num') td.textContent = fmtNum(r[c.key]);
          else td.textContent = r[c.key] === null || r[c.key] === undefined ? '' : String(r[c.key]);
          tr.appendChild(td);
        });
        tb.appendChild(tr);
      });
      count.textContent = fmtNum(list.length) + ' of ' + fmtNum(rows.length);
      if (bulk.length) {
        selInfo.textContent = sel.length ? fmtNum(sel.length) + ' selected' : 'Select rows for: ';
        bulkBtns.forEach(function (b) { b.disabled = !sel.length; });
        allBox.checked = !!list.length && sel.length === list.length; allBox.indeterminate = sel.length > 0 && sel.length < list.length;
      }
    }
    host.appendChild(el('div', { class: 'toolbar' }, search, count, clearBtn, opts.tools || null));
    if (bulk.length) host.appendChild(el('div', { class: 'toolbar bulkbar' }, selInfo, bulkBtns));
    host.appendChild(el('div', { class: 'twrap' }, el('table', { class: 'grid' }, el('thead', null, head, filt), tb)));
    if (!rows.length) host.appendChild(el('div', { class: 'empty', text: opts.empty || 'Nothing here yet.' }));
    draw();
    return host;
  }
  // a bulk action: ONE confirmation for the selection, then one call per row; every queued change is followed
  var bulkBusy = false;   // BULK-1: a second click while the first selection is still being sent sends nothing twice
  function bulkAction(title, text, rows, call) {
    if (bulkBusy) { notice('Still sending the previous selection - wait for it to finish.', 'warn'); return; }
    withReason(title + ' (' + rows.length + ')', text, function (reason) {
      var ids = [], errs = [], i = 0;
      bulkBusy = true;
      notice('Sending ' + fmtNum(rows.length) + ' changes ...');
      var next = function () {
        if (i >= rows.length) { bulkBusy = false; return Promise.resolve({ requestIds: ids, errors: errs, count: rows.length }); }
        var r = rows[i++];
        return call(r, reason).then(function (res) { if (res && res.queued && res.requestId) ids.push(res.requestId); }, function (e) { errs.push(e.message); }).then(next);
      };
      return next();
    });
  }
  // a server-paged table: the server filters, sorts (newest first) and counts (BRAND-2.7 "big or unbounded")
  function pagedTable(path, filters, cols, opts) {
    opts = opts || {};
    var st = { page: 1, values: {} };
    var host = el('div'), body = el('div'), info = el('span', { class: 'count' });
    var bar = el('div', { class: 'toolbar' });
    filters.forEach(function (f) {
      if (f.hidden) { st.values[f.key] = f.value; return; }   // a fixed filter the page sets (no input)
      var inp;
      if (f.options) { inp = el('select', { 'aria-label': f.label }, f.options.map(function (o) { return el('option', { value: o, text: o === '' ? f.label + ': any' : jobName(o) }); })); inp.addEventListener('change', function () { st.values[f.key] = inp.value; st.page = 1; load(); }); }
      else { inp = el('input', { type: f.type || 'search', placeholder: f.label, 'aria-label': f.label }); inp.addEventListener('change', function () { st.values[f.key] = inp.value; st.page = 1; load(); }); }
      if (f.value) { inp.value = f.value; st.values[f.key] = f.value; }
      bar.appendChild(inp);
    });
    bar.appendChild(info);
    var exp = opts.exportPath ? el('a', { href: '#', text: 'Export CSV (the whole filtered result)' }) : null;
    if (exp) { exp.addEventListener('click', function (ev) { ev.preventDefault(); window.location.href = opts.exportPath + '?' + qs(st.values); }); bar.appendChild(exp); }
    var prev = el('button', { type: 'button', class: 'secondary', text: 'Previous' }), next = el('button', { type: 'button', class: 'secondary', text: 'Next' });
    prev.addEventListener('click', function () { if (st.page > 1) { st.page--; load(); } });
    next.addEventListener('click', function () { st.page++; load(); });
    host.appendChild(bar); host.appendChild(body); host.appendChild(el('div', { class: 'pager' }, prev, next));
    function load() {
      var q = Object.assign({}, st.values, { page: st.page, pageSize: 100 });
      api('GET', path + '?' + qs(q)).then(function (j) {
        clear(body).appendChild(table(j.rows, cols, { empty: 'No rows match.' }));
        var from = (st.page - 1) * 100 + 1, to = from + j.rows.length - 1;
        info.textContent = j.total ? fmtNum(from) + '-' + fmtNum(to) + ' of ' + fmtNum(j.total) : '0 rows';
        prev.disabled = st.page <= 1; next.disabled = to >= j.total;
      }).catch(function (e) { clear(body).appendChild(el('div', { class: 'empty', text: e.message })); });
    }
    load();
    return host;
  }

  // ---- pages -------------------------------------------------------------------------------------------------------
  function card(num, label, alert) { return el('div', { class: 'card' + (alert ? ' alert' : '') }, el('div', { class: 'num', text: fmtNum(num) }), el('div', { class: 'lbl', text: label })); }
  function stCell(key) { return function (r) { return 'st-' + r[key]; }; }

  // ---- settings (SETTING-INFO-1): rendered from the catalog, nothing per setting is written in the page --------------
  function parseList(v) { try { var a = JSON.parse(v || '[]'); return Array.isArray(a) ? a.map(String) : []; } catch (e) { return []; } }
  function showValue(r, v) {
    if (v === null || v === undefined || v === '') return r.type === 'list' ? '(none)' : '(empty)';
    if (r.type === 'boolean') return v === 'true' ? 'On' : 'Off';
    if (r.type === 'list') { var a = parseList(v); return a.length ? a.join(', ') : '(none)'; }
    if (r.type === 'int' || r.type === 'number') return fmtNum(v);
    return String(v);
  }
  // the confirmation a switch needs (the catalog's confirm rules), compared with the value in force now
  function confirmFor(r, now, next) {
    var lower = function (a) { return a.map(function (x) { return x.toLowerCase(); }); };
    return (r.confirm || []).filter(function (c) {
      if (c.when === 'on') return next === 'true' && now !== 'true';
      if (c.when === 'off') return next === 'false' && now === 'true';
      if (c.when === 'value') return next === c.value && now !== c.value;
      if (c.when === 'raise') return Number(next) > Number(now);
      if (c.when === 'change') return next !== now;
      var a = lower(parseList(now)), b = lower(parseList(next));
      if (c.when === 'widen') return b.some(function (x) { return a.indexOf(x) < 0; });
      if (c.when === 'narrow') return a.some(function (x) { return b.indexOf(x) < 0; });
      return false;
    })[0] || null;
  }
  function infoPanel(r) {
    var i = r.info || {}, on = r.type === 'boolean' ? 'When on' : 'When set', off = r.type === 'boolean' ? 'When off' : 'When empty or default';
    var dl = el('dl', { class: 'info' });
    [['What it does', i.what], [on, i.enabled], [off, i.disabled], ['Risk and security', i.risk], ['Requires', i.requires], ['Recommended', i.recommended]].forEach(function (x) {
      if (x[1]) { dl.appendChild(el('dt', { text: x[0] })); dl.appendChild(el('dd', { text: x[1] })); }
    });
    dl.appendChild(el('dt', { text: 'Default' })); dl.appendChild(el('dd', { text: showValue(r, r.default) + (r.role === 'SuperAdmin' ? '. Changed by a SuperAdmin.' : '') }));
    var box = el('div', { class: 'infobox' }, dl);
    // DOC-LINKS: shown once Entra Policy Suite is public on invardia.com (set DOCS_LIVE = true with that release)
    if (DOCS_LIVE && i.docUrl && i.docUrl.indexOf('https://invardia.com/') === 0) box.appendChild(el('a', { href: i.docUrl, target: '_blank', rel: 'noopener noreferrer', text: 'Read more on invardia.com' }));
    return box;
  }
  function historyPanel(r) {
    var box = el('div', { class: 'infobox' }, el('span', { class: 'count', text: 'Loading the history ...' }));
    api('GET', '/api/settings/' + encodeURIComponent(r.key) + '/history').then(function (j) {
      clear(box);
      var val = function (js) { try { var o = JSON.parse(js); return o.value; } catch (e) { return null; } };
      var cols = [{ key: 'AtUtc', label: 'When', type: 'date' }, { key: 'Actor', label: 'Who' }, { key: 'Action', label: 'Action', type: 'cat' },
        { key: 'BeforeJson', label: 'Was', wrap: true, render: function (h) { return h.BeforeJson ? showValue(r, val(h.BeforeJson)) : '(not set)'; } },
        { key: 'AfterJson', label: 'Now', wrap: true, render: function (h) { return showValue(r, val(h.AfterJson)); } }];
      if (r.editable && isRole(r.role)) cols.push({ key: '_undo', label: '', render: function (h) {
        if (!h.BeforeJson) return null;
        return el('button', { type: 'button', class: 'secondary', text: 'Put this back', onclick: function () { saveSetting(r, val(h.BeforeJson)); } });
      } });
      box.appendChild(table(j.rows, cols, { sort: 'AtUtc', dir: -1, empty: 'Not changed since the install.' }));
    }).catch(function (e) { clear(box).appendChild(el('span', { text: 'Could not load: ' + e.message })); });
    return box;
  }
  function saveSetting(r, next) {
    var now = r.isSet ? r.value : r.default;
    var c = confirmFor(r, now, next);
    var title = c ? c.title : 'Change ' + r.label;
    var text = (c ? c.body + ' ' + (r.info && r.info.risk ? r.info.risk + ' ' : '') : '') + 'Now: ' + showValue(r, now) + '. New: ' + showValue(r, next) + '.';
    withReason(title, text, function (reason) { return api('PUT', '/api/settings/' + encodeURIComponent(r.key), { value: next, expected: r.isSet ? r.value : null, reason: reason }); });
  }
  function settingRow(r) {
    var now = r.isSet ? r.value : r.default;
    var canEdit = r.editable && isRole(r.role);
    var head = el('div', { class: 'srow' });
    var name = el('div', { class: 'sname' }, el('div', { class: 'slabel', text: r.label }), el('div', { class: 'skey', text: r.key }));
    if (!r.active) name.appendChild(el('span', { class: 'badge', text: 'not used in this release' }));
    head.appendChild(name);
    var ctl = null, read = null;
    if (canEdit) {
      if (r.type === 'boolean') ctl = el('select', { 'aria-label': r.label }, el('option', { value: 'true', text: 'On' }), el('option', { value: 'false', text: 'Off' }));
      else if (r.type === 'enum') ctl = el('select', { 'aria-label': r.label }, (r.values || []).map(function (v) { return el('option', { value: v, text: v }); }));
      else if (r.type === 'list') ctl = el('textarea', { rows: 3, 'aria-label': r.label, placeholder: 'one per line' + (r.itemHint ? ': ' + r.itemHint : '') });
      else ctl = el('input', { type: 'text', 'aria-label': r.label, inputmode: (r.type === 'int' || r.type === 'number') ? 'decimal' : null, maxlength: r.maxLength || null });
      ctl.value = r.type === 'list' ? parseList(now).join('\n') : (now === null || now === undefined ? '' : String(now));
      read = function () { return r.type === 'list' ? JSON.stringify(ctl.value.split('\n').map(function (x) { return x.trim(); }).filter(function (x) { return x; })) : ctl.value.trim(); };
      head.appendChild(el('div', { class: 'sctl' }, ctl));
    } else {
      head.appendChild(el('div', { class: 'sctl sval', text: showValue(r, now) }));
    }
    var panel = el('div', { class: 'spanel', hidden: true });
    var toggle = function (make) { return function () { var open = !panel.hidden && panel.getAttribute('data-kind') === make.name; clear(panel); panel.hidden = open; if (!open) { panel.setAttribute('data-kind', make.name); panel.appendChild(make(r)); } }; };
    var acts = el('div', { class: 'sacts' }, el('button', { type: 'button', class: 'link', text: 'More info', onclick: toggle(infoPanel) }), ' ',
      el('button', { type: 'button', class: 'link', text: 'History', onclick: toggle(historyPanel) }));
    if (canEdit) {
      acts.appendChild(document.createTextNode(' '));
      acts.appendChild(el('button', { type: 'button', text: 'Save', onclick: function () {
        var next = read();
        var norm = function (v) { return r.type === 'list' ? JSON.stringify(parseList(v)) : String(v === null || v === undefined ? '' : v); };
        if (norm(next) === norm(now)) { status('No change to save for ' + r.label + '.'); return; }
        saveSetting(r, next);
      } }));
      if (r.isSet && r.value !== r.default) { acts.appendChild(document.createTextNode(' ')); acts.appendChild(el('button', { type: 'button', class: 'secondary', text: 'Use default', onclick: function () { saveSetting(r, r.default); } })); }
    }
    head.appendChild(acts);
    var meta = el('div', { class: 'smeta' });
    if (!r.editable) meta.appendChild(document.createTextNode('Set by ' + r.setBy + ', not here. '));
    else if (!canEdit) meta.appendChild(document.createTextNode('Changed by a' + (r.role === 'Admin' ? 'n Admin' : ' SuperAdmin') + '. '));
    if (r.isSet && r.updatedAtUtc) { meta.appendChild(document.createTextNode('Changed ')); meta.appendChild(timeEl(r.updatedAtUtc)); if (r.updatedBy) meta.appendChild(document.createTextNode(' by ' + r.updatedBy)); meta.appendChild(document.createTextNode('.')); }
    else meta.appendChild(document.createTextNode('Default (' + showValue(r, r.default) + ').'));
    return el('div', { class: 'setting' }, head, meta, panel);
  }

  // ---- rules (DESIGN §5.9): one card per rule, no group number; a save that would break a reference is refused ------
  function textOf(v) { return v === null || v === undefined ? '' : String(v); }
// the job names people see (owner 2026-11-02: "chane the wording from tick to engine, we dont understand tick");
// the stored name stays 'Tick'
function jobName(j) { return j === 'Tick' ? 'Engine' : textOf(j); }
  function valueInput(tt, cur, label) {
    // the tag type's allowed values as suggestions; the server refuses a value that is not on the list
    var id = 'vals-' + Math.random().toString(36).substring(2);
    var dl = el('datalist', { id: id }, ((tt && tt.values) || []).map(function (v) { return el('option', { value: v.value, label: v.description || (v.isPattern ? 'pattern' : '') }); }));
    var inp = el('input', { type: 'text', list: id, 'aria-label': label, placeholder: label, maxlength: 1024 });
    inp.value = textOf(cur);
    return { node: el('span', null, inp, dl), input: inp };
  }
  function ruleEditor(ot, j, card, opts) {
    // card = an existing card (edit), a copy (duplicate) or {} (new); opts = { insertAfter, title, onDone }
    var box = el('div', { class: 'editor' });
    box.appendChild(el('h3', { text: opts.title }));
    var errs = el('div', { class: 'errors', hidden: true });
    var types = j.tagTypes.filter(function (t) { return t.enabled || t.name === card.TagType; });
    var tsel = el('select', { 'aria-label': 'Tag type' }, el('option', { value: '', text: '- tag type -' }), types.map(function (t) { return el('option', { value: t.name, text: t.name + ' (' + t.attribute + ', ' + t.valueMode + ')' + (t.enabled ? '' : ' - switched off') }); }));
    tsel.value = textOf(card.TagType);
    var persona = el('input', { type: 'text', 'aria-label': 'Persona', placeholder: 'e.g. Internal_Admin', maxlength: 200 }); persona.value = textOf(card.Persona);
    var notes = el('input', { type: 'text', 'aria-label': 'Notes', placeholder: 'why this rule exists (optional)', maxlength: 1000 }); notes.value = textOf(card.Notes);
    var enabled = el('input', { type: 'checkbox', 'aria-label': 'Enabled' }); enabled.checked = card.Enabled !== false;
    // RULE-EDITOR (owner 2026-11-02: "impossible to see the names, values etc"): a two-column form - a label, then the
    // field across the whole width - so a long tag type, value, note or condition target is readable in full
    var form = el('div', { class: 'rf-grid' });
    var fieldRow = function (label, node) { form.appendChild(el('div', { class: 'rf-l', text: label })); form.appendChild(el('div', { class: 'rf-c' }, node)); return node; };
    var valHost = el('div', { class: 'rf-vals' }), vAD = null, vCloud = null, vDev = null;
    function drawValues() {
      clear(valHost);
      var tt = j.tagTypes.filter(function (t) { return t.name === tsel.value; })[0];
      if (ot === 'User') {
        vAD = valueInput(tt, vAD ? vAD.input.value : card.TagValueAD, 'value for AD-synced users'); vCloud = valueInput(tt, vCloud ? vCloud.input.value : card.TagValueCloud, 'value for cloud users');
        valHost.appendChild(el('label', { class: 'rf-val' }, el('span', { text: 'AD-synced users' }), vAD.node));
        valHost.appendChild(el('label', { class: 'rf-val' }, el('span', { text: 'Cloud users' }), vCloud.node));
      } else { vDev = valueInput(tt, vDev ? vDev.input.value : card.TagValue, 'value (empty = clear the attribute)'); valHost.appendChild(vDev.node); }
    }
    tsel.addEventListener('change', drawValues); drawValues();
    var condHost = el('div', { class: 'conds' });
    var ctypes = j.conditionTypes;
    function condRow(c) {
      var s = el('select', { 'aria-label': 'Condition type' }, el('option', { value: '', text: '- condition -' }), ctypes.map(function (d) { return el('option', { value: d.id, text: d.id + (d.shipped ? '' : ' (yours)') }); }));
      s.value = textOf(c.ConditionType);
      var t = el('input', { type: 'text', 'aria-label': 'Target', placeholder: 'target, e.g. *@contoso.com or TRUE', maxlength: 1024 }); t.value = textOf(c.Target);
      var help = el('div', { class: 'smeta cond-help' });
      var showHelp = function () { var d = ctypes.filter(function (x) { return x.id === s.value; })[0]; help.textContent = d ? d.description + (d.modifiesValue ? ' (it also sets the value)' : '') : ''; };
      s.addEventListener('change', showHelp); showHelp();
      var row = el('div', { class: 'cond' }, s, t, el('button', { type: 'button', class: 'link', text: 'Remove', onclick: function () { condHost.removeChild(row); } }), help);
      row._read = function () { return { conditionType: s.value, target: t.value }; };
      condHost.appendChild(row);
    }
    (card.Conditions && card.Conditions.length ? card.Conditions : [{}]).forEach(condRow);
    if (ot === 'User') fieldRow('Persona', persona);
    fieldRow('Tag type', tsel);
    fieldRow(ot === 'User' ? 'Values' : 'Value', valHost);
    fieldRow('Enabled', el('label', { class: 'rf-check' }, enabled, ' the rule runs'));
    fieldRow('Notes', notes);
    box.appendChild(form);
    box.appendChild(el('h4', { class: 'rf-sub', text: 'Conditions - ALL must match' }));
    box.appendChild(el('div', { class: 'smeta', text: 'Rules run top to bottom; for a First tag type the first rule that matches sets the tag.' }));
    box.appendChild(condHost);
    box.appendChild(el('button', { type: 'button', class: 'secondary', text: 'Add condition', onclick: function () { condRow({}); } }));
    box.appendChild(errs);
    var read = function () {
      var b = { tagType: tsel.value, enabled: enabled.checked, notes: notes.value, conditions: Array.prototype.map.call(condHost.children, function (r) { return r._read(); }) };
      if (ot === 'User') { b.persona = persona.value; b.tagValueAD = vAD.input.value; b.tagValueCloud = vCloud.input.value; } else b.tagValue = vDev.input.value;
      return b;
    };
    var save = function () {
      var b = read();
      var call = card.RuleId && !opts.insertAfter && !opts.restore ? function (reason) { b.reason = reason; b.expected = card.UpdatedAtUtc; return api('PUT', '/api/rules/' + ot + '/' + card.RuleId, b); }
        : function (reason) { b.reason = reason; if (opts.insertAfter) b.insertAfter = opts.insertAfter; return api('POST', '/api/rules/' + ot, b); };
      withReason(opts.title, j.queueOn ? 'The change waits in the commit queue until an admin commits it; nothing is written to the directory by saving.' : 'A preview on everyone is queued after the save (when the feature is on); nothing is written to the directory by saving.', function (reason) {
        return call(reason).then(function (r) { if (opts.onSaved) opts.onSaved(); return r; }).catch(function (e) { errs.hidden = false; errs.textContent = 'Not saved: ' + e.message; throw e; });
      });
    };
    box.appendChild(el('div', { class: 'dlg-buttons' }, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: opts.onDone }), el('button', { type: 'button', text: 'Save', onclick: save })));
    return box;
  }
  function openRuleEditor(ot, j, card, opts) {
    // RULE-EDITOR: the editor opens as a WIDE dialog, not inside the narrow side panel; it closes on Cancel, Esc or a
    // save (the notice bar then follows the change)
    var d = el('dialog', { class: 'dlg-wide', 'aria-label': opts.title });
    var closed = false;
    var close = function () { if (closed) return; closed = true; try { d.close(); } catch (e) { /* already closed */ } if (d.parentNode) d.parentNode.removeChild(d); };
    d.appendChild(ruleEditor(ot, j, card, Object.assign({}, opts, { onDone: function () { close(); if (opts.onDone) opts.onDone(); }, onSaved: close })));
    d.addEventListener('close', close);
    document.body.appendChild(d);
    d.showModal();
    var first = d.querySelector('input[type=text], select'); if (first) first.focus();
  }
  function fromJournal(js) {
    // a journal row's card -> the shape the editor reads
    var o = {}; try { o = JSON.parse(js) || {}; } catch (e) { }
    return { RuleId: o.ruleId, Persona: o.persona, TagType: o.tagType, TagValueAD: o.tagValueAD, TagValueCloud: o.tagValueCloud, TagValue: o.tagValue, Enabled: o.enabled, Notes: o.notes,
      Conditions: (o.conditions || []).map(function (c) { return { ConditionType: c.conditionType, Target: c.target }; }) };
  }
  // ---- the commit queue (owner 2026-10-31, PIM's setup): staged rule changes, committed by hand -------------------------
  function prettyJson(s) { if (!s) return ''; try { var o = JSON.parse(s); delete o.reason; delete o.expected; return JSON.stringify(o, null, 1); } catch (e) { return textOf(s); } }
  function drawQueue(p) {
    p.appendChild(el('div', { class: 'guide', text: 'Changes to rules, tag types, tag values and condition types wait here until an admin commits them. A commit writes the chosen changes (each is checked again; one that someone changed meanwhile fails and says so) and then starts ONE tagging run on everyone, in the job\'s own mode - the mass-change guard still holds an unusually large run. Nothing is committed automatically. Discard keeps the change in the list as discarded.' }));
    return api('GET', '/api/queue').then(function (j) {
      if (!j.enabled) p.appendChild(el('div', { class: 'guide', text: 'The commit queue is switched off (Settings > Commit queue): saves are written at once.' }));
      var pending = j.rows.filter(function (r) { return r.Status === 'Pending'; });
      var picked = {};
      var cols = [];
      if (isRole('Admin')) cols.push({ key: '_pick', label: '', render: function (r) {
        if (r.Status !== 'Pending') return null;
        var cb = el('input', { type: 'checkbox', 'aria-label': 'Select change ' + r.Id }); cb.checked = !!picked[r.Id];
        cb.addEventListener('change', function () { picked[r.Id] = cb.checked; }); return cb; } });
      cols = cols.concat([{ key: 'Id', label: '#', type: 'num' }, { key: 'Status', label: 'State', type: 'cat', cls: stCell('Status') }, { key: 'ObjectType', label: 'For', type: 'cat' },
        { key: 'Op', label: 'Change', type: 'cat' }, { key: 'Summary', label: 'What', wrap: true }, { key: 'StagedBy', label: 'Staged by' }, { key: 'StagedAtUtc', label: 'Staged', type: 'date' },
        { key: 'StageReason', label: 'Why', wrap: true },
        { key: '_diff', label: 'Before / after', render: function (r) {
          var d = el('details'); d.appendChild(el('summary', { text: 'show' }));
          d.appendChild(el('div', null, el('strong', { text: 'Before' }), el('pre', { text: r.BeforeJson ? prettyJson(r.BeforeJson) : '(new)' })));
          d.appendChild(el('div', null, el('strong', { text: 'After' }), el('pre', { text: r.Op === 'Delete' ? '(deleted)' : prettyJson(r.BodyJson) }))); return d; } },
        { key: 'CommittedBy', label: 'Committed / discarded by', render: function (r) { return textOf(r.CommittedBy || r.DiscardedBy); } },
        { key: 'Error', label: 'Result', wrap: true, render: function (r) { return textOf(r.Error || r.DiscardReason || (r.Status === 'Applied' ? 'written' : '')); } }]);
      if (isRole('Admin')) {
        var ids = function (all) { return (all ? pending.map(function (r) { return r.Id; }) : Object.keys(picked).filter(function (k) { return picked[k]; }).map(Number)); };
        var commit = function (all) { return function () { var x = ids(all); if (!x.length) { status('Select at least one change.'); return; }
          withReason('Commit ' + x.length + ' change(s)', 'The changes are written now, then one tagging run on everyone is requested in the job\'s own mode (the scheduler starts it within 5 minutes).' + (j.secondApprover === 'all' ? ' A second approver is required: you cannot commit a change you staged.' : ''), function (reason) { return api('POST', '/api/queue/commit', { ids: x, reason: reason }); }); }; };
        p.appendChild(el('div', { class: 'toolbar' }, el('span', { class: 'count', text: fmtNum(pending.length) + ' change(s) waiting' }),
          el('button', { type: 'button', text: 'Commit selected', onclick: commit(false) }), ' ', el('button', { type: 'button', text: 'Commit all', onclick: commit(true) }), ' ',
          el('button', { type: 'button', class: 'secondary', text: 'Discard selected', onclick: function () { var x = ids(false); if (!x.length) { status('Select at least one change.'); return; }
            withReason('Discard ' + x.length + ' change(s)', 'Nothing is written. The changes stay in the list as discarded.', function (reason) { return api('POST', '/api/queue/discard', { ids: x, reason: reason }); }); } }),
          isRole('SuperAdmin') && pending.length ? el('button', { type: 'button', class: 'link', text: 'Discard ALL', onclick: function () {
            withReason('Discard ALL ' + pending.length + ' waiting change(s)', 'Every waiting change is discarded, also other admins\' changes.', function (reason) { return api('POST', '/api/queue/discard-all', { expectedCount: pending.length, reason: reason }); }); } }) : null));
      } else p.appendChild(el('div', { class: 'toolbar' }, el('span', { class: 'count', text: fmtNum(pending.length) + ' change(s) waiting' })));
      p.appendChild(table(j.rows, cols, { sort: 'Id', dir: -1, empty: 'Nothing waiting, and nothing committed yet.' }));
    });
  }
  function queueBanner(p) {
    return api('GET', '/api/queue').then(function (j) {
      var n = j.rows.filter(function (r) { return r.Status === 'Pending'; }).length;
      if (n) p.insertBefore(el('div', { class: 'guide' }, fmtNum(n) + ' change(s) wait in the commit queue and are NOT applied yet. ', el('a', { href: '#queue', text: 'Review and commit' })), p.firstChild);
    }).catch(function () { });
  }

  // ---- the rules grid (RULES-GRID, owner 2026-11-01: "does the rules support things like multi select, duplicate, copy
  // paste values search move" / "like excel edits"). The rules edit like a spreadsheet: select (click, shift, ctrl, all),
  // edit in place, copy / paste with Excel (tab-separated), fill down, duplicate, move a block, bulk on / off / delete /
  // set value, CSV export + import, the v1 files. Every change is ONE batch: the server checks it first (every cell, what
  // would change, the hints of the result), then it is staged in the commit queue with one reason - never written here.
  // undo / redo (RULES-GRID extras): the page's own unsaved edits (edits, new rows, rows marked for delete), step by step,
  // until "Review and stage"; a staged change is undone by discarding it in the commit queue. At most GRID_UNDO steps.
  var GRID = { ot: null, edits: {}, added: [], dels: {}, addSeq: 0, keys: {}, anchor: null, act: null, c1: 0, c2: 0, editing: null, setCol: '', setVal: '', moveTo: 'top', moveRef: '', undo: [], redo: [] };
  var GRID_UNDO = 100;
  var gridActive = null;   // the grid on screen: its copy / paste (the document's clipboard events land here)
  function gridCols(ot) {
    var c = [{ key: 'pos', label: '#', ro: true }, { key: 'enabled', label: 'On', kind: 'bool' }];   // the rule id is on the # cell's hover (owner 2026-11-03: # and Rule were redundant)
    if (ot === 'User') c.push({ key: 'persona', label: 'Persona' });
    c.push({ key: 'tagType', label: 'Tag type', kind: 'tagtype' });
    if (ot === 'User') { c.push({ key: 'tagValueAD', label: 'Value (AD-synced)', kind: 'value' }); c.push({ key: 'tagValueCloud', label: 'Value (cloud)', kind: 'value' }); }
    else c.push({ key: 'tagValue', label: 'Value', kind: 'value' });
    c.push({ key: 'conditions', label: 'Conditions (all must match)', kind: 'conds', wide: true });
    c.push({ key: 'notes', label: 'Description', wide: true });
    c.push({ key: 'matched', label: 'Matched', ro: true }); c.push({ key: 'state', label: 'State', ro: true });
    return c;
  }
  function cardBody(ot, c) {
    var b = { tagType: textOf(c.TagType), enabled: c.Enabled !== false, notes: textOf(c.Notes), conditions: (c.Conditions || []).map(function (x) { return { conditionType: textOf(x.ConditionType), target: textOf(x.Target) }; }) };
    if (ot === 'User') { b.persona = textOf(c.Persona); b.tagValueAD = textOf(c.TagValueAD); b.tagValueCloud = textOf(c.TagValueCloud); } else b.tagValue = textOf(c.TagValue);
    return b;
  }
  function blankBody(ot) { var b = { tagType: '', enabled: true, notes: '', conditions: [] }; if (ot === 'User') { b.persona = ''; b.tagValueAD = ''; b.tagValueCloud = ''; } else b.tagValue = ''; return b; }
  function cloneBody(b) { return JSON.parse(JSON.stringify(b)); }
  // conditions as one cell: "UPN_Like adm-* AND UserType_Like Member" (a target holding " AND " is edited in the side panel)
  function condText(conds) { return (conds || []).map(function (x) { return (textOf(x.conditionType) + ' ' + textOf(x.target)).trim(); }).join(' AND '); }
  function parseConds(s) {
    var out = [], parts = textOf(s).split(/\s+AND\s+/);
    for (var i = 0; i < parts.length; i++) { var p = parts[i].trim(); if (!p) continue; var m = /^([^\s:=]+)[:=]?\s*([\s\S]*)$/.exec(p); out.push({ conditionType: m[1], target: m[2] }); }
    return out;
  }
  function parseBool(s) { var v = textOf(s).trim().toLowerCase(); if (/^(true|1|yes|on|ja)$/.test(v)) return true; if (/^(false|0|no|off|nej)$/.test(v)) return false; return null; }
  // Excel's clipboard: tab-separated, a cell with a tab / new line / quote in quotes. A cell that starts with = + - @ is
  // written with a leading ' so Excel keeps it as text (a directory value is attacker-controlled text), and read back without
  function parseTsv(s) {
    s = textOf(s).replace(/\r\n?/g, '\n'); if (s.slice(-1) === '\n') s = s.slice(0, -1);
    var rows = [], row = [], cell = '', q = false;
    for (var i = 0; i < s.length; i++) {
      var ch = s.charAt(i);
      if (q) { if (ch === '"') { if (s.charAt(i + 1) === '"') { cell += '"'; i++; } else q = false; } else cell += ch; continue; }
      if (ch === '"' && cell === '') { q = true; continue; }
      if (ch === '\t') { row.push(cell); cell = ''; continue; }
      if (ch === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; continue; }
      cell += ch;
    }
    row.push(cell); rows.push(row);
    return rows;
  }
  function toTsv(m) {
    return m.map(function (line) { return line.map(function (v) { var s = textOf(v); if (/^[=+\-@]/.test(s)) s = "'" + s; return /[\t\n\r"]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }).join('\t'); }).join('\r\n');
  }
  function undefuse(v) { var s = textOf(v); return /^'[=+\-@]/.test(s) ? s.substring(1) : s; }
  function cellSet(body, col, text) {
    if (col.ro) return null;
    if (col.kind === 'bool') { var b = parseBool(text); if (b === null) return col.label + ' is TRUE or FALSE, not "' + textOf(text) + '"'; body.enabled = b; return null; }
    if (col.kind === 'conds') { body.conditions = parseConds(text); return null; }
    if (/[\u0000-\u001f]/.test(textOf(text))) return col.label + ': one line of text only';
    body[col.key] = textOf(text).trim(); return null;
  }

  // the review: what the batch would change, checked by the server - then ONE reason and it is staged
  function reviewBatch(ot, j, ops, title, done) {
    if (!ops.length) { status('Nothing to stage.'); return; }
    status('Checking ' + fmtNum(ops.length) + ' change(s) ...');
    api('POST', '/api/rules/' + ot + '/batch/check', { ops: ops }).then(function (chk) { status(''); showReview(ot, j, ops, chk, title, done, null); }).catch(function (e) { status('Could not check: ' + e.message); });
  }
  function showReview(ot, j, ops, chk, title, done, extra) {
    var d = el('dialog', { class: 'rg-dlg' }); document.body.appendChild(d);
    var close = function () { if (d.open) d.close(); if (d.parentNode) d.parentNode.removeChild(d); };
    d.addEventListener('close', function () { if (d.parentNode) d.parentNode.removeChild(d); });
    d.appendChild(el('h3', { text: title }));
    if (extra) d.appendChild(extra);
    d.appendChild(el('div', { class: chk.ok ? 'guide' : 'errors', text: (chk.ok ? 'What would change: ' : 'Not possible as it is: ') + textOf(chk.summary) }));
    var errs = chk.errors || [];
    if (errs.length) d.appendChild(el('div', { class: 'errors', text: errs.slice(0, 40).join('\n') + (errs.length > 40 ? '\n... and ' + fmtNum(errs.length - 40) + ' more' : '') }));
    var tb = el('tbody');
    (chk.items || []).forEach(function (it) {
      var label = it.op === 'addvalue' ? 'add tag value' : it.op + (it.ruleId ? ' ' + it.ruleId : '') + (it.row ? ' (row ' + it.row + ')' : '');
      var ch = it.unchanged ? [{ field: '', before: '', after: '(no change - left out)' }] : (it.changes || []);
      if (!ch.length) ch = [{ field: '', before: '', after: '' }];
      ch.forEach(function (c, i) { tb.appendChild(el('tr', { class: it.errors.length ? 'rg-bad' : null }, el('td', { text: i ? '' : label }), el('td', { text: textOf(c.field) }), el('td', { class: 'wrap', text: c.before === null ? '' : textOf(c.before) }), el('td', { class: 'wrap', text: c.after === null ? '(deleted)' : textOf(c.after) }))); });
      if (it.errors.length) tb.appendChild(el('tr', { class: 'rg-bad' }, el('td'), el('td', { colspan: '3', class: 'wrap', text: 'Refused: ' + it.errors.join('; ') })));
      if (it.hints && it.hints.length) tb.appendChild(el('tr', null, el('td'), el('td', { colspan: '3', class: 'wrap smeta', text: 'Hint: ' + it.hints.join(' ') })));
    });
    d.appendChild(el('div', { class: 'rg-dlgscroll' }, el('table', { class: 'grid' }, el('thead', null, el('tr', null, el('th', { text: 'Change' }), el('th', { text: 'Field' }), el('th', { text: 'Before' }), el('th', { text: 'After' }))), tb)));
    var bad = (chk.items || []).filter(function (it) { return it.errors.length; }).map(function (it) { return it.index; });
    var btns = el('div', { class: 'dlg-buttons' }, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: close }));
    if (!chk.ok && bad.length && bad.length < ops.length) btns.appendChild(el('button', { type: 'button', class: 'secondary', text: 'Leave out the ' + fmtNum(bad.length) + ' refused change(s) and check again', onclick: function () { close(); reviewBatch(ot, j, ops.filter(function (o, i) { return bad.indexOf(i) < 0; }), title, done); } }));
    if (chk.ok) btns.appendChild(el('button', { type: 'button', text: j.queueOn ? 'Stage in the commit queue' : 'Apply', onclick: function () {
      close();
      withReason(title, j.queueOn ? 'The changes wait in the commit queue as ONE entry until an admin commits it (checked again then); nothing is written by staging.' : 'The engine writes them within 5 minutes (checked again then); a preview on everyone follows when the feature is on.', function (reason) {
        return api('POST', '/api/rules/' + ot + '/batch', { ops: ops, reason: reason }).then(function (r) { if (done) done(); return r; });
      });
    } }));
    d.appendChild(btns);
    d.showModal();
  }
  // toggle (v1): read the files again with / without "add the missing values" (they are then added in the SAME batch)
  function importInfo(plan, toggle) {
    var box = el('div');
    if (plan.rowErrors && plan.rowErrors.length) box.appendChild(el('div', { class: 'errors', text: 'Rows not read (left out):\n' + plan.rowErrors.slice(0, 40).join('\n') }));
    var v = plan.v1;
    if (v) {
      box.appendChild(el('div', { class: 'smeta', text: 'Read ' + v.files.join(', ') + ': ' + fmtNum(v.rows) + ' rows = ' + fmtNum(v.cards) + ' rules (v1\'s grouping: one rule per Persona / tag type / values / ConditionGroup). ' + (v.mode === 'replace-imported' ? 'The rules an earlier v1 import made are deleted first.' : 'The rules are added after the last rule.') }));
      if (v.missingValues.length) {
        if (toggle) {
          var cb = el('input', { type: 'checkbox' }); cb.checked = !!v.addValues;
          cb.addEventListener('change', function () { var dl = cb.closest ? cb.closest('dialog') : null; if (dl && dl.open) dl.close(); toggle(cb.checked); });
          box.appendChild(el('label', { class: 'guide' }, cb, ' add these ' + fmtNum(v.missingValues.length) + ' value(s) to their tag types - in the same change as the rules (staged and committed together; plain values only, a pattern stays as it is)'));
        }
        box.appendChild(el('div', { class: 'guide', text: v.addValues ? 'These values are added to their tag type\'s list by this change, before the rules that set them:' : 'These values are not on their tag type\'s list yet - tick the box above to add them with the rules, or add them on the Tag types page first; else the rules that set them are refused:' }));
        var tb = el('tbody'); v.missingValues.forEach(function (x) { tb.appendChild(el('tr', null, el('td', { text: x.tagType }), el('td', { text: x.value }), el('td', { class: 'num', text: fmtNum(x.rules) }))); });
        box.appendChild(el('table', { class: 'grid' }, el('thead', null, el('tr', null, el('th', { text: 'Tag type' }), el('th', { text: 'Value' }), el('th', { class: 'num', text: 'Rules' }))), tb));
      }
      if (v.hints.length) { var h = el('details'); h.appendChild(el('summary', { text: 'Hints (' + fmtNum(v.hints.length) + ') - never blocking' })); v.hints.forEach(function (x) { h.appendChild(el('div', { class: 'smeta', text: x })); }); box.appendChild(h); }
    }
    return box;
  }
  function importDialog(ot, j, onDone) {
    var d = el('dialog', { class: 'rg-dlg' }); document.body.appendChild(d);
    var close = function () { if (d.open) d.close(); if (d.parentNode) d.parentNode.removeChild(d); };
    d.addEventListener('close', function () { if (d.parentNode) d.parentNode.removeChild(d); });
    var fmt = el('select', { 'aria-label': 'Format' }, el('option', { value: 'v2', text: 'This app\'s CSV export (v2)' }), el('option', { value: 'v1', text: 'v1 ' + (ot === 'User' ? 'Identity_Tagging*.csv' : 'Device_Tagging*.csv') + ' (one or more files)' }));
    var file = el('input', { type: 'file', accept: '.csv,text/csv', 'aria-label': 'CSV file' });
    var delMissing = el('input', { type: 'checkbox' }), replace = el('input', { type: 'checkbox' });
    var opt2 = el('label', null, delMissing, ' also delete the rules the file leaves out'), opt1 = el('label', null, replace, ' replace the rules an earlier v1 import made (instead of adding them)');
    var sync = function () { file.multiple = fmt.value === 'v1'; opt2.hidden = fmt.value !== 'v2'; opt1.hidden = fmt.value !== 'v1'; };
    fmt.addEventListener('change', sync); sync();
    var errs = el('div', { class: 'errors', hidden: true });
    var fail = function (t) { errs.hidden = false; errs.textContent = t; };
    d.appendChild(el('h3', { text: 'Import ' + ot.toLowerCase() + ' rules from CSV' }));
    d.appendChild(el('div', { class: 'smeta', text: 'Reading the file writes nothing: you see every change first, then stage it in the commit queue. v2 = this app\'s export (a row with a RuleId changes that rule, a row without one is a new rule placed after the row above it). v1 = the old tagging files, read as the setup import reads them (v1\'s grouping and hints). A demo file is never read.' }));
    d.appendChild(el('div', { class: 'form' }, el('label', null, 'Format ', fmt), el('label', { class: 'wide' }, 'File ', file), opt2, opt1));
    d.appendChild(errs);
    d.appendChild(el('div', { class: 'dlg-buttons' }, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: close }), el('button', { type: 'button', text: 'Read the file', onclick: function () {
      var fs = Array.prototype.slice.call(file.files || []);
      if (!fs.length) { fail('Choose a file.'); return; }
      var demo = fs.filter(function (f) { return /demo/i.test(f.name); })[0];
      if (demo) { fail(demo.name + ' is demo material - it is never read.'); return; }
      if (fs.some(function (f) { return f.size > 900 * 1024; })) { fail('A file is larger than 900 KB.'); return; }
      var run = function (body, first) {
        return api('POST', '/api/rules/' + ot + '/import', body).then(function (plan) {
          if (first) close();
          var again = body.format === 'v1' ? function (on) { body.addValues = on; status('Reading the files again ...'); run(body, false).then(function () { status(''); }).catch(function (e) { status('Could not read the files again: ' + e.message); }); } : null;
          showReview(ot, j, plan.ops || [], plan.check, 'Import ' + ot.toLowerCase() + ' rules (' + plan.format + ')', onDone, importInfo(plan, again));
        });
      };
      Promise.all(fs.map(function (f) { return f.text().then(function (t) { return { name: f.name, text: t }; }); })).then(function (arr) {
        var body = fmt.value === 'v2' ? { format: 'v2', text: arr[0].text, deleteMissing: delMissing.checked } : { format: 'v1', files: arr, mode: replace.checked ? 'replace-imported' : 'append', addValues: false };
        return run(body, true);
      }).catch(function (e) { fail(e.message); });
    } })));
    d.showModal();
  }
  function pasteDialog(onText) {
    var d = el('dialog', { class: 'rg-dlg' }); document.body.appendChild(d);
    var close = function () { if (d.open) d.close(); if (d.parentNode) d.parentNode.removeChild(d); };
    d.addEventListener('close', function () { if (d.parentNode) d.parentNode.removeChild(d); });
    var ta = el('textarea', { rows: '10', 'aria-label': 'Cells from Excel', placeholder: 'Paste the cells here (Ctrl+V)' });
    d.appendChild(el('h3', { text: 'Paste from Excel' }));
    d.appendChild(el('div', { class: 'smeta', text: 'Into the cells from the active cell down and right; one value into every selected cell; with a header row (the grid\'s column names) a row with a Rule number changes that rule and a row without one is a new rule. Nothing is staged until you review it.' }));
    d.appendChild(ta);
    d.appendChild(el('div', { class: 'dlg-buttons' }, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: close }), el('button', { type: 'button', text: 'Paste', onclick: function () { var t = ta.value; close(); onText(t); } })));
    d.showModal(); ta.focus();
  }

  function drawRuleGrid(host, x) {
    var ot = x.ot, j = x.j, admin = x.admin, G = GRID;
    if (G.ot !== ot) { G.ot = ot; G.edits = {}; G.added = []; G.dels = {}; G.keys = {}; G.anchor = null; G.act = null; G.c1 = 0; G.c2 = 0; G.setCol = ''; G.undo = []; G.redo = []; }
    // drag and drop reorders only the run order as it is: not while a search or filter hides rules (a drop between two
    // shown rules would say nothing about the hidden ones in between)
    var dragOk = admin && !x.filtered, drag = null, pendClick = null;
    var cols = gridCols(ot), lastC = cols.length - 1, colIdx = {};
    cols.forEach(function (c, i) { colIdx[c.key] = i; });
    var editable = cols.filter(function (c) { return !c.ro; });
    if (!G.setCol) G.setCol = editable[0].key;
    var byId = {}; x.all.forEach(function (r) { if (r.id) byId[r.id] = r; });
    var R = [];
    var wOf = function (r) { var base = cardBody(ot, r.card); return { key: r.id ? 'r' + r.id : 's' + r.staged, id: r.id, r: r, base: base, body: r.id && G.edits[r.id] ? G.edits[r.id] : base, ro: !r.id }; };
    var build = function () {
      R = x.list.slice().sort(function (a, b) { return (a.pos || 1e9) - (b.pos || 1e9); }).map(wOf);
      G.added.forEach(function (a) { R.push({ key: 'a' + a.k, id: null, r: null, added: a, base: null, body: a.body, ro: false }); });
    };
    var rowIndex = function (k) { for (var i = 0; i < R.length; i++) if (R[i].key === k) return i; return -1; };
    var actRow = function () { return G.act ? rowIndex(G.act.k) : -1; };
    var cellGet = function (w, c) {
      switch (c.key) {
        case 'pos': return w.added ? '+' : (w.r.pos ? String(w.r.pos) : 'new');
        case 'id': return w.id ? String(w.id) : '';
        case 'enabled': return w.body.enabled === false ? 'FALSE' : 'TRUE';
        case 'conditions': return condText(w.body.conditions);
        case 'matched': return w.r && w.r.matched !== null && w.r.matched !== undefined ? String(w.r.matched) : '';
        case 'state': return w.added ? 'new - not staged' + (w.added.after ? ', goes after rule ' + w.added.after : '') : w.id && G.dels[w.id] ? 'delete - not staged' : (w.r.staged ? 'staged: ' + w.r.staged : ({ off: 'off', hint: 'hint: ' + w.r.hints.map(function (h) { return h.text; }).join(' '), on: 'on', staged: 'staged' })[x.stateOf(w.r)]);
        default: return textOf(w.body[c.key]);
      }
    };
    var ensureDraft = function (w) { if (w.added) return w.added.body; if (!G.edits[w.id]) G.edits[w.id] = cloneBody(w.base); w.body = G.edits[w.id]; return w.body; };
    var prune = function (w) { if (w.id && G.edits[w.id] && JSON.stringify(G.edits[w.id]) === JSON.stringify(w.base)) delete G.edits[w.id]; };
    var setCell = function (w, c, text) { if (!c || c.ro || w.ro) return null; var b = ensureDraft(w); var e = cellSet(b, c, text); prune(w); return e; };
    var isDraft = function (w, c) { if (c.ro) return false; if (w.added) return true; return !!(w.id && G.edits[w.id]) && cellGet({ body: G.edits[w.id], r: w.r }, c) !== cellGet({ body: w.base, r: w.r }, c); };
    var selRows = function () { return R.filter(function (w) { return G.keys[w.key]; }); };
    var selExisting = function () { return selRows().filter(function (w) { return w.id && !w.ro; }); };
    var selectOnly = function (i, c, full) { var w = R[i]; if (!w) return; G.keys = {}; G.keys[w.key] = true; G.anchor = { k: w.key, c: c }; G.act = { k: w.key, c: c }; G.c1 = full ? 0 : c; G.c2 = full ? lastC : c; };
    var extendTo = function (i, c, full) {
      var a = G.anchor ? rowIndex(G.anchor.k) : -1; if (a < 0) { selectOnly(i, c, full); return; }
      var lo = Math.min(a, i), hi = Math.max(a, i); G.keys = {}; for (var k = lo; k <= hi; k++) G.keys[R[k].key] = true;
      G.c1 = full ? 0 : Math.min(G.anchor.c, c); G.c2 = full ? lastC : Math.max(G.anchor.c, c); G.act = { k: R[i].key, c: c };
    };
    var selectAll = function () { G.keys = {}; R.forEach(function (w) { G.keys[w.key] = true; }); G.c1 = 0; G.c2 = lastC; if (R.length && actRow() < 0) { G.act = { k: R[0].key, c: 2 }; G.anchor = { k: R[0].key, c: 0 }; } };
    var moveAct = function (dr, dc, extend) { var i = actRow(); if (i < 0) i = 0; var ni = Math.max(0, Math.min(R.length - 1, i + dr)), nc = Math.max(0, Math.min(lastC, (G.act ? G.act.c : 2) + dc)); if (extend) extendTo(ni, nc, false); else selectOnly(ni, nc, false); };
    var lastSelId = function () { var s = selExisting(); return s.length ? s[s.length - 1].id : null; };
    var newRow = function (after) { var a = { k: ++G.addSeq, body: blankBody(ot), after: after || null }; G.added.push(a); return { key: 'a' + a.k, id: null, r: null, added: a, body: a.body, ro: false }; };
    var need = function (t) { status(t || 'Select one or more rules first (click, shift-click, ctrl-click).'); };
    // the history: a snapshot of the page's drafts before each change that changed something
    var snapOf = function () { return JSON.stringify({ e: G.edits, a: G.added, d: G.dels, s: G.addSeq }); };
    var restoreSnap = function (t) { var o = JSON.parse(t); G.edits = o.e; G.added = o.a; G.dels = o.d; G.addSeq = o.s; };
    var change = function (fn) {
      var before = snapOf(); fn();
      if (snapOf() !== before) { G.undo.push(before); if (G.undo.length > GRID_UNDO) G.undo.shift(); G.redo = []; }
    };
    var undo = function () {
      if (!G.undo.length) { status('Nothing to undo on this page. A change already staged is undone by discarding it in the commit queue.'); return; }
      G.redo.push(snapOf()); restoreSnap(G.undo.pop()); paint(); wrap.focus();
      status('Undone - ' + fmtNum(G.undo.length) + ' more step(s) can be undone, Ctrl+Y redoes.');
    };
    var redo = function () {
      if (!G.redo.length) { status('Nothing to redo.'); return; }
      G.undo.push(snapOf()); restoreSnap(G.redo.pop()); paint(); wrap.focus();
      status('Redone - ' + fmtNum(G.redo.length) + ' more step(s) can be redone.');
    };
    var staged = function () { G.edits = {}; G.added = []; G.dels = {}; G.undo = []; G.redo = []; };

    var bar = el('div', { class: 'toolbar rg-bar' });
    var wrap = el('div', { class: 'rg-wrap', tabindex: '0', role: 'grid', 'aria-label': 'The rules as a grid: arrows move, Enter edits, Ctrl+C / Ctrl+V copy and paste with Excel' });
    var table = el('table', { class: 'rg' }), tbody = el('tbody'), hr = el('tr');
    cols.forEach(function (c) { hr.appendChild(el('th', { scope: 'col', class: c.wide ? 'rg-wide' : null, text: c.label, title: c.ro ? 'read only' : 'Enter or double-click to edit' })); });
    table.appendChild(el('thead', null, hr)); table.appendChild(tbody); wrap.appendChild(table);
    host.appendChild(bar); host.appendChild(wrap);
    host.appendChild(el('div', { class: 'smeta', text: 'Click a cell; shift-click a range; ctrl-click more rules; click # for whole rows. Arrows move (shift extends), Enter / F2 or typing edits, Esc cancels, Ctrl+A all shown, Ctrl+C / Ctrl+V with Excel, Ctrl+D fills down, Delete marks the selected rules for delete (again = unmark). Edits stay on this page (marked) until you review and stage them; Ctrl+Z / Ctrl+Y (Undo / Redo) take them back and forth, step by step (up to ' + GRID_UNDO + ' steps). Once staged, a change is undone by discarding it in the commit queue. To reorder: select the rules, then drag their # between two rules (without a search or filter), or use Move - both are reviewed at once. Conditions: "UPN_Like adm-* AND UserType_Like Member".' }));

    var scrollAct = function () { var i = actRow(); if (i < 0) return; var td = tbody.querySelector('td[data-r="' + i + '"][data-c="' + G.act.c + '"]'); if (td && td.scrollIntoView) td.scrollIntoView({ block: 'nearest', inline: 'nearest' }); };
    var paint = function () {
      build(); clear(tbody);
      var ai = actRow();
      R.forEach(function (w, ri) {
        var tr = el('tr', { class: (w.ro ? 'rg-rro ' : '') + (w.added ? 'rg-new ' : '') + (w.id && G.dels[w.id] ? 'rg-del ' : '') + (G.keys[w.key] ? 'rg-rsel' : '') });
        cols.forEach(function (c, ci) {
          var cls = [];
          if (c.ro || w.ro) cls.push('rg-ro');
          if (G.keys[w.key] && ci >= G.c1 && ci <= G.c2) cls.push('rg-sel');
          if (ri === ai && G.act.c === ci) cls.push('rg-act');
          if (isDraft(w, c)) cls.push('rg-draft');
          if (c.wide) cls.push('rg-wide');
          if (c.key === 'pos' || c.key === 'id' || c.key === 'matched') cls.push('num');
          var v = cellGet(w, c), tip = c.wide && v.length > 40 ? v : (c.key === 'pos' && w.id ? 'Rule ' + w.id : null), grab = false;
          if (ci === 0 && admin && w.id && !w.ro) {
            if (dragOk) { grab = true; cls.push('rg-grab'); tip = 'Rule ' + w.id + ' - select the rules, then drag their # to a new place in the run order'; }
            else tip = 'Clear the search and filters to drag rules to a new place (Move works with a filter too)';
          }
          tr.appendChild(el('td', { 'data-r': String(ri), 'data-c': String(ci), class: cls.join(' '), title: tip, draggable: grab ? 'true' : null, text: c.key === 'matched' && v !== '' ? fmtNum(v) : v }));
        });
        tbody.appendChild(tr);
      });
      if (!R.length) tbody.appendChild(el('tr', null, el('td', { colspan: String(cols.length), class: 'empty', text: x.all.length ? 'No rule matches the filters.' : 'No rules yet - import them, or add a row.' })));
      drawBar();
    };

    // in-place edit of the active cell (seed = the key that started it)
    var startEdit = function (seed) {
      var ri = actRow(); if (ri < 0) return;
      if (!admin) { status('Editing the rules needs the Admin role.'); return; }
      var w = R[ri], c = cols[G.act.c];
      if (c.ro) { status(c.label + ' is not edited here.'); return; }
      if (w.ro) { status('A staged new rule is changed in the commit queue (discard it there).'); return; }
      var td = tbody.querySelector('td[data-r="' + ri + '"][data-c="' + G.act.c + '"]'); if (!td) return;
      var cur = cellGet(w, c), inp, extra = null;
      if (c.kind === 'bool') { inp = el('select', { 'aria-label': c.label }, el('option', { value: 'TRUE', text: 'TRUE' }), el('option', { value: 'FALSE', text: 'FALSE' })); inp.value = cur; }
      else if (c.kind === 'tagtype') { inp = el('select', { 'aria-label': c.label }, el('option', { value: '', text: '-' }), j.tagTypes.filter(function (t) { return t.enabled || t.name === cur; }).map(function (t) { return el('option', { value: t.name, text: t.name }); })); inp.value = cur; }
      else {
        inp = el('input', { type: 'text', 'aria-label': c.label, maxlength: c.kind === 'conds' ? '20000' : '1024' });
        inp.value = seed !== undefined ? seed : cur;
        if (c.kind === 'value') { var tt = j.tagTypes.filter(function (t) { return t.name === w.body.tagType; })[0]; if (tt && tt.values.length) { var lid = 'rgv-' + ri + '-' + G.act.c; inp.setAttribute('list', lid); extra = el('datalist', { id: lid }, tt.values.map(function (v) { return el('option', { value: v.value }); })); } }
      }
      inp.className = 'rg-in';
      clear(td).appendChild(inp); if (extra) td.appendChild(extra);
      G.editing = { inp: inp };
      var finish = function (save, mv) {
        if (!G.editing) return; G.editing = null;
        if (save) change(function () { var e = setCell(w, c, inp.value); if (e) status('Not taken: ' + e); });
        if (mv) moveAct(mv[0], mv[1], false);
        paint(); wrap.focus(); scrollAct();
      };
      inp.addEventListener('keydown', function (e) {
        e.stopPropagation();
        if (e.key === 'Enter') { e.preventDefault(); finish(true, [1, 0]); }
        else if (e.key === 'Tab') { e.preventDefault(); finish(true, [0, e.shiftKey ? -1 : 1]); }
        else if (e.key === 'Escape') { e.preventDefault(); finish(false); }
      });
      inp.addEventListener('blur', function () { finish(true); });
      inp.focus();
      if (inp.select && seed === undefined) inp.select();
    };

    // copy / paste (Excel), fill down, bulk actions - each a batch reviewed by the server first
    var copyText = function (withHead) {
      var ws = selRows(); if (!ws.length) { if (!withHead) return null; ws = R; }
      var cs = withHead ? cols : cols.slice(G.c1, G.c2 + 1);
      var m = ws.map(function (w) { return cs.map(function (c) { return cellGet(w, c); }); });
      if (withHead) m.unshift(cs.map(function (c) { return c.label; }));
      return toTsv(m);
    };
    var copyOut = function (withHead) {
      var t = copyText(withHead); if (t === null) { need(); return; }
      var ok = function () { status('Copied ' + fmtNum(t.split('\r\n').length) + ' row(s) - paste them into Excel.'); };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(t).then(ok).catch(function () { status('The browser refused the clipboard - select cells and press Ctrl+C.'); });
      else status('The browser has no clipboard access - select cells and press Ctrl+C.');
    };
    var headerOf = function (line) {
      var map = {}, hit = 0;
      for (var i = 0; i < line.length; i++) {
        var h = textOf(line[i]).trim().toLowerCase(); if (!h) continue;
        var c = cols.filter(function (k) { return k.label.toLowerCase() === h || k.key.toLowerCase() === h; })[0];
        if (!c) return null; map[c.key] = i; hit++;
      }
      return hit >= 2 ? map : null;
    };
    var pasteText = function (t) { change(function () { pasteRaw(t); }); };
    var pasteRaw = function (t) {
      if (!admin) { status('Pasting changes the rules: that needs the Admin role.'); return; }
      var m = parseTsv(t);
      if (!m.length || (m.length === 1 && m[0].length === 1 && m[0][0] === '')) return;
      var errs = [], n = 0;
      var put = function (w, c, v) { if (!c || c.ro || w.ro) return; var e = setCell(w, c, undefuse(v)); if (e) errs.push(e); else n++; };
      var hm = headerOf(m[0]);
      if (hm) {
        var after = lastSelId();
        m.slice(1).forEach(function (line) {
          if (!line.join('').trim()) return;
          var id = hm.id !== undefined ? textOf(line[hm.id]).trim() : '';
          var w = id && byId[id] ? wOf(byId[id]) : newRow(after);
          Object.keys(hm).forEach(function (key) { put(w, cols[colIdx[key]], line[hm[key]]); });
        });
      } else {
        var i0 = actRow(); if (i0 < 0) { status('Click the cell to paste into first.'); return; }
        var c0 = G.act.c, cells = 0;
        R.forEach(function (w) { if (G.keys[w.key]) cells += G.c2 - G.c1 + 1; });
        if (m.length === 1 && m[0].length === 1 && cells > 1) selRows().forEach(function (w) { for (var ci = G.c1; ci <= G.c2; ci++) put(w, cols[ci], m[0][0]); });
        else { var snap = R.slice(); m.forEach(function (line, li) { var w = snap[i0 + li] || newRow(null); line.forEach(function (v, lj) { put(w, cols[c0 + lj], v); }); }); }
      }
      paint();
      status((errs.length ? 'Not taken: ' + errs.slice(0, 3).join('; ') + '. ' : '') + 'Pasted ' + fmtNum(n) + ' cell(s) - marked; review and stage them when done (every cell is checked by the server then).');
    };
    var fillDown = function () {
      if (!admin) { status('Editing the rules needs the Admin role.'); return; }
      var ws = selRows().filter(function (w) { return !w.ro; });
      if (ws.length < 2) { need('Select two or more rows (shift-click) to fill down.'); return; }
      var cs = cols.slice(G.c1, G.c2 + 1).filter(function (c) { return !c.ro; });
      if (!cs.length) { need('Select an editable column to fill down.'); return; }
      change(function () { ws.slice(1).forEach(function (w) { cs.forEach(function (c) { setCell(w, c, cellGet(ws[0], c)); }); }); });
      paint(); status('Filled ' + fmtNum(ws.length - 1) + ' row(s) from the first - review and stage them when done.');
    };
    var draftOps = function () {
      var ops = [];
      Object.keys(G.edits).forEach(function (id) { var r = byId[id]; if (r && !G.dels[id]) ops.push({ op: 'update', id: Number(id), expected: r.card.UpdatedAtUtc, rule: G.edits[id] }); });
      G.added.forEach(function (a, i) { ops.push({ op: 'create', rule: a.body, insertAfter: i > 0 && G.added[i - 1].after === a.after ? 'prev' : (a.after || 0) }); });
      // the deletes last: a new row may go after a rule this batch deletes
      Object.keys(G.dels).forEach(function (id) { var r = byId[id]; if (r) ops.push({ op: 'delete', id: Number(id), expected: r.card.UpdatedAtUtc }); });
      return ops;
    };
    // On / Off, Delete and Duplicate are page edits too (marked, undoable) until "Review and stage"
    var bulkEnable = function (on) {
      if (!admin) return;
      var ws = selRows().filter(function (w) { return !w.ro; }); if (!ws.length) { need(); return; }
      change(function () { ws.forEach(function (w) { setCell(w, cols[colIdx.enabled], on ? 'TRUE' : 'FALSE'); }); });
      paint(); status((on ? 'Switched on: ' : 'Switched off: ') + fmtNum(ws.length) + ' rule(s) - marked; review and stage them when done (Ctrl+Z undoes).');
    };
    var deleteSel = function () {
      if (!admin) return;
      var ws = selRows();
      var adds = ws.filter(function (w) { return w.added; });
      var ex = ws.filter(function (w) { return w.id && !w.ro; });
      if (!adds.length && !ex.length) { need(); return; }
      var unmark = ex.length > 0 && ex.every(function (w) { return G.dels[w.id]; });
      change(function () {
        if (adds.length) G.added = G.added.filter(function (a) { return !adds.some(function (w) { return w.added.k === a.k; }); });
        ex.forEach(function (w) { if (unmark) delete G.dels[w.id]; else G.dels[w.id] = true; });
      });
      paint();
      status(unmark ? 'No longer marked for delete: ' + fmtNum(ex.length) + ' rule(s).' : (ex.length ? fmtNum(ex.length) + ' rule(s) marked for delete' : '') + (adds.length ? (ex.length ? ', ' : '') + fmtNum(adds.length) + ' new row(s) removed' : '') + ' - review and stage when done (Ctrl+Z undoes).');
    };
    var duplicateSel = function () {
      if (!admin) return;
      var ws = selExisting(); if (!ws.length) { need(); return; }
      var last = ws[ws.length - 1];
      change(function () { ws.forEach(function (w) { var nw = newRow(last.id); nw.added.body = cloneBody(w.body); }); });
      paint(); status('Duplicated ' + fmtNum(ws.length) + ' rule(s) - the copies (new rows at the end of the grid) go right after rule ' + last.id + ' when staged. Ctrl+Z undoes.');
    };
    var moveOp = function (ws, to, ref, refPos) {
      var op = { op: 'move', ids: ws.map(function (w) { return w.id; }), to: to };
      if (ref) op.ref = ref;
      reviewBatch(ot, j, [op], 'Move ' + fmtNum(ws.length) + ' rule(s) ' + (ref ? to + ' #' + refPos : 'to the ' + to), null);
    };
    var moveSel = function () {
      var ws = selExisting(); if (!ws.length) { need(); return; }
      if (G.moveTo === 'before' || G.moveTo === 'after') {
        var pos = parseInt(G.moveRef, 10), ref = x.all.filter(function (r) { return r.id && r.pos === pos; })[0];
        if (!ref) { status('Give the number (#) of the rule to move them ' + G.moveTo + '.'); return; }
        moveOp(ws, G.moveTo, ref.id, pos); return;
      }
      moveOp(ws, G.moveTo, null, null);
    };
    var setValueSel = function () {
      var ws = selRows().filter(function (w) { return !w.ro; }); if (!ws.length) { need(); return; }
      var c = cols[colIdx[G.setCol]], errs = [];
      change(function () { ws.forEach(function (w) { var e = setCell(w, c, G.setVal); if (e) errs.push(e); }); });
      paint(); status(errs.length ? 'Not taken: ' + errs[0] : c.label + ' set on ' + fmtNum(ws.length) + ' rule(s) - marked; review and stage them when done.');
    };
    var addRow = function () { var w = null; change(function () { w = newRow(lastSelId()); }); build(); var i = rowIndex(w.key); selectOnly(i, colIdx[ot === 'User' ? 'persona' : 'tagType'], false); paint(); scrollAct(); wrap.focus(); };
    var nDraft = function () { return Object.keys(G.edits).filter(function (id) { return !G.dels[id]; }).length + G.added.length + Object.keys(G.dels).length; };

    var drawBar = function () {
      clear(bar);
      var nSel = selRows().length, nd = nDraft();
      bar.appendChild(el('span', { class: 'count', text: fmtNum(R.length) + ' shown, ' + fmtNum(nSel) + ' selected' }));
      bar.appendChild(el('button', { type: 'button', class: 'secondary', text: 'Select all shown', onclick: function () { selectAll(); paint(); wrap.focus(); } }));
      bar.appendChild(el('button', { type: 'button', class: 'secondary', text: 'Copy', title: 'the selected cells, tab-separated (Excel)', onclick: function () { copyOut(false); } }));
      bar.appendChild(el('button', { type: 'button', class: 'secondary', text: 'Copy with headers', title: 'every column of the selected rules (or all shown) with the column names - paste it back to change them', onclick: function () { copyOut(true); } }));
      bar.appendChild(el('button', { type: 'button', class: 'secondary', text: 'Export CSV', onclick: function () { window.location.href = '/api/rules/' + ot + '/export'; } }));
      if (admin) {
        bar.appendChild(el('span', { class: 'rg-grp' },
          el('button', { type: 'button', class: 'secondary', text: 'Undo', disabled: !G.undo.length, title: 'Ctrl+Z - the last edit on this page (' + fmtNum(G.undo.length) + ' step(s)); a staged change is discarded in the commit queue', onclick: undo }),
          el('button', { type: 'button', class: 'secondary', text: 'Redo', disabled: !G.redo.length, title: 'Ctrl+Y (or Ctrl+Shift+Z) - ' + fmtNum(G.redo.length) + ' step(s)', onclick: redo })));
        if (nd) {
          bar.appendChild(el('button', { type: 'button', text: 'Review and stage ' + fmtNum(nd) + ' edited rule(s)', onclick: function () { reviewBatch(ot, j, draftOps(), 'Stage ' + fmtNum(nd) + ' edited / new / deleted rule(s)', staged); } }));
          bar.appendChild(el('button', { type: 'button', class: 'link', text: 'Discard the edits', onclick: function () { change(function () { G.edits = {}; G.added = []; G.dels = {}; }); paint(); status('The edits on this page are discarded (nothing was staged) - Undo brings them back.'); } }));
        }
        var g1 = el('span', { class: 'rg-grp' },
          el('button', { type: 'button', class: 'secondary', text: 'Paste ...', title: 'paste cells from Excel (or press Ctrl+V in the grid)', onclick: function () { pasteDialog(pasteText); } }),
          el('button', { type: 'button', class: 'secondary', text: 'Fill down', title: 'Ctrl+D', onclick: fillDown }),
          el('button', { type: 'button', class: 'secondary', text: 'Add row', onclick: addRow }),
          el('button', { type: 'button', class: 'secondary', text: 'Duplicate', onclick: duplicateSel }),
          el('button', { type: 'button', class: 'secondary', text: 'On', title: 'switch the selected rules on', onclick: function () { bulkEnable(true); } }),
          el('button', { type: 'button', class: 'secondary', text: 'Off', title: 'switch the selected rules off', onclick: function () { bulkEnable(false); } }),
          el('button', { type: 'button', class: 'link', text: 'Delete', onclick: deleteSel }));
        var sc = el('select', { 'aria-label': 'Column to set' }, editable.map(function (c) { return el('option', { value: c.key, text: c.label }); })); sc.value = G.setCol;
        sc.addEventListener('change', function () { G.setCol = sc.value; });
        var sv = el('input', { type: 'text', 'aria-label': 'Value to set', placeholder: 'value', maxlength: '1024' }); sv.value = G.setVal;
        sv.addEventListener('input', function () { G.setVal = sv.value; });
        var g2 = el('span', { class: 'rg-grp' }, 'Set ', sc, ' to ', sv, el('button', { type: 'button', class: 'secondary', text: 'Set', onclick: setValueSel }));
        var mt = el('select', { 'aria-label': 'Move to' }, [['top', 'to the top'], ['bottom', 'to the bottom'], ['before', 'before #'], ['after', 'after #']].map(function (o) { return el('option', { value: o[0], text: o[1] }); })); mt.value = G.moveTo;
        var mr = el('input', { type: 'text', 'aria-label': 'Rule number', placeholder: '#', size: '4', maxlength: '6' }); mr.value = G.moveRef;
        mt.addEventListener('change', function () { G.moveTo = mt.value; }); mr.addEventListener('input', function () { G.moveRef = mr.value; });
        var g3 = el('span', { class: 'rg-grp' }, 'Move ', mt, mr, el('button', { type: 'button', class: 'secondary', text: 'Move', onclick: moveSel }));
        bar.appendChild(g1); bar.appendChild(g2); bar.appendChild(g3);
        bar.appendChild(el('button', { type: 'button', class: 'secondary', text: 'Import CSV ...', onclick: function () { importDialog(ot, j, null); } }));
      }
    };

    tbody.addEventListener('mousedown', function (e) {
      var td = e.target.closest ? e.target.closest('td[data-c]') : null;
      if (!td || G.editing) return;
      var ri = Number(td.getAttribute('data-r')), ci = Number(td.getAttribute('data-c')), full = ci <= 1;
      // the # of a SELECTED rule is the drag handle: keep the selection (no repaint, which would end the drag before it
      // starts); a plain click on it without a drag selects that row alone (the click event below)
      if (ci === 0 && dragOk && R[ri] && R[ri].id && !R[ri].ro && G.keys[R[ri].key] && !e.shiftKey && !e.ctrlKey && !e.metaKey) { pendClick = ri; wrap.focus(); return; }
      pendClick = null;
      e.preventDefault();
      if (e.shiftKey && G.anchor) extendTo(ri, ci, full);
      else if (e.ctrlKey || e.metaKey) { var k = R[ri].key; if (G.keys[k]) delete G.keys[k]; else G.keys[k] = true; G.act = { k: k, c: ci }; G.anchor = { k: k, c: ci }; if (full) { G.c1 = 0; G.c2 = lastC; } }
      else { selectOnly(ri, ci, full); if (R[ri].r && R[ri].id) x.side(R[ri].r); }
      paint(); wrap.focus();
    });
    tbody.addEventListener('click', function () {
      if (pendClick === null) return;
      var ri = pendClick; pendClick = null; if (!R[ri]) return;
      selectOnly(ri, 0, true); if (R[ri].r && R[ri].id) x.side(R[ri].r); paint(); wrap.focus();
    });
    tbody.addEventListener('dblclick', function (e) { var td = e.target.closest ? e.target.closest('td[data-c]') : null; if (td && !G.editing) startEdit(); });

    // drag and drop (RULES-GRID extras): the selected rules' # dragged between two rules = the same move-to-position as
    // "Move before / after #" (one block, kept in its run order), reviewed by the server first. Only on the unfiltered
    // run order (dragOk); Move (and the keyboard) stays for everything else.
    var dropMark = null;
    var clearDrop = function () { if (dropMark) { dropMark.classList.remove('rg-drop-before'); dropMark.classList.remove('rg-drop-after'); dropMark = null; } };
    var dropAt = function (e) {
      var td = e.target.closest ? e.target.closest('td[data-r]') : null; if (!td || !drag) return null;
      var w = R[Number(td.getAttribute('data-r'))]; if (!w || !w.id || w.ro || drag.keys[w.key]) return null;
      var tr = td.parentNode, rc = tr.getBoundingClientRect();
      return { w: w, tr: tr, before: e.clientY < rc.top + rc.height / 2 };
    };
    var dropChanges = function (t) {
      // a drop right next to the block leaves the run order as it is: not a change
      var ids = R.filter(function (w) { return w.id && !w.ro; }).map(function (w) { return w.id; });
      var rest = ids.filter(function (id) { return drag.ids.indexOf(id) < 0; }), at = rest.indexOf(t.w.id) + (t.before ? 0 : 1);
      return rest.slice(0, at).concat(drag.ids, rest.slice(at)).join(',') !== ids.join(',');
    };
    tbody.addEventListener('dragstart', function (e) {
      var ws = selExisting();
      if (!dragOk || G.editing || !ws.length) { e.preventDefault(); return; }
      pendClick = null;
      drag = { ids: ws.map(function (w) { return w.id; }), keys: {} }; ws.forEach(function (w) { drag.keys[w.key] = true; });
      if (e.dataTransfer) { e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', drag.ids.join(',')); }
      status('Drop the ' + fmtNum(ws.length) + ' selected rule(s) between two rules (Esc cancels).');
    });
    tbody.addEventListener('dragover', function (e) {
      var t = dropAt(e); clearDrop(); if (!t) return;
      e.preventDefault(); if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
      dropMark = t.tr; dropMark.classList.add(t.before ? 'rg-drop-before' : 'rg-drop-after');
    });
    tbody.addEventListener('drop', function (e) {
      var t = dropAt(e); clearDrop(); if (!t) return;
      e.preventDefault();
      var ws = selExisting().filter(function (w) { return drag.keys[w.key]; }), moves = dropChanges(t);
      drag = null;
      if (!moves) { status('That is where they are already.'); return; }
      moveOp(ws, t.before ? 'before' : 'after', t.w.id, t.w.r.pos);
    });
    tbody.addEventListener('dragend', function () { clearDrop(); if (drag) status(''); drag = null; });

    wrap.addEventListener('keydown', function (e) {
      if (G.editing) return;
      var k = e.key, ctl = e.ctrlKey || e.metaKey;
      // undo / redo of the page's own edits (an input being edited keeps its own Ctrl+Z: its keydown stops here)
      if (ctl && !e.altKey && (k === 'z' || k === 'Z')) { e.preventDefault(); if (e.shiftKey) redo(); else undo(); return; }
      if (ctl && !e.altKey && (k === 'y' || k === 'Y')) { e.preventDefault(); redo(); return; }
      if (!R.length) return;
      if (actRow() < 0 && k !== 'Tab') { selectOnly(0, 2, false); paint(); }
      var mv = { ArrowUp: [-1, 0], ArrowDown: [1, 0], ArrowLeft: [0, -1], ArrowRight: [0, 1] }[k];
      if (mv) { e.preventDefault(); moveAct(mv[0], mv[1], e.shiftKey); paint(); scrollAct(); return; }
      if (ctl && (k === 'a' || k === 'A')) { e.preventDefault(); selectAll(); paint(); return; }
      if (ctl && (k === 'd' || k === 'D')) { e.preventDefault(); fillDown(); return; }
      if (ctl || e.altKey || k === 'Tab') return;   // Ctrl+C / Ctrl+V arrive as the copy / paste events; Tab leaves the grid
      if (k === 'Enter' || k === 'F2') { e.preventDefault(); startEdit(); return; }
      if (k === 'Escape') { var i = actRow(); if (i >= 0) { selectOnly(i, G.act.c, false); paint(); } return; }
      if (k === 'Delete') { e.preventDefault(); deleteSel(); return; }
      if (k === 'Backspace') { e.preventDefault(); startEdit(''); return; }
      if (k.length === 1) { e.preventDefault(); startEdit(k); }
    });
    gridActive = { wrap: wrap, copy: function () { return copyText(false); }, paste: pasteText, editing: function () { return !!G.editing; } };
    paint();
  }
  // the clipboard events reach the document; the grid on screen takes them while it has the focus (and no cell is edited)
  document.addEventListener('copy', function (e) {
    if (!gridActive || !document.body.contains(gridActive.wrap) || !gridActive.wrap.contains(document.activeElement) || gridActive.editing()) return;
    var t = gridActive.copy(); if (t === null || !e.clipboardData) return;
    e.clipboardData.setData('text/plain', t); e.preventDefault(); status('Copied - paste it into Excel.');
  });
  document.addEventListener('paste', function (e) {
    if (!gridActive || !document.body.contains(gridActive.wrap) || !gridActive.wrap.contains(document.activeElement) || gridActive.editing() || !e.clipboardData) return;
    e.preventDefault(); gridActive.paste(e.clipboardData.getData('text/plain'));
  });

  // ---- the rules view (RULES-UX, owner 2026-10-31: "it must be grouped differently. like condition groups. why not
  // grids. filter options" - the mock-up approved: "love it"). A grid grouped by persona (each rule = one condition
  // group, its conditions ANDed, the alternatives for a tag type ORed in run order), filters with counts, a side panel
  // for the selected rule and "Try on a user". Staged changes from the commit queue show in place.
  var RULES = { view: store.get('eps.rules.view', 'cards'), groupBy: store.get('eps.rules.groupBy', 'persona'), q: '',tags: {}, states: {}, conds: {}, open: {}, sel: null, tryReq: null, tryOut: null };
  var RULE_STATE_TEXT = { off: 'Off', staged: 'Staged - not applied', hint: 'Hint', on: 'On' };
  function drawRules(p, ot, j) {
    var admin = isRole('Admin'), S = RULES;
    var attr = {}; j.tagTypes.forEach(function (t) { attr[t.name] = t.attribute; });
    var valueOf = function (r) { return ot === 'User' ? (textOf(r.TagValueAD) === textOf(r.TagValueCloud) ? (textOf(r.TagValueAD) || '-') : 'AD ' + (textOf(r.TagValueAD) || '-') + ' / cloud ' + (textOf(r.TagValueCloud) || '-')) : (textOf(r.TagValue) || '(clear)'); };
    var rows = j.rows.map(function (r, i) { return { id: r.RuleId, pos: i + 1, card: r, persona: ot === 'User' ? textOf(r.Persona) : textOf(r.TagType), tagType: r.TagType, value: valueOf(r),
      conds: r.Conditions || [], enabled: r.Enabled, hints: r.Hints || [], matched: r.Matched, staged: null }; });
    var host = el('div', { class: 'rx' }); p.appendChild(host);

    var build = function (queue) {
      // staged changes from the commit queue: a changed / deleted / moved rule is marked; a new rule shows as a row of its own
      rows = rows.filter(function (r) { return r.id; }); rows.forEach(function (r) { r.staged = null; });   // build runs again on Clear filters
      var stagedNew = function (b, q) {
        var c = { Persona: b.persona, TagType: b.tagType, TagValueAD: b.tagValueAD, TagValueCloud: b.tagValueCloud, TagValue: b.tagValue, Notes: b.notes, Enabled: b.enabled !== false,
          Conditions: (b.conditions || []).map(function (x) { return { ConditionType: x.conditionType, Target: x.target }; }) };
        rows.push({ id: null, pos: null, card: c, persona: ot === 'User' ? textOf(b.persona) : textOf(b.tagType), tagType: b.tagType, value: valueOf(c),
          conds: c.Conditions, enabled: b.enabled !== false, hints: [], matched: null, staged: 'new (#' + q.Id + ')' });
      };
      var markStaged = function (id, what) { var hit = rows.filter(function (r) { return r.id && String(r.id) === String(id); })[0]; if (hit) hit.staged = what; };
      (queue || []).filter(function (q) { return q.Status === 'Pending' && q.Entity === ot + 'TagRule'; }).forEach(function (q) {
        var b = {}; try { b = JSON.parse(q.BodyJson) || {}; } catch (e) { }
        if (q.Op === 'Batch') {
          // a grid batch (RULES-GRID): every rule it touches is marked, its new rules show as rows of their own
          (b.ops || []).forEach(function (o) {
            if (o.op === 'create') stagedNew(o.rule || {}, q);
            else if (o.op === 'move') (o.ids || []).forEach(function (id) { markStaged(id, 'move (#' + q.Id + ')'); });
            else if (o.op === 'addvalue') return;   // a tag value the batch adds (the v1 import): no rule to mark
            else markStaged(o.id, o.op + ' (#' + q.Id + ')');
          });
        } else if (q.Op === 'Create') stagedNew(b, q);
        else markStaged(q.Op === 'Move' ? String(q.EntityKey).split(':')[1] : String(q.EntityKey).split(':').pop(), q.Op.toLowerCase() + ' (#' + q.Id + ')');
      });
      clear(host);
      if (!j.featureEnabled) host.appendChild(el('div', { class: 'guide', text: (ot === 'User' ? 'User' : 'Device') + ' tagging is switched off (Settings): rules can be edited, nothing runs.' }));
      var nStaged = rows.filter(function (r) { return r.staged; }).length;
      if (nStaged) host.appendChild(el('div', { class: 'bar bar-warn rx-banner' }, el('strong', { text: fmtNum(nStaged) + ' change(s) wait in the commit queue' }), ' - not applied yet; marked "staged" below. ', el('a', { href: '#queue', text: 'Review and commit' })));

      var stateOf = function (r) { return !r.enabled ? 'off' : r.staged ? 'staged' : r.hints.length ? 'hint' : 'on'; };
      var search = el('input', { type: 'search', placeholder: 'persona, value, condition, target ...', 'aria-label': 'Search the rules' }); search.value = S.q;
      var group = el('select', { 'aria-label': 'Group by' }, [['persona', ot === 'User' ? 'Persona (condition groups)' : 'Tag type'], ['tagtype', ot === 'User' ? 'Tag type' : 'Value'], ['condition', 'Condition type'], ['none', 'None - run order']].map(function (o) { return el('option', { value: o[0], text: o[1] }); }));
      group.value = S.groupBy;
      var bar = el('div', { class: 'toolbar rx-bar' },
        el('span', { class: 'rx-seg' }, el('a', { href: '#rules/User', class: ot === 'User' ? 'on' : null, text: 'User tagging rules' }), el('a', { href: '#rules/Device', class: ot === 'Device' ? 'on' : null, text: 'Device tagging rules' })),
        el('span', { class: 'rx-seg', role: 'group', 'aria-label': 'View' }, [['cards', 'Groups'], ['grid', 'Grid (Excel-like)']].map(function (v) {
          return el('button', { type: 'button', class: S.view === v[0] ? 'on' : null, 'aria-pressed': S.view === v[0] ? 'true' : 'false', text: v[1], onclick: function () { S.view = v[0]; store.set('eps.rules.view', v[0]); build(queue); } }); })),
        el('label', { class: 'rx-search' }, 'Search ', search), S.view === 'grid' ? null : el('label', null, 'Group by ', group),
        admin ? el('button', { type: 'button', text: 'New rule', onclick: function () { side(null, 'new'); } }) : null,
        admin ? el('button', { type: 'button', class: 'secondary', text: 'Deleted rules', onclick: function () { side(null, 'deleted'); } }) : null,
        el('a', { href: '#conditions', text: 'Condition types' }));
      host.appendChild(bar);
      var lay = el('div', { class: 'rx-lay' }), filt = el('aside', { class: 'rx-filters', 'aria-label': 'Filters' }), main = el('div', { class: 'rx-main' }), sideBox = el('aside', { class: 'rx-side', 'aria-label': 'The selected rule' });
      lay.appendChild(filt); lay.appendChild(main); lay.appendChild(sideBox); host.appendChild(lay);

      var anyOn = function (o) { return Object.keys(o).some(function (k) { return o[k]; }); };
      var visible = function () {
        var q = S.q.trim().toLowerCase();
        return rows.filter(function (r) {
          if (anyOn(S.tags) && !S.tags[r.tagType]) return false;
          if (anyOn(S.states) && !S.states[stateOf(r)]) return false;
          if (anyOn(S.conds) && !r.conds.some(function (c) { return S.conds[c.ConditionType]; })) return false;
          if (q && [r.persona, r.tagType, r.value].concat(r.conds.map(function (c) { return c.ConditionType + ' ' + textOf(c.Target); })).join(' ').toLowerCase().indexOf(q) < 0) return false;
          return true;
        });
      };
      var facet = function (title, key, names, test, label) {
        var box = el('div', { class: 'rx-facet' }, el('strong', { text: title }));
        names.forEach(function (n) {
          var cb = el('input', { type: 'checkbox' }); cb.checked = !!S[key][n];
          cb.addEventListener('change', function () { S[key][n] = cb.checked; drawMain(); });
          box.appendChild(el('label', null, cb, ' ', el('span', { class: 'rx-fname', text: label ? label(n) : n }), el('span', { class: 'count', text: fmtNum(rows.filter(function (r) { return test(r, n); }).length) })));
        });
        return box;
      };
      var uniq = function (a) { return a.filter(function (x, i) { return x && a.indexOf(x) === i; }).sort(); };
      filt.appendChild(facet('Tag type', 'tags', uniq(rows.map(function (r) { return r.tagType; })), function (r, n) { return r.tagType === n; }, function (n) { return n + (attr[n] ? ' (' + attr[n].replace('extensionAttribute', 'ext') + ')' : ''); }));
      filt.appendChild(facet('Show only', 'states', ['staged', 'hint', 'off', 'on'], function (r, n) { return stateOf(r) === n; }, function (n) { return { staged: 'Staged in the queue', hint: 'Has a hint', off: 'Switched off', on: 'On' }[n]; }));
      filt.appendChild(facet('Condition type', 'conds', uniq([].concat.apply([], rows.map(function (r) { return r.conds.map(function (c) { return c.ConditionType; }); }))), function (r, n) { return r.conds.some(function (c) { return c.ConditionType === n; }); }));
      filt.appendChild(el('button', { type: 'button', class: 'link', text: 'Clear filters', onclick: function () { S.q = ''; S.tags = {}; S.states = {}; S.conds = {}; build(queue); } }));

      var stCls = { off: 'rx-st rx-off', staged: 'rx-st rx-staged', hint: 'rx-st rx-hint', on: 'rx-st rx-on' };
      var drawMain = function () {
        clear(main);
        var list = visible();
        main.appendChild(el('div', { class: 'rx-head' }, el('h2', { text: (ot === 'User' ? 'User' : 'Device') + ' tagging rules' }), el('span', { class: 'count', text: fmtNum(list.length) + ' of ' + fmtNum(rows.length) + ' rules' }),
          el('span', { class: 'smeta', text: 'Per tag type the FIRST matching rule wins, top down.' + (j.matchedRun ? ' Matched = objects the rule decided in the last run (' + j.matchedRun.mode + ', ' + fmtTime(j.matchedRun.startedAtUtc) + ').' : ' Matched shows after the next run on everyone.') })));
        if (S.view === 'grid') { drawRuleGrid(main, { ot: ot, j: j, admin: admin, list: list, all: rows, filtered: list.length !== rows.length, stateOf: stateOf, side: function (r) { S.sel = r; side(r); } }); return; }
        var keys = {
          persona: [function (r) { return [r.persona]; }, function (r) { return r.tagType; }],
          tagtype: [function (r) { return [ot === 'User' ? r.tagType : r.tagType + ' = ' + r.value]; }, function (r) { return r.persona; }],
          condition: [function (r) { return uniq(r.conds.map(function (c) { return c.ConditionType; })); }, function (r) { return r.tagType; }],
          none: [function () { return ['All rules in run order']; }, function () { return ''; }]
        }[S.groupBy] || null;
        var gmap = {}, gorder = [];
        list.forEach(function (r) { keys[0](r).forEach(function (g) { if (!gmap[g]) { gmap[g] = []; gorder.push(g); } gmap[g].push(r); }); });
        // expand / collapse every group at once (owner 2026-11-02: "i need a expand/collapse all button in the rules")
        if (gorder.length > 1) main.appendChild(el('div', { class: 'toolbar' },
          el('button', { type: 'button', class: 'link', text: 'Expand all', onclick: function () { gorder.forEach(function (g) { S.open[g] = true; }); drawMain(); } }),
          el('button', { type: 'button', class: 'link', text: 'Collapse all', onclick: function () { S.open = {}; drawMain(); } })));
        if (!gorder.length) main.appendChild(el('div', { class: 'empty', text: rows.length ? 'No rule matches the filters.' : 'No rules yet. Import them (Grid > Import CSV: this app\'s export or the v1 files), or make a new rule.' }));
        gorder.forEach(function (g) {
          var grs = gmap[g].slice().sort(function (a, b) { return (a.pos || 1e9) - (b.pos || 1e9); });
          var open = !!S.open[g] || !!S.q;   // collapsed by default (owner 2026-11-03); a search shows what it found
          var tts = uniq(grs.map(function (r) { return r.tagType; }));
          var maxM = grs.reduce(function (m, r) { return Math.max(m, r.matched || 0); }, 0);
          var sec = el('section', { class: 'rx-group' });
          sec.appendChild(el('button', { type: 'button', class: 'rx-ghead', 'aria-expanded': open ? 'true' : 'false', onclick: function () { S.open[g] = !open; drawMain(); } },
            el('span', { class: 'rx-caret', 'aria-hidden': 'true', text: open ? '▾' : '▸' }), el('strong', { text: g }),
            el('span', { class: 'count', text: grs.length + ' rule' + (grs.length === 1 ? '' : 's') + (S.groupBy === 'persona' ? ' · ' + tts.length + ' tag type' + (tts.length === 1 ? '' : 's') : '') }),
            j.matchedRun ? el('span', { class: 'rx-gm', text: fmtNum(maxM) + ' matched (largest rule)' }) : null));
          if (open) {
            var body = el('div', { class: 'rx-gbody' }); sec.appendChild(body);
            var smap = {}, sorder = [];
            grs.forEach(function (r) { var k = keys[1](r); if (!smap[k]) { smap[k] = []; sorder.push(k); } smap[k].push(r); });
            sorder.forEach(function (k) {
              if (k) body.appendChild(el('div', { class: 'rx-sub' }, el('strong', { text: k + (S.groupBy !== 'tagtype' && attr[k] ? ' (' + attr[k].replace('extensionAttribute', 'ext') + ')' : '') }),
                smap[k].length > 1 ? el('span', { class: 'smeta', text: smap[k].length + ' alternatives, tried top down - the first that matches wins' }) : null));
              var tb = el('tbody');
              smap[k].forEach(function (r, i) {
                if (i > 0) tb.appendChild(el('tr', { class: 'rx-or' }, el('td', { colspan: '5' }, el('span', { text: 'OR' }))));
                var chips = el('div', { class: 'rx-chips' });
                r.conds.forEach(function (c, ci) { if (ci) chips.appendChild(el('span', { class: 'rx-and', text: 'AND' })); chips.appendChild(el('span', { class: 'rx-chip' }, el('code', { text: c.ConditionType }), ' ', textOf(c.Target))); });
                if (!r.conds.length) chips.appendChild(el('span', { class: 'smeta', text: '(no condition)' }));
                var st = stateOf(r);
                var tr = el('tr', { class: 'rx-row' + (S.sel === r ? ' sel' : ''), tabindex: '0' },
                  el('td', { class: 'num', text: r.pos ? '#' + r.pos : 'new' }), el('td', null, chips), el('td', null, el('code', { text: r.value })),
                  el('td', { class: 'num', text: r.matched === null || r.matched === undefined ? '-' : fmtNum(r.matched) }),
                  el('td', null, el('span', { class: stCls[st], text: (r.staged ? 'Staged: ' + r.staged : RULE_STATE_TEXT[st]) }), r.hints.length ? el('div', { class: 'smeta', text: r.hints.map(function (h) { return h.text; }).join(' ') }) : null));
                var pick = function () { S.sel = r; drawMain(); side(r); };
                tr.addEventListener('click', pick); tr.addEventListener('keydown', function (e) { if (e.key === 'Enter') pick(); });
                tb.appendChild(tr);
              });
              body.appendChild(el('div', { class: 'rx-scroll' }, el('table', { class: 'rx-table' },
                el('thead', null, el('tr', null, el('th', { class: 'num', scope: 'col', text: 'Order' }), el('th', { scope: 'col', text: 'Conditions (all must match)' }), el('th', { scope: 'col', text: 'Tag Value' }), el('th', { class: 'num', scope: 'col', text: 'Matched', title: 'How many accounts this rule matched in the last run' }), el('th', { scope: 'col', text: 'State' }))), tb)));
            });
          }
          main.appendChild(sec);
        });
      };

      // the side panel: the selected rule, its actions, and "Try on a user"
      var side = function (r, mode) {
        clear(sideBox);
        var panel = el('div');
        if (mode === 'new') { openRuleEditor(ot, j, {}, { title: 'New ' + ot.toLowerCase() + ' rule' }); mode = null; r = S.sel; }
        if (mode === 'deleted') {
          panel.appendChild(el('h3', { text: 'Deleted rules' }));
          api('GET', '/api/rules/' + ot + '/deleted').then(function (d) {
            panel.appendChild(table(d.rows, [{ key: 'AtUtc', label: 'Deleted', type: 'date' }, { key: 'EntityKey', label: 'Rule' },
              { key: 'BeforeJson', label: 'The rule', wrap: true, render: function (h) { var c = fromJournal(h.BeforeJson); return (c.Persona || c.TagType) + ': ' + c.Conditions.map(function (x) { return x.ConditionType + ' ' + textOf(x.Target); }).join(' AND '); } },
              { key: '_b', label: '', render: function (h) { return admin ? el('button', { type: 'button', class: 'secondary', text: 'Put back', onclick: function () { openRuleEditor(ot, j, fromJournal(h.BeforeJson), { restore: true, title: 'Put back rule ' + h.EntityKey + ' (as a new rule, last)' }); } }) : null; } }],
              { sort: 'AtUtc', dir: -1, empty: 'No rule was deleted.' }));
          }).catch(function (e) { status('Could not load: ' + e.message); });
        } else if (r) {
          var c = r.card, st = stateOf(r);
          panel.appendChild(el('div', { class: 'rx-sidehead' }, el('h3', { text: r.id ? 'Rule ' + r.id + (r.pos ? ' - number ' + r.pos : '') : 'New rule (staged)' }), el('span', { class: stCls[st], text: r.staged ? 'Staged: ' + r.staged : RULE_STATE_TEXT[st] })));
          var dl = el('dl', { class: 'rx-dl' });
          [[ot === 'User' ? 'Persona' : 'Tag type', r.persona], ['Tag type', r.tagType + (attr[r.tagType] ? ' (' + attr[r.tagType] + ')' : '')], ['Value', r.value],
           ['Matched', r.matched === null || r.matched === undefined ? 'not run yet' : fmtNum(r.matched) + ' in the last run'], ['Notes', textOf(c.Notes) || '-']].forEach(function (x) { dl.appendChild(el('dt', { text: x[0] })); dl.appendChild(el('dd', { text: x[1] })); });
          panel.appendChild(dl);
          panel.appendChild(el('strong', { class: 'smeta', text: 'Conditions - all must match' }));
          r.conds.forEach(function (x) { panel.appendChild(el('div', { class: 'rx-chip rx-chip-l' }, el('code', { text: x.ConditionType }), ' ', textOf(x.Target))); });
          r.hints.forEach(function (h) { panel.appendChild(el('div', { class: 'guide', text: h.text })); });
          var slot = el('div');
          if (r.id) {
            var acts = el('div', { class: 'rx-acts' });
            if (admin) {
              acts.appendChild(el('button', { type: 'button', text: 'Edit', onclick: function () { openRuleEditor(ot, j, c, { title: 'Edit rule ' + r.id }); } }));
              acts.appendChild(el('button', { type: 'button', class: 'secondary', text: 'Duplicate', onclick: function () { openRuleEditor(ot, j, Object.assign({}, c, { RuleId: null }), { insertAfter: r.id, title: 'New rule after rule ' + r.id + ' (a copy - change what differs)' }); } }));
              ['up', 'down'].forEach(function (d) { acts.appendChild(el('button', { type: 'button', class: 'secondary', text: d === 'up' ? 'Move up' : 'Move down', onclick: function () { withReason('Move rule ' + r.id + ' ' + d, 'For a First tag type a rule higher up wins over the ones below it.', function (reason) { return api('POST', '/api/rules/' + ot + '/' + r.id + '/move', { direction: d, reason: reason }); }); } })); });
            }
            acts.appendChild(el('button', { type: 'button', class: 'secondary', text: 'History', onclick: function () {
              api('GET', '/api/rules/' + ot + '/' + r.id + '/history').then(function (h) {
                clear(slot).appendChild(table(h.rows, [{ key: 'AtUtc', label: 'When', type: 'date' }, { key: 'Actor', label: 'Who' }, { key: 'Action', label: 'Action', type: 'cat' },
                  { key: '_r', label: '', render: function (x) { if (!admin || x.Action !== 'Update' || !x.BeforeJson) return null; return el('button', { type: 'button', class: 'secondary', text: 'Restore the version before', onclick: function () {
                    var o = fromJournal(x.BeforeJson); o.RuleId = r.id; o.UpdatedAtUtc = c.UpdatedAtUtc; openRuleEditor(ot, j, o, { title: 'Restore rule ' + r.id + ' as it was before ' + fmtTime(x.AtUtc) }); } }); } }],
                  { sort: 'AtUtc', dir: -1, empty: 'No change recorded (imported as it is).' }));
              }).catch(function (e) { status('Could not load: ' + e.message); });
            } }));
            if (admin) acts.appendChild(el('button', { type: 'button', class: 'link', text: 'Delete', onclick: function () { withReason('Delete rule ' + r.id, 'Objects it tagged keep their tag until another rule or the fallback changes it. Deleted rules can put it back.', function (reason) { return api('DELETE', '/api/rules/' + ot + '/' + r.id, { expected: c.UpdatedAtUtc, reason: reason }); }); } }));
            panel.appendChild(acts);
            if (j.queueOn) panel.appendChild(el('div', { class: 'smeta', text: 'Edits wait in the commit queue - nothing changes until a commit.' }));
          }
          panel.appendChild(slot);
        } else panel.appendChild(el('div', { class: 'smeta', text: 'Select a rule to see it, change it, or see its history.' }));
        sideBox.appendChild(panel);
        sideBox.appendChild(tryBox());
      };

      // "Try on a user": a traced preview of one object (the engine reads it); the answer comes with the next tick
      var tryBox = function () {
        var box = el('div', { class: 'rx-try' }, el('h3', { text: 'Try on a ' + (ot === 'User' ? 'user' : 'device') }));
        var inp = el('input', { type: 'text', placeholder: ot === 'User' ? 'user@contoso.com' : 'device name', 'aria-label': 'Object to try' });
        var out = el('div', { class: 'rx-tryout' });
        var show = function (res) {
          clear(out);
          if (!res.done) { out.appendChild(el('div', { class: 'smeta', text: 'Waiting for the engine (' + res.status + ') - within 5 minutes; nothing is written.' })); return; }
          if (!res.traces.length) { out.appendChild(el('div', { class: 'guide', text: res.status === 'Done' ? 'The object was not found, or the run did not trace it.' : res.status + ': ' + textOf(res.statusText) })); return; }
          res.traces.forEach(function (t) {
            out.appendChild(el('strong', { text: textOf(t.Name) + (t.Synced ? ' (AD-synced)' : '') }));
            var dec = el('ul', { class: 'rx-dec' });
            (t.Decisions || []).forEach(function (d) { dec.appendChild(el('li', null, el('strong', { text: d.TagType + ': ' }), el('code', { text: textOf(d.Wanted) || '(empty)' }), ' - ' + (d.Persona ? 'rule for ' + d.Persona : textOf(d.Reason)) + (d.Action === 'Change' ? ' (would CHANGE from ' + (textOf(d.Current) || 'empty') + ')' : ' (already so)'))); });
            out.appendChild(dec);
            var why = el('details'); why.appendChild(el('summary', { text: 'Why - every rule, top down' }));
            (t.Rules || []).forEach(function (x) { why.appendChild(el('div', { class: 'smeta', text: '#' + x.RuleId + ' ' + textOf(x.Persona) + ' / ' + x.TagType + ': ' + x.Result + (x.Reason ? ' - ' + x.Reason : '') +
              (x.Conditions ? ' - ' + x.Conditions.map(function (k) { return k.ConditionType + (k.Met ? ' yes' : ' NO'); }).join(', ') : '') })); });
            out.appendChild(why);
          });
        };
        var poll = function (id, n) {
          api('GET', '/api/rules/try/' + id).then(function (res) { S.tryOut = res; show(res); if (!res.done && n < 40) setTimeout(function () { if (S.tryReq === id) poll(id, n + 1); }, 10000); }).catch(function (e) { out.textContent = 'Could not read the answer: ' + e.message; });
        };
        box.appendChild(el('div', { class: 'rx-tryrow' }, inp, admin ? el('button', { type: 'button', text: 'Try', onclick: function () {
          if (!inp.value.trim()) { inp.focus(); return; }
          api('POST', '/api/rules/' + ot + '/try', { object: inp.value.trim() }).then(function (res) { S.tryReq = res.requestId; status(res.text); poll(res.requestId, 0); }).catch(function (e) { status('Refused: ' + e.message); });
        } }) : null));
        box.appendChild(el('div', { class: 'smeta', text: 'Shows which rule wins per tag type, and why. A preview: nothing is written.' }));
        box.appendChild(out);
        if (S.tryOut) show(S.tryOut);
        return box;
      };

      search.addEventListener('input', function () { S.q = search.value; drawMain(); });
      group.addEventListener('change', function () { S.groupBy = group.value; S.open = {}; store.set('eps.rules.groupBy', group.value); drawMain(); });
      if (S.sel && !rows.some(function (r) { return r.id && S.sel && r.id === S.sel.id; })) S.sel = null;
      if (S.sel) S.sel = rows.filter(function (r) { return r.id === S.sel.id; })[0];
      drawMain(); side(S.sel);
    };
    api('GET', '/api/queue').then(function (q) { build(q.rows); }).catch(function () { build([]); });
  }

  // ---- tag types and their values (DESIGN §5.6a) -------------------------------------------------------------------
  function tagTypeEditor(t, onDone) {
    var isNew = !t.Name;
    var box = el('div', { class: 'editor' }, el('h3', { text: isNew ? 'New tag type' : 'Edit ' + t.ObjectType.toLowerCase() + ' tag type ' + t.Name }));
    var ot = el('select', { 'aria-label': 'Object', disabled: !isNew }, el('option', { value: 'User', text: 'users' }), el('option', { value: 'Device', text: 'devices' })); ot.value = t.ObjectType || 'User';
    var name = el('input', { type: 'text', 'aria-label': 'Name', placeholder: 'e.g. Department', maxlength: 60, disabled: !isNew }); name.value = textOf(t.Name);
    var attr = el('select', { 'aria-label': 'Attribute' }); for (var i = 1; i <= 15; i++) attr.appendChild(el('option', { value: 'extensionAttribute' + i, text: 'extensionAttribute' + i })); attr.value = t.Attribute || 'extensionAttribute10';
    var mode = el('select', { 'aria-label': 'Value mode' }, ['First', 'Last', 'Multiple'].map(function (m) { return el('option', { value: m, text: m }); })); mode.value = t.ValueMode || 'First';
    var multi = el('input', { type: 'checkbox' }); multi.checked = !!t.AllowMultiple;
    var en = el('input', { type: 'checkbox' }); en.checked = t.Enabled !== false;
    var desc = el('input', { type: 'text', 'aria-label': 'Description', maxlength: 1000 }); desc.value = textOf(t.Description);
    var fa = el('input', { type: 'text', 'aria-label': 'Fallback AD', maxlength: 1024 }); fa.value = textOf(t.FallbackAD);
    var fc = el('input', { type: 'text', 'aria-label': 'Fallback cloud', maxlength: 1024 }); fc.value = textOf(t.FallbackCloud);
    box.appendChild(el('div', { class: 'form' }, el('label', null, 'For ', ot), el('label', null, 'Name ', name), el('label', null, 'Attribute ', attr), el('label', null, 'Value mode ', mode),
      el('label', null, multi, ' allow several values'), el('label', null, en, ' enabled'), el('label', { class: 'wide' }, 'Description ', desc),
      el('label', null, 'Fallback (AD-synced) ', fa), el('label', null, 'Fallback (cloud) ', fc)));
    box.appendChild(el('div', { class: 'smeta', text: 'The fallback is what an object gets when no rule matches. First: the first matching rule wins; Last: the last; Multiple: every match is kept (only with "allow several values" - Conditional Access reads single values).' }));
    var errs = el('div', { class: 'errors', hidden: true }); box.appendChild(errs);
    box.appendChild(el('div', { class: 'dlg-buttons' }, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: onDone }), el('button', { type: 'button', text: 'Save', onclick: function () {
      var off = !isNew && t.Enabled && !en.checked;
      withReason(isNew ? 'Create tag type ' + name.value : 'Save tag type ' + t.Name, off ? 'Switched off, no rule sets this tag any more and the tamper monitor stops watching its attribute. Rules of it cannot be saved while it is off.' : 'The next run uses it.', function (reason) {
        return api('PUT', '/api/tagtypes/' + ot.value + '/' + encodeURIComponent(name.value.trim()), { attribute: attr.value, valueMode: mode.value, allowMultiple: multi.checked, enabled: en.checked, description: desc.value, fallbackAD: fa.value, fallbackCloud: fc.value, expected: isNew ? null : t.UpdatedAtUtc, reason: reason })
          .catch(function (e) { errs.hidden = false; errs.textContent = 'Not saved: ' + e.message; throw e; });
      });
    } })));
    return box;
  }
  function drawTagTypes(p, rows) {
    var admin = isRole('Admin'), panel = el('div');
    if (admin) p.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', text: 'New tag type', onclick: function () { clear(panel).appendChild(tagTypeEditor({}, function () { clear(panel); })); } })));
    p.appendChild(panel);
    rows.forEach(function (t) {
      var slot = el('div');
      var vals = el('div', { class: 'values' });
      (t.Values || []).forEach(function (v) {
        vals.appendChild(el('span', { class: 'val' }, el('span', { text: v.Value + (v.IsPattern ? ' (pattern)' : '') }), v.Description ? el('span', { class: 'skey', text: ' ' + v.Description }) : null,
          admin ? el('button', { type: 'button', class: 'link', text: 'Remove', onclick: function () { withReason('Remove the value ' + v.Value, 'A rule that sets it keeps it from being removed. Dynamic groups and policies that read it are not checked here.', function (reason) { return api('DELETE', '/api/tagtypes/' + t.ObjectType + '/' + encodeURIComponent(t.Name) + '/values', { value: v.Value, reason: reason }); }); } }) : null));
      });
      if (!(t.Values || []).length) vals.appendChild(el('span', { class: 'skey', text: 'no list: any value (free text)' }));
      var acts = el('div', { class: 'sacts' });
      if (admin) {
        acts.appendChild(el('button', { type: 'button', class: 'link', text: 'Edit', onclick: function () { clear(slot).appendChild(tagTypeEditor(t, function () { clear(slot); })); } }));
        acts.appendChild(el('button', { type: 'button', class: 'link', text: 'Add value', onclick: function () {
          var v = el('input', { type: 'text', 'aria-label': 'Value', maxlength: 1024 }), d = el('input', { type: 'text', 'aria-label': 'Description', placeholder: 'what it means', maxlength: 1000 }), pt = el('input', { type: 'checkbox' });
          clear(slot).appendChild(el('div', { class: 'editor' }, el('div', { class: 'form' }, el('label', null, 'Value ', v), el('label', { class: 'wide' }, 'Description ', d), el('label', null, pt, ' a pattern (wildcards, for generated values)')),
            el('div', { class: 'dlg-buttons' }, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: function () { clear(slot); } }), el('button', { type: 'button', text: 'Add', onclick: function () {
              withReason('Add a value to ' + t.Name, v.value, function (reason) { return api('PUT', '/api/tagtypes/' + t.ObjectType + '/' + encodeURIComponent(t.Name) + '/values', { value: v.value, description: d.value, isPattern: pt.checked, reason: reason }); }); } }))));
        } }));
        if (!t.Shipped) acts.appendChild(el('button', { type: 'button', class: 'link', text: 'Delete', onclick: function () { withReason('Delete tag type ' + t.Name, 'Only a tag type without rules and values can be deleted.', function (reason) { return api('DELETE', '/api/tagtypes/' + t.ObjectType + '/' + encodeURIComponent(t.Name), { reason: reason }); }); } }));
      }
      p.appendChild(el('div', { class: 'rule' + (t.Enabled ? '' : ' off') },
        el('div', { class: 'rhead' }, el('span', { class: 'slabel', text: t.Name }), el('span', { class: 'skey', text: t.ObjectType + ' · ' + t.Attribute + ' · ' + t.ValueMode + ' · ' + fmtNum(t.Rules) + ' rule(s)' }),
          t.Enabled ? null : el('span', { class: 'badge', text: 'off' }), t.Shipped ? el('span', { class: 'badge', text: 'shipped' }) : null),
        t.Description ? el('div', { class: 'smeta', text: t.Description }) : null,
        el('div', { class: 'smeta', text: 'Fallback: AD-synced ' + (textOf(t.FallbackAD) || '-') + ', cloud ' + (textOf(t.FallbackCloud) || '-') }), vals, acts, slot));
    });
  }

  // ---- the customer's own condition types (DESIGN §5.6b kind 1) ---------------------------------------------------
  function drawConditions(p, rows) {
    var admin = isRole('Admin'), panel = el('div');
    var edit = function (c) {
      var ot = el('select', { disabled: !!c.id }, el('option', { value: 'User', text: 'users' }), el('option', { value: 'Device', text: 'devices' })); ot.value = c.objectType || 'User';
      var id = el('input', { type: 'text', 'aria-label': 'Id', placeholder: 'e.g. Department_Like', maxlength: 100, disabled: !!c.id }); id.value = textOf(c.id);
      var prop = el('input', { type: 'text', 'aria-label': 'Property', placeholder: 'e.g. department', maxlength: 200 }); prop.value = textOf(c.property);
      var op = el('select', null, ['like', 'notlike', 'equals', 'boolMatch', 'boolEquals', 'contains', 'notcontains'].map(function (o) { return el('option', { value: o, text: o }); })); op.value = c.operator || 'like';
      var g = el('select', null, [['none', 'empty compares as empty text'], ['notNull', 'no value never matches'], ['notEmpty', 'an empty value never matches'], ['emptyMatches', 'an empty value matches']].map(function (o) { return el('option', { value: o[0], text: o[1] }); })); g.value = c.guard || 'none';
      var d = el('input', { type: 'text', 'aria-label': 'Description', maxlength: 1000 }); d.value = textOf(c.description);
      var en = el('input', { type: 'checkbox' }); en.checked = c.enabled !== false;
      clear(panel).appendChild(el('div', { class: 'editor' }, el('h3', { text: c.id ? 'Edit ' + c.id : 'New condition type' }),
        el('div', { class: 'form' }, el('label', null, 'For ', ot), el('label', null, 'Id ', id), el('label', null, 'Graph property ', prop), el('label', null, 'Compare ', op), el('label', null, 'Empty value ', g), el('label', null, en, ' enabled'), el('label', { class: 'wide' }, 'Description ', d)),
        el('div', { class: 'dlg-buttons' }, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: function () { clear(panel); } }), el('button', { type: 'button', text: 'Save', onclick: function () {
          withReason((c.id ? 'Save ' : 'Create ') + (id.value || 'condition type'), 'The engine reads the property in its next run (one fetch for every rule).', function (reason) { return api('PUT', '/api/conditions/' + ot.value + '/' + encodeURIComponent(id.value.trim()), { property: prop.value, operator: op.value, guard: g.value, description: d.value, enabled: en.checked, reason: reason }); }); } }))));
    };
    if (admin) p.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', text: 'New condition type', onclick: function () { edit({}); } })));
    p.appendChild(panel);
    var cols = [{ key: 'objectType', label: 'For', type: 'cat' }, { key: 'id', label: 'Condition type' }, { key: 'kind', label: 'Kind', type: 'cat' }, { key: 'shipped', label: 'Shipped', type: 'cat' },
      { key: 'property', label: 'Property' }, { key: 'operator', label: 'Compare', type: 'cat' }, { key: 'enabled', label: 'Enabled', type: 'cat' }, { key: 'description', label: 'What it tests', wrap: true }];
    if (admin) cols.push({ key: '_e', label: '', render: function (c) { if (c.shipped) return null; return el('span', null, el('button', { type: 'button', class: 'link', text: 'Edit', onclick: function () { edit(c); } }),
      el('button', { type: 'button', class: 'link', text: 'Delete', onclick: function () { withReason('Delete ' + c.id, 'Refused while a rule uses it.', function (reason) { return api('DELETE', '/api/conditions/' + c.objectType + '/' + encodeURIComponent(c.id), { reason: reason }); }); } })); } });
    p.appendChild(table(rows, cols, { sort: 'id', dir: 1 }));
  }

  // ---- scopes (DESIGN §5.8): run on one user or a subset --------------------------------------------------------------
  function scopeFields() {
    var kind = el('select', { 'aria-label': 'Scope' }, el('option', { value: 'Objects', text: 'named objects' }), el('option', { value: 'Filter', text: 'a filter' }));
    var objs = el('textarea', { rows: 3, 'aria-label': 'Objects', placeholder: 'one per line: UPN, display name or object id' });
    var prop = el('input', { type: 'text', 'aria-label': 'Property', placeholder: 'property, e.g. userPrincipalName' }), pat = el('input', { type: 'text', 'aria-label': 'Pattern', placeholder: 'pattern, e.g. *@pilot.contoso.com' });
    var fil = el('span', { hidden: true }, prop, ' like ', pat);
    kind.addEventListener('change', function () { objs.hidden = kind.value !== 'Objects'; fil.hidden = kind.value !== 'Filter'; });
    return { node: el('span', { class: 'scope' }, kind, ' ', objs, fil), read: function () {
      return kind.value === 'Objects' ? { kind: 'Objects', values: objs.value.split('\n').map(function (x) { return x.trim(); }).filter(function (x) { return x; }) } : { kind: 'Filter', property: prop.value, pattern: pat.value }; } };
  }
  function describeScope(def) { try { var d = JSON.parse(def); return d.Kind === 'Objects' ? fmtNum(d.Values.length) + ' object(s): ' + d.Values.slice(0, 5).join(', ') + (d.Values.length > 5 ? ' ...' : '') : d.Property + ' like ' + d.Pattern; } catch (e) { return textOf(def); } }

  // ---- the CA Policy Analyzer (DESIGN §5.7): READ ONLY towards the tenant; ad hoc first, sign-in logs by default ------
  // CA-ONE (owner 2026-11-02: "merge the ca policy analyzer and new monitor into one module, so either you analyze first,
  // then you can setup monitor or setup monitor. dont make them 2 separate"; about the options: "we dont understand,
  // simplify"): ONE form in three steps - 1. which policies, 2. which sign-ins, 3. Analyse now / Save as monitor - whose
  // first control picks a new or an existing monitor (CA-MONADD: "need an easy way to add/remove ca policy to
  // existing/new monitor"). CA-PERSONA ("it should be possible edit/delete/create existing monitors persona. this
  // functionality replaces the series button"): the personas are a list the admin manages (Manage personas).
  // CA-LIMITS (owner 2026-11-02: "fix all 4 limits"; "templates is a import only feature. then it is the real policies in
  // scope for mgmt and monitor, not the templates"): a persona and a monitor each have their own "left out" list; the
  // groups here are the MANAGED personas over the real policies - a policy in none is under "No persona"
  var CA_OTHER = 'No persona';
  var CA_NAME = /^[A-Za-z0-9_.-]{1,100}$/;
  var CA_PERIODS = [[24, 'the last 24 hours'], [72, 'the last 3 days'], [168, 'the last 7 days'], [336, 'the last 14 days'], [720, 'the last 30 days']];
  // the persona groups: Global first, the personas A-Z, Other last (an explicit rank: the old sort keyed Other on a tilde, which localeCompare ignores)
  function personaRank(g) { return g === 'Global' ? 0 : g === CA_OTHER ? 2 : 1; }
  function personaSort(x, y) { return personaRank(x) - personaRank(y) || (x < y ? -1 : x > y ? 1 : 0); }
  // a name rule (the engine's Test-EpsCaNameRule): * ? are wildcards; a full number CA006 never takes CA0060; a shorter
  // series such as CA2 takes every policy that starts with it
  function caRuleMatch(name, rule) {
    var n = textOf(name).toLowerCase(), x = String(rule).trim().toLowerCase();
    if (!x) return false;
    if (/[*?]/.test(x)) { var re = new RegExp('^' + x.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$'); return re.test(n); }
    if (n.indexOf(x) !== 0) return false;
    if (!/^ca\d{3}$/.test(x)) return true;
    return n.length === x.length || !/[0-9a-z]/.test(n.charAt(x.length));
  }
  function splitList(s) { return String(s || '').split(/[,;\n]+/).map(function (x) { return x.trim(); }).filter(function (x) { return x; }); }
  function caPeriodText(h) { var x = CA_PERIODS.filter(function (p) { return String(p[0]) === String(h); })[0]; return x ? x[1] : 'the last ' + fmtNum(h) + ' hours'; }

  function caOneForm(data, onSaved) {
    // data: { policies (with Personas + Monitors), personas (with takes + monitors), monitors }
    var policies = data.policies, monitors = data.monitors, personas = data.personas;
    var byId = {}; policies.forEach(function (p) { byId[String(p.PolicyId).toLowerCase()] = p; });
    var groups = {};
    personas.forEach(function (pe) { groups[pe.name] = (pe.takes || []).map(function (id) { return byId[String(id).toLowerCase()]; }).filter(function (x) { return x; }); });
    var others = policies.filter(function (p) { return !(p.Personas || []).length; });
    if (others.length) groups[CA_OTHER] = others;
    var gnames = Object.keys(groups).sort(personaSort);
    var st = { mon: '', picked: {}, personas: {}, excluded: {}, open: {}, series: { prefixes: [], patterns: [], names: [] }, dropSeries: false };

    // the Monitor chooser: a new monitor, or an existing one (its selection loads into the tree)
    var chooser = el('select', { 'aria-label': 'Monitor' }, el('option', { value: '', text: 'New ...' }), monitors.map(function (m) { return el('option', { value: m.Name, text: m.Name + (m.Enabled ? '' : ' (off)') }); }));
    chooser.addEventListener('change', function () { load(chooser.value); });

    // 1. Which policies
    var filter = el('input', { type: 'search', placeholder: 'filter: name, CA2, persona ...', 'aria-label': 'Filter policies' });
    var listBox = el('div', { class: 'plist' });
    var pickInfo = el('div', { class: 'smeta' });
    var seriesBox = el('div', { class: 'smeta' });
    // covered = the monitor takes the policy through a ticked persona or an older series rule (not one by one)
    function bySeries(p) { if (st.dropSeries) return false; var rules = st.series.prefixes.concat(st.series.patterns); return rules.some(function (r) { return caRuleMatch(p.DisplayName, r); }) || st.series.names.some(function (x) { return x.toLowerCase() === textOf(p.DisplayName).toLowerCase(); }); }
    function covered(p) { return (p.Personas || []).some(function (x) { return st.personas[x]; }) || bySeries(p); }
    function selection() {
      var n = {};
      Object.keys(st.personas).forEach(function (g) { if (st.personas[g]) (groups[g] || []).forEach(function (p) { n[String(p.PolicyId).toLowerCase()] = 1; }); });
      Object.keys(st.picked).forEach(function (id) { if (st.picked[id]) n[id] = 1; });
      policies.forEach(function (p) { if (bySeries(p)) n[String(p.PolicyId).toLowerCase()] = 1; });
      // the monitor's own "left out" policies (CA-LIMITS) never count
      return Object.keys(n).filter(function (id) { return !st.excluded[id]; });
    }
    function leftOut() { return Object.keys(st.excluded).filter(function (k) { return st.excluded[k]; }); }
    function info() {
      var ps = Object.keys(st.personas).filter(function (k) { return st.personas[k]; });
      var ids = Object.keys(st.picked).filter(function (k) { return st.picked[k]; });
      var lo = leftOut();
      clear(pickInfo);
      pickInfo.appendChild(document.createTextNode((ps.length ? 'Personas: ' + ps.join(', ') + '. ' : '') + (ids.length ? fmtNum(ids.length) + ' single policy(ies). ' : '') + 'Takes ' + fmtNum(selection().length) + ' policy(ies) now.'));
      if (lo.length) {
        // left out of this monitor: each with a way to take it back
        pickInfo.appendChild(el('div', { class: 'leftout' }, 'Left out of this monitor (' + fmtNum(lo.length) + '): ', lo.map(function (id) {
          var p = byId[id];
          return el('span', { class: 'mtag out' }, p ? p.DisplayName : id, ' ', el('button', { type: 'button', class: 'link', text: 'take back', title: 'take it back into this monitor', onclick: function () { delete st.excluded[id]; if (!p || !covered(p)) st.picked[id] = true; drawList(); } }));
        })));
      }
      clear(seriesBox);
      var old = st.series.prefixes.concat(st.series.patterns);
      if (old.length && !st.dropSeries) {
        seriesBox.appendChild(document.createTextNode('Older series rules of this monitor (still applied): ' + old.join(', ') + '. Personas replace them. '));
        seriesBox.appendChild(el('button', { type: 'button', class: 'link', text: 'Remove them', onclick: function () { st.dropSeries = true; drawList(); } }));
      } else if (old.length) {
        seriesBox.appendChild(document.createTextNode('The older series rules (' + old.join(', ') + ') go when you save. '));
        seriesBox.appendChild(el('button', { type: 'button', class: 'link', text: 'Keep them', onclick: function () { st.dropSeries = false; drawList(); } }));
      }
    }
    function drawList() {
      clear(listBox); var f = filter.value.trim().toLowerCase();
      gnames.forEach(function (g) {
        var all = groups[g], isOther = g === CA_OTHER;
        var items = all.filter(function (p) { return !f || textOf(p.DisplayName).toLowerCase().indexOf(f) >= 0 || g.toLowerCase().indexOf(f) >= 0; });
        if (!items.length && f) return;
        var nOn = all.filter(function (p) { return st.picked[String(p.PolicyId).toLowerCase()]; }).length;
        var gcb = el('input', { type: 'checkbox', 'aria-label': 'All of ' + g });
        gcb.checked = isOther ? (!!all.length && nOn === all.length) : !!st.personas[g];
        gcb.addEventListener('change', function () {
          // Other is not a persona: ticking it picks its policies one by one
          if (isOther) all.forEach(function (p) { st.picked[String(p.PolicyId).toLowerCase()] = gcb.checked; }); else st.personas[g] = gcb.checked;
          drawList();
        });
        var tog = el('button', { type: 'button', class: 'link', text: (st.open[g] || f) ? '▾' : '▸', 'aria-label': 'Show the policies of ' + g });
        tog.addEventListener('click', function () { st.open[g] = !st.open[g]; drawList(); });
        listBox.appendChild(el('div', { class: 'pgroup' }, tog, ' ', el('label', null, gcb, ' ', el('b', { text: g })),
          el('span', { class: 'skey', text: ' ' + fmtNum(all.length) + ' policies' + (!isOther && st.personas[g] ? ' - all, also new ones' : nOn ? ' - ' + fmtNum(nOn) + ' picked' : '') })));
        if (!(st.open[g] || f)) return;
        items.forEach(function (p) {
          var id = String(p.PolicyId).toLowerCase(), cov = covered(p), out = !!st.excluded[id];
          // CA-LIMITS: a policy a ticked persona (or an older series rule) takes can be unticked - it is then LEFT OUT of
          // this monitor (excludePolicyIds); ticking it again takes it back
          var cb = el('input', { type: 'checkbox', title: cov ? (out ? 'left out of this monitor - tick to take it back' : 'in a ticked persona - untick to leave it out of this monitor') : null });
          cb.checked = !out && (cov || !!st.picked[id]);
          cb.addEventListener('change', function () {
            if (cb.checked) { delete st.excluded[id]; if (!cov) st.picked[id] = true; }
            else { st.picked[id] = false; if (cov) st.excluded[id] = true; }
            drawList();
          });
          // the monitors the policy is in now (CA-MONADD)
          var tags = (p.Monitors || []).map(function (m) { return el('span', { class: 'mtag' + (m === st.mon ? ' on' : ''), title: 'in monitor ' + m, text: m }); });
          listBox.appendChild(el('label', { class: 'pitem pindent' }, cb, ' ', p.DisplayName, el('span', { class: 'skey', text: ' ' + textOf(p.State) }), out ? el('span', { class: 'mtag out', text: 'left out of this monitor' }) : null, tags));
        });
      });
      if (!policies.length) listBox.appendChild(el('div', { class: 'smeta', text: 'No policy list yet: Refresh the list asks the engine to read it (read only).' }));
      info();
    }
    var allOpen = el('button', { type: 'button', class: 'link', text: 'Expand all', onclick: function () { gnames.forEach(function (g) { st.open[g] = true; }); drawList(); } });
    var allShut = el('button', { type: 'button', class: 'link', text: 'Collapse all', onclick: function () { st.open = {}; drawList(); } });
    var noneBtn = el('button', { type: 'button', class: 'link', text: 'Clear', onclick: function () { st.picked = {}; st.personas = {}; st.excluded = {}; drawList(); } });
    var manageBtn = el('button', { type: 'button', class: 'secondary', text: 'Manage personas', onclick: function () { personaManager(data); } });
    filter.addEventListener('input', drawList);
    var refresh = el('button', { type: 'button', class: 'link', text: 'Refresh the list', onclick: function () { withReason('Refresh the policy list', 'Read only: the engine reads the Conditional Access policies again.', function (reason) { return api('POST', '/api/ca/analyze', { listOnly: true, reason: reason }); }); } });
    var listInfo = el('span', { class: 'count' }, fmtNum(policies.length) + ' policies' + (policies.length ? ', read ' : ''), policies.length ? timeEl(policies[0].SeenAtUtc) : null, ' ', refresh);

    // 2. Which sign-ins: a period; the rest under More options (closed)
    var period = el('select', { 'aria-label': 'Period' }, CA_PERIODS.map(function (x) { return el('option', { value: String(x[0]), text: x[1] }); }));
    var nonInt = el('input', { type: 'checkbox' }), guests = el('input', { type: 'checkbox' }), disabled = el('input', { type: 'checkbox' });
    var slice = el('input', { type: 'text', inputmode: 'numeric', 'aria-label': 'Hours per part', maxlength: 3, size: 3 }); slice.value = '0';
    var more = el('details', { class: 'more' }, el('summary', { text: 'More options' }),
      el('div', { class: 'form' },
        el('label', { class: 'wide' }, nonInt, ' Include non-interactive sign-ins (apps signing in for the user - a much larger log)'),
        el('label', { class: 'wide' }, guests, ' Include guests'),
        el('label', { class: 'wide' }, disabled, ' Include disabled accounts'),
        // CA-ANALYZER-PARTS (owner 2026-11-03: "this is too complex for people to dcide on"): EPS decides how it reads a
        // large log - the field is gone; a window longer than a day is read a day at a time
        el('p', { class: 'smeta', text: 'A window longer than a day is read a day at a time - Entra Policy Suite decides this, there is nothing to set.' })));

    // 3. Analyse now / Save as monitor; name, schedule, on and Alert to only for saving
    var name = el('input', { type: 'text', 'aria-label': 'Monitor name', maxlength: 100, placeholder: 'e.g. users-internal' });
    var sch = el('input', { type: 'text', 'aria-label': 'Schedule', placeholder: 'daily 07:00' }); sch.value = 'daily 07:00';
    var en = el('input', { type: 'checkbox' }); en.checked = true;
    var alertTo = el('input', { type: 'text', 'aria-label': 'Alert to', placeholder: 'team@contoso.com, other@contoso.com (empty = the alert recipients in Settings)' });
    var saveBox = el('div', { class: 'editor', hidden: true },
      el('div', { class: 'form' }, el('label', null, 'Name ', name), el('label', null, 'Schedule ', sch), el('label', null, en, ' on'),
        el('label', { class: 'wide' }, 'Alert to ', alertTo),
        el('div', { class: 'wide smeta', text: 'Schedule examples: daily 07:00 (every day at 07:00), every 4h, weekly mon 06:00. An alert mail goes out only when users are impacted.' })),
      el('div', { class: 'dlg-buttons' }, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: function () { saveBox.hidden = true; } }), el('button', { type: 'button', text: 'Save', onclick: save })));
    var saveBtn = el('button', { type: 'button', class: 'secondary', text: 'Save as monitor', onclick: function () { saveBox.hidden = false; (st.mon ? sch : name).focus(); } });
    var runBtn = el('button', { type: 'button', text: 'Analyse now', onclick: analyse });

    function read() {
      var ser = st.dropSeries ? { prefixes: [], patterns: [], names: st.series.names } : st.series;
      return { personas: Object.keys(st.personas).filter(function (k) { return st.personas[k]; }), policyIds: Object.keys(st.picked).filter(function (k) { return st.picked[k] && !st.excluded[k]; }),
        excludePolicyIds: leftOut(), policyNames: ser.names, policyPrefixes: ser.prefixes, policyPatterns: ser.patterns,
        mode: 'SignInLogs', lookbackHours: period.value, sliceHours: slice.value.trim() || '0', includeNonInteractive: nonInt.checked, includeGuests: guests.checked, includeDisabled: disabled.checked };
    }
    function describe(b) { return [b.personas.length ? b.personas.join(', ') : '', b.policyIds.length ? fmtNum(b.policyIds.length) + ' picked' : '', b.policyPrefixes.concat(b.policyPatterns).join(', ')].filter(function (x) { return x; }).join(' + ') + (b.excludePolicyIds.length ? ' (' + fmtNum(b.excludePolicyIds.length) + ' left out)' : ''); }
    function analyse() {
      var b = read();
      if (!selection().length && !b.personas.length) { notice('Pick a persona or a policy first (step 1).', 'warn'); return; }
      withReason('Analyse ' + (st.mon ? 'monitor ' + st.mon + ': ' : '') + describe(b), 'Read only: the engine reads the policies and the sign-ins of ' + caPeriodText(b.lookbackHours) + ' and changes nothing.', function (reason) { b.reason = reason; return api('POST', '/api/ca/analyze', b); });
    }
    function save() {
      var n = st.mon || name.value.trim();
      if (!CA_NAME.test(n)) { notice('A monitor name is 1-100 letters, digits, - _ or .', 'warn'); name.focus(); return; }
      if (!st.mon && monitors.some(function (m) { return m.Name.toLowerCase() === n.toLowerCase(); })) { notice('A monitor ' + n + ' exists already - pick it under Monitor to change it.', 'warn'); return; }
      var b = read(); b.alertTo = splitList(alertTo.value);
      if (!selection().length && !b.personas.length) { notice('Pick a persona or a policy first (step 1).', 'warn'); return; }
      withReason((st.mon ? 'Save monitor ' : 'Save as monitor ') + n, 'It analyses ' + describe(b) + ' (' + caPeriodText(b.lookbackHours) + ') ' + (en.checked ? sch.value : '(off)') + ', read only.', function (reason) {
        return api('PUT', '/api/ca/monitors/' + encodeURIComponent(n), { definition: b, schedule: sch.value, enabled: en.checked, reason: reason }).then(function (r) { saveBox.hidden = true; if (onSaved) onSaved(n); return r; }); });
    }
    function load(mn) {
      var m = monitors.filter(function (x) { return x.Name === mn; })[0];
      var def = {}; if (m) { try { def = JSON.parse(m.Definition || '{}') || {}; } catch (e) { def = {}; } }
      st.mon = m ? m.Name : ''; chooser.value = st.mon; st.picked = {}; st.personas = {}; st.excluded = {}; st.dropSeries = false;
      (def.policyIds || []).forEach(function (id) { st.picked[String(id).toLowerCase()] = true; });
      (def.excludePolicyIds || []).forEach(function (id) { st.excluded[String(id).toLowerCase()] = true; });
      (def.personas || []).forEach(function (x) { st.personas[x] = true; st.open[x] = true; });
      st.series = { prefixes: (def.policyPrefixes || []).slice(), patterns: (def.policyPatterns || []).slice(), names: (def.policyNames || []).slice() };
      var h = String(def.lookbackHours || 24);
      if (!CA_PERIODS.some(function (x) { return String(x[0]) === h; })) period.appendChild(el('option', { value: h, text: 'the last ' + fmtNum(h) + ' hours' }));
      period.value = h;
      nonInt.checked = !!def.includeNonInteractive; guests.checked = !!def.includeGuests; disabled.checked = !!def.includeDisabled; slice.value = textOf(def.sliceHours || 0);
      more.open = false;
      name.value = st.mon; name.disabled = !!st.mon; sch.value = m ? textOf(m.Schedule) : 'daily 07:00'; en.checked = m ? !!m.Enabled : true; alertTo.value = (def.alertTo || []).join(', ');
      saveBtn.textContent = st.mon ? 'Save monitor' : 'Save as monitor'; saveBox.hidden = true;
      drawList();
    }
    var node = el('div', { class: 'ca-one', id: 'caOne' },
      el('div', { class: 'toolbar' }, el('label', null, 'Monitor ', chooser), el('span', { class: 'smeta', text: 'New = analyse now and / or save as a new monitor; pick a monitor to change it.' })),
      el('h4', { class: 'ca-step', text: '1. Which policies' }),
      el('div', { class: 'toolbar' }, filter, allOpen, allShut, noneBtn, manageBtn, listInfo), listBox, pickInfo, seriesBox,
      el('h4', { class: 'ca-step', text: '2. Which sign-ins' }),
      el('div', { class: 'toolbar' }, el('label', null, 'Sign-ins of ', period)), more,
      el('h4', { class: 'ca-step', text: '3. Analyse or save' }),
      el('div', { class: 'toolbar' }, runBtn, saveBtn), saveBox);
    load('');
    return { node: node, load: function (mn) { load(mn); node.scrollIntoView(); } };
  }

  // Manage personas (CA-PERSONA): create, rename, add / remove policies and rules, delete - written by the engine
  function personaManager(data) {
    var d = el('dialog', { class: 'dlg-wide', 'aria-label': 'Manage personas' }); document.body.appendChild(d);
    var close = function () { if (d.open) d.close(); if (d.parentNode) d.parentNode.removeChild(d); };
    d.addEventListener('close', function () { if (d.parentNode) d.parentNode.removeChild(d); });
    var body = el('div', { class: 'editor' }); d.appendChild(body);
    var policies = data.policies.slice().sort(function (a, b) { return textOf(a.DisplayName) < textOf(b.DisplayName) ? -1 : 1; });
    function list() {
      clear(body);
      body.appendChild(el('h3', { text: 'Personas' }));
      body.appendChild(el('div', { class: 'smeta', text: 'A persona is a group of policies a monitor can name: picked policies and / or name rules (CA2 = every CA2xx, CA006 = the CA006 policies, CA6* = a wildcard). A monitor resolves its personas at each run, so a change here - or a new policy a rule takes - joins at its next run. A policy a rule takes can be unticked: it is left out of the persona. The starting list was made once from the built-in personas and your policies; change or delete any of them - an empty list stays empty.' + (data.seeded ? '' : ' (The starting list is made the first time the engine runs the analyzer or you change a persona.)') }));
      body.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', text: 'New persona', onclick: function () { edit(null); } })));
      body.appendChild(table(data.personas.map(function (pe) { return { Name: pe.name, Source: pe.managed === false ? 'from the template (not managed yet - edit to manage it)' : (pe.source === 'custom' ? 'yours' : 'starting list'), Rules: (pe.rules || []).join(', '), Picked: (pe.policyIds || []).length, Out: (pe.excludeIds || []).length, Takes: (pe.takes || []).length, Monitors: (pe.monitors || []).join(', '), _pe: pe }; }), [
        { key: 'Name', label: 'Persona' }, { key: 'Rules', label: 'Name rules', wrap: true }, { key: 'Picked', label: 'Picked', type: 'num' }, { key: 'Out', label: 'Left out', type: 'num' }, { key: 'Takes', label: 'Takes now', type: 'num' },
        { key: 'Monitors', label: 'Used by monitors', wrap: true }, { key: 'Source', label: 'From', type: 'cat' },
        { key: '_a', label: '', render: function (r) { return el('span', null, el('button', { type: 'button', class: 'link', text: 'Edit', onclick: function () { edit(r._pe); } }), ' ', el('button', { type: 'button', class: 'link', text: 'Delete', onclick: function () { del(r._pe); } })); } }],
        { sort: 'Name', dir: 1, empty: 'No persona yet.' }));
      body.appendChild(el('div', { class: 'dlg-buttons' }, el('button', { type: 'button', class: 'secondary', text: 'Close', onclick: close })));
    }
    function edit(pe) {
      clear(body);
      var picked = {}; ((pe && pe.policyIds) || []).forEach(function (id) { picked[String(id).toLowerCase()] = true; });
      // CA-LIMITS: the persona's EXCLUDE list - a policy a rule takes, unticked, stays out; ticking it again takes it back
      var excl = {}; ((pe && pe.excludeIds) || []).forEach(function (id) { excl[String(id).toLowerCase()] = true; });
      var nm = el('input', { type: 'text', 'aria-label': 'Persona name', maxlength: 100, placeholder: 'e.g. Users-Internal' }); nm.value = pe ? pe.name : '';
      var rules = el('input', { type: 'text', 'aria-label': 'Name rules', placeholder: 'e.g. CA2 (every CA2xx), CA006, CA6* - comma separated' }); rules.value = pe ? (pe.rules || []).join(', ') : '';
      var hits = el('div', { class: 'smeta' }), filter = el('input', { type: 'search', placeholder: 'filter policies', 'aria-label': 'Filter policies' });
      var box = el('div', { class: 'plist' });
      function draw() {
        var rs = splitList(rules.value), f = filter.value.trim().toLowerCase();
        var byRule = policies.filter(function (p) { return rs.some(function (r) { return caRuleMatch(p.DisplayName, r); }); });
        var n = {}; byRule.forEach(function (p) { n[String(p.PolicyId).toLowerCase()] = 1; }); Object.keys(picked).forEach(function (k) { if (picked[k]) n[k] = 1; });
        var nOut = Object.keys(n).filter(function (k) { return excl[k]; }).length;
        hits.textContent = 'The rules take ' + fmtNum(byRule.length) + (byRule.length ? ': ' + byRule.slice(0, 30).map(function (p) { return p.DisplayName; }).join(', ') + (byRule.length > 30 ? ', ...' : '') : '') + '.' + (nOut ? ' ' + fmtNum(nOut) + ' left out.' : '') + ' The persona takes ' + fmtNum(Object.keys(n).length - nOut) + ' policy(ies) now.';
        clear(box);
        policies.forEach(function (p) {
          if (f && textOf(p.DisplayName).toLowerCase().indexOf(f) < 0) return;
          var id = String(p.PolicyId).toLowerCase(), viaRule = rs.some(function (r) { return caRuleMatch(p.DisplayName, r); }), out = viaRule && !!excl[id];
          var cb = el('input', { type: 'checkbox', title: viaRule ? (out ? 'left out - tick to take it back' : 'taken by a name rule - untick to leave it out') : null });
          cb.checked = !out && (viaRule || !!picked[id]);
          cb.addEventListener('change', function () {
            if (cb.checked) { delete excl[id]; if (!viaRule) picked[id] = true; }
            else { picked[id] = false; if (viaRule) excl[id] = true; }
            draw();
          });
          box.appendChild(el('label', { class: 'pitem' }, cb, ' ', p.DisplayName, viaRule ? el('span', { class: 'skey', text: out ? ' (by a rule - left out)' : ' (by a rule)' }) : null));
        });
      }
      rules.addEventListener('input', draw); filter.addEventListener('input', draw);
      body.appendChild(el('h3', { text: pe ? 'Persona ' + pe.name : 'New persona' }));
      if (pe && (pe.monitors || []).length) body.appendChild(el('div', { class: 'smeta', text: 'Named by the monitor(s) ' + pe.monitors.join(', ') + ': a rename is followed by them; a change joins at their next run.' }));
      body.appendChild(el('div', { class: 'form' }, el('label', { class: 'wide' }, 'Name ', nm), el('label', { class: 'wide' }, 'Name rules ', rules), el('div', { class: 'wide' }, hits)));
      body.appendChild(el('div', { class: 'toolbar' }, filter, el('span', { class: 'smeta', text: 'Tick single policies. A policy a rule takes is ticked already - untick it to leave it out.' })));
      body.appendChild(box);
      body.appendChild(el('div', { class: 'dlg-buttons' }, el('button', { type: 'button', class: 'secondary', text: 'Back', onclick: list }), el('button', { type: 'button', text: 'Save', onclick: function () {
        var n = nm.value.trim(), rs = splitList(rules.value), ids = Object.keys(picked).filter(function (k) { return picked[k]; });
        if (!CA_NAME.test(n)) { notice('A persona name is 1-100 letters, digits, - _ or .', 'warn'); nm.focus(); return; }
        var clash = data.personas.filter(function (x) { return x.name.toLowerCase() === n.toLowerCase() && (!pe || x.name !== pe.name); })[0];
        if (clash) { notice('A persona ' + clash.name + ' exists already.', 'warn'); return; }
        if (!rs.length && !ids.length) { notice('A persona takes at least one policy or one name rule.', 'warn'); return; }
        // excludeIds: only the left-out policies a rule still takes (an exclude without a rule means nothing)
        var xs = policies.filter(function (p) { var id = String(p.PolicyId).toLowerCase(); return excl[id] && rs.some(function (r) { return caRuleMatch(p.DisplayName, r); }); }).map(function (p) { return String(p.PolicyId).toLowerCase(); });
        var b = { policyIds: ids, rules: rs, excludeIds: xs }; if (pe && n !== pe.name) b.newName = n;
        close();
        withReason(pe ? (b.newName ? 'Rename persona ' + pe.name + ' to ' + n : 'Save persona ' + n) : 'New persona ' + n, (b.newName && (pe.monitors || []).length ? 'The monitor(s) ' + pe.monitors.join(', ') + ' follow the new name. ' : '') + 'Monitors take the change at their next run. Nothing in the tenant changes.', function (reason) {
          b.reason = reason; return api('PUT', '/api/ca/personas/' + encodeURIComponent(pe ? pe.name : n), b); });
      } })));
      draw(); nm.focus();
    }
    function del(pe) {
      var used = pe.monitors || [];
      close();
      // a persona a monitor names: the delete names the monitors and asks again (force takes it out of them)
      withReason('Delete persona ' + pe.name, used.length ? 'The monitor(s) ' + used.join(', ') + ' name this persona: it is taken out of them (a monitor left with nothing to analyse is switched off). The policies themselves stay.' : 'No monitor names it. The policies themselves stay.', function (reason) {
        return api('DELETE', '/api/ca/personas/' + encodeURIComponent(pe.name), { reason: reason, force: used.length > 0 }); });
    }
    list();
    d.showModal();
  }

  function drawCa(p) {
    var admin = isRole('Admin');
    p.appendChild(el('div', { class: 'guide', text: 'Before you move a policy to pilot or production: put it in report-only (or on for the pilot), then analyse the sign-in logs - who it would have blocked or challenged, and why. Analyse once, or save the same choice as a monitor that runs on a schedule. The analyzer only READS: it never changes a Conditional Access policy.' }));
    return Promise.all([api('GET', '/api/ca/policies'), api('GET', '/api/ca/monitors'), api('GET', '/api/ca/personas')]).then(function (all) {
      var data = { policies: all[0].rows || [], monitors: all[1].rows || [], personas: all[2].rows || [], seeded: !!all[2].seeded };
      var form = null;
      if (admin) { form = caOneForm(data); p.appendChild(form.node); }
      p.appendChild(el('h3', { text: 'Analyses' }));
      p.appendChild(pagedTable('/api/ca/analyses', [{ key: 'q', label: 'Search policy' }, { key: 'monitor', label: 'Monitor' }], [
        { key: 'CreatedAtUtc', label: 'When', type: 'date' }, { key: 'DisplayName', label: 'Policy' }, { key: 'PolicyState', label: 'State', type: 'cat' }, { key: 'Mode', label: 'Method', type: 'cat' },
        { key: 'InScope', label: 'In scope', type: 'num' }, { key: 'Impacted', label: 'Impacted', type: 'num', cls: function (r) { return r.Impacted > 0 ? 'c-danger' : ''; } }, { key: 'Errors', label: 'Errors', type: 'num' },
        { key: 'Monitor', label: 'Monitor', type: 'cat' }, { key: 'AnalysisId', label: '', render: function (r) { return el('a', { href: '#ca/' + r.AnalysisId, text: 'users' }); } }]));
      p.appendChild(el('h3', { text: 'Monitors' }));
      // CA-MONPEND: a save the engine has not applied yet is not in the table - say it is on its way
      if ((all[1].pending || []).length) p.appendChild(el('div', { class: 'bar bar-info' }, caPendingText(all[1].pending) + ' ', el('button', { type: 'button', class: 'link', text: 'Reload', onclick: function () { render(); } })));
      p.appendChild(el('div', { class: 'guide', text: 'A monitor is a saved analysis that runs on a schedule - several side by side, e.g. one per persona (Users-Internal, Admins, ...) and one for the global policies (CA00x). A persona takes all its policies, also ones added later. An alert mail goes out only when users are impacted, to the monitor\'s own recipients (a team) or else to the alert recipients in Settings. Edit loads a monitor into the form above.' }));
      var mcols = [{ key: 'Name', label: 'Monitor' }, { key: 'Schedule', label: 'Schedule' }, { key: 'Enabled', label: 'On', type: 'cat' },
        { key: 'Definition', label: 'Policies', wrap: true, render: function (m) { try { var d = JSON.parse(m.Definition); var ids = (d.policyIds || []).length; var old = (d.policyPrefixes || []).concat(d.policyPatterns || []); return [].concat((d.personas || []).map(function (x) { return 'persona ' + x; }), ids ? [ids + ' picked'] : [], old.length ? ['older series ' + old.join(', ')] : [], (d.excludePolicyIds || []).length ? [d.excludePolicyIds.length + ' left out'] : []).join(', ') + ((d.alertTo || []).length ? ' · alert to ' + d.alertTo.join(', ') : ''); } catch (e) { return ''; } } },
        { key: 'LastStartedUtc', label: 'Last start', type: 'date' }, { key: 'LastStartResult', label: 'Result', wrap: true }];
      if (admin) mcols.push({ key: '_e', label: '', render: function (m) { return el('span', null, el('button', { type: 'button', class: 'link', text: 'Edit', onclick: function () { form.load(m.Name); } }),
        el('button', { type: 'button', class: 'link', text: 'Delete', onclick: function () { withReason('Delete monitor ' + m.Name, 'Its analyses stay.', function (reason) { return api('DELETE', '/api/ca/monitors/' + encodeURIComponent(m.Name), { reason: reason }); }); } })); } });
      p.appendChild(table(data.monitors, mcols, { sort: 'Name', dir: 1, empty: 'No monitor yet.', bulk: admin ? [{ label: 'Delete', run: function (rows) { bulkAction('Delete monitors', 'Their analyses stay.', rows, function (m, reason) { return api('DELETE', '/api/ca/monitors/' + encodeURIComponent(m.Name), { reason: reason }); }); } }] : [] }));
    });
  }
  // CA-MONADD on the Conditional Access page: the selected policies into / out of a monitor - pick the monitor, ONE
  // confirmation, ONE change of that monitor. CA-LIMITS (owner 2026-11-02: "fix all 4 limits"): Remove takes out ANY
  // policy - a single-picked one is unpicked; one that comes through a persona or an older series rule goes on the
  // monitor's own "left out" list (excludePolicyIds). Add takes a left-out policy back. The confirmation says per policy
  // what happens.
  function caMonitorPick(kind, sel) {
    Promise.all([api('GET', '/api/ca/monitors'), api('GET', '/api/ca/policies'), api('GET', '/api/ca/personas')]).then(function (all) {
      var mons = all[0].rows || [], waiting = all[0].pending || [];
      // CA-MONPEND (owner 2026-11-05: "nothing happens when i click add to monitor"): a saved monitor the engine has not
      // applied yet is not in the list - say so instead of "no monitor"; a monitor with a change still waiting is not
      // changed again (this PUT would overwrite it)
      var waitFor = function (n) { return waiting.filter(function (w) { return String(w.Name).toLowerCase() === String(n).toLowerCase(); }).length > 0; };
      if (!mons.length) { notice(waiting.length ? caPendingText(waiting) + ' Try again when it is applied.' : 'No monitor yet - make one on the CA Policy Analyzer page (Save as monitor).', 'warn'); return; }
      var pols = all[1].rows || [], takes = {};
      (all[2].rows || []).forEach(function (pe) { takes[pe.name.toLowerCase()] = (pe.takes || []).map(function (x) { return String(x).toLowerCase(); }); });
      var d = el('dialog', { class: 'rg-dlg', 'aria-label': 'Pick the monitor' }); document.body.appendChild(d);
      var close = function () { if (d.open) d.close(); if (d.parentNode) d.parentNode.removeChild(d); };
      d.addEventListener('close', function () { if (d.parentNode) d.parentNode.removeChild(d); });
      var pick = el('select', { 'aria-label': 'Monitor' }, mons.map(function (m) { return el('option', { value: m.Name, text: m.Name + (m.Enabled ? '' : ' (off)') + (waitFor(m.Name) ? ' (a change waits for the engine)' : '') }); }));
      d.appendChild(el('h3', { text: (kind === 'add' ? 'Add ' : 'Remove ') + fmtNum(sel.length) + ' policy(ies) ' + (kind === 'add' ? 'to' : 'from') + ' a monitor' }));
      d.appendChild(el('div', { class: 'form' }, el('label', null, 'Monitor ', pick)));
      d.appendChild(el('div', { class: 'dlg-buttons' }, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: close }), el('button', { type: 'button', text: 'Next', onclick: function () {
        var m = mons.filter(function (x) { return x.Name === pick.value; })[0]; close(); if (!m) return;
        if (waitFor(m.Name)) { notice('Monitor ' + m.Name + ' has a change waiting for the engine (its next check, within 5 minutes) - try again when it is applied, so this change does not overwrite it.', 'warn'); return; }
        var def = {}; try { def = JSON.parse(m.Definition || '{}') || {}; } catch (e) { def = {}; }
        var plan = caMonitorPlan(kind, def, sel, takes, pols);
        if (!plan.changed) { notice(plan.lines.join(' '), 'warn'); return; }
        var title = (kind === 'add' ? 'Add to monitor ' : 'Remove from monitor ') + m.Name + ': ' + plan.summary;
        withReason(title, plan.lines.join('\n') + '\n' + (kind === 'add' ? 'It analyses them from its next run - read only.' : 'The policies themselves stay as they are.'), function (reason) {
          return api('PUT', '/api/ca/monitors/' + encodeURIComponent(m.Name), { definition: plan.def, schedule: m.Schedule, enabled: !!m.Enabled, reason: reason }); });
      } })));
      d.showModal();
    }).catch(function (e) { notice('Could not read the monitors: ' + e.message, 'warn'); });
  }
  // CA-MONPEND: the monitor saves / deletes the engine has not applied yet, in one sentence
  function caPendingText(waiting) {
    return 'Waiting for the engine (it applies changes at its next check, every 5 minutes): ' + waiting.map(function (w) {
      return (w.Method === 'DELETE' ? 'delete' : 'save') + ' monitor ' + w.Name + ' (requested ' + fmtTime(w.RequestedAtUtc) + (w.RequestedBy ? ' by ' + w.RequestedBy : '') + ')'; }).join('; ') + '.';
  }
  // the change to ONE monitor's definition and a plain line per policy - kept apart from the dialog so it can be read
  // on its own: { def, changed, lines, summary }
  function caMonitorPlan(kind, def, sel, takes, pols) {
    var lc = function (x) { return String(x).toLowerCase(); };
    var nd = JSON.parse(JSON.stringify(def || {}));
    var ids = (nd.policyIds || []).map(lc), out = (nd.excludePolicyIds || []).map(lc);
    var nameOf = {}; (pols || []).forEach(function (p) { nameOf[lc(p.PolicyId)] = p.DisplayName; });
    // through what else the monitor takes a policy: a persona it names, or an older series rule
    var via = function (r) {
      var id = lc(r.PolicyId), why = [];
      (nd.personas || []).forEach(function (pn) { if ((takes[lc(pn)] || []).indexOf(id) >= 0) why.push('persona ' + pn); });
      var rules = (nd.policyPrefixes || []).concat(nd.policyPatterns || []);
      if (rules.some(function (x) { return caRuleMatch(r.DisplayName, x); }) || (nd.policyNames || []).some(function (x) { return lc(x) === lc(r.DisplayName); })) why.push('an older series rule');
      return why;
    };
    var lines = [], n = { added: 0, back: 0, unpicked: 0, left: 0, none: 0 };
    sel.forEach(function (r) {
      var id = lc(r.PolicyId), nm = r.DisplayName || nameOf[id] || id, why = via(r), isPicked = ids.indexOf(id) >= 0, isOut = out.indexOf(id) >= 0;
      if (kind === 'add') {
        if (isOut) { out = out.filter(function (x) { return x !== id; }); if (!why.length && !isPicked) ids.push(id); n.back++; lines.push(nm + ': taken back (it was left out of this monitor).'); }
        else if (isPicked || why.length) { n.none++; lines.push(nm + ': in it already' + (why.length ? ' (through ' + why.join(', ') + ')' : '') + ' - nothing changes.'); }
        else { ids.push(id); n.added++; lines.push(nm + ': added.'); }
      } else {
        if (isOut) { n.none++; lines.push(nm + ': left out already - nothing changes.'); return; }
        if (!isPicked && !why.length) { n.none++; lines.push(nm + ': not in this monitor - nothing changes.'); return; }
        if (isPicked) ids = ids.filter(function (x) { return x !== id; });
        if (why.length) { out.push(id); n.left++; lines.push(nm + ': left out of this monitor' + (isPicked ? ' and unpicked' : '') + ' (it comes through ' + why.join(', ') + ').'); }
        else { n.unpicked++; lines.push(nm + ': removed (it was picked one by one).'); }
      }
    });
    nd.policyIds = ids; nd.excludePolicyIds = out;
    var parts = kind === 'add' ? [[n.added, 'added'], [n.back, 'taken back'], [n.none, 'in it already']] : [[n.unpicked, 'removed'], [n.left, 'left out'], [n.none, 'unchanged']];
    return { def: nd, changed: kind === 'add' ? (n.added + n.back) > 0 : (n.unpicked + n.left) > 0, lines: lines,
      summary: parts.filter(function (x) { return x[0]; }).map(function (x) { return fmtNum(x[0]) + ' ' + x[1]; }).join(', ') };
  }  function drawCaAnalysis(p, id) {
    var all = false;
    var host = el('div');
    var load = function () {
      clear(host);
      return api('GET', '/api/ca/analyses/' + encodeURIComponent(id) + '?pageSize=1').then(function (j) {
        var a = j.analysis;
        host.appendChild(el('h2', { text: a.DisplayName + ' - ' + (a.Mode === 'SignInLogs' ? 'observed (sign-in logs)' : 'predicted (What-If)') }));
        host.appendChild(el('div', { class: 'cards' }, card(a.InScope, 'in scope'), card(a.Impacted, 'impacted (blocked / challenged)', a.Impacted > 0), card(a.NotImpacted, 'not impacted'), card(a.Errors, 'errors', a.Errors > 0)));
        host.appendChild(el('p', null, 'State ' + textOf(a.PolicyState) + '. ', a.WindowStartUtc ? 'Window ' : '', a.WindowStartUtc ? timeEl(a.WindowStartUtc) : null, a.WindowStartUtc ? ' - ' : '', a.WindowEndUtc ? timeEl(a.WindowEndUtc) : null, '. Analysed ', timeEl(a.CreatedAtUtc), a.Monitor ? ' by monitor ' + a.Monitor : '', '.'));
        var notes = [].concat(JSON.parse(a.WarningsJson || '[]'), JSON.parse(a.UnresolvedJson || '[]').map(function (x) { return 'not simulated: ' + x; }));
        if (notes.length) host.appendChild(el('ul', { class: 'hints' }, notes.map(function (n) { return el('li', { text: n }); })));
        var toggle = el('button', { type: 'button', class: 'secondary', text: all ? 'Only impacted users' : 'All in-scope users', onclick: function () { all = !all; load(); } });
        host.appendChild(el('div', { class: 'toolbar' }, toggle, el('a', { href: '/api/ca/analyses/' + encodeURIComponent(id) + '/export', text: 'Export CSV (every user)' })));
        host.appendChild(pagedTable('/api/ca/analyses/' + encodeURIComponent(id), [{ key: 'q', label: 'Search user or classification' }, { key: 'all', hidden: true, value: all ? '1' : '' }], [
          { key: 'DisplayName', label: 'User' }, { key: 'UserPrincipalName', label: 'UPN' }, { key: 'Classification', label: 'Result', type: 'cat', cls: function (r) { return r.Impacted ? 'c-danger' : ''; } },
          { key: 'Reason', label: 'Why', wrap: true }, { key: 'GrantControls', label: 'Controls' }, { key: 'LastSignInUtc', label: 'Last sign-in', type: 'date' }, { key: 'Country', label: 'Country', type: 'cat' },
          { key: 'Application', label: 'App' }, { key: 'DeviceOS', label: 'OS', type: 'cat' }, { key: 'ClientApp', label: 'Client', type: 'cat' }, { key: 'SignInCount', label: 'Sign-ins', type: 'num' }, { key: 'FailureReason', label: 'Failure', wrap: true }]));
      });
    };
    p.appendChild(host);
    return load();
  }

  // ---- the identity report (DESIGN §5.4; owner 2026-10-31: "gui view with filters", "lots of relevant views", "that
  // shows gaps", "similar to excel pivots", "save views like fx si can"). Read only: the engine's last snapshot.
  var ID_OPS = [['contains', 'contains'], ['notContains', 'does not contain'], ['equals', 'is'], ['startsWith', 'starts with'], ['anyOf', 'is one of'], ['atLeast', 'at least'], ['atMost', 'at most']];
  var ID_SEV_CLS = { High: 'c-danger', Medium: 'c-warning', Low: '', Info: 'smeta' };
  function newUuid() { if (window.crypto && crypto.randomUUID) return crypto.randomUUID(); return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) { var r = Math.random() * 16 | 0; return (c === 'x' ? r : (r & 3 | 8)).toString(16); }); }
  // ID-ACTIONS (owner 2026-11-03: "we need a way to add 4 fields per user: notes + action (dropdwn) like disable, delete,
  // investigate, remove sync cloud + ActionWho (text field) + ActionStatus (not started, in progress, closed). it must be
  // possible to do multiselect"): one dialog for many users; a field left on "leave as it is" is not changed
  function idActionDialog(lists, what, body) {
    var d = el('dialog', { class: 'dlg-wide', 'aria-label': 'Set action' });
    var closed = false;
    var close = function () { if (closed) return; closed = true; try { d.close(); } catch (e) { /* closed */ } if (d.parentNode) d.parentNode.removeChild(d); };
    d.addEventListener('close', close);
    var KEEP = '__keep', CLEAR = '';
    var pick = function (vals) { return el('select', null, [el('option', { value: KEEP, text: '(leave as it is)' }), el('option', { value: CLEAR, text: '(clear)' })].concat(vals.map(function (v) { return el('option', { value: v, text: v }); }))); };
    var act = pick(lists.actions || []), stat = pick(lists.states || []);
    var who = el('input', { type: 'text', maxlength: 200, placeholder: '(leave as it is) - e.g. the AD team / a name', style: 'width:100%' });
    var notes = el('textarea', { rows: 3, maxlength: 2000, placeholder: '(leave as it is) - e.g. service account, not needed in the cloud: take it out of the sync scope', style: 'width:100%' });
    var clrWho = el('input', { type: 'checkbox' }), clrNotes = el('input', { type: 'checkbox' });
    d.appendChild(el('h3', { text: 'Set action on ' + what }));
    d.appendChild(el('div', { class: 'guide', text: 'A record for follow-up, kept per user across report runs and shown in every view (filter, sort, pivot, export). Nothing in the tenant or AD changes.' }));
    [['Action', act], ['Status', stat]].forEach(function (x) { d.appendChild(el('label', { class: 'fld' }, el('span', { text: x[0] }), x[1])); });
    d.appendChild(el('label', { class: 'fld' }, el('span', { text: 'Who (responsible)' }), who, el('label', null, clrWho, ' clear it')));
    d.appendChild(el('label', { class: 'fld' }, el('span', { text: 'Notes' }), notes, el('label', null, clrNotes, ' clear it')));
    var go = el('button', { type: 'button', text: 'Set' });
    go.addEventListener('click', function () {
      var set = {};
      if (act.value !== KEEP) set.action = act.value;
      if (stat.value !== KEEP) set.actionStatus = stat.value;
      if (clrWho.checked) set.actionWho = ''; else if (who.value.trim()) set.actionWho = who.value.trim();
      if (clrNotes.checked) set.notes = ''; else if (notes.value.trim()) set.notes = notes.value.trim();
      if (!Object.keys(set).length) { notice('Nothing to change: pick an action, a status, a name or a note.', 'warn'); return; }
      close();
      withReason('Set action on ' + what, 'Sets the follow-up fields only - nothing in the tenant or AD changes.', function (reason) { body.set = set; body.reason = reason; return api('POST', '/api/identity/actions', body); });
    });
    d.appendChild(el('div', { class: 'toolbar' }, go, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: close })));
    document.body.appendChild(d); d.showModal();
  }
  function drawIdentity(p, arg) {
    return Promise.all([api('GET', '/api/identity'), api('GET', '/api/identity/saved')]).then(function (res) {
      var j = res[0], saved = res[1].rows || [];
      var views = j.views || [], byName = {}; views.forEach(function (v) { byName[v.name] = v; });
      var prev = (j.history || [])[1], prevCounts = {}; try { prevCounts = prev ? JSON.parse(prev.ViewCountsJson || '{}') : {}; } catch (e) { }
      var admin = isRole('Admin'), superAdmin = isRole('SuperAdmin');
      // the header: the snapshot, what it could not see, Run now
      var head = el('div', { class: 'toolbar' });
      if (j.snapshot) head.appendChild(el('span', null, 'Snapshot ', timeEl(j.snapshot.CreatedAtUtc), ' · ' + fmtNum(j.snapshot.Users) + ' users · ' + fmtNum(j.snapshot.Devices) + ' devices'));
      else head.appendChild(el('span', { text: j.enabled ? 'No snapshot yet - Run now, or wait for the schedule (Jobs).' : 'The identity report is off - switch it on in Settings > Identity report.' }));
      if (j.ad) head.appendChild(el('span', { class: 'count', text: j.ad.RefreshedAtUtc ? ' · AD read ' + fmtTime(j.ad.RefreshedAtUtc) + (j.ad.Users ? ' (' + fmtNum(j.ad.Users) + ' users)' : '') : ' · AD not read yet (needs the hybrid worker)' }));
      if (admin && j.enabled) head.appendChild(el('button', { type: 'button', text: 'Run now', onclick: function () { withReason('Run the identity report now', 'Read only: nothing in the tenant or AD is changed. The page shows the new snapshot when it is done (a few minutes).', function (reason) { return api('POST', '/api/identity/run', { reason: reason }); }); } }));
      p.appendChild(head);
      var notes = []; try { notes = JSON.parse((j.snapshot && j.snapshot.NotesJson) || '[]'); } catch (e) { }
      if (notes.length) p.appendChild(el('ul', { class: 'hints' }, notes.map(function (n) { return el('li', { text: n }); })));
      if (!j.snapshot) return;
      var gapsOf = function (sev) { return views.filter(function (v) { return v.severity === sev && v.count > 0; }); };
      var sum = function (a) { return a.reduce(function (t, v) { return t + v.count; }, 0); };
      p.appendChild(el('div', { class: 'cards' },
        card(gapsOf('High').length, 'High gaps open (' + fmtNum(sum(gapsOf('High'))) + ' objects)', gapsOf('High').length > 0),
        card(gapsOf('Medium').length, 'Medium gaps open (' + fmtNum(sum(gapsOf('Medium'))) + ' objects)'),
        card(gapsOf('Low').length, 'Low gaps open'), card(j.snapshot.Users, 'users'), card(j.snapshot.Devices, 'devices')));

      var layout = el('div', { class: 'idlayout' }), nav = el('nav', { class: 'idnav', 'aria-label': 'Views' }), pane = el('div', { class: 'idpane' });
      layout.appendChild(nav); layout.appendChild(pane); p.appendChild(layout);
      var active = null;
      var navItem = function (label, count, sev, delta, onClick, key) {
        var b = el('button', { type: 'button', class: 'idnav-item' + (active === key ? ' on' : ''), onclick: function () { active = key; Array.prototype.forEach.call(nav.querySelectorAll('.idnav-item'), function (x) { x.classList.remove('on'); }); b.classList.add('on'); onClick(); } },
          el('span', { class: 'idnav-l ' + (ID_SEV_CLS[sev] || ''), text: label }),
          count === null || count === undefined ? null : el('span', { class: 'badge' + (sev === 'High' && count > 0 ? ' danger' : ''), text: fmtNum(count) }),
          delta ? el('span', { class: 'iddelta ' + (delta > 0 ? 'c-danger' : 'c-good'), title: 'since the previous snapshot', text: (delta > 0 ? '+' : '') + fmtNum(delta) }) : null);
        b.setAttribute('data-key', key);
        return b;
      };
      // saved views first, then the open gaps by severity, then every view by topic, then the ready-made pivots
      var mine = saved.filter(function (s) { return !s.Shared; }), shared = saved.filter(function (s) { return s.Shared; });
      var openSaved = function (s) { var d = {}; try { d = JSON.parse(s.Definition); } catch (e) { } openView(d.base, d, s); };
      if (shared.length) { nav.appendChild(el('h4', { text: 'Shared views' })); shared.forEach(function (s) { nav.appendChild(navItem(s.Name + (s.IsDefault ? ' (default)' : ''), null, '', 0, function () { openSaved(s); }, 'saved:' + s.ViewId)); }); }
      if (mine.length) { nav.appendChild(el('h4', { text: 'My views' })); mine.forEach(function (s) { nav.appendChild(navItem(s.Name, null, '', 0, function () { openSaved(s); }, 'saved:' + s.ViewId)); }); }
      var groups = []; views.forEach(function (v) { if (groups.indexOf(v.group) < 0) groups.push(v.group); });
      var sevOrder = { High: 0, Medium: 1, Low: 2, Info: 3, '': 4 };
      groups.forEach(function (g) {
        nav.appendChild(el('h4', { text: g }));
        views.filter(function (v) { return v.group === g; }).sort(function (a, b) { return (sevOrder[a.severity] - sevOrder[b.severity]) || ((b.count || 0) - (a.count || 0)); }).forEach(function (v) {
          var d = (prevCounts[v.name] !== undefined && v.count !== null) ? v.count - prevCounts[v.name] : 0;
          nav.appendChild(navItem(v.title, v.count, v.severity, v.severity && v.severity !== 'Info' ? d : 0, function () { openView(v.name, null, null); }, 'view:' + v.name));
        });
      });
      if ((j.pivots || []).length) {
        nav.appendChild(el('h4', { text: 'Pivots' }));
        j.pivots.forEach(function (pv) { nav.appendChild(navItem(pv.Title, null, '', 0, function () { openPivot(pv); }, 'pivot:' + pv.Name)); });
      }

      function pivotTable(pv, onCell) {
        var cols = pv.columns || pv.Columns || [], rows = pv.rows || pv.Rows || [];
        var t = el('table', { class: 'grid pivot' }), hr = el('tr', null, el('th', { text: (pv.rowKey || pv.RowKey || '') + (pv.columnKey || pv.ColumnKey ? ' \\ ' + (pv.columnKey || pv.ColumnKey) : '') }));
        cols.forEach(function (c) { hr.appendChild(el('th', { class: 'num', text: c })); }); hr.appendChild(el('th', { class: 'num', text: 'Total' }));
        var tb = el('tbody');
        rows.forEach(function (r) {
          var tr = el('tr', null, el('td', { text: r.Value }));
          cols.forEach(function (c) {
            var n = (r.Counts || {})[c] || 0;
            tr.appendChild(el('td', { class: 'num' }, n ? el('button', { type: 'button', class: 'link', text: fmtNum(n), title: 'show these ' + n, onclick: function () { onCell(r.Value, c); } }) : el('span', { class: 'smeta', text: '0' })));
          });
          tr.appendChild(el('td', { class: 'num' }, el('button', { type: 'button', class: 'link', text: fmtNum(r.Total), onclick: function () { onCell(r.Value, null); } })));
          tb.appendChild(tr);
        });
        t.appendChild(el('thead', null, hr)); t.appendChild(tb);
        return el('div', { class: 'twrap' }, t);
      }
      function cellFilters(rowKey, colKey, rv, cv) {
        var f = [{ col: rowKey, op: 'equals', value: rv === '(empty)' ? '' : rv }];
        if (colKey && cv !== null && cv !== 'Count') f.push({ col: colKey, op: 'equals', value: cv === '(empty)' ? '' : cv });
        return f;
      }
      function openPivot(pv) {
        clear(pane);
        pane.appendChild(el('h3', { text: pv.Title }));
        pane.appendChild(el('div', { class: 'guide', text: 'Counts of ' + pv.Rows + ' by ' + pv.Columns + ' over ' + (byName[pv.View] ? byName[pv.View].title : pv.View) + '. Click a number to see those objects.' }));
        pane.appendChild(pivotTable(pv.Pivot, function (rv, cv) { openView(pv.View, { v: 1, base: pv.View, filters: cellFilters(pv.Rows, pv.Columns, rv, cv), pivot: null }, null); }));
      }

      // one view: filters (LIST-1), columns, pivot, grid, export, save
      function openView(name, def, savedRow) {
        var v = byName[name]; if (!v) { clear(pane).appendChild(el('div', { class: 'empty', text: 'This view does not exist any more.' })); return; }
        def = def || {};
        var allCols = Object.keys((j.columns || {})[v.kind] || {}), types = (j.columns || {})[v.kind] || {};
        var st = { filters: (def.filters || []).slice(), q: def.search || '', sort: def.sort ? def.sort.col : null, dir: def.sort ? def.sort.dir : 1,
          columns: (def.columns && def.columns.length ? def.columns : v.columns).filter(function (c) { return allCols.indexOf(c) >= 0; }), page: 1, pageSize: def.pageSize || 100, pivot: def.pivot || null, sel: {} };
        var canAct = admin && v.kind === 'User';
        if (v.kind === 'User' && !(def.columns && def.columns.length)) ['Action', 'ActionStatus', 'ActionWho', 'Notes'].forEach(function (c) { if (allCols.indexOf(c) >= 0 && st.columns.indexOf(c) < 0) st.columns.push(c); });
        if (!st.columns.length) st.columns = allCols.slice(0, 8);
        clear(pane);
        pane.appendChild(el('h3', null, savedRow ? savedRow.Name + ' ' : v.title + ' ', v.severity ? el('span', { class: 'badge' + (v.severity === 'High' ? ' danger' : ''), text: v.severity }) : null, savedRow ? el('span', { class: 'smeta', text: ' (based on ' + v.title + ')' }) : null));
        if (v.what) pane.appendChild(el('p', { text: v.what }));
        if (v.fix) pane.appendChild(el('div', { class: 'guide' }, el('b', { text: 'How to close it: ' }), v.fix));
        // the filter bar
        var chips = el('div', { class: 'idchips' });
        var search = el('input', { type: 'search', placeholder: 'Search every column', 'aria-label': 'Search' }); search.value = st.q;
        search.addEventListener('change', function () { st.q = search.value; st.page = 1; reload(); });
        var fcol = el('select', { 'aria-label': 'Column' }, allCols.map(function (c) { return el('option', { value: c, text: c }); }));
        var fop = el('select', { 'aria-label': 'Condition' });
        var fval = el('input', { type: 'text', placeholder: 'value (is one of: a, b, c)', 'aria-label': 'Value' });
        var syncOps = function () { var num = types[fcol.value] === 'number'; clear(fop); ID_OPS.forEach(function (o) { if (!num && (o[0] === 'atLeast' || o[0] === 'atMost')) return; fop.appendChild(el('option', { value: o[0], text: o[1] })); }); };
        fcol.addEventListener('change', syncOps); syncOps();
        var addF = el('button', { type: 'button', class: 'secondary', text: 'Add filter', onclick: function () {
          var f = { col: fcol.value, op: fop.value };
          if (f.op === 'anyOf') f.values = fval.value.split(',').map(function (x) { return x.trim(); }); else f.value = fval.value.trim();
          st.filters.push(f); fval.value = ''; st.page = 1; reload(); } });
        pane.appendChild(el('div', { class: 'toolbar' }, search, fcol, fop, fval, addF));
        pane.appendChild(chips);
        // columns + pivot + export + save
        var colBox = el('details', { class: 'idcols' }, el('summary', { text: 'Columns' }));
        var colList = el('div', { class: 'idcol-list' });
        allCols.forEach(function (c) { var cb = el('input', { type: 'checkbox' }); cb.checked = st.columns.indexOf(c) >= 0; cb.addEventListener('change', function () { if (cb.checked) st.columns.push(c); else st.columns = st.columns.filter(function (x) { return x !== c; }); drawGrid(); }); colList.appendChild(el('label', null, cb, ' ' + c)); });
        colBox.appendChild(colList);
        var pr = el('select', { 'aria-label': 'Pivot rows' }, [el('option', { value: '', text: 'Pivot: rows by ...' })].concat(allCols.map(function (c) { return el('option', { value: c, text: c }); })));
        var pc = el('select', { 'aria-label': 'Pivot columns' }, [el('option', { value: '', text: '... and columns by (optional)' })].concat(allCols.map(function (c) { return el('option', { value: c, text: c }); })));
        if (st.pivot) { pr.value = st.pivot.rows || ''; pc.value = st.pivot.columns || ''; }
        var pivotOn = function () { st.pivot = pr.value ? { rows: pr.value, columns: pc.value || null } : null; reload(); };
        pr.addEventListener('change', pivotOn); pc.addEventListener('change', pivotOn);
        var qsNow = function (extra) { return qs(Object.assign({ view: v.name, q: st.q, filters: st.filters.length ? JSON.stringify(st.filters) : '', sort: st.sort || '', dir: st.dir }, extra || {})); };
        var exp = function (fmt) { return el('a', { href: '#', text: fmt === 'xlsx' ? 'Excel' : 'CSV', onclick: function (ev) { ev.preventDefault(); window.location.href = '/api/identity/export?' + qsNow({ format: fmt, columns: st.columns.join(',') }); } }); };
        var layoutOf = function () { return { v: 1, base: v.name, columns: st.columns, hidden: [], sort: st.sort ? { col: st.sort, dir: st.dir } : null, search: st.q, filters: st.filters, pageSize: st.pageSize, pivot: st.pivot }; };
        var saveAs = function (row) {
          var nm = el('input', { type: 'text', maxlength: 100, 'aria-label': 'View name', placeholder: 'e.g. Admins in Sales without a passkey' }); nm.value = row ? row.Name : '';
          var sh = el('input', { type: 'checkbox' }); sh.checked = !!(row && row.Shared); var df = el('input', { type: 'checkbox' }); df.checked = !!(row && row.IsDefault);
          var box = el('div', { class: 'editor' }, el('div', { class: 'form' }, el('label', null, 'Name ', nm), superAdmin ? el('label', null, sh, ' shared with everyone') : null, superAdmin ? el('label', null, df, ' the default view') : null),
            el('div', { class: 'dlg-buttons' }, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: function () { box.remove(); } }),
              el('button', { type: 'button', text: 'Save', onclick: function () {
                api('PUT', '/api/identity/saved/' + (row ? row.ViewId : newUuid()), { name: nm.value, shared: sh.checked, isDefault: df.checked, definition: layoutOf() })
                  .then(function (r) { status(r.text); render(); }).catch(function (e) { status('Refused: ' + e.message); }); } })));
          tools.parentNode.insertBefore(box, tools.nextSibling); nm.focus();
        };
        var tools = el('div', { class: 'toolbar' }, colBox, pr, pc, el('span', { class: 'count', text: 'Export:' }), exp('csv'), exp('xlsx'),
          el('button', { type: 'button', class: 'secondary', text: savedRow ? 'Save as new view' : 'Save as view', onclick: function () { saveAs(null); } }),
          savedRow && (savedRow.Mine || superAdmin) ? el('button', { type: 'button', class: 'secondary', text: 'Save changes', onclick: function () { saveAs(savedRow); } }) : null,
          savedRow && ((!savedRow.Shared && savedRow.Mine) || superAdmin) ? el('button', { type: 'button', class: 'link', text: 'Delete view', onclick: function () { api('DELETE', '/api/identity/saved/' + savedRow.ViewId, {}).then(function (r) { status(r.text); render(); }).catch(function (e) { status('Refused: ' + e.message); }); } }) : null);
        pane.appendChild(tools);
        var pivotHost = el('div'), gridHost = el('div');
        pane.appendChild(pivotHost); pane.appendChild(gridHost);
        var last = null;
        function drawChips() {
          clear(chips);
          st.filters.forEach(function (f, i) {
            var lab = ID_OPS.filter(function (o) { return o[0] === f.op; })[0];
            chips.appendChild(el('span', { class: 'rx-chip' }, el('code', { text: f.col }), ' ' + (lab ? lab[1] : f.op) + ' ' + (f.op === 'anyOf' ? (f.values || []).join(', ') : (f.value === '' ? '(empty)' : f.value)) + ' ',
              el('button', { type: 'button', class: 'link', 'aria-label': 'Remove filter', text: '×', onclick: function () { st.filters.splice(i, 1); st.page = 1; reload(); } })));
          });
          if (st.filters.length) chips.appendChild(el('button', { type: 'button', class: 'link', text: 'Clear filters', onclick: function () { st.filters = []; st.page = 1; reload(); } }));
        }
        function drawGrid() {
          if (!last) return;
          var cols = st.columns.map(function (c) { var t = types[c]; return { key: c, label: c, type: t === 'number' ? 'num' : (t === 'date' ? 'date' : null) }; });
          var t = el('table', { class: 'grid' }), hr = el('tr'), tb = el('tbody');
          var selIds = function () { return Object.keys(st.sel).filter(function (k) { return st.sel[k]; }); };
          if (canAct) {
            var all = el('input', { type: 'checkbox', 'aria-label': 'Select every user on this page' });
            all.checked = last.rows.length > 0 && last.rows.every(function (r) { return st.sel[r.Id]; });
            all.addEventListener('change', function () { last.rows.forEach(function (r) { st.sel[r.Id] = all.checked; }); drawGrid(); });
            hr.appendChild(el('th', { class: 'sel' }, all));
          }
          cols.forEach(function (c) {
            var th = el('th', { class: c.type === 'num' ? 'num' : null, scope: 'col', text: c.label + (st.sort === c.key ? (st.dir > 0 ? ' ▲' : ' ▼') : '') });
            th.addEventListener('click', function () { if (st.sort === c.key) st.dir = -st.dir; else { st.sort = c.key; st.dir = 1; } st.page = 1; reload(); });
            hr.appendChild(th);
          });
          last.rows.forEach(function (r) {
            var tr = el('tr');
            if (canAct) { var cb = el('input', { type: 'checkbox', 'aria-label': 'Select ' + (r.UserPrincipalName || r.DisplayName || r.Id) }); cb.checked = !!st.sel[r.Id]; cb.addEventListener('change', function () { st.sel[r.Id] = cb.checked; drawGrid(); }); tr.appendChild(el('td', { class: 'sel' }, cb)); }
            cols.forEach(function (c) {
              var val = r[c.key], td = el('td', { class: c.type === 'num' ? 'num' : '' });
              if (c.type === 'date') td.appendChild(timeEl(val)); else if (c.type === 'num') td.textContent = fmtNum(val);
              else if (val === true || val === false) { td.textContent = val ? 'yes' : 'no'; if (!val) td.className = 'smeta'; }
              else td.textContent = val === null || val === undefined ? '' : String(val);
              tr.appendChild(td);
            });
            tb.appendChild(tr);
          });
          t.appendChild(el('thead', null, hr)); t.appendChild(tb);
          var from = (st.page - 1) * st.pageSize + 1, to = from + last.rows.length - 1;
          var prevB = el('button', { type: 'button', class: 'secondary', text: 'Previous', disabled: st.page <= 1, onclick: function () { st.page--; reload(); } });
          var nextB = el('button', { type: 'button', class: 'secondary', text: 'Next', disabled: to >= last.total, onclick: function () { st.page++; reload(); } });
          var size = el('select', { 'aria-label': 'Rows per page' }, [25, 50, 100, 200].map(function (n) { return el('option', { value: n, text: n + ' per page' }); })); size.value = String(st.pageSize);
          size.addEventListener('change', function () { st.pageSize = Number(size.value); st.page = 1; reload(); });
          clear(gridHost).appendChild(el('div', { class: 'toolbar' }, el('span', { class: 'count', text: last.total ? fmtNum(from) + '-' + fmtNum(to) + ' of ' + fmtNum(last.total) : '0 rows - nothing open here' }), size));
          if (canAct && last.total) {
            var n = selIds().length;
            gridHost.appendChild(el('div', { class: 'toolbar' },
              el('span', { class: 'count', text: n ? n + ' selected' : 'Tick users to set an action, or:' }),
              n ? el('button', { type: 'button', text: 'Set action on ' + n + '...', onclick: function () { idActionDialog(j.actionLists || {}, n + ' user(s)', { ids: selIds() }); } }) : null,
              el('button', { type: 'button', class: 'secondary', text: 'Set action on all ' + fmtNum(last.total) + ' shown by this view...', disabled: last.total > 5000, title: last.total > 5000 ? 'at most 5,000 - narrow the filter' : 'every user that matches the view, its filters and the search', onclick: function () { idActionDialog(j.actionLists || {}, 'all ' + fmtNum(last.total) + ' user(s) of this view', { selection: { view: v.name, filters: st.filters, q: st.q } }); } }),
              n ? el('button', { type: 'button', class: 'link', text: 'Clear selection', onclick: function () { st.sel = {}; drawGrid(); } }) : null));
          }
          gridHost.appendChild(el('div', { class: 'twrap' }, t));
          gridHost.appendChild(el('div', { class: 'pager' }, prevB, nextB));
        }
        function reload() {
          drawChips();
          if (st.pivot) {
            api('GET', '/api/identity/pivot?' + qsNow({ rows: st.pivot.rows, cols: st.pivot.columns || '' })).then(function (pv) {
              clear(pivotHost).appendChild(el('h4', { text: 'Pivot: ' + pv.rowKey + (pv.columnKey ? ' by ' + pv.columnKey : '') + (pv.truncated ? ' (first 5,000 cells)' : '') }));
              pivotHost.appendChild(pivotTable(pv, function (rv, cv) { st.filters = st.filters.concat(cellFilters(pv.rowKey, pv.columnKey, rv, cv)); st.page = 1; reload(); }));
            }).catch(function (e) { clear(pivotHost).appendChild(el('div', { class: 'empty', text: e.message })); });
          } else clear(pivotHost);
          api('GET', '/api/identity/rows?' + qsNow({ page: st.page, pageSize: st.pageSize })).then(function (r) { last = r; drawGrid(); })
            .catch(function (e) { clear(gridHost).appendChild(el('div', { class: 'empty', text: e.message })); });
        }
        reload();
      }
      // open: the hash's view, else the shared default view, else the first open High gap, else all users
      var a = arg || '', def = shared.filter(function (s) { return s.IsDefault; })[0];
      var firstHigh = views.filter(function (v) { return v.severity === 'High' && v.count > 0; })[0];
      var start = a && byName[a] ? 'view:' + a : (a.indexOf('saved:') === 0 ? a : (def ? 'saved:' + def.ViewId : 'view:' + (firstHigh ? firstHigh.name : 'Users_ALL')));
      var btn = nav.querySelector('[data-key="' + start + '"]') || nav.querySelector('[data-key="view:Users_ALL"]');
      if (btn) btn.click();
    });
  }

  // ---- Conditional Access (DESIGN §5.1): the engine's last read of the tenant's policies, each compared with its
  // template. Adopt and Release only RECORD what the operator decided (owner 2026-10-30: "dont touch any ca policy stuff
  // ... otherwise i can be locked out of my tenant"). The one change in the tenant is a SuperAdmin's stage move
  // (CA-LIFECYCLE, owner 2026-11-03: "Write on approval"), applied by the engine after he saw it.
  var CAP_BG_CLS = { MISSING: 'c-danger', unknown: 'smeta' };
  function capSubnav(p, on) {
    var seg = el('div', { class: 'rx-seg' });
    [['', 'Policies'], ['groups', 'Groups'], ['doc', 'Documentation'], ['templates', 'Templates'], ['updates', 'Template updates']].forEach(function (x) {
      seg.appendChild(el('button', { type: 'button', class: on === x[0] ? 'on' : null, text: x[1], onclick: function () { location.hash = '#capolicies' + (x[0] ? '/' + x[0] : ''); } }));
    });
    p.appendChild(seg);
  }
  function capReadButton() {
    return el('button', { type: 'button', class: 'secondary', text: 'Read the policy list', onclick: function () { withReason('Read the Conditional Access policies again', 'Read only: the engine reads every policy and compares it with its template. Nothing in the tenant is changed.', function (reason) { return api('POST', '/api/ca/analyze', { listOnly: true, reason: reason }); }); } });
  }
  function capAdopt(r) {
    withReason('Adopt ' + r.DisplayName, 'Entra Policy Suite RECORDS that you adopt this policy as it is now: its body becomes the baseline the monitor compares with. Nothing in the tenant changes - not now, not later.', function (reason) {
      return api('POST', '/api/capolicies/policies/' + encodeURIComponent(r.PolicyId) + '/adopt', { expected: r.Hash, reason: reason }); });
  }
  function capRelease(r) {
    withReason('Release ' + r.DisplayName, 'Entra Policy Suite stops managing this policy (the record says so, its findings are cleared). Nothing in the tenant changes.', function (reason) {
      return api('POST', '/api/capolicies/policies/' + encodeURIComponent(r.PolicyId) + '/release', { reason: reason }); });
  }
  // CA-LIFECYCLE (owner 2026-11-03: "in ca policy i need buttons to easily controll and movevto another lufecycle phase
  // like pilot1, pilot2"; "Write on approval", "SuperAdmin only"): ONE adopted policy moves to ANY stage (owner 2026-11-03). The dialog shows
  // what changes (from the last read); the engine reads the policy again, refuses when it changed since or when the
  // break-glass accounts would not stay excluded, makes the one change and reads it back.
  var CAP_STAGES = ['Initial', 'Pilot1', 'Pilot2', 'Pilot3', 'Prod'];
  var CAP_STAGE_TEXT = { Initial: 'off', Pilot1: 'report-only, pilot group', Pilot2: 'on, pilot group', Pilot3: 'on, wider pilot', Prod: 'on, its targets' };
  function capMoves(stage) {
    // owner 2026-11-03: "the move should allow me to move to any lifecycle phase" / "not just one back"
    var i = CAP_STAGES.indexOf(stage), m = [];
    if (i >= 0) CAP_STAGES.forEach(function (s) { if (s !== 'Initial' && s !== stage) m.push(s); });
    if (stage && stage !== 'Initial') m.push('Disabled');
    return m;
  }
  function capMoveLabel(from, to) {
    if (to === 'Disabled') return 'Disable';
    return CAP_STAGES.indexOf(to) < CAP_STAGES.indexOf(from) ? 'Back to ' + to : 'Move to ' + to;
  }
  function capStage(r, to) {
    var d = el('dialog', { class: 'dlg-wide', 'aria-label': 'Move ' + r.DisplayName });
    var closed = false;
    var close = function () { if (closed) return; closed = true; try { d.close(); } catch (e) { /* already closed */ } if (d.parentNode) d.parentNode.removeChild(d); };
    d.addEventListener('close', close);
    var body = el('div', null, el('p', { class: 'smeta', text: 'Working out what changes ...' }));
    d.appendChild(el('h3', { text: capMoveLabel(r.Stage, to) + ': ' + r.DisplayName }));
    d.appendChild(body);
    document.body.appendChild(d); d.showModal();
    api('GET', '/api/capolicies/policies/' + encodeURIComponent(r.PolicyId) + '/stage-plan?' + qs({ to: to })).then(function (pl) {
      clear(body);
      body.appendChild(el('div', { class: 'guide', text: 'This CHANGES the policy in your tenant: ' + textOf(pl.from) + ' -> ' + (to === 'Disabled' ? 'off' : to) + '. The engine applies it at its next check (within 5 minutes): it reads the policy again first and refuses if it changed since this view, or if the break-glass accounts would not stay excluded. Nothing else in the policy changes.' }));
      if (!pl.ok) {
        body.appendChild(el('p', { class: 'c-danger', text: 'Cannot move: ' + textOf(pl.reason) }));
        body.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', class: 'secondary', text: 'Close', onclick: close })));
        return;
      }
      body.appendChild(table(pl.changes || [], [{ key: 'field', label: 'Setting', type: 'cat' }, { key: 'before', label: 'Now', wrap: true }, { key: 'after', label: 'After the move', wrap: true }]));
      var bg = pl.breakGlass || {};
      body.appendChild(el('p', { class: bg.ok === false ? 'c-danger' : null, text: 'Break-glass: ' + textOf(bg.text) + (to === 'Disabled' ? '' : ' (checked again on the result before the change)') }));
      if ((pl.notes || []).length) body.appendChild(el('ul', { class: 'hints' }, pl.notes.map(function (n) { return el('li', { text: n }); })));
      var enforce = to === 'Pilot2' || to === 'Pilot3' || to === 'Prod';
      var ack = el('input', { type: 'checkbox' });
      var reason = el('input', { type: 'text', placeholder: 'Reason (optional) - e.g. pilot ran 2 weeks, no blocked sign-ins', style: 'width:100%' });
      var go = el('button', { type: 'button', text: capMoveLabel(pl.from, to) });
      go.disabled = enforce;
      ack.addEventListener('change', function () { go.disabled = enforce && !ack.checked; });
      go.addEventListener('click', function () {
        go.disabled = true; close();
        var title = capMoveLabel(pl.from, to) + ': ' + r.DisplayName;
        notice('Sending: ' + title + ' ...');
        api('POST', '/api/capolicies/policies/' + encodeURIComponent(r.PolicyId) + '/stage', { to: to, expected: pl.expected, reason: reason.value.trim() })
          .then(function (x) { afterAction(x, title); }).catch(function (e) { notice('Refused: ' + e.message, 'warn'); });
      });
      if (enforce) body.appendChild(el('label', null, ack, ' I have checked who this ENFORCES the policy for (the CA Policy Analyzer shows the sign-ins it would have blocked).'));
      body.appendChild(el('p', null, reason));
      body.appendChild(el('div', { class: 'toolbar' }, go, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: close })));
    }).catch(function (e) { clear(body).appendChild(el('p', { class: 'c-danger', text: e.message })); body.appendChild(el('button', { type: 'button', class: 'secondary', text: 'Close', onclick: close })); });
  }
  function capStageBar(r) {
    // the stages as a strip (the current one marked) and a button per move from here
    var strip = el('div', { class: 'rx-seg' });
    CAP_STAGES.forEach(function (s) { strip.appendChild(el('button', { type: 'button', class: s === r.Stage ? 'on' : null, disabled: true, title: CAP_STAGE_TEXT[s], text: s })); });
    var bar = el('div', { class: 'toolbar' }, strip);
    capMoves(r.Stage).forEach(function (to) { bar.appendChild(el('button', { type: 'button', class: to === 'Disabled' ? 'secondary' : null, text: capMoveLabel(r.Stage, to), onclick: function () { capStage(r, to); } })); });
    if (!capMoves(r.Stage).length) bar.appendChild(el('span', { class: 'count', text: r.Stage === 'Custom' ? 'Not one of the template\'s stages: look at it in the tenant first (Disable is the only move).' : '' }));
    return bar;
  }
  // CA-EDIT (owner 2026-11-05: "where is the option to modify or/and clone a policy" -> "Edit + clone, any field"; "again
  // once a policy is imported into from the templates, then it should be fuly manageable in the gui"; "but it is always
  // 100% opeator controlled"): a wide form with every part of the policy and an Advanced (JSON) box. Check shows what
  // changes (from the last read, nothing written); Apply sends the operator's request - the engine reads the policy
  // again, refuses when it changed since or when the break-glass accounts would not stay excluded, writes once and reads
  // it back. A copy is always created OFF and adopted.
  var CAP_EDIT_LISTS = [
    ['Users', [['conditions.users.includeUsers', 'includeUsers', 'Include users', 'a UPN, an id, or All / None / GuestsOrExternalUsers'], ['conditions.users.excludeUsers', 'excludeUsers', 'Exclude users', 'a UPN or an id'],
      ['conditions.users.includeGroups', 'includeGroups', 'Include groups', 'a group\'s name or id'], ['conditions.users.excludeGroups', 'excludeGroups', 'Exclude groups', 'a group\'s name or id'],
      ['conditions.users.includeRoles', 'includeRoles', 'Include roles', 'a directory role\'s name or id'], ['conditions.users.excludeRoles', 'excludeRoles', 'Exclude roles', 'a directory role\'s name or id']]],
    ['Applications', [['conditions.applications.includeApplications', 'includeApplications', 'Include applications', 'an application id, or All / Office365 / MicrosoftAdminPortals / None'], ['conditions.applications.excludeApplications', 'excludeApplications', 'Exclude applications', 'an application id'],
      ['conditions.applications.includeUserActions', 'includeUserActions', 'User actions', 'urn:user:registersecurityinfo / urn:user:registerdevice']]],
    ['Conditions', [['conditions.clientAppTypes', 'clientAppTypes', 'Client apps', 'all, browser, mobileAppsAndDesktopClients, exchangeActiveSync, other'],
      ['conditions.platforms.includePlatforms', 'includePlatforms', 'Include platforms', 'all, android, iOS, windows, macOS, linux'], ['conditions.platforms.excludePlatforms', 'excludePlatforms', 'Exclude platforms', 'android, iOS, windows, macOS, linux'],
      ['conditions.locations.includeLocations', 'includeLocations', 'Include locations', 'a named location\'s name or id, or All / AllTrusted'], ['conditions.locations.excludeLocations', 'excludeLocations', 'Exclude locations', 'a named location\'s name or id, or AllTrusted'],
      ['conditions.signInRiskLevels', 'signInRiskLevels', 'Sign-in risk', 'low, medium, high, none'], ['conditions.userRiskLevels', 'userRiskLevels', 'User risk', 'low, medium, high, none']]],
    ['Grant', [['grantControls.builtInControls', 'builtInControls', 'Grant controls', 'block, mfa, compliantDevice, domainJoinedDevice, approvedApplication, compliantApplication, passwordChange']]]];
  function capGet(o, path) { return path.split('.').reduce(function (a, k) { return a === null || a === undefined ? undefined : a[k]; }, o); }
  function capSet(o, path, v) { var ks = path.split('.'), a = o; for (var i = 0; i < ks.length - 1; i++) { if (a[ks[i]] === null || a[ks[i]] === undefined || typeof a[ks[i]] !== 'object') a[ks[i]] = {}; a = a[ks[i]]; } a[ks[ks.length - 1]] = v; }
  function capEditable(body) {
    var o = {}; ['displayName', 'state', 'conditions', 'grantControls', 'sessionControls'].forEach(function (k) { o[k] = body && body[k] !== undefined ? JSON.parse(JSON.stringify(body[k])) : null; });
    if (o.grantControls && o.grantControls.authenticationStrength) o.grantControls.authenticationStrength = o.grantControls.authenticationStrength.id ? { id: o.grantControls.authenticationStrength.id } : null;
    return o;
  }
  function caPolicyEditor(j, mode) {
    // mode: 'Edit' or 'Clone'. j = the policy page's answer (body, names, review)
    var pol = j.policy, names = j.names || {}, base = capEditable(j.body || {});
    if (mode === 'Clone') base.displayName = 'Copy of ' + textOf(pol.DisplayName);
    var title = (mode === 'Clone' ? 'Clone ' : 'Edit ') + pol.DisplayName;
    var d = el('dialog', { class: 'dlg-wide', 'aria-label': title });
    var closed = false;
    var close = function () { if (closed) return; closed = true; try { d.close(); } catch (e) { /* already closed */ } if (d.parentNode) d.parentNode.removeChild(d); };
    d.addEventListener('close', close);
    d.appendChild(el('h3', { text: title }));
    d.appendChild(el('div', { class: 'guide', text: mode === 'Clone'
      ? 'A NEW policy, copied from this one with your changes. It is created OFF whatever this one\'s state is, and adopted - move it through the stages when it is ready. Lists: one per line; a name (group, UPN, role, named location) is looked up by the engine.'
      : 'Change any part of this policy. Check shows what changes before anything is sent; Apply CHANGES the policy in your tenant (the engine reads it again first and refuses if it changed since, or if the break-glass accounts would not stay excluded). Lists: one per line; a name (group, UPN, role, named location) is looked up by the engine.' }));
    var form = el('div', { class: 'rf-grid' });
    var row = function (label, node) { form.appendChild(el('div', { class: 'rf-l', text: label })); form.appendChild(el('div', { class: 'rf-c' }, node)); return node; };
    var name = row('Name', el('input', { type: 'text', 'aria-label': 'Name', maxlength: 256 })); name.value = textOf(base.displayName);
    var state = row('State', el('select', { 'aria-label': 'State' }, [['enabled', 'On'], ['enabledForReportingButNotEnforced', 'Report-only'], ['disabled', 'Off']].map(function (s) { return el('option', { value: s[0], text: s[1] }); })));
    state.value = mode === 'Clone' ? 'disabled' : textOf(base.state); if (mode === 'Clone') state.disabled = true;
    var lists = {};
    var shown = function (v) { var n = names[v]; return n ? n : v; };
    CAP_EDIT_LISTS.forEach(function (grp) {
      form.appendChild(el('h4', { class: 'rf-sub', text: grp[0], style: 'grid-column:1 / -1' }));
      grp[1].forEach(function (f) {
        var vals = capGet(base, f[0]) || [];
        var isApp = f[1] === 'includeApplications' || f[1] === 'excludeApplications';
        var ta = row(f[2], el('textarea', { rows: Math.min(6, Math.max(2, vals.length + 1)), 'aria-label': f[2], 'data-field': f[1], placeholder: 'one per line: ' + f[3] }));
        // an application stays its id (its name follows after #, for reading); the others show the name the engine knows
        ta.value = vals.map(function (v) { return isApp ? (names[v] ? v + ' # ' + names[v] : v) : shown(v); }).join('\n');
        lists[f[0]] = ta;
      });
    });
    var op = row('Grant: require', el('select', { 'aria-label': 'Grant operator' }, el('option', { value: 'OR', text: 'one of the controls (OR)' }), el('option', { value: 'AND', text: 'all the controls (AND)' })));
    op.value = textOf(capGet(base, 'grantControls.operator')) || 'OR';
    var as = row('Authentication strength', el('input', { type: 'text', 'aria-label': 'authenticationStrength', 'data-field': 'authenticationStrength', placeholder: 'its id (empty = none)' }));
    as.value = textOf(capGet(base, 'grantControls.authenticationStrength.id'));
    form.appendChild(el('h4', { class: 'rf-sub', text: 'Session', style: 'grid-column:1 / -1' }));
    var sif = capGet(base, 'sessionControls.signInFrequency') || {};
    var sifOn = el('input', { type: 'checkbox', 'aria-label': 'signInFrequency' }); sifOn.checked = !!sif.isEnabled;
    var sifVal = el('input', { type: 'text', 'aria-label': 'Sign-in frequency value', inputmode: 'numeric', style: 'width:6em' }); sifVal.value = textOf(sif.value);
    var sifType = el('select', { 'aria-label': 'Sign-in frequency unit' }, el('option', { value: 'hours', text: 'hours' }), el('option', { value: 'days', text: 'days' })); sifType.value = sif.type || 'hours';
    var sifEvery = el('input', { type: 'checkbox', 'aria-label': 'Every time' }); sifEvery.checked = sif.frequencyInterval === 'everyTime';
    row('Sign-in frequency', el('span', { class: 'rf-check' }, sifOn, ' on, every ', sifVal, ' ', sifType, ' ', el('label', { class: 'rf-check' }, sifEvery, ' or every time')));
    var pb = capGet(base, 'sessionControls.persistentBrowser') || {};
    var pbOn = el('input', { type: 'checkbox', 'aria-label': 'persistentBrowser' }); pbOn.checked = !!pb.isEnabled;
    var pbMode = el('select', { 'aria-label': 'Persistent browser mode' }, el('option', { value: 'never', text: 'never persistent' }), el('option', { value: 'always', text: 'always persistent' })); pbMode.value = pb.mode || 'never';
    row('Persistent browser', el('span', { class: 'rf-check' }, pbOn, ' on: ', pbMode));
    d.appendChild(form);
    // the form -> the policy body (the parts it does not show stay as they are in the base)
    var lines = function (ta) { return ta.value.split('\n').map(function (x) { return x.replace(/\s+#.*$/, '').trim(); }).filter(function (x) { return x; }); };
    var fromForm = function () {
      var b = JSON.parse(JSON.stringify(base));
      b.displayName = name.value.trim(); b.state = mode === 'Clone' ? 'disabled' : state.value;
      if (!b.conditions) b.conditions = {};
      Object.keys(lists).forEach(function (path) {
        var v = lines(lists[path]), had = capGet(base, path);
        if (v.length || (had !== null && had !== undefined)) capSet(b, path, v);
      });
      ['platforms', 'locations'].forEach(function (k) { var c = b.conditions[k]; if (c && !Object.keys(c).some(function (x) { return Array.isArray(c[x]) ? c[x].length : c[x] !== null && c[x] !== undefined; })) b.conditions[k] = null; });
      var bic = capGet(b, 'grantControls.builtInControls') || [], asId = as.value.trim(), tou = capGet(b, 'grantControls.termsOfUse') || [];
      if (!bic.length && !asId && !tou.length) b.grantControls = null;
      else { if (!b.grantControls) b.grantControls = {}; b.grantControls.operator = op.value; b.grantControls.builtInControls = bic; b.grantControls.authenticationStrength = asId ? { id: asId } : null; }
      var sc = b.sessionControls ? b.sessionControls : {};
      sc.signInFrequency = sifOn.checked ? (sifEvery.checked ? { isEnabled: true, frequencyInterval: 'everyTime', authenticationType: (sif.authenticationType || 'primaryAndSecondaryAuthentication') } : { isEnabled: true, value: parseInt(sifVal.value, 10) || 1, type: sifType.value, frequencyInterval: 'timeBased', authenticationType: (sif.authenticationType || 'primaryAndSecondaryAuthentication') }) : null;
      sc.persistentBrowser = pbOn.checked ? { isEnabled: true, mode: pbMode.value } : null;
      b.sessionControls = Object.keys(sc).some(function (k) { return sc[k] !== null && sc[k] !== undefined && sc[k] !== false; }) ? sc : null;
      return b;
    };
    // Advanced (JSON): the whole body as it will be sent - for any part the form does not show
    var adv = el('textarea', { rows: 14, 'aria-label': 'Advanced (JSON)', style: 'width:100%;font-family:ui-monospace,Consolas,monospace;font-size:11.5px' });
    var useAdv = el('input', { type: 'checkbox', 'aria-label': 'Send the JSON instead of the form' });
    var advBox = el('details', null, el('summary', { text: 'Advanced (JSON) - every part, for what the form does not show' }),
      el('p', { class: 'smeta', text: 'The policy as it will be sent: displayName, state, conditions, grantControls, sessionControls. Ids, times and other read-only parts are refused.' }),
      el('div', { class: 'toolbar' }, el('button', { type: 'button', class: 'secondary', text: 'Fill from the form', onclick: function () { adv.value = JSON.stringify(fromForm(), null, 2); } }),
        el('label', { class: 'rf-check' }, useAdv, ' send this JSON instead of the form')), adv);
    adv.value = JSON.stringify(base, null, 2);
    d.appendChild(advBox);
    var out = el('div');
    d.appendChild(out);
    var pending = null;
    var check = el('button', { type: 'button', text: 'Check' });
    var buttons = el('div', { class: 'toolbar' }, check, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: close }));
    d.appendChild(buttons);
    check.addEventListener('click', function () {
      var b;
      if (useAdv.checked) { try { b = JSON.parse(adv.value); } catch (e) { clear(out).appendChild(el('p', { class: 'c-danger', text: 'The JSON does not parse: ' + e.message })); return; } }
      else b = fromForm();
      pending = b; clear(out).appendChild(el('p', { class: 'smeta', text: 'Checking ...' }));
      api('POST', '/api/capolicies/policies/' + encodeURIComponent(pol.PolicyId) + '/edit-plan', { mode: mode, policy: b }).then(function (pl) {
        clear(out);
        if (!pl.ok) { out.appendChild(el('p', { class: 'c-danger', text: 'Cannot ' + (mode === 'Clone' ? 'copy' : 'change') + ': ' + textOf(pl.reason) })); return; }
        out.appendChild(el('h4', { text: mode === 'Clone' ? 'The copy differs from this policy in' : 'What changes' }));
        out.appendChild(table(pl.changes || [], [{ key: 'path', label: 'Setting', type: 'cat' }, { key: 'before', label: mode === 'Clone' ? 'This policy' : 'Now', wrap: true }, { key: 'after', label: mode === 'Clone' ? 'The copy' : 'After', wrap: true }], { empty: 'Only the name and the state.' }));
        var bg = pl.breakGlass || {};
        out.appendChild(el('p', { class: bg.ok === false ? 'c-danger' : null, text: 'Break-glass: ' + textOf(bg.text) + ' (checked again on the result before the change)' }));
        if ((pl.unresolved || []).length) out.appendChild(el('ul', { class: 'hints' }, pl.unresolved.map(function (n) { return el('li', { text: 'looked up by the engine when it applies: ' + n }); })));
        var reason = el('input', { type: 'text', placeholder: 'Reason (optional) - why this change', style: 'width:100%' });
        var ack = el('input', { type: 'checkbox' });
        var on = mode === 'Edit' && pl.stateAfter !== 'disabled';
        var go = el('button', { type: 'button', text: mode === 'Clone' ? 'Create the copy (off)' : 'Apply the change' });
        go.disabled = on;
        ack.addEventListener('change', function () { go.disabled = on && !ack.checked; });
        go.addEventListener('click', function () {
          go.disabled = true; close();
          var t = (mode === 'Clone' ? 'Clone ' : 'Edit ') + pol.DisplayName;
          notice('Sending: ' + t + ' ...');
          var payload = { policy: pending, expected: pl.expected, reason: reason.value.trim() };
          (mode === 'Clone' ? api('POST', '/api/capolicies/policies/' + encodeURIComponent(pol.PolicyId) + '/clone', payload) : api('POST', '/api/capolicies/policies/' + encodeURIComponent(pol.PolicyId) + '/edit', payload))
            .then(function (x) { afterAction(x, t); }).catch(function (e) { notice('Refused: ' + e.message, 'warn'); });
        });
        if (on) out.appendChild(el('label', null, ack, ' I have checked who this policy is ON for after the change (the CA Policy Analyzer shows the sign-ins it would have blocked).'));
        out.appendChild(el('p', null, reason));
        out.appendChild(el('div', { class: 'toolbar' }, go));
      }).catch(function (e) { clear(out).appendChild(el('p', { class: 'c-danger', text: e.message })); });
    });
    document.body.appendChild(d); d.showModal();
  }
  // CA-TEMPLATES (owner 2026-11-05: Templates "Side-by-side only"; "fully manageable in the gui"; "always 100% operator
  // controlled"; V1-PARITY P5 / P6): deploy a template as a new policy, test a newer version NEXT TO the policy it
  // replaces, then promote it / roll it back / remove the old one. Each shows the plan (from the last read, nothing
  // written) before the SuperAdmin approves; the engine reads the tenant again before it writes.
  function capPlanDialog(o) {
    // o: { title; guide; stages ([value, label] or none); load(stage) -> plan; show(plan, box); go (the button);
    //      send(plan, reason, stage, typed) -> request; enforce(plan) -> a tick box first; confirmName(plan) -> a name to type }
    var d = el('dialog', { class: 'dlg-wide', 'aria-label': o.title });
    var closed = false;
    var close = function () { if (closed) return; closed = true; try { d.close(); } catch (e) { /* already closed */ } if (d.parentNode) d.parentNode.removeChild(d); };
    d.addEventListener('close', close);
    d.appendChild(el('h3', { text: o.title }));
    d.appendChild(el('div', { class: 'guide', text: o.guide }));
    var stageSel = null;
    if (o.stages) { stageSel = el('select', { 'aria-label': 'Start it as' }, o.stages.map(function (s) { return el('option', { value: s[0], text: s[1] }); })); d.appendChild(el('div', { class: 'toolbar' }, el('label', null, 'Start it as: ', stageSel))); }
    var body = el('div');
    d.appendChild(body);
    var load = function () {
      clear(body).appendChild(el('p', { class: 'smeta', text: 'Working out what it does ...' }));
      o.load(stageSel ? stageSel.value : null).then(function (pl) {
        clear(body);
        if (!pl.ok) { body.appendChild(el('p', { class: 'c-danger', text: 'Cannot: ' + textOf(pl.reason) })); body.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', class: 'secondary', text: 'Close', onclick: close }))); return; }
        o.show(pl, body);
        if ((pl.notes || []).length) body.appendChild(el('ul', { class: 'hints' }, pl.notes.map(function (n) { return el('li', { text: n }); })));
        var reason = el('input', { type: 'text', placeholder: 'Reason (optional)', style: 'width:100%' });
        var go = el('button', { type: 'button', text: o.go });
        var need = o.confirmName ? o.confirmName(pl) : null, typed = null, ack = null, enforce = o.enforce ? o.enforce(pl) : false;
        var upd = function () { go.disabled = !!((need && typed.value.trim() !== need) || (enforce && !ack.checked)); };
        if (need) { typed = el('input', { type: 'text', 'aria-label': 'Type the name to confirm', placeholder: need, style: 'width:100%' }); typed.addEventListener('input', upd); body.appendChild(el('p', null, 'Type ', el('b', { text: need }), ' to confirm: ', typed)); }
        if (enforce) { ack = el('input', { type: 'checkbox' }); ack.addEventListener('change', upd); body.appendChild(el('label', null, ack, ' I have checked who this ENFORCES the policy for (the CA Policy Analyzer shows the sign-ins it would have blocked).')); }
        upd();
        go.addEventListener('click', function () {
          go.disabled = true; close();
          notice('Sending: ' + o.title + ' ...');
          o.send(pl, reason.value.trim(), stageSel ? stageSel.value : null, typed ? typed.value.trim() : null).then(function (x) { afterAction(x, o.title); }).catch(function (e) { notice('Refused: ' + e.message, 'warn'); });
        });
        body.appendChild(el('p', null, reason));
        body.appendChild(el('div', { class: 'toolbar' }, go, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: close })));
      }).catch(function (e) { clear(body).appendChild(el('p', { class: 'c-danger', text: e.message })); });
    };
    if (stageSel) stageSel.addEventListener('change', load);
    document.body.appendChild(d); d.showModal();
    load();
  }
  function capDeployShow(pl, box) {
    box.appendChild(el('p', null, el('b', { text: pl.displayName }), ' - ' + (pl.state === 'disabled' ? 'off' : pl.state === 'enabledForReportingButNotEnforced' ? 'report-only for the pilot group' : textOf(pl.state)) + ' · ' + textOf(pl.templateId) + ' ' + textOf(pl.version)));
    box.appendChild(el('h4', { text: 'The groups it uses' }));
    box.appendChild(table(pl.groups || [], [{ key: 'name', label: 'Group' }, { key: 'use', label: 'Used to', type: 'cat' }, { key: 'inTenant', label: 'In the tenant', type: 'cat', cls: function (g) { return g.inTenant === 'missing' ? 'c-warning' : ''; } }], { empty: 'No group.' }));
    box.appendChild(el('h4', { text: 'The new policy' }));
    box.appendChild(table(pl.rows || [], [{ key: 'path', label: 'Setting', type: 'cat' }, { key: 'value', label: 'Value', wrap: true }], { empty: 'Nothing.' }));
    var bg = pl.breakGlass || {};
    box.appendChild(el('p', { class: bg.ok === false ? 'c-danger' : null, text: 'Break-glass: ' + textOf(bg.text) + ' (checked again by the engine on the result)' }));
  }
  function capDeploy(t) {
    capPlanDialog({ title: 'Deploy ' + t.id + ' ' + t.version + ' as a new policy',
      guide: 'Creates a NEW policy in your tenant from the template, as v1\'s Initial_Setup does: the groups it needs are created first when they are missing, then the policy - OFF, or report-only for the pilot group. It is adopted at once; move it through the stages from its page. The engine reads the tenant again first and refuses if the template is already there, a name or group cannot be found, or the break-glass accounts would not be excluded.',
      stages: [['Initial', 'Initial - off'], ['Pilot1', 'Pilot1 - report-only for the pilot group']],
      load: function (stage) { return api('GET', '/api/catemplates/' + encodeURIComponent(t.id) + '/deploy-plan?' + qs({ stage: stage })); },
      show: capDeployShow, go: 'Create the policy',
      send: function (pl, reason, stage) { return api('POST', '/api/catemplates/' + encodeURIComponent(t.id) + '/deploy', { stage: stage, reason: reason }); } });
  }
  function capNewVersion(j) {
    var pol = j.policy, vi = j.versionInfo || {};
    capPlanDialog({ title: 'Test ' + textOf(vi.library) + ' next to ' + pol.DisplayName,
      guide: 'Creates a SECOND policy from the newer template version (v1\'s Install_Latest_Policy_Disabled), named with its version. This policy (' + textOf(vi.current || 'its version') + ') is NOT touched. Compare the two; then Promote turns the new one on in Prod and this one off (kept), and Roll back undoes that.',
      stages: [['Pilot1', 'Pilot1 - report-only for the pilot group'], ['Initial', 'Initial - off']],
      load: function (stage) { return api('GET', '/api/capolicies/policies/' + encodeURIComponent(pol.PolicyId) + '/version-plan?' + qs({ action: 'test', stage: stage })); },
      show: capDeployShow, go: 'Create the test policy',
      send: function (pl, reason, stage) { return api('POST', '/api/capolicies/policies/' + encodeURIComponent(pol.PolicyId) + '/newversion', { stage: stage, expected: pl.expected, reason: reason }); } });
  }
  function capPairShow(pl, box) {
    box.appendChild(table(pl.changes || [], [{ key: 'policy', label: 'Policy', type: 'cat' }, { key: 'field', label: 'Setting', type: 'cat' }, { key: 'before', label: 'Now', wrap: true }, { key: 'after', label: 'After', wrap: true }], { empty: 'Nothing changes.' }));
  }
  var CAP_PAIR = {
    promote: ['Promote', 'promote', 'The new version is turned ON in Prod first, then the old one OFF - it is kept, so Roll back can put it back as it is now. Both CHANGE in your tenant; the engine reads both again first and refuses if one changed since this view, or if the break-glass accounts would not stay excluded.'],
    rollback: ['Roll back', 'rollback', 'The old version is turned back on as it was before the promote first, then the new one OFF (kept - promote it again when it is ready). Both CHANGE in your tenant; the engine reads both again first.'],
    removeold: ['Remove the old version', 'remove', 'DELETES the old version from your tenant. It must be off (after a promote). This cannot be rolled back from here: type its name to confirm.'] };
  function capPair(j, what) {
    var pol = j.policy, x = CAP_PAIR[what];
    capPlanDialog({ title: x[0] + ': ' + j.pair.TemplateId + ' ' + textOf(j.pair.OldVersion) + ' / ' + textOf(j.pair.NewVersion), guide: x[2],
      load: function () { return api('GET', '/api/capolicies/policies/' + encodeURIComponent(pol.PolicyId) + '/version-plan?' + qs({ action: x[1] })); },
      show: capPairShow, go: x[0],
      enforce: function () { return what === 'promote'; },
      confirmName: what === 'removeold' ? function (pl) { return pl.old ? pl.old.displayNameBefore : ''; } : null,
      send: function (pl, reason, stage, typed) {
        var b = { expectedOld: pl.expectedOld, expectedNew: pl.expectedNew, reason: reason };
        if (what === 'removeold') return api('POST', '/api/capolicies/policies/' + encodeURIComponent(pol.PolicyId) + '/removeold', { confirm: typed, expectedOld: pl.expectedOld, reason: reason });
        if (what === 'promote') return api('POST', '/api/capolicies/policies/' + encodeURIComponent(pol.PolicyId) + '/promote', b);
        return api('POST', '/api/capolicies/policies/' + encodeURIComponent(pol.PolicyId) + '/rollback', b); } });
  }
  function capVersionSection(p, j) {
    // the version pair this policy is in, and its buttons (SuperAdmin); or a newer version of its template to test
    var pr = j.pair, vi = j.versionInfo || {}, owner = isRole('SuperAdmin');
    p.appendChild(el('h3', { text: 'Template version' }));
    if (pr && pr.Status !== 'Removed') {
      var isNew = String(pr.NewPolicyId).toLowerCase() === String(j.policy.PolicyId).toLowerCase();
      var other = isNew ? pr.OldPolicyId : pr.NewPolicyId;
      var what = { Testing: 'the new version is under test next to the old one', Promoted: 'the new version is promoted; the old one is off and kept', RolledBack: 'rolled back: the old version is on, the new one off' }[pr.Status] || pr.Status;
      p.appendChild(el('p', null, pr.TemplateId + ': ' + textOf(pr.OldVersion || 'the adopted version') + ' (old) and ' + textOf(pr.NewVersion) + ' (new) - ' + what + '. This is the ' + (isNew ? 'new' : 'old') + ' one; ', el('a', { href: '#capolicies/' + other, text: 'the ' + (isNew ? 'old' : 'new') + ' one' }), '.'));
      if (owner) {
        var bar = el('div', { class: 'toolbar' });
        if (pr.Status === 'Testing' || pr.Status === 'RolledBack') bar.appendChild(el('button', { type: 'button', text: 'Promote ' + textOf(pr.NewVersion), onclick: function () { capPair(j, 'promote'); } }));
        if (pr.Status === 'Promoted') {
          bar.appendChild(el('button', { type: 'button', class: 'secondary', text: 'Roll back to ' + textOf(pr.OldVersion || 'the old version'), onclick: function () { capPair(j, 'rollback'); } }));
          bar.appendChild(el('button', { type: 'button', class: 'secondary', text: 'Remove the old version', onclick: function () { capPair(j, 'removeold'); } }));
        }
        p.appendChild(bar);
      }
    } else if (vi.available) {
      p.appendChild(el('p', null, 'The library has ' + textOf(vi.library) + ' of this template; this policy is ' + textOf(vi.current || 'from an earlier version') + '. ' + (owner ? 'Test the new version next to it - this policy is not touched.' : 'A SuperAdmin can test it next to this policy.')));
      if (owner) p.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', text: 'Test a new version (' + textOf(vi.library) + ')', onclick: function () { capNewVersion(j); } })));
    } else p.appendChild(el('p', { class: 'smeta', text: 'No newer version to test' + (vi.reason ? ': ' + vi.reason : '') + '.' + (pr && pr.Status === 'Removed' ? ' The old version (' + textOf(pr.OldVersion) + ') was removed.' : '') }));
  }
  // UNDO-BACKUP (owner 2026-11-05: "i need to have both a new feature Undo + another new feature backup/restore. look at
  // how PIM does it"; "it must work for both ca policies + tagging so i can recover"; "ok go with daily keep 30"): the
  // Backups / Undo page, the undo of one change of a policy, of a tagging run and of a commit. Every restore and undo is
  // shown first as a plan (nothing written) and sent with a reason; the engine applies it through the same checks as the
  // change it puts back.
  function sendRequests(title, reqs, reason) {
    // the requests of a configuration restore, one after the other through their own routes (the commit queue stages
    // those it stages); then the usual follow-up of what the engine did
    if (bulkBusy) { notice('Still sending the previous changes - wait for them to finish.', 'warn'); return; }
    var ids = [], errs = [], i = 0;
    bulkBusy = true;
    notice('Sending ' + fmtNum(reqs.length) + ' change(s) ...');
    var next = function () {
      if (i >= reqs.length) { bulkBusy = false; afterAction({ requestIds: ids, errors: errs, count: reqs.length }, title); return; }
      var q = reqs[i++], body = JSON.parse(JSON.stringify(q.body || {}));
      body.reason = title + (reason ? ': ' + reason : '');
      api(q.method, q.path, body).then(function (res) { if (res && res.queued && res.requestId) ids.push(res.requestId); }, function (e) { errs.push(q.summary + ' - ' + e.message); }).then(next);
    };
    next();
  }
  function configRestoreDialog(title, guide, load) {
    // a configuration restore / the undo of a commit: the plan as the requests the pages make, each ticked; the operator
    // unticks what he does not want, gives a reason, sends
    var d = el('dialog', { class: 'dlg-wide', 'aria-label': title });
    var close = function () { try { d.close(); } catch (e) { /* closed */ } if (d.parentNode) d.parentNode.removeChild(d); };
    d.addEventListener('close', close);
    d.appendChild(el('h3', { text: title }));
    d.appendChild(el('div', { class: 'guide', text: guide }));
    var body = el('div', null, el('p', { class: 'smeta', text: 'Working out what it changes ...' }));
    d.appendChild(body);
    document.body.appendChild(d); d.showModal();
    load().then(function (pl) {
      clear(body);
      if (!pl.ok && !(pl.requests || []).length) { body.appendChild(el('p', { class: 'c-danger', text: 'Cannot: ' + textOf(pl.reason) })); body.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', class: 'secondary', text: 'Close', onclick: close }))); return; }
      body.appendChild(el('p', { text: textOf(pl.summary) }));
      var picks = (pl.requests || []).map(function (q) { var cb = el('input', { type: 'checkbox', 'aria-label': q.summary }); cb.checked = true; return { q: q, cb: cb }; });
      body.appendChild(el('div', { class: 'plist' }, picks.map(function (x) { return el('label', { class: 'pitem' }, x.cb, ' ' + x.q.summary + ' ', el('span', { class: 'smeta', text: '(' + x.q.method + ' ' + x.q.path + ')' })); })));
      if ((pl.notes || []).length) body.appendChild(el('ul', { class: 'hints' }, pl.notes.map(function (n) { return el('li', { text: n }); })));
      var reason = el('input', { type: 'text', placeholder: 'Reason (optional)', style: 'width:100%' });
      var go = el('button', { type: 'button', text: 'Send the ticked changes' });
      go.addEventListener('click', function () {
        var reqs = picks.filter(function (x) { return x.cb.checked; }).map(function (x) { return x.q; });
        if (!reqs.length) { notice('Nothing ticked.', 'warn'); return; }
        close(); sendRequests(title, reqs, reason.value.trim());
      });
      body.appendChild(el('p', null, reason));
      body.appendChild(el('div', { class: 'toolbar' }, go, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: close })));
    }).catch(function (e) { clear(body).appendChild(el('p', { class: 'c-danger', text: e.message })); });
  }
  function caRestoreShow(pl, box) {
    var s = pl.summary || {};
    box.appendChild(el('p', { text: fmtNum(s.patch) + ' changed back, ' + fmtNum(s.create) + ' created again (OFF), ' + fmtNum(s.same) + ' as in the backup already, ' + fmtNum(s.refused) + ' refused.' }));
    box.appendChild(table(pl.items || [], [{ key: 'displayName', label: 'Policy', wrap: true }, { key: 'action', label: 'Does', type: 'cat', render: function (r) { return !r.ok ? 'refused' : { patch: 'changed back', create: 'created again, OFF', none: 'nothing (as in the backup)' }[r.action] || r.action; } },
      { key: 'stateAfter', label: 'State after', type: 'cat' }, { key: 'changes', label: 'What changes', wrap: true, render: function (r) { return (r.changes || []).map(function (c) { return c.path + ': ' + textOf(c.before) + ' -> ' + textOf(c.after); }).join('\n') || textOf(r.reason); } },
      { key: 'breakGlass', label: 'Break-glass', wrap: true, render: function (r) { return r.breakGlass ? textOf(r.breakGlass.text) : ''; } }], { empty: 'No policy picked.' }));
  }
  function caRestoreDialog(backupId, ids) {
    capPlanDialog({ title: 'Put back from Conditional Access backup ' + backupId,
      guide: 'Each policy is put back as it is in the backup: only the parts that differ are changed, and a policy that is no longer in your tenant is created again - always OFF, adopted, ready to move through the stages. The engine reads each policy again first, takes a backup of it as it is now, and refuses one that changed since this view or that would no longer exclude the break-glass accounts. This CHANGES your tenant.',
      load: function () { return api('POST', '/api/backups/ca/' + backupId + '/restore-plan', { policyIds: ids }).then(function (pl) { pl.ok = (pl.items || []).some(function (r) { return r.ok && r.action !== 'none'; }); if (!pl.ok) pl.reason = 'nothing to put back: ' + ((pl.items || []).map(function (r) { return r.displayName + ' (' + textOf(r.reason || 'as in the backup already') + ')'; }).join('; ') || 'no policy'); return pl; }); },
      show: caRestoreShow, go: 'Put them back',
      send: function (pl, reason) { var todo = (pl.items || []).filter(function (r) { return r.ok && r.action !== 'none'; }), exp = {}; todo.forEach(function (r) { exp[r.policyId] = r.expected; });
        return api('POST', '/api/backups/ca/' + backupId + '/restore', { policyIds: todo.map(function (r) { return r.policyId; }), expected: exp, reason: reason }); } });
  }
  function caUndoDialog(policyId, m) {
    capPlanDialog({ title: 'Undo: ' + textOf(m.DisplayName) + ' (' + textOf(m.FromStage) + ' -> ' + textOf(m.ToStage) + ', ' + fmtTime(m.MovedAtUtc) + ')',
      guide: 'Puts the policy back as it was before this change - a NEW change, made like any other (a copy or a deploy is turned OFF, never deleted). The engine reads the policy again first, takes a backup of it as it is now, and refuses if it changed since this view or if the result would no longer exclude the break-glass accounts. This CHANGES your tenant.',
      load: function () { return api('GET', '/api/capolicies/policies/' + encodeURIComponent(policyId) + '/undo-plan?' + qs({ move: m.MoveId })).then(function (pl) { if (pl.ok && pl.action === 'none') { pl.ok = false; pl.reason = 'nothing to undo: ' + textOf(pl.reason); } return pl; }); },
      show: function (pl, box) { box.appendChild(el('p', { text: textOf(pl.label) })); caRestoreShow({ items: [pl], summary: { patch: pl.action === 'patch' ? 1 : 0, create: pl.action === 'create' ? 1 : 0, same: 0, refused: 0 } }, box); },
      go: 'Undo this change',
      send: function (pl, reason) { return api('POST', '/api/capolicies/policies/' + encodeURIComponent(policyId) + '/undo', { move: m.MoveId, expected: pl.expected, reason: reason }); } });
  }
  function runUndoDialog(runId) {
    capPlanDialog({ title: 'Undo this tagging run',
      guide: 'A NEW run writes every tag this run applied back to the value it had before - only where the object still has the value this run wrote (a later change is never overwritten). The mass-change guard measures it like a run; AD-synced users are written by the hybrid worker. This CHANGES your directory.',
      load: function () { return api('GET', '/api/runs/' + encodeURIComponent(runId) + '/undo-plan'); },
      show: function (pl, box) {
        box.appendChild(el('p', { text: fmtNum(pl.applied) + ' tag(s) this run applied' + (pl.applied > (pl.changes || []).length ? ' (the first ' + fmtNum((pl.changes || []).length) + ' shown)' : '') + '.' }));
        box.appendChild(table(pl.changes || [], [{ key: 'object', label: 'Object' }, { key: 'tagType', label: 'Tag type', type: 'cat' }, { key: 'directory', label: 'Directory', type: 'cat' }, { key: 'now', label: 'Now (as the run wrote it)', wrap: true }, { key: 'back', label: 'Put back', wrap: true }], { empty: 'Nothing.' }));
        var ap = el('input', { type: 'checkbox' }); ap.addEventListener('change', function () { pl.approve = ap.checked; });
        box.appendChild(el('label', null, ap, ' Approve it if the mass-change guard holds it (I have checked the numbers).'));
      },
      go: 'Undo this run',
      send: function (pl, reason) { return api('POST', '/api/runs/' + encodeURIComponent(runId) + '/undo', { approve: !!pl.approve, reason: reason }); } });
  }
  function backNow() {
    withReason('Back up now', 'The Backup job stores every Conditional Access policy, named location and authentication strength, and the tagging configuration, now (it only reads the tenant). Kept 30 days.', function (reason) { return api('POST', '/api/jobs/Backup/run', { mode: 'Apply', reason: reason }); });
  }
  function drawBackupCa(p, id) {
    var owner = isRole('SuperAdmin');
    p.appendChild(el('p', null, el('a', { href: '#backups', text: '< Backups / Undo' })));
    return api('GET', '/api/backups/ca/' + encodeURIComponent(id)).then(function (j) {
      var b = j.backup;
      p.appendChild(el('h2', { text: 'Conditional Access backup ' + b.BackupId + ' - ' + fmtTime(b.TakenAtUtc) }));
      p.appendChild(el('p', { text: b.Kind + ' · ' + fmtNum(b.Policies) + ' policies, ' + fmtNum(b.NamedLocations) + ' named locations, ' + fmtNum(b.AuthStrengths) + ' authentication strengths · ' + textOf(b.TakenBy) + (b.Cause ? ' · ' + b.Cause : '') }));
      if (isRole('Admin')) p.appendChild(el('div', { class: 'toolbar' }, el('a', { href: '/api/backups/ca/' + b.BackupId + '/export', text: 'Download as JSON files (v1\'s export)' })));
      p.appendChild(el('div', { class: 'guide', text: 'Pick the policies to put back' + (owner ? '' : ' (a SuperAdmin puts them back)') + '. Each one is shown first with what changes; a policy that is no longer in your tenant is created again, OFF. Named locations and authentication strengths are kept in the backup and in the download; they are put back by hand.' }));
      var pol = (j.items || []).filter(function (r) { return r.ItemType === 'policy'; });
      p.appendChild(table(pol, [{ key: 'DisplayName', label: 'Policy', wrap: true }, { key: 'State', label: 'State in the backup', type: 'cat' }, { key: 'Now', label: 'Now', type: 'cat', cls: function (r) { return r.Now === 'not in the tenant' ? 'c-warning' : ''; } }, { key: 'ObjectId', label: 'Id' }],
        { sort: 'DisplayName', dir: 1, empty: 'No policy in this backup.', bulk: owner ? [{ label: 'Put back...', run: function (sel) { caRestoreDialog(b.BackupId, sel.map(function (r) { return r.ObjectId; })); } }] : [] }));
      var other = (j.items || []).filter(function (r) { return r.ItemType !== 'policy'; });
      if (other.length) { p.appendChild(el('h3', { text: 'Named locations and authentication strengths' })); p.appendChild(table(other, [{ key: 'ItemType', label: 'Kind', type: 'cat' }, { key: 'DisplayName', label: 'Name', wrap: true }, { key: 'ObjectId', label: 'Id' }], { sort: 'DisplayName', dir: 1 })); }
    });
  }
  function drawBackups(p, arg) {
    if (/^ca-\d+$/.test(arg || '')) return drawBackupCa(p, arg.substring(3));
    var admin = isRole('Admin'), owner = isRole('SuperAdmin');
    p.appendChild(el('div', { class: 'guide', text: 'Every night the Backup job stores every Conditional Access policy (adopted or not), named location and authentication strength, and the tagging configuration - the newest 30 are kept. A backup is also taken BEFORE every change Entra Policy Suite makes to a policy and before every commit of the tagging rules; a change whose backup cannot be written is refused. Putting something back is a new change: you see it first, and it goes through the same checks. Nothing is restored by itself.' }));
    return api('GET', '/api/backups').then(function (j) {
      if (admin) p.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', text: 'Back up now', onclick: backNow }), el('span', { class: 'count', text: 'Daily sets kept: ' + j.keepDaily + '; backups before a change and manual ones: ' + j.keepDays + ' days.' })));
      p.appendChild(el('h3', { text: 'Conditional Access backups' }));
      p.appendChild(table(j.ca || [], [{ key: 'TakenAtUtc', label: 'Taken', type: 'date' }, { key: 'Kind', label: 'Kind', type: 'cat' }, { key: 'Policies', label: 'Policies', type: 'num' }, { key: 'NamedLocations', label: 'Named locations', type: 'num' }, { key: 'AuthStrengths', label: 'Strengths', type: 'num' },
        { key: 'Cause', label: 'Why', wrap: true }, { key: 'TakenBy', label: 'By', type: 'cat' }, { key: '_o', label: '', render: function (r) { return el('a', { href: '#backups/ca-' + r.BackupId, text: 'Open' }); } }], { sort: 'TakenAtUtc', dir: -1, empty: 'No backup yet - the first one is taken tonight, or now with Back up now.' }));
      p.appendChild(el('h3', { text: 'Tagging configuration backups' }));
      p.appendChild(table(j.config || [], [{ key: 'TakenAtUtc', label: 'Taken', type: 'date' }, { key: 'Kind', label: 'Kind', type: 'cat' }, { key: 'CountsJson', label: 'Holds', wrap: true, render: function (r) { try { var o = JSON.parse(r.CountsJson || '{}'); return Object.keys(o).map(function (k) { return o[k] + ' ' + k; }).join(', '); } catch (e) { return textOf(r.CountsJson); } } },
        { key: 'Cause', label: 'Why', wrap: true }, { key: 'TakenBy', label: 'By', type: 'cat' },
        { key: '_r', label: '', render: function (r) { return admin ? el('button', { type: 'button', class: 'secondary', text: 'Restore...', onclick: function () { configRestoreDialog('Restore the tagging configuration from backup ' + r.BackupId, 'The rules, tag types, values, condition types and settings go back as they are in this backup (' + fmtTime(r.TakenAtUtc) + '): each as the change the pages make, through its own checks - with the commit queue on, the rules and tag types are STAGED for a commit. Untick what you want to keep as it is. Secrets are never in a backup.', function () { return api('GET', '/api/backups/config/' + r.BackupId + '/restore-plan'); }); } }) : null; } }],
        { sort: 'TakenAtUtc', dir: -1, empty: 'No backup yet.' }));
      p.appendChild(el('h3', { text: 'Undo a recent change' }));
      p.appendChild(el('h4', { text: 'Conditional Access' }));
      p.appendChild(table(j.moves || [], [{ key: 'MovedAtUtc', label: 'When', type: 'date' }, { key: 'DisplayName', label: 'Policy', render: function (m) { return el('a', { href: '#capolicies/' + m.PolicyId, text: m.DisplayName }); } }, { key: 'FromStage', label: 'From', type: 'cat' }, { key: 'ToStage', label: 'To', type: 'cat' }, { key: 'RequestedBy', label: 'By', type: 'cat' }, { key: 'Reason', label: 'Reason', wrap: true },
        { key: '_u', label: '', render: function (m) { return owner ? el('button', { type: 'button', class: 'secondary', text: 'Undo...', onclick: function () { caUndoDialog(m.PolicyId, m); } }) : null; } }], { sort: 'MovedAtUtc', dir: -1, empty: 'No change made from here yet.' }));
      p.appendChild(el('h4', { text: 'Tagging runs' }));
      p.appendChild(table(j.runs || [], [{ key: 'StartedAtUtc', label: 'Run', type: 'date', render: function (r) { return el('a', { href: '#run/' + r.RunId, text: fmtTime(r.StartedAtUtc) }); } }, { key: 'Job', label: 'Job', type: 'cat' }, { key: 'Status', label: 'Status', type: 'cat' }, { key: 'Applied', label: 'Tags written', type: 'num' },
        { key: 'UndoneBy', label: 'Undone', render: function (r) { return r.UndoneBy ? el('a', { href: '#run/' + r.UndoneBy, text: 'yes' }) : ''; } },
        { key: '_u', label: '', render: function (r) { return admin && !r.UndoneBy ? el('button', { type: 'button', class: 'secondary', text: 'Undo this run...', onclick: function () { runUndoDialog(r.RunId); } }) : null; } }], { sort: 'StartedAtUtc', dir: -1, empty: 'No tagging run wrote anything yet.' }));
      p.appendChild(el('h4', { text: 'Commits of the tagging rules' }));
      p.appendChild(table(j.commits || [], [{ key: 'CommittedAtUtc', label: 'Committed', type: 'date' }, { key: 'CommittedBy', label: 'By', type: 'cat' }, { key: 'Changes', label: 'Changes', type: 'num' }, { key: 'FirstChange', label: 'First change', wrap: true },
        { key: '_u', label: '', render: function (c) { return admin && c.BackupId ? el('button', { type: 'button', class: 'secondary', text: 'Undo this commit...', onclick: function () { configRestoreDialog('Undo the commit of ' + fmtTime(c.CommittedAtUtc), 'What this commit changed goes back as it was just before it (the backup taken before the commit), as the changes the pages make - with the commit queue on, they are STAGED for a commit. A later change to the same rules is undone with it: check the list.', function () { return api('GET', '/api/commits/' + c.CommitId + '/undo-plan'); }); } }) : (c.BackupId ? null : el('span', { class: 'smeta', text: 'no backup before it' })); } }], { sort: 'CommittedAtUtc', dir: -1, empty: 'No commit yet.' }));
    });
  }
  function drawCaPolicies(p) {
    var admin = isRole('Admin'), owner = isRole('SuperAdmin');   // Adopt / Release: SuperAdmin only (owner 2026-11-01)
    p.appendChild(el('div', { class: 'guide', text: 'The engine reads the tenant\'s Conditional Access policies and compares each with its template (by the CA number in its name): the stage it is really in, what differs, and whether it excludes the break-glass accounts. Adopt only RECORDS that you manage a policy from here. The ONE change this page makes in the tenant: a SuperAdmin moves an adopted policy to another stage (Move stage), after seeing what changes. Nothing changes a policy by itself.' }));
    capSubnav(p, '');
    return api('GET', '/api/capolicies').then(function (j) {
      var rows = j.rows || [];
      rows.forEach(function (r) { r.Compared = r.InLibrary ? (r.Matches ? 'as the template' : 'differs (' + fmtNum(r.DiffCount) + ')') : (r.TemplateId ? 'not in the library' : 'no CA number'); r.StageShown = r.Stage + (r.StageMismatch ? ' (name says ' + r.NameStage + ')' : ''); });
      p.appendChild(el('div', { class: 'cards' },
        card(rows.length, 'policies'), card(rows.filter(function (r) { return r.InLibrary; }).length, 'matched to a template'),
        card(rows.filter(function (r) { return r.InLibrary && !r.Matches; }).length, 'differ from their template'),
        card(rows.filter(function (r) { return r.BreakGlass === 'MISSING'; }).length, 'without the break-glass exclusion', rows.some(function (r) { return r.BreakGlass === 'MISSING'; })),
        card(rows.filter(function (r) { return r.Adoption === 'Adopted'; }).length, 'adopted'),
        card((j.findings || []).filter(function (f) { return f.Status === 'Open'; }).length, 'open monitor findings', (j.findings || []).some(function (f) { return f.Status === 'Open'; }))));
      p.appendChild(el('div', { class: 'toolbar' }, admin ? capReadButton() : null,
        el('span', { class: 'count', text: j.readAtUtc ? 'Read ' : 'Not read yet - the CA Policy Analyzer reads the list on every run.' }), j.readAtUtc ? timeEl(j.readAtUtc) : null,
        el('span', { class: 'count', text: ' · monitor ' + (j.monitoring ? 'ON (adopted policies: drift, break-glass)' : 'off (Settings > Conditional Access)') + ' · ' + fmtNum(j.templates) + ' templates (' + textOf(j.library) + ')' + (j.method ? ' · targeting ' + j.method : '') })));
      if ((j.findings || []).length) {
        p.appendChild(el('h3', { text: 'Monitor findings' }));
        p.appendChild(el('div', { class: 'guide', text: 'Shown and alerted only: Entra Policy Suite never acts on a finding. What happens next is your decision and your own action in the tenant. A change you made yourself: adopt the policy again.' }));
        p.appendChild(table(j.findings, [{ key: 'LastSeenUtc', label: 'Seen', type: 'date' }, { key: 'Status', label: 'Status', type: 'cat' }, { key: 'Kind', label: 'Finding', type: 'cat', cls: function (r) { return r.Kind !== 'Drift' && r.Status === 'Open' ? 'c-danger' : ''; } },
          { key: 'DisplayName', label: 'Policy', render: function (r) { return el('a', { href: '#capolicies/' + r.PolicyId, text: r.DisplayName }); } }, { key: 'Detail', label: 'What', wrap: true }, { key: 'AlertedAtUtc', label: 'Alerted', type: 'date' }], { sort: 'LastSeenUtc', dir: -1 }));
      }
      p.appendChild(el('h3', { text: 'Policies' }));
      var cols = [{ key: 'DisplayName', label: 'Policy', render: function (r) { return el('a', { href: '#capolicies/' + r.PolicyId, text: r.DisplayName }); } },
        { key: 'TemplateId', label: 'Template', type: 'cat' }, { key: 'Persona', label: 'Persona', type: 'cat', multi: ', ' }, { key: 'StageShown', label: 'Stage', type: 'cat', cls: function (r) { return r.StageMismatch ? 'c-danger' : ''; } },
        { key: 'State', label: 'State', type: 'cat' }, { key: 'Compared', label: 'Against its template', type: 'cat', cls: function (r) { return r.InLibrary && !r.Matches ? 'c-danger' : ''; } },
        { key: 'BreakGlass', label: 'Break-glass', type: 'cat', cls: function (r) { return CAP_BG_CLS[r.BreakGlass] || ''; } }, { key: 'Adoption', label: 'Adopted', type: 'cat' },
        { key: 'Findings', label: 'Findings', type: 'cat' }, { key: 'ModifiedAtUtc', label: 'Changed in the tenant', type: 'date' }];
      if (owner) cols.push({ key: '_s', label: 'Move stage', render: function (r) {
        if (r.Adoption !== 'Adopted') return null;
        // owner 2026-11-03 ("move to any lifecycle phase"): one picker per row - every stage it can go to, and Disable.
        // Picking one only opens the move dialog (what changes, the confirmation); the picker goes back to its label.
        var mv = capMoves(r.Stage);
        if (!mv.length) return null;
        var sel = el('select', { 'aria-label': 'Move ' + r.DisplayName + ' to another stage' }, [el('option', { value: '', text: 'Move to ...' })].concat(mv.map(function (to) {
          return el('option', { value: to, text: to === 'Disabled' ? 'Disable (off)' : capMoveLabel(r.Stage, to) + ' (' + CAP_STAGE_TEXT[to] + ')' }); })));
        sel.addEventListener('click', function (e) { e.stopPropagation(); });   // never the row's own click
        sel.addEventListener('change', function () { var to = sel.value; sel.value = ''; if (to) capStage(r, to); });
        return sel; } });
      if (owner) cols.push({ key: '_a', label: '', render: function (r) {
        if (r.Adoption === 'Adopted') return el('button', { type: 'button', class: 'link', text: 'Release', onclick: function () { capRelease(r); } });
        return el('button', { type: 'button', class: 'secondary', text: 'Adopt', onclick: function () { capAdopt(r); } }); } });
      var capBulk = owner ? [
        { label: 'Adopt', run: function (sel) { var todo = sel.filter(function (r) { return r.Adoption !== 'Adopted'; }); if (!todo.length) { notice('All selected policies are adopted already.'); return; }
          bulkAction('Adopt policies', 'Entra Policy Suite RECORDS that you adopt these policies as they are now: each body becomes the baseline the monitor compares with. Nothing in the tenant changes.', todo, function (r, reason) { return api('POST', '/api/capolicies/policies/' + encodeURIComponent(r.PolicyId) + '/adopt', { expected: r.Hash, reason: reason }); }); } },
        { label: 'Release', run: function (sel) { var todo = sel.filter(function (r) { return r.Adoption === 'Adopted'; }); if (!todo.length) { notice('None of the selected policies is adopted.'); return; }
          bulkAction('Release policies', 'Entra Policy Suite stops recording these policies as managed here. Nothing in the tenant changes.', todo, function (r, reason) { return api('POST', '/api/capolicies/policies/' + encodeURIComponent(r.PolicyId) + '/release', { reason: reason }); }); } }] : [];
      // CA-MONADD (owner 2026-11-02: "need an easy way to add/remove ca policy to existing/new monitor"): an analyzer monitor
      // is Admin - it only reads the tenant
      if (admin) capBulk = capBulk.concat([{ label: 'Add to monitor...', run: function (sel) { caMonitorPick('add', sel); } }, { label: 'Remove from monitor...', run: function (sel) { caMonitorPick('remove', sel); } }]);
      p.appendChild(table(rows, cols, { sort: 'DisplayName', dir: 1, empty: 'No policy read yet. Read the policy list (read only).', bulk: capBulk }));
    });
  }
  function drawCaPolicy(p, id) {
    var owner = isRole('SuperAdmin');
    capSubnav(p, '');
    return api('GET', '/api/capolicies/policies/' + encodeURIComponent(id)).then(function (j) {
      var pol = j.policy, rv = j.review || {}, ad = j.adoption, bg = rv.breakGlass || {};
      p.appendChild(el('h2', { text: pol.DisplayName }));
      var row = { PolicyId: pol.PolicyId, DisplayName: pol.DisplayName, Hash: rv.hash, Stage: rv.stage };
      p.appendChild(el('dl', { class: 'info' },
        el('dt', { text: 'State' }), el('dd', { text: textOf(pol.State) }),
        el('dt', { text: 'Stage (from the real state)' }), el('dd', { text: textOf(rv.stage) + (rv.stageNote ? ' - ' + rv.stageNote : '') + (rv.stageMismatch ? ' - its name says ' + rv.nameStage : '') }),
        el('dt', { text: 'Template' }), el('dd', { text: rv.templateId ? (rv.templateId + ' ' + textOf(rv.templateVersion) + ' ' + textOf(rv.templateName) + (rv.inLibrary ? '' : ' (not in the library)')) : 'none (no CA number in the name)' }),
        el('dt', { text: 'Break-glass' }), el('dd', { class: bg.ok === false ? 'c-danger' : null, text: textOf(bg.text) }),
        el('dt', { text: 'Adopted' }), el('dd', { text: ad ? (ad.Status === 'Adopted' ? 'yes, by ' + ad.AdoptedBy + ' (' + fmtTime(ad.AdoptedAtUtc) + '): ' + textOf(ad.AdoptReason) : 'released by ' + ad.ReleasedBy + ' (' + fmtTime(ad.ReleasedAtUtc) + '): ' + textOf(ad.ReleaseReason)) : 'no' }),
        el('dt', { text: 'Read' }), el('dd', null, timeEl(pol.SeenAtUtc), ' · changed in the tenant ', timeEl(pol.ModifiedAtUtc))));
      if (owner) p.appendChild(el('div', { class: 'toolbar' }, ad && ad.Status === 'Adopted' ? el('button', { type: 'button', class: 'secondary', text: 'Release', onclick: function () { capRelease(row); } }) : el('button', { type: 'button', text: 'Adopt as it is', onclick: function () { capAdopt(row); } }),
        el('span', { class: 'count', text: 'Recorded in Entra Policy Suite only - nothing in the tenant changes.' })));
      // CA-EDIT: Edit and Clone - any adopted policy, template-matched or not (SuperAdmin; each after a check and approval)
      if (isRole('SuperAdmin') && ad && ad.Status === 'Adopted') p.appendChild(el('div', { class: 'toolbar' },
        el('button', { type: 'button', text: 'Edit', onclick: function () { caPolicyEditor(j, 'Edit'); } }),
        el('button', { type: 'button', class: 'secondary', text: 'Clone', onclick: function () { caPolicyEditor(j, 'Clone'); } }),
        el('span', { class: 'count', text: 'Edit changes this policy in your tenant; Clone creates a new one, off. Each shows what changes before you approve it.' })));
      else if (owner) p.appendChild(el('p', { class: 'smeta', text: 'Adopt it first to edit or clone it from here.' }));
      // CA-LIFECYCLE: the stage buttons (SuperAdmin, an adopted policy) and the moves made from here
      p.appendChild(el('h3', { text: 'Stage' }));
      if (owner && ad && ad.Status === 'Adopted') {
        p.appendChild(el('div', { class: 'guide', text: 'Move this policy to any stage: Pilot1 (report-only for the pilot group), Pilot2 / Pilot3 (on for the pilot group), Prod (on for its targets), or Disable (off, as Initial). Each move shows what changes before you approve it, and CHANGES the policy in your tenant.' }));
        p.appendChild(capStageBar(row));
      } else p.appendChild(el('p', { class: 'smeta', text: 'Now ' + textOf(rv.stage) + '. ' + (ad && ad.Status === 'Adopted' ? 'A SuperAdmin moves it between stages.' : 'Adopt it first to move it between stages from here.') }));
      // UNDO-BACKUP: each applied change can be undone (SuperAdmin) - its body before it put back, after a plan
      if ((j.moves || []).length) p.appendChild(table(j.moves, [{ key: 'MovedAtUtc', label: 'When', type: 'date' }, { key: 'FromStage', label: 'From', type: 'cat' }, { key: 'ToStage', label: 'To', type: 'cat' },
        { key: 'RequestedBy', label: 'By', type: 'cat' }, { key: 'Reason', label: 'Reason', wrap: true }, { key: 'Result', label: 'Result', type: 'cat', cls: function (m) { return m.Result !== 'applied' ? 'c-danger' : ''; } }, { key: 'ResultText', label: 'Note', wrap: true },
        { key: '_undo', label: '', render: function (m) { return owner && /^applied/.test(m.Result || '') ? el('button', { type: 'button', class: 'link', text: 'Undo...', onclick: function () { m.DisplayName = m.DisplayName || pol.DisplayName; caUndoDialog(pol.PolicyId, m); } }) : null; } }], { sort: 'MovedAtUtc', dir: -1 }));
      if (owner) p.appendChild(el('p', { class: 'smeta' }, 'Every change made from here can be undone (a new change, shown first). A whole earlier state: ', el('a', { href: '#backups', text: 'Backups / Undo' }), '.'));
      // CA-TEMPLATES: a newer version of its template - tested next to it, then promoted / rolled back / the old one removed
      if (ad && ad.Status === 'Adopted' || j.pair) capVersionSection(p, j);
      if ((rv.notes || []).length) p.appendChild(el('ul', { class: 'hints' }, rv.notes.map(function (n) { return el('li', { text: n }); })));
      p.appendChild(el('h3', { text: rv.inLibrary ? (rv.matches ? 'As the template (' + textOf(rv.stage) + ')' : 'What differs from the template at ' + textOf(rv.stage)) : 'No template to compare with' }));
      if (rv.inLibrary && (rv.diff || []).length) p.appendChild(table(rv.diff, [{ key: 'path', label: 'Setting', type: 'cat' }, { key: 'expected', label: 'Template wants', wrap: true }, { key: 'actual', label: 'Tenant has', wrap: true },
        { key: 'missing', label: 'Missing', wrap: true, render: function (d) { return (d.missing || []).join(', '); } }, { key: 'extra', label: 'Extra', wrap: true, render: function (d) { return (d.extra || []).join(', '); } }], { empty: 'No difference.' }));
      if ((j.findings || []).length) {
        p.appendChild(el('h3', { text: 'Monitor findings' }));
        p.appendChild(table(j.findings, [{ key: 'LastSeenUtc', label: 'Seen', type: 'date' }, { key: 'Status', label: 'Status', type: 'cat' }, { key: 'Kind', label: 'Finding', type: 'cat' }, { key: 'Detail', label: 'What', wrap: true },
          { key: 'DetailJson', label: 'Details', wrap: true, render: function (f) { return f.DetailJson ? el('pre', { class: 'log', text: prettyJson(f.DetailJson) }) : null; } }], { sort: 'LastSeenUtc', dir: -1 }));
      }
      if (j.documentation) {
        p.appendChild(el('h3', { text: 'Documentation (names resolved)' }));
        var dl = el('dl', { class: 'info' });
        Object.keys(j.documentation).forEach(function (k) { var v = j.documentation[k]; if (v === '' || v === null || v === undefined) return; dl.appendChild(el('dt', { text: k })); dl.appendChild(el('dd', { text: String(v) })); });
        p.appendChild(dl);
      }
      p.appendChild(el('h3', { text: 'The policy as read (JSON)' }));
      p.appendChild(el('pre', { class: 'log', text: JSON.stringify(j.body, null, 2) }));
    });
  }
  function drawCaDoc(p) {
    capSubnav(p, 'doc');
    var ids = store.get('eps.capDocIds', '') === '1';
    p.appendChild(el('div', { class: 'guide', text: 'The Conditional Access documentation (v1: Entra-CA-Policies-Documentation): one row per policy, every id resolved to a name where the engine could read it with its read-only rights; an id it could not read stays an id.' }));
    var tg = el('input', { type: 'checkbox' }); tg.checked = ids;
    tg.addEventListener('change', function () { store.set('eps.capDocIds', tg.checked ? '1' : ''); render(); });
    p.appendChild(el('div', { class: 'toolbar' }, el('label', null, tg, ' keep the ids next to the names'),
      el('a', { href: '/api/capolicies/documentation/export?format=xlsx' + (ids ? '&ids=1' : ''), text: 'Export Excel' }), ' ',
      el('a', { href: '/api/capolicies/documentation/export?format=csv' + (ids ? '&ids=1' : ''), text: 'Export CSV' })));
    return api('GET', '/api/capolicies/documentation?' + qs({ ids: ids ? '1' : '' })).then(function (j) {
      var cols = (j.columns || []).map(function (c) { return { key: c, label: c, type: c === 'Template' || c === 'Stage' || c === 'State' ? 'cat' : null, wrap: /Users|Groups|Roles|Applications|Locations|Controls|Session/.test(c) }; });
      p.appendChild(table(j.rows || [], cols, { sort: 'DisplayName', dir: 1, empty: 'No policy read yet.' }));
    });
  }
  function drawCaTemplates(p) {
    capSubnav(p, 'templates');
    var owner = isRole('SuperAdmin');
    p.appendChild(el('div', { class: 'guide', text: 'The template library of this release (v1\'s CA000-CA800, converted to data). A template names groups, accounts and names by their role ({breakGlassGroup}, {group:Admins_All}, ...): the values are your settings, never part of the template. A SuperAdmin deploys a template as a NEW policy (Deploy: off or report-only, the groups it needs created first, adopted at once - v1\'s Initial_Setup). A template already in your tenant is not deployed again: a newer version is TESTED next to its policy (Test a new version, on the policy\'s page), then promoted. Nothing is deployed by itself.' }));
    var slot = el('div');
    return api('GET', '/api/capolicies/templates').then(function (j) {
      if (owner && !j.method) p.appendChild(el('p', { class: 'c-warning', text: 'The group-targeting method is not set (Settings > Conditional Access > CA.GroupTargetingMethod): set it before you deploy.' }));
      var cols = [{ key: 'id', label: 'Template', render: function (t) { return el('button', { type: 'button', class: 'link', text: t.id, onclick: function () {
          api('GET', '/api/capolicies/templates?' + qs({ id: t.id })).then(function (x) { clear(slot).appendChild(el('h3', { text: x.template.id + ' ' + x.template.version + ' ' + x.template.name })); slot.appendChild(el('pre', { class: 'log', text: JSON.stringify(x.template, null, 2) })); slot.scrollIntoView(); }).catch(function (e) { status(e.message); }); } }); } },
        { key: 'version', label: 'Version', type: 'cat' }, { key: 'name', label: 'Name' }, { key: 'persona', label: 'Persona', type: 'cat' }, { key: 'inTenant', label: 'In the tenant', wrap: true },
        { key: 'breakGlassPolicy', label: 'Break-glass policy', type: 'cat' }, { key: 'incomplete', label: 'Incomplete', type: 'cat' }, { key: 'notes', label: 'Notes', wrap: true }];
      if (owner) cols.push({ key: '_d', label: '', render: function (t) { if (t.inTenant || t.incomplete) return null; return el('button', { type: 'button', class: 'secondary', text: 'Deploy', onclick: function (e) { e.stopPropagation(); capDeploy(t); } }); } });
      var bulk = owner ? [{ label: 'Deploy (off)', run: function (sel) {
        var todo = sel.filter(function (t) { return !t.inTenant && !t.incomplete; });
        if (!todo.length) { notice('Every selected template is in the tenant already (or incomplete in v1).'); return; }
        bulkAction('Deploy templates (off)', 'Each template becomes a NEW policy in your tenant, OFF (v1\'s Initial_Setup), adopted at once; the groups each needs are created first when missing. The engine checks each again first and refuses one that is already there or would not exclude the break-glass accounts. Open one with its Deploy button first to see what it creates.', todo,
          function (t, reason) { return api('POST', '/api/catemplates/' + encodeURIComponent(t.id) + '/deploy', { stage: 'Initial', reason: reason }); }); } }] : [];
      p.appendChild(table(j.rows || [], cols, { sort: 'id', dir: 1, bulk: bulk }));
      p.appendChild(slot);
    });
  }
  // TEMPLATE-UPDATES (owner 2026-11-02: "templates can be used for updates if new features are added but always operator
  // controlled. easy to see chg is importantant"): what a newer library brings, against what this install has taken. A
  // persona change is applied to the persona (or skipped); a template change is only marked as seen - nothing here writes
  // a Conditional Access policy.
  var TU_KIND = { 'new': 'new template', changed: 'changed', removed: 'removed from the library' };
  function tuTake(title, text, body) {
    withReason(title, text, function (reason) { body.reason = reason; return api('POST', '/api/ca/template-updates/take', body); });
  }
  function tuPersonaTake(rows, apply) {
    var names = rows.map(function (r) { return r.name; });
    tuTake((apply ? 'Apply to the persona' : 'Skip the persona change') + (rows.length > 1 ? 's (' + rows.length + ')' : ': ' + names[0]),
      apply ? 'The CA numbers are added to / taken out of ' + names.join(', ') + ' as name rules (a persona that does not exist is created). The monitors that name it take the change at their next run. No Conditional Access policy is changed.'
        : 'Recorded as taken without changing ' + names.join(', ') + ' - it will not be offered again.',
      { personas: names.map(function (n) { return { name: n, apply: apply }; }) });
  }
  function tuSeen(rows) {
    var ids = rows.map(function (r) { return r.id; });
    tuTake('Mark as seen' + (ids.length > 1 ? ' (' + ids.length + ')' : ': ' + ids[0]),
      'Records that you have seen the change to ' + (ids.length > 5 ? ids.slice(0, 5).join(', ') + ' ...' : ids.join(', ')) + ': the next update compares from this version. Nothing else changes - your policies stay as they are; change them yourself in the tenant if you want the new template.',
      { templates: ids });
  }
  function tuDetail(slot, t) {
    clear(slot);
    slot.appendChild(el('h3', { text: t.id + ' - ' + (TU_KIND[t.kind] || t.kind) + (t.versionBefore || t.versionAfter ? ' (' + textOf(t.versionBefore || 'not taken') + ' -> ' + textOf(t.versionAfter || 'gone') + ')' : '') }));
    if (t.nameBefore !== t.nameAfter) slot.appendChild(el('p', { text: 'Name: ' + textOf(t.nameBefore || '(none)') + ' -> ' + textOf(t.nameAfter || '(none)') }));
    slot.appendChild(el('div', { class: 'toolbar' },
      t.versionAfter ? el('a', { href: '/api/ca/template-updates/export?' + qs({ id: t.id }), text: 'Export the new template (JSON)' }) : null, ' ',
      t.versionBefore ? el('a', { href: '/api/ca/template-updates/export?' + qs({ id: t.id, which: 'before' }), text: 'Export as taken before (JSON)' }) : null));
    if (t.kind === 'changed') {
      slot.appendChild(el('h3', { text: 'What changed in the template' }));
      slot.appendChild(table(t.changes || [], [{ key: 'field', label: 'Setting', type: 'cat' }, { key: 'before', label: 'Before', wrap: true }, { key: 'after', label: 'After', wrap: true }], { empty: 'No field differs (only the order of a list).' }));
    } else if (t.kind === 'new') slot.appendChild(el('p', { text: 'A template this install has not taken before' + (t.persona ? ' (persona ' + t.persona + ')' : '') + '. Its body: export it, or open it under Templates.' }));
    else slot.appendChild(el('p', { text: 'The library no longer has this template. Your policies with this number are not touched.' }));
    var pols = t.policies || [];
    slot.appendChild(el('h3', { text: 'Your policies with ' + t.id + ' against the ' + (t.kind === 'removed' ? 'old' : 'new') + ' template' }));
    if (!pols.length) { slot.appendChild(el('p', { text: 'None of your policies carries ' + t.id + ' in its name.' })); return; }
    var rows = [];
    pols.forEach(function (x) {
      if (!x.diff || !x.diff.length) rows.push({ policyId: x.policyId, displayName: x.displayName, stage: x.stage, setting: t.kind === 'removed' ? '' : 'as the template', template: '', tenant: '' });
      else x.diff.forEach(function (d) { rows.push({ policyId: x.policyId, displayName: x.displayName, stage: x.stage, setting: d.setting, template: d.template, tenant: d.tenant }); });
    });
    slot.appendChild(el('div', { class: 'guide', text: 'Shown only. A template update never changes a Conditional Access policy: if you want what the new template does, make the change yourself in the tenant (export the template for reference), then read the policy list again.' }));
    slot.appendChild(table(rows, [{ key: 'displayName', label: 'Policy', render: function (r) { return el('a', { href: '#capolicies/' + r.policyId, text: r.displayName }); } }, { key: 'stage', label: 'Stage', type: 'cat' },
      { key: 'setting', label: 'Setting', type: 'cat' }, { key: 'template', label: 'Template wants', wrap: true }, { key: 'tenant', label: 'Your policy has', wrap: true }], { sort: 'displayName', dir: 1 }));
    slot.scrollIntoView();
  }
  function drawCaTemplateUpdates(p) {
    capSubnav(p, 'updates');
    var admin = isRole('Admin');
    p.appendChild(el('div', { class: 'guide', text: 'A new release can bring a newer template library. Nothing changes by itself: this page shows what is new or changed since the library this install took, and you decide. A persona change is applied to your persona (or skipped). A template change is only shown - with your policies against the new template and an export - and marked as seen. No Conditional Access policy is ever changed from here.' }));
    var slot = el('div');
    return api('GET', '/api/ca/template-updates').then(function (j) {
      var tpl = j.templates || [], per = j.personas || [];
      p.appendChild(el('div', { class: 'toolbar' }, el('span', { class: 'count', text: 'This release: library ' + textOf(j.library) + ' · this install took: ' + ((j.taken || []).length ? j.taken.join(', ') : 'not recorded yet') })));
      if (!j.recorded) {
        p.appendChild(el('p', { text: 'Not recorded yet: the engine records the library this install imported at its next read of the policy list.' }));
        if (admin) p.appendChild(el('div', { class: 'toolbar' }, capReadButton()));
        return;
      }
      if (!tpl.length && !per.length) { p.appendChild(el('p', { text: 'Nothing new: this install has taken everything in library ' + textOf(j.library) + '.' })); return; }
      p.appendChild(el('div', { class: 'cards' }, card(tpl.filter(function (t) { return t.kind === 'new'; }).length, 'new templates'), card(tpl.filter(function (t) { return t.kind === 'changed'; }).length, 'changed templates'),
        card(tpl.filter(function (t) { return t.kind === 'removed'; }).length, 'removed templates'), card(per.length, 'persona changes')));
      if (per.length) {
        p.appendChild(el('h3', { text: 'Persona changes' }));
        per.forEach(function (x) { x.adds = (x.add || []).join(', '); x.removes = (x.remove || []).join(', '); x.now = x.exists ? 'rules: ' + ((x.rules || []).join(', ') || '(none)') : 'no such persona - Apply creates it'; });
        var pcols = [{ key: 'name', label: 'Persona', type: 'cat' }, { key: 'adds', label: 'The library adds', wrap: true }, { key: 'removes', label: 'The library takes out', wrap: true }, { key: 'now', label: 'Your persona now', wrap: true }];
        if (admin) pcols.push({ key: '_a', label: '', render: function (r) { return el('span', null, el('button', { type: 'button', class: 'secondary', text: 'Apply', onclick: function () { tuPersonaTake([r], true); } }), ' ',
          el('button', { type: 'button', class: 'link', text: 'Skip', onclick: function () { tuPersonaTake([r], false); } })); } });
        p.appendChild(table(per, pcols, { sort: 'name', dir: 1, bulk: admin ? [{ label: 'Apply to the personas', run: function (sel) { tuPersonaTake(sel, true); } }, { label: 'Skip', run: function (sel) { tuPersonaTake(sel, false); } }] : [] }));
      }
      if (tpl.length) {
        p.appendChild(el('h3', { text: 'Templates' }));
        tpl.forEach(function (t) { t.kindText = TU_KIND[t.kind] || t.kind; t.versions = textOf(t.versionBefore || '-') + ' -> ' + textOf(t.versionAfter || '-'); t.name = t.nameAfter || t.nameBefore; t.changeCount = (t.changes || []).length;
          var ps = t.policies || []; t.yours = ps.length ? fmtNum(ps.length) + ' (' + fmtNum(ps.filter(function (x) { return !x.matches; }).length) + ' differ)' : 'none'; });
        var tcols = [{ key: 'id', label: 'Template', render: function (t) { return el('button', { type: 'button', class: 'link', text: t.id, onclick: function () { tuDetail(slot, t); } }); } },
          { key: 'kindText', label: 'What', type: 'cat' }, { key: 'versions', label: 'Version' }, { key: 'name', label: 'Name', wrap: true }, { key: 'persona', label: 'Persona', type: 'cat' },
          { key: 'changeCount', label: 'Changed settings', type: 'num' }, { key: 'yours', label: 'Your policies' }];
        if (admin) tcols.push({ key: '_a', label: '', render: function (t) { return el('button', { type: 'button', class: 'link', text: 'Mark as seen', onclick: function () { tuSeen([t]); } }); } });
        p.appendChild(table(tpl, tcols, { sort: 'id', dir: 1, bulk: admin ? [{ label: 'Mark as seen', run: function (sel) { tuSeen(sel); } }] : [] }));
      }
      p.appendChild(slot);
    });
  }

  // GET-STARTED (owner 2026-11-03: "i also need a get started wizard to onboard fxbreak glass, auth methods, naming conv
  // for groups etc. see all req in v1 scripts"; DESIGN §5.10): each step with what the engine found in the tenant. The
  // check only reads; what is missing is created step by step in later releases ("Check + create on approval").
  var GS_STATE = { ok: 'ready', missing: 'missing', check: 'check', info: 'info', unknown: 'not checked' };
  var GS_CLS = { missing: 'c-danger', check: 'c-warning', unknown: 'smeta' };
  function gsBreakGlassEdit(a) {
    var d = el('dialog', { class: 'dlg-wide', 'aria-label': 'Break-glass account' });
    var closed = false;
    var close = function () { if (closed) return; closed = true; try { d.close(); } catch (e) { /* closed */ } if (d.parentNode) d.parentNode.removeChild(d); };
    d.addEventListener('close', close);
    var upn = el('input', { type: 'text', value: a ? a.UserPrincipalName : '', placeholder: 'bga-1@contoso.onmicrosoft.com', style: 'width:100%' }); if (a) upn.readOnly = true;
    var dn = el('input', { type: 'text', value: a && a.DisplayName ? a.DisplayName : '', style: 'width:100%' });
    var mth = el('select', null, ['', 'FIDO', 'MFA'].map(function (v) { var o = el('option', { value: v, text: v || '(not set)' }); if (a && a.AuthenticationMethod === v) o.selected = true; return o; }));
    var pl = el('input', { type: 'text', value: a && a.Placement ? a.Placement : '', placeholder: 'e.g. the safe at the head office - never a password', style: 'width:100%' });
    var en = el('input', { type: 'checkbox' }); en.checked = a ? !!a.Enabled : true;
    d.appendChild(el('h3', { text: a ? 'Break-glass account ' + a.UserPrincipalName : 'Add a break-glass account' }));
    d.appendChild(el('div', { class: 'guide', text: 'Entra Policy Suite\'s list of the emergency accounts every Conditional Access policy must exclude. Saving changes the list only - nothing in the tenant. Never write a password here.' }));
    [['User principal name', upn], ['Display name', dn], ['Sign-in method', mth], ['Where it is kept', pl]].forEach(function (x) { d.appendChild(el('label', { class: 'fld' }, el('span', { text: x[0] }), x[1])); });
    d.appendChild(el('label', null, en, ' in use (unticked = kept in the list, not checked)'));
    var go = el('button', { type: 'button', text: 'Save' });
    go.addEventListener('click', function () {
      close();
      withReason('Save break-glass account ' + upn.value.trim(), 'Changes Entra Policy Suite\'s break-glass list only - nothing in the tenant.', function (reason) {
        return api('POST', '/api/breakglass', { upn: upn.value.trim(), displayName: dn.value.trim(), method: mth.value, placement: pl.value.trim(), enabled: en.checked, reason: reason }); });
    });
    d.appendChild(el('div', { class: 'toolbar' }, go, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: close })));
    document.body.appendChild(d); d.showModal(); (a ? dn : upn).focus();
  }
  function gsMethodPicker(j) {
    var sel = el('select', null, [''].concat(j.methods || []).map(function (v) { var o = el('option', { value: v, text: v || '(choose)' }); if (v === j.method) o.selected = true; return o; }));
    var go = el('button', { type: 'button', class: 'secondary', text: 'Save the method', onclick: function () {
      if (!sel.value || sel.value === j.method) return;
      withReason('Group targeting method: ' + sel.value, 'Which pilot and target group names the templates expect (v1\'s Group_Targeting_Method). Changes no group and no policy.', function (reason) {
        return api('PUT', '/api/settings/CA.GroupTargetingMethod', { value: sel.value, expected: j.method || null, reason: reason }); }); } });
    return el('div', { class: 'toolbar' }, el('span', { text: 'Method: ' }), sel, go);
  }
  // IMPORT v1 (SEC-08 row 8, 2.0.69: no person needs database rights to import v1): upload the v1 files, the server
  // reads them and shows the plan (POST /api/v1import/check - nothing saved), a SuperAdmin approves (POST /api/v1import)
  // and the engine writes it from the signed request
  function drawV1Import(p) {
    p.appendChild(el('div', { class: 'guide', text: 'Brings a v1 install over in one go: the tagging rules, the tag types and their values, the settings, the break-glass accounts, the administrative units, the target groups and the service tags. Choose the files from v1\'s DATA folder (and Entra-Policy-Suite\\Entra-ID-User-Tagging.ps1 for the attribute per tag type). Reading them saves nothing; you see what is added and what changes first. A new import replaces the rules an earlier v1 import made; rules made in this app are never touched. v1\'s files are only read. A demo file is never read.' }));
    var file = el('input', { type: 'file', multiple: true, accept: '.csv,.config,.ps1', 'aria-label': 'v1 files' });
    var errs = el('div', { class: 'errors', hidden: true });
    var out = el('div');
    var read = el('button', { type: 'button', text: 'Read the files', onclick: function () {
      errs.hidden = true; clear(out);
      var fs = Array.prototype.slice.call(file.files || []);
      if (!fs.length) { errs.hidden = false; errs.textContent = 'Choose the v1 files.'; return; }
      var demo = fs.filter(function (f) { return /demo/i.test(f.name); })[0];
      if (demo) { errs.hidden = false; errs.textContent = demo.name + ' is demo material - it is never read.'; return; }
      status('Reading the files ...');
      Promise.all(fs.map(function (f) { return f.text().then(function (t) { return { name: f.name, text: t }; }); })).then(function (arr) {
        return api('POST', '/api/v1import/check', { files: arr }).then(function (r) { status(''); v1ImportPlan(out, r, arr); });
      }).catch(function (e) { status(''); errs.hidden = false; errs.textContent = e.message; });
    } });
    p.appendChild(el('div', { class: 'toolbar' }, file, read));
    p.appendChild(errs); p.appendChild(out);
    return Promise.resolve();
  }
  function v1ImportPlan(out, r, files) {
    var pl = r.plan || {};
    out.appendChild(el('h3', { text: 'The plan' }));
    out.appendChild(el('div', { class: 'smeta', text: 'Read: ' + (r.files || []).join(', ') }));
    out.appendChild(table((pl.areas || []).map(function (a) { return { area: a.area, add: a.add, change: a.change, same: a.same, note: a.replaces !== undefined ? 'replaces ' + fmtNum(a.replaces) + ' rule(s) from an earlier v1 import; keeps ' + fmtNum(a.keeps) + ' made in this app' : '' }; }),
      [{ key: 'area', label: 'Area' }, { key: 'add', label: 'New', type: 'num' }, { key: 'change', label: 'Changed', type: 'num' }, { key: 'same', label: 'Already so', type: 'num' }, { key: 'note', label: '', wrap: true }]));
    (pl.areas || []).forEach(function (a) {
      if (!a.items || !a.items.length) return;
      var d = el('details'); d.appendChild(el('summary', { text: a.area + ': ' + fmtNum(a.add) + ' new, ' + fmtNum(a.change) + ' changed' }));
      a.items.forEach(function (x) { d.appendChild(el('div', { class: 'smeta', text: (x.state === 'add' ? 'new: ' : 'changed: ') + x.key + (x.text ? ' - ' + x.text : '') })); });
      out.appendChild(d);
    });
    if (pl.hints && pl.hints.length) { var h = el('details'); h.appendChild(el('summary', { text: 'Hints on the rules (' + fmtNum(pl.hints.length) + ') - never blocking' })); pl.hints.forEach(function (x) { h.appendChild(el('div', { class: 'smeta', text: x })); }); out.appendChild(h); }
    (pl.notMoved || []).forEach(function (x) { out.appendChild(el('div', { class: 'smeta', text: 'Not moved: ' + x })); });
    out.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', text: 'Import', onclick: function () {
      withReason('Import from v1', 'Entra Policy Suite writes this plan: ' + (pl.summary || '') + '. Nothing in the tenant changes.', function (reason) {
        return api('POST', '/api/v1import', { files: files, reason: reason }); });
    } })));
  }
  // ---- CA-GROUPS (owner 2026-11-05: "make sure to also include the underlying groups that must be provisioned and
  // managed"; "Yes, Group.ReadWrite.All"; V1-PARITY): the groups the policies use, made and kept as v1 does. Every change
  // is shown first (the plan), needs a SuperAdmin, and is applied by the engine - read back, journaled, audited.
  var GRP_KIND = { breakglass: 'break-glass', sspr: 'registration', target: 'target', pilot: 'pilot', exclude: 'exclude' };
  // the five change routes, written out (tests/Test-EpsApiReference.ps1 matches every page call to a route)
  var GRP_PATH = { create: '/api/groups/create', rule: '/api/groups/rule', members: '/api/groups/members', forceupdate: '/api/groups/forceupdate', au: '/api/groups/au' };
  var GRP_DO = { create: 'create', rule: 'set the rule', update: 'update', add: 'add member', remove: 'remove member', place: 'place in unit', skip: 'no change', refused: 'refused' };
  function grpQuery(payload) {
    var q = {}; Object.keys(payload).forEach(function (k) { var v = payload[k]; q[k] = Array.isArray(v) ? v.join(',') : v; }); return q;
  }
  function grpDialog(action, payload, title) {
    // the plan from the last read, then the reason, then the engine request (it plans again from the tenant)
    var d = el('dialog', { class: 'dlg-wide', 'aria-label': title });
    var closed = false;
    var close = function () { if (closed) return; closed = true; try { d.close(); } catch (e) { /* already closed */ } if (d.parentNode) d.parentNode.removeChild(d); };
    d.addEventListener('close', close);
    var body = el('div', null, el('p', { class: 'smeta', text: 'Working out what changes ...' }));
    d.appendChild(el('h3', { text: title }));
    d.appendChild(body);
    document.body.appendChild(d); d.showModal();
    api('GET', '/api/groups/plan?' + qs(grpQuery(Object.assign({ action: action }, payload)))).then(function (pl) {
      clear(body);
      body.appendChild(el('div', { class: 'guide', text: 'This CHANGES groups in your tenant, as v1 does. The engine applies it at its next check (within 5 minutes): it reads the groups again first and plans again from what it finds; each change is read back. Only the groups Entra Policy Suite manages are ever touched.' }));
      body.appendChild(table(pl.items || [], [{ key: 'name', label: 'Group', wrap: true }, { key: 'do', label: 'Change', type: 'cat', render: function (r) { return el('span', { class: r.do === 'refused' ? 'c-danger' : null, text: GRP_DO[r.do] || r.do }); } }, { key: 'detail', label: 'What', wrap: true }], { sort: null, empty: 'Nothing.' }));
      if (!pl.ok) {
        body.appendChild(el('p', { class: 'c-danger', text: 'Nothing to send: ' + textOf(pl.reason) }));
        body.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', class: 'secondary', text: 'Close', onclick: close })));
        return;
      }
      var reason = el('input', { type: 'text', placeholder: 'Reason (optional) - e.g. onboarding the pilot', style: 'width:100%' });
      var go = el('button', { type: 'button', text: 'Change the groups (' + pl.summary + ')' });
      go.addEventListener('click', function () {
        go.disabled = true; close();
        notice('Sending: ' + title + ' ...');
        api('POST', GRP_PATH[action], Object.assign({}, payload, { reason: reason.value.trim() }))
          .then(function (x) { afterAction(x, title); }).catch(function (e) { notice('Refused: ' + e.message, 'warn'); });
      });
      body.appendChild(el('p', null, reason));
      body.appendChild(el('div', { class: 'toolbar' }, go, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: close })));
    }).catch(function (e) { clear(body).appendChild(el('p', { class: 'c-danger', text: e.message })); body.appendChild(el('button', { type: 'button', class: 'secondary', text: 'Close', onclick: close })); });
  }
  function grpMembers(r) {
    var d = el('dialog', { class: 'dlg-wide', 'aria-label': 'Members of ' + r.name });
    var close = function () { try { d.close(); } catch (e) { /* closed */ } if (d.parentNode) d.parentNode.removeChild(d); };
    var add = el('textarea', { rows: 4, style: 'width:100%', placeholder: 'user@contoso.com - one per line' });
    var rem = el('textarea', { rows: 4, style: 'width:100%', placeholder: 'user@contoso.com - one per line' });
    var lines = function (t) { return t.value.split(/[\n,;]/).map(function (x) { return x.trim(); }).filter(function (x) { return x; }); };
    d.appendChild(el('h3', { text: 'Members of ' + r.name }));
    d.appendChild(el('p', { class: 'smeta', text: r.members === null || r.members === undefined ? 'Members: not read yet.' : 'Members now: ' + r.members + (r.kind === 'pilot' ? '. v1\'s advice: Pilot1 1-2 users, Pilot2 5-10, Pilot3 30-50.' : '.') }));
    d.appendChild(el('div', { class: 'rf-grid' }, el('div', { class: 'rf-l', text: 'Add' }), el('div', { class: 'rf-c' }, add), el('div', { class: 'rf-l', text: 'Remove' }), el('div', { class: 'rf-c' }, rem)));
    d.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', text: 'Show the change', onclick: function () {
      var a = lines(add), x = lines(rem); close();
      grpDialog('members', { name: r.name, add: a, remove: x }, 'Members of ' + r.name);
    } }), el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: close })));
    document.body.appendChild(d); d.showModal();
  }
  function drawCaGroups(p) {
    var admin = isRole('Admin'), owner = isRole('SuperAdmin');
    p.appendChild(el('div', { class: 'guide', text: 'The groups your Conditional Access policies use, as v1 makes them: the target groups of your group targeting method, the break-glass group, the registration group, and for each adopted policy its exclude group and pilot group(s). "Read the groups" reads the tenant (it changes nothing). A SuperAdmin can create a missing group, set a dynamic group\'s rule back to Entra Policy Suite\'s, change the members of an assigned pilot, exclude or break-glass group, run v1\'s group force update for one policy, and make the administrative units - always after seeing the change. A stage move sets the dynamic pilot group\'s rule for the stage, as v1 does.' }));
    capSubnav(p, 'groups');
    return api('GET', '/api/groups').then(function (j) {
      var rows = j.rows || [];
      var missing = rows.filter(function (r) { return r.canCreate; }), ruleOff = rows.filter(function (r) { return r.canRule; });
      p.appendChild(el('div', { class: 'cards' }, card(rows.length, 'groups managed'), card(missing.length, 'missing', missing.length > 0),
        card(ruleOff.length, 'dynamic rule differs', ruleOff.length > 0), card(rows.filter(function (r) { return r.inAdminUnit === false; }).length, 'not in their administrative unit')));
      p.appendChild(el('div', { class: 'toolbar' },
        admin ? el('button', { type: 'button', class: 'secondary', text: 'Read the groups', onclick: function () { withReason('Read the groups', 'The engine reads the managed groups and administrative units in the tenant. Read only: nothing changes.', function (reason) { return api('POST', '/api/groups/check', { reason: reason }); }); } }) : null,
        owner && missing.length ? el('button', { type: 'button', text: 'Create all missing (' + missing.length + ')', onclick: function () { grpDialog('create', { names: missing.map(function (r) { return r.name; }) }, 'Create the missing groups'); } }) : null,
        owner && ruleOff.length ? el('button', { type: 'button', class: 'secondary', text: 'Set every rule (' + ruleOff.length + ')', onclick: function () { grpDialog('rule', { names: ruleOff.map(function (r) { return r.name; }) }, 'Set the dynamic rules'); } }) : null,
        owner ? el('button', { type: 'button', class: 'secondary', text: 'Administrative units', onclick: function () { grpDialog('au', {}, 'Administrative units: create and place'); } }) : null,
        el('span', { class: 'count', text: 'Targeting method: ' + (j.method || 'not set (Get started, step 4)') + '. ' + (j.checkedAtUtc ? 'Last read ' : 'Not read yet.') }), j.checkedAtUtc ? timeEl(j.checkedAtUtc) : null));
      p.appendChild(el('h3', { text: 'Administrative units' }));
      p.appendChild(table(j.adminUnits || [], [{ key: 'purpose', label: 'For', type: 'cat' }, { key: 'name', label: 'Administrative unit' }, { key: 'inTenant', label: 'In the tenant', type: 'cat', cls: function (r) { return r.inTenant === 'missing' ? 'c-danger' : (r.inTenant === 'unknown' ? 'smeta' : ''); } }, { key: 'error', label: 'Note', wrap: true }], { sort: null }));
      p.appendChild(el('h3', { text: 'Groups' }));
      var cols = [{ key: 'name', label: 'Group', wrap: true }, { key: 'kind', label: 'Kind', type: 'cat', render: function (r) { return GRP_KIND[r.kind] || r.kind; } }, { key: 'assignment', label: 'Type', type: 'cat' },
        { key: 'inTenant', label: 'In the tenant', type: 'cat', cls: function (r) { return r.inTenant === 'missing' ? 'c-danger' : (r.inTenant === 'unknown' ? 'smeta' : ''); } },
        { key: 'members', label: 'Members', type: 'num' },
        { key: 'ruleOk', label: 'Rule', type: 'cat', render: function (r) { return el('span', { class: r.ruleOk === false ? 'c-warning' : null, title: r.ruleOk === false ? 'now: ' + textOf(r.ruleInTenant) + ' (' + textOf(r.processingInTenant) + ')\nshould be: ' + textOf(r.rule) + ' (' + textOf(r.processing) + ')' : textOf(r.rule), text: r.assignment !== 'Dynamic' ? '-' : (r.ruleOk === null ? 'not read' : (r.ruleOk ? 'as it should be' + (r.processing === 'Paused' ? ' (paused)' : '') : 'differs')) }); } },
        { key: 'adminUnit', label: 'Administrative unit', wrap: true, render: function (r) { return el('span', { class: r.inAdminUnit === false ? 'c-warning' : null, text: r.adminUnit + (r.inAdminUnit === false ? ' (not in it)' : (r.inAdminUnit === null ? ' (not read)' : '')) }); } },
        { key: 'templates', label: 'Used by', wrap: true, render: function (r) { return (r.templates || []).join(', '); } }];
      if (owner) cols.push({ key: '_act', label: '', render: function (r) {
        var b = [];
        if (r.canCreate) b.push(el('button', { type: 'button', text: 'Create', onclick: function () { grpDialog('create', { names: [r.name] }, 'Create ' + r.name); } }));
        if (r.canRule) b.push(el('button', { type: 'button', class: 'secondary', text: 'Set rule', onclick: function () { grpDialog('rule', { names: [r.name] }, 'Set the rule of ' + r.name); } }));
        if (r.canMembers) b.push(el('button', { type: 'button', class: 'secondary', text: 'Members', onclick: function () { grpMembers(r); } }));
        if (r.kind === 'exclude' && (r.templates || []).length) b.push(el('button', { type: 'button', class: 'link', text: 'Force update ' + r.templates[0], onclick: function () { grpDialog('forceupdate', { template: r.templates[0] }, 'Group force update for ' + r.templates[0]); } }));
        return el('span', null, b);
      } });
      p.appendChild(table(rows, cols, { empty: 'No group to manage yet: set the group targeting method (Get started) and adopt your policies.' }));
    });
  }
  // ---- GET-STARTED phase 2, the rest (V1-PARITY P7 / P8 / P9; owner 2026-11-03 "Check + create on approval"): the
  // authentication strengths, the denied-countries and trusted locations, the break-glass accounts - as v1 makes them.
  // The plan first (from the last check), then a reason; the engine reads the tenant again, writes and reads it back.
  // the four create routes, written out (tests/Test-EpsApiReference.ps1 matches every page call to a route)
  var ONB_PATH = { strengths: '/api/onboarding/strengths', deniedcountries: '/api/onboarding/deniedcountries', trusted: '/api/onboarding/trusted', breakglass: '/api/onboarding/breakglass' };
  var ONB_DO = { create: 'create', update: 'update', skip: 'no change', refused: 'cannot yet' };
  function onbDialog(action, payload, title) {
    var d = el('dialog', { class: 'dlg-wide', 'aria-label': title });
    var closed = false;
    var close = function () { if (closed) return; closed = true; try { d.close(); } catch (e) { /* already closed */ } if (d.parentNode) d.parentNode.removeChild(d); };
    d.addEventListener('close', close);
    var body = el('div', null, el('p', { class: 'smeta', text: 'Working out what changes ...' }));
    d.appendChild(el('h3', { text: title }));
    d.appendChild(body);
    document.body.appendChild(d); d.showModal();
    api('GET', '/api/onboarding/plan?' + qs(grpQuery(Object.assign({ action: action }, payload)))).then(function (pl) {
      clear(body);
      body.appendChild(el('div', { class: 'guide', text: 'This CHANGES your tenant, as v1 does. The engine applies it at its next check (within 5 minutes): it reads the tenant again first and plans again from what it finds; each change is read back. Nothing that is there already is changed, unless it says so below.' }));
      body.appendChild(table(pl.items || [], [{ key: 'name', label: 'What', wrap: true }, { key: 'do', label: 'Change', type: 'cat', render: function (r) { return el('span', { class: r.do === 'refused' ? 'c-danger' : null, text: ONB_DO[r.do] || r.do }); } }, { key: 'detail', label: 'How', wrap: true }], { sort: null, empty: 'Nothing.' }));
      if (!pl.ok) {
        body.appendChild(el('p', { class: 'c-danger', text: 'Nothing to send: ' + textOf(pl.reason) }));
        body.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', class: 'secondary', text: 'Close', onclick: close })));
        return;
      }
      var reason = el('input', { type: 'text', placeholder: 'Reason (optional) - e.g. onboarding as v1', style: 'width:100%' });
      var go = el('button', { type: 'button', text: 'Make the change (' + pl.summary + ')' });
      go.addEventListener('click', function () {
        go.disabled = true; close();
        notice('Sending: ' + title + ' ...');
        api('POST', ONB_PATH[action], Object.assign({}, payload, { reason: reason.value.trim() }))
          .then(function (x) { afterAction(x, title); }).catch(function (e) { notice('Refused: ' + e.message, 'warn'); });
      });
      body.appendChild(el('p', null, reason));
      body.appendChild(el('div', { class: 'toolbar' }, go, el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: close })));
    }).catch(function (e) { clear(body).appendChild(el('p', { class: 'c-danger', text: e.message })); body.appendChild(el('button', { type: 'button', class: 'secondary', text: 'Close', onclick: close })); });
  }
  function onbTrusted() {
    // a trusted (IP) named location: your office / NAT addresses - v1 never made one, about 90 template conditions use one
    var d = el('dialog', { class: 'dlg-wide', 'aria-label': 'A trusted location' });
    var close = function () { try { d.close(); } catch (e) { /* closed */ } if (d.parentNode) d.parentNode.removeChild(d); };
    var name = el('input', { type: 'text', maxlength: 256, placeholder: 'e.g. Office Copenhagen', style: 'width:100%' });
    var ranges = el('textarea', { rows: 5, style: 'width:100%', placeholder: '203.0.113.10/32 - one IP range (CIDR) per line' });
    var trusted = el('input', { type: 'checkbox', 'aria-label': 'Trusted' }); trusted.checked = true;
    d.appendChild(el('h3', { text: 'A trusted location (IP ranges)' }));
    d.appendChild(el('p', { class: 'smeta', text: 'Made in the tenant as an IP named location; when one by this name is there, its ranges and trust are set. The service-tag locations (Azure.Network.ServiceTag.*) are kept by their own job.' }));
    d.appendChild(el('div', { class: 'rf-grid' }, el('div', { class: 'rf-l', text: 'Name' }), el('div', { class: 'rf-c' }, name), el('div', { class: 'rf-l', text: 'IP ranges' }), el('div', { class: 'rf-c' }, ranges),
      el('div', { class: 'rf-l', text: 'Trusted' }), el('div', { class: 'rf-c' }, el('label', { class: 'rf-check' }, trusted, ' mark it as a trusted location'))));
    d.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', text: 'Show the change', onclick: function () {
      var r = ranges.value.split(/[\n,;\s]+/).map(function (x) { return x.trim(); }).filter(function (x) { return x; });
      var n = name.value.trim(); close();
      onbDialog('trusted', { name: n, ranges: r, trusted: trusted.checked }, 'Trusted location ' + n);
    } }), el('button', { type: 'button', class: 'secondary', text: 'Cancel', onclick: close })));
    document.body.appendChild(d); d.showModal();
  }
  function onbButtons(s) {
    // the create buttons of a step (SuperAdmin), from what the last check found
    var it = s.items || [];
    var st = function (k) { var x = it.filter(function (r) { return r.item === k; })[0]; return x ? x.state : null; };
    var b = [];
    if (s.key === 'auth') {
      var miss = ['FIDO', 'WHfB'].filter(function (k) { return st('strength:' + k) === 'missing'; });
      if (miss.length) b.push(el('button', { type: 'button', text: 'Create the missing strengths (' + miss.length + ')', onclick: function () { onbDialog('strengths', { names: miss }, 'Create the authentication strengths'); } }));
    }
    if (s.key === 'locations') {
      if (st('denied') === 'missing') b.push(el('button', { type: 'button', text: 'Create the denied-countries location', onclick: function () { onbDialog('deniedcountries', {}, 'Create the denied-countries location'); } }));
      if (st('denied') === 'check') b.push(el('button', { type: 'button', class: 'secondary', text: 'Add v1\'s missing countries', onclick: function () { onbDialog('deniedcountries', {}, 'Add v1\'s countries to the denied-countries location'); } }));
      b.push(el('button', { type: 'button', class: 'secondary', text: 'Add or set a trusted location', onclick: onbTrusted }));
    }
    if (s.key === 'breakglass') {
      var acc = it.filter(function (r) { return /^account:/.test(r.item || '') && r.state === 'missing'; }).map(function (r) { return r.item.substring(8); });
      if (acc.length) b.push(el('button', { type: 'button', text: 'Create the missing accounts (' + acc.length + ')', onclick: function () { onbDialog('breakglass', { names: acc }, 'Create the break-glass accounts'); } }));
    }
    return b.length ? el('div', { class: 'toolbar' }, b) : null;
  }
  function drawGetStarted(p) {
    var admin = isRole('Admin'), owner = isRole('SuperAdmin');
    p.appendChild(el('div', { class: 'guide', text: 'Everything Entra Policy Suite needs before the templates, tagging and reports work - what v1\'s scripts set up first: the engine\'s rights, the break-glass accounts, the authentication strengths, the group targeting method and the groups, administrative units, named locations, the tag attributes, mail, the hybrid worker. "Check now" reads the tenant (it changes nothing); each step says what is ready, missing or worth a look. Do the steps in any order.' }));
    // V1-IMPORT-GUIDE (owner 2026-11-03: "i am missing instructions on how to import v1 csv files for eps, where is the
    // docs for that in the gui"): the two ways in, step by step
    var v1 = el('details', { class: 'gs-step', open: true });
    v1.appendChild(el('summary', null, el('strong', { text: 'Coming from v1? Import it first' })));
    v1.appendChild(el('p', { text: 'Two ways, depending on what you want to bring over. v1\'s files are only read, never changed.' }));
    v1.appendChild(el('h4', { text: 'A. Only the tagging rules - here in the browser (Admin)' }));
    v1.appendChild(el('ol', null,
      el('li', { text: 'Open Tagging > Tagging Rules, pick Users (or Devices), and press "Import CSV ...".' }),
      el('li', { text: 'Choose "v1 files" and pick the files from v1\'s DATA folder: for users Identity_Tagging.csv and Identity_Tagging_AccountInfo.csv; for devices Device_Tagging.csv and Device_Tagging_AccountInfo.csv. Leave out Identity_Tagging_Demo_Reset.csv.' }),
      el('li', { text: 'Look at the plan it shows (the rule cards it makes, any row it cannot read, the hints) and confirm. "Replace" swaps out an earlier v1 import; rules made here are never touched.' })));
    // SEC-08 row 8 (2.0.69): B is the Import v1 page - no database right, no script; the engine writes it
    v1.appendChild(el('h4', { text: 'B. Everything - rules, tag types, settings, break-glass accounts, target groups, admin units, service tags (SuperAdmin)' }));
    v1.appendChild(el('ol', null,
      el('li', null, 'Open ', el('a', { href: '#v1import', text: 'Overview > Import v1' }), ' and choose the files from v1\'s DATA folder (Identity_Tagging*.csv, Device_Tagging*.csv, EntraNamedLocations_AzureNetworkServiceTags.csv, Entra_Policy_Suite_custom.config, Entra_Policy_Suite_locked.config) and, for the attribute per tag type, Entra-Policy-Suite\\Entra-ID-User-Tagging.ps1.'),
      el('li', { text: 'Read the files: the plan shows what is added and what changes, area by area, with the hints. Nothing is saved yet.' }),
      el('li', { text: 'Import: Entra Policy Suite writes it within 5 minutes. A new import replaces the rules an earlier v1 import made; rules made here are never touched.' }),
      el('li', { text: 'Then press "Check now" below: every step shows what the import filled and what is still missing.' })));
    p.appendChild(v1);
    return api('GET', '/api/onboarding').then(function (j) {
      var steps = j.steps || [];
      var done = steps.filter(function (s) { return s.state === 'ok'; }).length;
      p.appendChild(el('div', { class: 'cards' }, card(done + ' / ' + steps.length, 'steps ready'),
        card(steps.reduce(function (n, s) { return n + (s.counts.missing || 0); }, 0), 'items missing', steps.some(function (s) { return s.counts.missing; })),
        card(steps.reduce(function (n, s) { return n + (s.counts.check || 0); }, 0), 'items to check')));
      p.appendChild(el('div', { class: 'toolbar' },
        admin ? el('button', { type: 'button', text: 'Check now', onclick: function () { withReason('Check the onboarding steps', 'The engine reads the tenant and compares it with what Entra Policy Suite needs. Read only: nothing in the tenant changes.', function (reason) { return api('POST', '/api/onboarding/check', { reason: reason }); }); } }) : null,
        el('span', { class: 'count', text: j.checkedAtUtc ? 'Last checked ' : 'Not checked yet.' }), j.checkedAtUtc ? timeEl(j.checkedAtUtc) : null, j.checkedBy ? el('span', { class: 'count', text: ' by ' + j.checkedBy }) : null));
      steps.forEach(function (s, i) {
        var box = el('details', { class: 'gs-step' });
        if (s.state !== 'ok') box.open = true;
        box.appendChild(el('summary', null, el('strong', { text: (i + 1) + '. ' + s.title }), ' ', el('span', { class: GS_CLS[s.state] || null, text: '- ' + (GS_STATE[s.state] || s.state) + (s.counts.missing ? ', ' + s.counts.missing + ' missing' : '') + (s.counts.check ? ', ' + s.counts.check + ' to check' : '') })));
        box.appendChild(el('p', { class: 'smeta', text: s.what }));
        if (s.key === 'breakglass') {
          box.appendChild(table(j.breakGlass || [], [{ key: 'UserPrincipalName', label: 'Account' }, { key: 'DisplayName', label: 'Name' }, { key: 'AuthenticationMethod', label: 'Method', type: 'cat' },
            { key: 'Placement', label: 'Kept', wrap: true }, { key: 'Enabled', label: 'In use', type: 'cat' }, owner ? { key: '_e', label: '', render: function (a) { return el('button', { type: 'button', class: 'link', text: 'Edit', onclick: function () { gsBreakGlassEdit(a); } }); } } : null].filter(Boolean),
            { empty: 'No break-glass account in the list.' }));
          if (owner) box.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', class: 'secondary', text: 'Add a break-glass account', onclick: function () { gsBreakGlassEdit(null); } })));
        }
        if (s.key === 'method' && admin) box.appendChild(gsMethodPicker(j));
        // CA-GROUPS (Get started phase 2): a missing group is created from here - the plan first, then the engine
        var gsMissing = (s.items || []).filter(function (r) { return /^group:/.test(r.item || '') && r.state === 'missing'; }).map(function (r) { return r.item.substring(6); });
        if (owner && gsMissing.length) box.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', text: 'Create the missing groups (' + gsMissing.length + ')', onclick: function () { grpDialog('create', { names: gsMissing }, 'Create the missing groups: ' + s.title); } }), el('a', { href: '#capolicies/groups', text: 'All groups' })));
        // GET-STARTED phase 2: the strengths, the locations, the break-glass accounts (the plan first, then the engine)
        var ob = owner ? onbButtons(s) : null; if (ob) box.appendChild(ob);
        if ((s.items || []).length) box.appendChild(table(s.items, [{ key: 'title', label: 'Item', wrap: true }, { key: 'state', label: 'State', type: 'cat', cls: function (r) { return GS_CLS[r.state] || ''; }, render: function (r) { return el('span', { text: GS_STATE[r.state] || r.state }); } },
          { key: 'detail', label: 'What was found', wrap: true },
          owner ? { key: '_g', label: '', render: function (r) { return /^group:/.test(r.item || '') && r.state === 'missing' ? el('button', { type: 'button', class: 'secondary', text: 'Create', onclick: function () { grpDialog('create', { names: [r.item.substring(6)] }, 'Create ' + r.item.substring(6)); } }) : null; } } : null].filter(Boolean), { sort: null }));
        else box.appendChild(el('p', { class: 'smeta', text: 'Not checked yet - press Check now.' }));
        p.appendChild(box);
      });
    });
  }
  // ---- WORKER-GUI (2.0.82, owner 2026-11-05: "i didnt see the ad hybrid worker anywhere in the gui or where to configure
  // it or see the services" / "is that not built"): Administration > Hybrid worker - each worker with its scheduled task,
  // AD domain, environment, version and last report; the AD work queue (waiting / failed, Try again); a connection test;
  // the three commands that add a worker to THIS install; the AD environments (V1-PARITY P14)
  function workerLine(w, stale) {
    // one worker in words: what to look at first
    if (!w) return 'No hybrid worker has reported yet - AD-synced users get their tags once one runs.';
    var bits = [w.name + ' on ' + w.machine];
    if (w.stale) bits.push('LATE: last report ' + fmtNum(w.minutesSinceSeen) + ' min ago (late after ' + fmtNum(stale) + ')');
    if (w.taskProblem) bits.push('its scheduled task is ' + (w.taskState || 'off'));
    if (w.behind) bits.push('version ' + w.version + ' is behind');
    return bits.join(' - ');
  }
  function drawWorker(p) {
    p.appendChild(el('div', { class: 'guide', text: 'The hybrid worker is a small program on a domain-joined Windows server in your network. It writes the tags of AD-synced users in Active Directory and reads AD group members for the rules. It runs as the scheduled task \'EntraPolicySuite Hybrid Worker\' every 5 minutes, as its gMSA, and talks to Entra Policy Suite only through the database - nothing comes in to it. It needs no password.' }));
    return api('GET', '/api/worker').then(function (j) {
      var admin = isRole('Admin');
      // the workers
      p.appendChild(el('h3', { text: 'Workers' }));
      var bad = (j.workers || []).filter(function (w) { return w.stale || w.taskProblem || w.behind; });
      if (!(j.workers || []).length) p.appendChild(el('div', { class: 'bar bar-warn', text: 'No hybrid worker has reported yet. Tags of AD-synced users wait in the queue below until one runs - add one with the steps further down.' }));
      bad.forEach(function (w) { p.appendChild(el('div', { class: 'bar bar-warn', text: workerLine(w, j.staleMinutes) })); });
      p.appendChild(table(j.workers || [], [
        { key: 'name', label: 'Worker' }, { key: 'machine', label: 'Machine' }, { key: 'environment', label: 'AD environment', type: 'cat', render: function (w) { return w.environment || '(the only one)'; } },
        { key: 'adDomain', label: 'AD domain', render: function (w) { return (w.adDomain || '?') + (w.adServer ? ' (' + w.adServer + ')' : ''); } },
        { key: 'runAs', label: 'Runs as' }, { key: 'hostType', label: 'Host', type: 'cat' },
        { key: 'taskState', label: 'Scheduled task', type: 'cat', cls: function (w) { return w.taskProblem ? 'c-danger' : ''; }, render: function (w) { return (w.taskState || '?') + (w.taskEnabled === false ? ' (disabled)' : '') + (w.taskLastResult ? ' - last result ' + w.taskLastResult : ''); } },
        { key: 'taskNextRunUtc', label: 'Next run', type: 'date' },
        { key: 'version', label: 'Version', cls: function (w) { return w.behind ? 'c-warning' : ''; }, render: function (w) { return w.version + (w.behind ? ' (behind ' + j.release + ')' : ''); } },
        { key: 'lastSeenUtc', label: 'Last report', type: 'date', cls: function (w) { return w.stale ? 'c-danger' : 'c-good'; } },
        { key: 'lastResult', label: 'Last cycle', wrap: true }], { empty: 'No hybrid worker has reported.' }));
      // the queue
      p.appendChild(el('h3', { text: 'AD changes for the worker' }));
      var by = {}; (j.counts || []).forEach(function (c) { by[c.status] = (by[c.status] || 0) + c.count; });
      p.appendChild(el('div', { class: 'cards' }, card(by.Queued || 0, 'waiting'), card(by.Claimed || 0, 'being written now'), card(by.Done || 0, 'written and read back'), card(by.Failed || 0, 'failed', (by.Failed || 0) > 0)));
      (j.environmentsWithoutWorker || []).forEach(function (e) { p.appendChild(el('div', { class: 'bar bar-warn', text: 'AD environment ' + e + ' has no worker that reports: its changes wait. Install one with -Environment ' + e + '.' })); });
      if ((j.perDay || []).length) p.appendChild(el('details', null, el('summary', { text: 'Per day (14 days)' }), table(j.perDay, [{ key: 'day', label: 'Day' }, { key: 'queued', label: 'Queued', type: 'num' }, { key: 'done', label: 'Written', type: 'num' }, { key: 'failed', label: 'Failed', type: 'num' }], { sort: 'day', dir: -1 })));
      var pkgCols = [{ key: 'packageId', label: '#', type: 'num' }, { key: 'upn', label: 'User' }, { key: 'attribute', label: 'Attribute', type: 'cat' }, { key: 'value', label: 'Value', wrap: true },
        { key: 'environment', label: 'Environment', type: 'cat' }, { key: 'attempts', label: 'Tries', type: 'num' }, { key: 'queuedAtUtc', label: 'Queued', type: 'date' }];
      p.appendChild(el('h3', { text: 'Failed' }));
      var fcols = pkgCols.concat([{ key: 'error', label: 'Why', wrap: true }, { key: 'doneAtUtc', label: 'Failed at', type: 'date' }]);
      if (admin) fcols.push({ key: '_r', label: '', render: function (r) {
        if (r.retried) return el('span', { class: 'smeta', text: 'tried again' });
        if (!r.canRetry) return el('span', { class: 'smeta', text: 'not retried (did not match the engine\'s record)' });
        return el('button', { type: 'button', class: 'secondary', text: 'Try again', onclick: function () {
          withReason('Try again: ' + r.upn + ' ' + r.attribute, 'A new change and a new work package for the same user, attribute and value; the failed ones stay in the history. A worker takes it on its next cycle.', function (reason) { return api('POST', '/api/worker/retry', { packageId: r.packageId, reason: reason }); }); } }); } });
      p.appendChild(table(j.failed || [], fcols, { sort: 'doneAtUtc', dir: -1, empty: 'No AD change failed.' }));
      p.appendChild(el('h3', { text: 'Waiting' }));
      p.appendChild(table(j.waiting || [], pkgCols.concat([{ key: 'status', label: 'State', type: 'cat' }, { key: 'claimedBy', label: 'Taken by' }]), { sort: 'queuedAtUtc', dir: 1, empty: 'Nothing waits for the worker.' }));
      // the connection test
      p.appendChild(el('h3', { text: 'Connection test' }));
      p.appendChild(el('div', { class: 'guide', text: 'Asks a worker, on its next cycle, what it is connected to: the domain, the domain controller, the account it runs as, and whether it can read AD users. It reads AD only - nothing is written.' }));
      if (admin) {
        var envs = [''].concat((j.environments || []).map(function (e) { return e.environment; }).filter(function (v, i, a) { return a.indexOf(v) === i; }));
        var es = el('select', { 'aria-label': 'AD environment' }, envs.map(function (e) { return el('option', { value: e, text: e || 'any worker' }); }));
        p.appendChild(el('div', { class: 'toolbar' }, envs.length > 1 ? es : null, el('button', { type: 'button', text: 'Test connection', onclick: function () {
          withReason('Test the hybrid worker connection', 'A read-only request; a worker' + (es.value ? ' of ' + es.value : '') + ' answers on its next cycle (every 5 minutes). Reload this page to see the answer.', function (reason) { return api('POST', '/api/worker/test', { environment: es.value, reason: reason }); }); } })));
      }
      p.appendChild(table(j.tests || [], [{ key: 'queuedAtUtc', label: 'Asked', type: 'date' }, { key: 'requestedBy', label: 'By' }, { key: 'environment', label: 'Environment', type: 'cat' }, { key: 'status', label: 'State', type: 'cat', cls: stCell('status') },
        { key: 'worker', label: 'Answered by' }, { key: 'answer', label: 'Answer', wrap: true, render: function (t) { return t.answer || (t.status === 'Queued' ? 'waiting for the next worker cycle' : ''); } }], { sort: 'queuedAtUtc', dir: -1, empty: 'No test yet.' }));
      // add a worker
      p.appendChild(el('h3', { text: 'Add a worker' }));
      p.appendChild(el('div', { class: 'guide', text: 'Three steps, in this order. Each script is one self-contained file from invardia.com/support/eps/ - no module. The values of this install are filled in; replace what is in <angle brackets>. With several AD forests or domains, install one worker per environment (-Environment) and list the environments in Settings > Hybrid worker.' }));
      (j.setup || []).forEach(function (s) {
        var code = el('pre', { class: 'log', text: s.command });
        p.appendChild(el('div', { class: 'card' },
          el('div', { class: 'lbl', text: 'Step ' + s.step + ': ' + s.script + ' - ' + s.where }),
          el('p', { text: s.what }), el('p', { class: 'smeta', text: 'Needs: ' + s.needs }), code,
          el('button', { type: 'button', class: 'secondary', text: 'Copy', onclick: function () { if (navigator.clipboard) navigator.clipboard.writeText(s.command).then(function () { status('Copied step ' + s.step + '.'); }); } })));
      });
      // the AD environments (P14)
      p.appendChild(el('h3', { text: 'AD environments' }));
      p.appendChild(el('p', null, (j.environments || []).length ? 'Changes go to the worker of their user\'s environment: ' : 'One AD: every worker takes every change. For several forests or domains, set ',
        (j.environments || []).length ? (j.environments || []).map(function (e) { return e.suffix + ' -> ' + e.environment; }).join(', ') + '. ' : null,
        el('a', { href: '#settings', text: 'Settings > Hybrid worker' }), (j.environments || []).length ? ' changes it.' : '.'));
      if ((j.environmentErrors || []).length) p.appendChild(el('div', { class: 'bar bar-warn', text: 'Not read (not "<upn suffix>=<environment>"): ' + j.environmentErrors.join('; ') }));
    });
  }
  var PAGES = [
    { id: 'overview', label: 'Overview', role: 'Reader', draw: function (p) {
      return api('GET', '/api/overview').then(function (o) {
        p.appendChild(el('div', { class: 'cards' },
          card(o.tamperOpen, 'open tag changes not made by the engine', o.tamperOpen > 0), card(o.tamperOpenHigh, 'of them HIGH', o.tamperOpenHigh > 0),
          card(o.userRules, 'user tag rules enabled'), card(o.deviceRules, 'device tag rules enabled'),
          card(o.requestsOpen, 'job requests waiting or running'), card(o.workPackagesQueued, 'AD changes queued for the worker')));
        p.appendChild(el('h3', { text: 'The last run of each job' }));
        p.appendChild(table(o.lastRuns, [
          { key: 'Job', label: 'Job', type: 'cat', render: function (r) { return jobName(r.Job); } }, { key: 'Mode', label: 'Mode', type: 'cat' }, { key: 'Status', label: 'Status', type: 'cat', cls: stCell('Status') },
          { key: 'StartedAtUtc', label: 'Started', type: 'date' }, { key: 'Objects', label: 'Objects', type: 'num' }, { key: 'Planned', label: 'Planned', type: 'num' },
          { key: 'Applied', label: 'Applied', type: 'num' }, { key: 'Failed', label: 'Failed', type: 'num' }, { key: 'HeldReason', label: 'Held because', wrap: true }], { empty: 'No job has run yet.' }));
        // WORKER-GUI: one line per worker here; the details on Administration > Hybrid worker
        p.appendChild(el('h3', { text: 'Hybrid worker' }));
        var ws = o.workers || [], late = ws.filter(function (w) { return (Date.now() - new Date(w.LastSeenUtc).getTime()) / 60000 > (o.workerStaleMinutes || 15); });
        p.appendChild(el('p', { class: !ws.length || late.length || o.workPackagesFailed ? 'c-warning' : '' },
          !ws.length ? 'No hybrid worker has reported - AD-synced users wait for one. ' : fmtNum(ws.length) + ' worker(s), ' + (late.length ? fmtNum(late.length) + ' LATE (' + late.map(function (w) { return w.WorkerName; }).join(', ') + ')' : 'all reporting') + '; ',
          ws.length ? fmtNum(o.workPackagesQueued) + ' AD change(s) waiting, ' + fmtNum(o.workPackagesFailed) + ' failed in 7 days. ' : null,
          el('a', { href: '#worker', text: 'Hybrid worker page' })));
        // UPLINK-1: Invardia telemetry and the support state Invardia reported (shown only - no access is granted from it)
        p.appendChild(el('h3', { text: 'Invardia telemetry and support' }));
        var ul = o.uplink || {}, su = o.support;
        p.appendChild(el('p', { text: 'Telemetry: ' + (ul.last || 'the uplink job has not run yet') + (ul.heartbeatUtc ? ' - last heartbeat ' + fmtTime(ul.heartbeatUtc) : '') }));
        p.appendChild(el('p', { class: su && su.Active ? 'c-danger' : null, text: 'Invardia support: ' + (!su ? 'none reported' :
          (su.Active ? 'OPEN until ' + fmtTime(su.MaxUntilUtc) + (su.TicketNumber ? ', ticket ' + su.TicketNumber : '') + (su.AccessLevel ? ', level ' + su.AccessLevel : '') + (su.OpenedBy ? ', opened by ' + su.OpenedBy : '') + (su.Reason ? ' (' + su.Reason + ')' : '')
            : (su.State === 'open' ? 'ended ' + fmtTime(su.MaxUntilUtc) : 'closed') + ' - as reported ' + fmtTime(su.LastSeenUtc)) +
          '. Recorded only: Entra Policy Suite grants no access from it.') }));
        document.getElementById('statusCounts').textContent = '';
        var sc = document.getElementById('statusCounts');
        if (o.tamperOpen) sc.appendChild(el('span', { class: 'c-danger', text: fmtNum(o.tamperOpen) + ' open tamper event(s)' }));
      });
    } },
    { id: 'start', label: 'Get started', role: 'Reader', draw: function (p) { return drawGetStarted(p); } },
    { id: 'v1import', label: 'Import v1', role: 'SuperAdmin', draw: function (p) { return drawV1Import(p); } },
    { id: 'tamper', label: 'Tamper', role: 'Reader', draw: function (p) {
      p.appendChild(el('div', { class: 'guide', text: 'Changes to watched tags that the engine did not make. Accept one that was legitimate, or Restore: the engine writes its value back at its next run. Both need a reason and are audited.' }));
      // SEC-08 row 10: the external Azure Monitor alarm's inputs as a file for Deploy-EpsAzureMonitorAlerts.ps1 -InputFile (no database right)
      if (isRole('Admin')) p.appendChild(el('p', null, el('button', { type: 'button', class: 'secondary', text: 'Download the alarm inputs', onclick: function () {
        api('GET', '/api/tamper/alarm-inputs').then(function (j) {
          var a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(j, null, 2)], { type: 'application/json' })); a.download = 'eps-alarm-inputs.json';
          document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
        });
      } }), ' The break-glass accounts, the watched tag attributes and the known writers, as one file for the external Azure Monitor alarm (Deploy-EpsAzureMonitorAlerts.ps1 -InputFile). Download it again after any of them change.'));
      return api('GET', '/api/tamper').then(function (j) {
        var cols = [{ key: 'FoundAtUtc', label: 'Found', type: 'date' }, { key: 'Severity', label: 'Severity', type: 'cat', cls: function (r) { return 'sev-' + r.Severity; } },
          { key: 'Status', label: 'Status', type: 'cat' }, { key: 'ObjectType', label: 'Type', type: 'cat' }, { key: 'ObjectName', label: 'Object' },
          { key: 'Attribute', label: 'Attribute', type: 'cat' }, { key: 'OldValue', label: 'Was' }, { key: 'NewValue', label: 'Now' },
          { key: 'Initiator', label: 'Changed by' }, { key: 'Detail', label: 'What it means', wrap: true }, { key: 'ResolvedBy', label: 'Resolved by' }];
        if (isRole('Admin')) cols.push({ key: '_act', label: '', render: function (r) {
          if (r.Status !== 'Open') return null;
          return el('span', null,
            el('button', { type: 'button', class: 'secondary', text: 'Accept', onclick: function () { withReason('Accept this change', r.ObjectName + ': ' + r.Attribute + ' = ' + r.NewValue + '. It stays as it is.', function (reason) { return api('POST', '/api/tamper/' + r.EventId + '/accept', { reason: reason }); }); } }), ' ',
            el('button', { type: 'button', text: 'Restore', onclick: function () { withReason('Restore the value', r.ObjectName + ': ' + r.Attribute + ' goes back to the engine\'s value at the next monitor run.', function (reason) { return api('POST', '/api/tamper/' + r.EventId + '/restore', { reason: reason }); }); } }));
        } });
        var openOnly = function (sel) { return sel.filter(function (r) { return r.Status === 'Open'; }); };
        p.appendChild(table(j.rows, cols, { sort: 'FoundAtUtc', dir: -1, empty: 'No foreign change found.', bulk: isRole('Admin') ? [
          { label: 'Accept', run: function (sel) { var t = openOnly(sel); if (!t.length) { notice('None of the selected changes is open.'); return; } bulkAction('Accept changes', 'They stay as they are.', t, function (r, reason) { return api('POST', '/api/tamper/' + r.EventId + '/accept', { reason: reason }); }); } },
          { label: 'Restore', run: function (sel) { var t = openOnly(sel); if (!t.length) { notice('None of the selected changes is open.'); return; } bulkAction('Restore values', 'The engine writes its value back at the next monitor run.', t, function (r, reason) { return api('POST', '/api/tamper/' + r.EventId + '/restore', { reason: reason }); }); } }] : [] }));
      });
    } },
    { id: 'runs', label: 'Runs', role: 'Reader', draw: function (p) {
      p.appendChild(pagedTable('/api/runs', [{ key: 'job', label: 'Job', options: ['', 'UserTagging', 'DeviceTagging', 'TamperMonitor', 'Tick'] }, { key: 'status', label: 'Status', options: ['', 'Running', 'Succeeded', 'Failed', 'Held', 'PartlyFailed'] }], [
        { key: 'StartedAtUtc', label: 'Started', type: 'date' }, { key: 'Job', label: 'Job', type: 'cat', render: function (r) { return jobName(r.Job); } }, { key: 'Mode', label: 'Mode', type: 'cat' },
        { key: 'Status', label: 'Status', type: 'cat', cls: stCell('Status') }, { key: 'Objects', label: 'Objects', type: 'num' }, { key: 'Planned', label: 'Planned', type: 'num' },
        { key: 'Overwrites', label: 'Overwrites', type: 'num' }, { key: 'Applied', label: 'Applied', type: 'num' }, { key: 'Failed', label: 'Failed', type: 'num' },
        { key: 'HeldReason', label: 'Held because', wrap: true }, { key: 'RunId', label: '', render: function (r) { return el('a', { href: '#run/' + r.RunId, text: 'details' }); } }]));
      return Promise.resolve();
    } },
    { id: 'changes', label: 'Tag changes', role: 'Reader', draw: function (p, arg) {
      p.appendChild(pagedTable('/api/changes', [{ key: 'q', label: 'Search object, value, persona' }, { key: 'status', label: 'Status', options: ['', 'Planned', 'Applied', 'Failed', 'Skipped', 'Queued'] }, { key: 'runId', label: 'Run id', value: arg || '' }], [
        { key: 'AtUtc', label: 'When', type: 'date' }, { key: 'ObjectType', label: 'Type', type: 'cat' }, { key: 'ObjectName', label: 'Object' }, { key: 'Directory', label: 'Dir', type: 'cat' },
        { key: 'TagType', label: 'Tag type', type: 'cat' }, { key: 'Attribute', label: 'Attribute', type: 'cat' }, { key: 'OldValue', label: 'Was' }, { key: 'NewValue', label: 'Now' },
        { key: 'Reason', label: 'Why', type: 'cat' }, { key: 'Persona', label: 'Persona' }, { key: 'Status', label: 'Status', type: 'cat', cls: stCell('Status') }, { key: 'Via', label: 'Via', type: 'cat' }, { key: 'Error', label: 'Error', wrap: true }],
        { exportPath: '/api/changes/export' }));
      return Promise.resolve();
    } },
    { id: 'rules', label: 'Tagging Rules', role: 'Reader', draw: function (p, arg) {
      var ot = arg === 'Device' ? 'Device' : 'User';
      return api('GET', '/api/rules?objectType=' + ot).then(function (j) { drawRules(p, ot, j); });
    } },
    { id: 'identity', label: 'Identity', role: 'Reader', draw: function (p, arg) { return drawIdentity(p, arg); } },
    { id: 'tagtypes', label: 'Tag types', role: 'Reader', draw: function (p) {
      p.appendChild(el('div', { class: 'guide', text: 'A tag type is a tag the engine writes, each in its own extension attribute, with the values a rule may set. A value a rule sets cannot be removed, and two tag types cannot share an attribute. Moving a tag type that rules use to another attribute is a planned move, not a save. Dynamic groups and Conditional Access policies that read a value are not checked here: look before you remove one.' }));
      queueBanner(p);
      return api('GET', '/api/tagtypes').then(function (j) { drawTagTypes(p, j.rows); });
    } },
    { id: 'queue', label: 'Commit queue', role: 'Reader', draw: function (p) { return drawQueue(p); } },
    { id: 'conditions', label: null, role: 'Reader', draw: function (p) {
      p.appendChild(el('h2', { text: 'Condition types' }));
      p.appendChild(el('div', { class: 'guide', text: 'What a rule can test. Shipped ones come with the product (some are code: group membership, mailbox type, Teams Rooms). Your own are property conditions: any user or device property by its Graph name, compared with the rule\'s target. The next run reads a change; a condition type a rule uses cannot be deleted (switch it off instead).' }));
      queueBanner(p);
      return api('GET', '/api/conditions').then(function (j) { drawConditions(p, j.rows); });
    } },
    { id: 'capolicies', label: 'Conditional Access', role: 'Reader', draw: function (p, arg) {
      if (arg === 'doc') return drawCaDoc(p);
      if (arg === 'templates') return drawCaTemplates(p);
      if (arg === 'updates') return drawCaTemplateUpdates(p);
      if (arg === 'groups') return drawCaGroups(p);
      if (arg) { p.removeChild(p.lastChild); return drawCaPolicy(p, arg); }
      return drawCaPolicies(p); } },
    { id: 'ca', label: 'CA Policy Analyzer', role: 'Reader', draw: function (p, arg) { if (arg) { p.removeChild(p.lastChild); return drawCaAnalysis(p, arg); } return drawCa(p); } },
    { id: 'jobs', label: 'Jobs', role: 'Reader', draw: function (p) {
      p.appendChild(el('div', { class: 'guide', text: 'A schedule is daily HH:mm, weekly sun HH:mm, every 3h, every 15m or manual, in the install\'s time zone. Run now writes a request; the engine starts the job within 5 minutes. Preview shows what would change and changes nothing. Apply changes the directory: it is recorded with your name and reason, and the engine checks your role before it runs it. A new or changed rule set: preview it on everyone, apply it on a test scope (one user or a few), check them, then let the schedule run it on everyone.' }));
      return Promise.all([api('GET', '/api/jobs'), api('GET', '/api/scopes')]).then(function (both) {
        var j = both[0], scopes = both[1].rows;
        var otOf = { UserTagging: 'User', DeviceTagging: 'Device' };
        var cols = [{ key: 'Job', label: 'Job', render: function (r) { return jobName(r.Job); } }, { key: 'Schedule', label: 'Schedule' }, { key: 'Enabled', label: 'Enabled', type: 'cat' }, { key: 'LastRunUtc', label: 'Last run', type: 'date' },
          { key: 'LastStatus', label: 'Last status', type: 'cat', cls: stCell('LastStatus') }, { key: 'LastStartResult', label: 'Last start', wrap: true }];
        // the schedule and on / off per job (owner 2026-10-31: "i must be able to configure this in the patform")
        if (isRole('Admin')) cols.push({ key: '_sched', label: 'Change schedule', render: function (r) {
          if (!r.Implemented || r.Job === 'CAPolicyAnalyzer') return null;
          var inp = el('input', { type: 'text', 'aria-label': 'Schedule for ' + r.Job, value: r.Schedule, maxlength: 40, size: 14, title: "daily 01:00 · weekly sun 19:00 · every 3h · every 15m · manual" });
          var on = el('input', { type: 'checkbox', 'aria-label': r.Job + ' on' }); on.checked = !!r.Enabled;
          return el('span', null, inp, ' ', el('label', null, on, ' on'), ' ', el('button', { type: 'button', class: 'secondary', text: 'Save', onclick: function () {
            withReason('Schedule ' + r.Job + ': ' + inp.value + (on.checked ? '' : ' (off)'), on.checked ? 'The engine starts ' + r.Job + ' on this schedule from its next check (within 5 minutes).' : 'The schedule no longer starts ' + r.Job + '. Run now still works.', function (reason) {
              return api('PUT', '/api/jobs/' + r.Job + '/schedule', { schedule: inp.value.trim(), enabled: on.checked, reason: reason }); }); } }));
        } });
        if (isRole('Admin')) cols.push({ key: '_run', label: '', render: function (r) {
          if (!r.Implemented || r.Job === 'TamperMonitor') return null;
          if (r.Job === 'CAPolicyAnalyzer') return el('a', { href: '#ca', text: 'Analyse on its page' });
          var pick = el('select', { 'aria-label': 'Scope for ' + r.Job }, el('option', { value: '', text: 'everyone' }),
            scopes.filter(function (s) { return s.ObjectType === otOf[r.Job]; }).map(function (s) { return el('option', { value: 'saved:' + s.Name, text: 'scope ' + s.Name }); }), el('option', { value: 'adhoc', text: 'named now ...' }));
          var adhoc = scopeFields(); adhoc.node.hidden = true;
          pick.addEventListener('change', function () { adhoc.node.hidden = pick.value !== 'adhoc'; });
          var run = function (mode) { return function () {
            var body = { mode: mode };
            if (pick.value.indexOf('saved:') === 0) body.scopeName = pick.value.substring(6); else if (pick.value === 'adhoc') body.scope = adhoc.read();
            var who = pick.value ? 'the objects in the scope' : 'EVERYONE';
            withReason(mode + ': ' + r.Job + (pick.value ? ' (scoped)' : ''), mode === 'Apply' ? 'The job CHANGES the directory for ' + who + ' (the mass-change guard still applies).' : 'The job computes every change for ' + who + ' and writes none.', function (reason) { body.reason = reason; return api('POST', '/api/jobs/' + r.Job + '/run', body); }); }; };
          return el('span', null, pick, ' ', el('button', { type: 'button', class: 'secondary', text: 'Preview', onclick: run('Preview') }), ' ', el('button', { type: 'button', text: 'Apply', onclick: run('Apply') }), adhoc.node);
        } });
        p.appendChild(table(j.rows, cols));
        p.appendChild(el('h3', { text: 'Saved scopes' }));
        var sp = el('div');
        if (isRole('Admin')) {
          var nm = el('input', { type: 'text', 'aria-label': 'Scope name', placeholder: 'name, e.g. pilot-users', maxlength: 100 });
          var sot = el('select', { 'aria-label': 'For' }, el('option', { value: 'User', text: 'users' }), el('option', { value: 'Device', text: 'devices' }));
          var f = scopeFields();
          sp.appendChild(el('div', { class: 'toolbar' }, nm, sot, f.node, el('button', { type: 'button', text: 'Save scope', onclick: function () {
            withReason('Save scope ' + nm.value, 'A saved scope can be picked for Preview / Apply.', function (reason) { return api('PUT', '/api/scopes/' + encodeURIComponent(nm.value.trim()), { objectType: sot.value, scope: f.read(), reason: reason }); }); } })));
        }
        var scols = [{ key: 'Name', label: 'Scope' }, { key: 'ObjectType', label: 'For', type: 'cat' }, { key: 'Definition', label: 'Who', wrap: true, render: function (s) { return describeScope(s.Definition); } }, { key: 'UpdatedAtUtc', label: 'Changed', type: 'date' }];
        if (isRole('Admin')) scols.push({ key: '_d', label: '', render: function (s) { return el('button', { type: 'button', class: 'link', text: 'Delete', onclick: function () { withReason('Delete scope ' + s.Name, 'Requests already made with it keep their copy.', function (reason) { return api('DELETE', '/api/scopes/' + encodeURIComponent(s.Name), { reason: reason }); }); } }); } });
        sp.appendChild(table(scopes, scols, { sort: 'Name', dir: 1, empty: 'No saved scope yet.', bulk: isRole('Admin') ? [{ label: 'Delete', run: function (sel) { bulkAction('Delete scopes', 'Requests already made with them keep their copy.', sel, function (s, reason) { return api('DELETE', '/api/scopes/' + encodeURIComponent(s.Name), { reason: reason }); }); } }] : [] }));
        p.appendChild(sp);
        p.appendChild(el('h3', { text: 'Requests' }));
        p.appendChild(table(j.requests, [{ key: 'RequestedAtUtc', label: 'Requested', type: 'date' }, { key: 'Job', label: 'Job', type: 'cat', render: function (r) { return jobName(r.Job); } }, { key: 'Mode', label: 'Mode', type: 'cat' },
          { key: 'RequestedBy', label: 'By' }, { key: 'Reason', label: 'Reason', wrap: true }, { key: 'Status', label: 'Status', type: 'cat', cls: stCell('Status') }, { key: 'StatusText', label: 'Result', wrap: true },
          { key: 'RunId', label: '', render: function (r) { return r.RunId ? el('a', { href: '#run/' + r.RunId, text: 'run' }) : null; } }], { sort: 'RequestedAtUtc', dir: -1, empty: 'No requests yet.' }));
      });
    } },
    { id: 'worker', label: 'Hybrid worker', role: 'Reader', draw: drawWorker },
    { id: 'settings', label: 'Settings', role: 'Reader', draw: function (p) {
      p.appendChild(el('div', { class: 'guide', text: 'Every behaviour of Entra Policy Suite is a setting. "More info" explains each one: what it does, what happens when it is on or off, the risk, and what it needs. A save needs a reason, is checked before it is stored, and goes into the audit trail and the setting\'s history (where an earlier value can be put back).' }));
      return api('GET', '/api/settings').then(function (j) {
        j.groups.forEach(function (g) {
          var rows = j.rows.filter(function (r) { return r.group === g.id; });
          if (!rows.length) return;
          p.appendChild(el('h3', { text: g.label }));
          var list = el('div', { class: 'settings' });
          rows.forEach(function (r) { list.appendChild(settingRow(r)); });
          p.appendChild(list);
          if (g.id === 'Mail' && isRole('Admin')) p.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', class: 'secondary', text: 'Send a test mail', onclick: function () {
            withReason('Send a test mail', 'The engine sends one mail from the sender mailbox to the alert recipients, as its own identity - the way every alert goes.', function (reason) { return api('POST', '/api/mail/test', { reason: reason }); }); } })));
        });
        if (j.unknown.length) {
          p.appendChild(el('h3', { text: 'Other stored settings' }));
          p.appendChild(el('div', { class: 'guide', text: 'Stored in the database but not in this version\'s settings catalog: nothing reads them. Shown so that nothing is hidden.' }));
          p.appendChild(table(j.unknown, [{ key: 'key', label: 'Setting' }, { key: 'value', label: 'Value', wrap: true }, { key: 'updatedAtUtc', label: 'Changed', type: 'date' }, { key: 'updatedBy', label: 'By' }], { sort: 'key', dir: 1 }));
        }
      });
    } },
    { id: 'access', label: 'Access', role: 'Admin', draw: function (p) {
      p.appendChild(el('div', { class: 'guide', text: 'Who may use this app. Reader sees everything except the audit trail and this list; Admin runs jobs and resolves tamper events; SuperAdmin manages this list. Anyone else who signs in is a Reader. The last SuperAdmin cannot be removed.' }));
      return api('GET', '/api/access').then(function (j) {
        if (isRole('SuperAdmin')) {
          var who = el('input', { type: 'text', placeholder: 'user@contoso.com', 'aria-label': 'User principal name' });
          var role = el('select', { 'aria-label': 'Role' }, ['Reader', 'Admin', 'SuperAdmin'].map(function (r) { return el('option', { value: r, text: r }); }));
          p.appendChild(el('div', { class: 'toolbar' }, who, role, el('button', { type: 'button', text: 'Grant', onclick: function () {
            withReason('Grant ' + role.value, who.value + ' becomes ' + role.value + '.', function (reason) { return api('PUT', '/api/access', { principal: who.value, role: role.value, reason: reason }); }); } })));
        }
        var cols = [{ key: 'Principal', label: 'Person' }, { key: 'Role', label: 'Role', type: 'cat' }, { key: 'GrantedBy', label: 'Granted by' }, { key: 'GrantedAtUtc', label: 'When', type: 'date' }, { key: 'ObjectId', label: 'Object id' }];
        if (isRole('SuperAdmin')) cols.push({ key: '_rm', label: '', render: function (r) { return el('button', { type: 'button', class: 'secondary', text: 'Remove', onclick: function () { withReason('Remove access', r.Principal + ' becomes a Reader (as anyone who is not named).', function (reason) { return api('DELETE', '/api/access/' + encodeURIComponent(r.Principal), { reason: reason }); }); } }); } });
        p.appendChild(table(j.rows, cols, { bulk: isRole('SuperAdmin') ? [{ label: 'Remove access', run: function (sel) { bulkAction('Remove access', 'They become Readers (as anyone who is not named).', sel, function (r, reason) { return api('DELETE', '/api/access/' + encodeURIComponent(r.Principal), { reason: reason }); }); } }] : [] }));
      });
    } },
    { id: 'audit', label: 'Audit', role: 'Admin', draw: function (p) {
      p.appendChild(pagedTable('/api/audit', [{ key: 'q', label: 'Search actor, action, target, change' },
        { key: 'category', label: 'Category', options: ['', 'access', 'setting', 'rule', 'tagtype', 'tagvalue', 'condition', 'scope', 'queue', 'job', 'tamper', 'mail', 'audit', 'changes', 'auth', 'web', 'guard', 'identity', 'ca', 'setup', 'update', 'support', 'backup', 'v1import', 'worker'] }, { key: 'outcome', label: 'Outcome', options: ['', 'ok', 'error', 'refused', 'held'] },
        { key: 'from', label: 'From', type: 'date' }, { key: 'to', label: 'To', type: 'date' }], [
        { key: 'TsUtc', label: 'When', type: 'date' }, { key: 'Action', label: 'Action', type: 'cat' }, { key: 'Actor', label: 'Who' }, { key: 'ActorSource', label: 'From', type: 'cat' },
        { key: 'Target', label: 'Target', wrap: true }, { key: 'Reason', label: 'Reason', wrap: true }, { key: 'Outcome', label: 'Outcome', type: 'cat', cls: stCell('Outcome') }, { key: 'OutcomeText', label: 'Detail', wrap: true },
        { key: 'AfterJson', label: 'Change', wrap: true, render: function (r) { return (r.BeforeJson ? r.BeforeJson + ' → ' : '') + (r.AfterJson || ''); } }, { key: 'WhatIf', label: 'Plan', type: 'cat' }],
        { exportPath: '/api/audit/export' }));
      return Promise.resolve();
    } },
    // the API reference (framework APIDOC-1): generated from the route table of the version that runs, filtered to the role
    { id: 'apiref', label: 'API reference', role: 'Reader', draw: function (p) {
      // owner 2026-11-01: "api mcp is pro" - the routes are this app's own backend; API access for scripts is Pro (coming)
      p.appendChild(el('div', { class: 'guide', text: 'API access for scripts is part of Entra Policy Suite Pro (coming). In this edition the routes below are the backend of this app\'s own pages, used by a signed-in person through the app.' }));
      p.appendChild(el('div', { class: 'guide', text: 'The web API of this version, generated from its code: every route your role (' + me.role + ') may call, with its parameters, its answer, its errors and its audit action. The pages of this app use the same routes.' }));
      return api('GET', '/api/reference').then(function (j) {
        var search = el('input', { type: 'search', placeholder: 'Search method, path, text, parameters, audit action', 'aria-label': 'Search the API reference', size: 48 });
        var count = el('span', { class: 'count' }), host = el('div', { class: 'apiref' });
        p.appendChild(el('div', { class: 'toolbar' }, search, count));
        p.appendChild(el('p', { class: 'apiref-codes', text: Object.keys(j.errorCodes || {}).map(function (k) { return k + ' ' + j.errorCodes[k]; }).join(' · ') }));
        p.appendChild(host);
        var areas = [];
        j.routes.forEach(function (r) { if (areas.indexOf(r.area) < 0) areas.push(r.area); });
        var words = function (r) { return [r.area, r.method, r.path, r.role, r.summary, r.parameters, r.answer, r.applied, (r.audit || []).join(' ')].join(' ').toLowerCase(); };
        var params = function (r) { return (r.parameters ? r.in + ': ' + r.parameters : '') + (/^optional/.test(r.reason || '') ? (r.parameters ? '; ' : '') + 'reason (optional, a note kept in the audit trail)' : ''); };
        var draw = function () {
          var q = search.value.trim().toLowerCase(), n = 0;
          clear(host);
          areas.forEach(function (a) {
            var rows = j.routes.filter(function (r) { return r.area === a && (!q || words(r).indexOf(q) >= 0); });
            if (!rows.length) return;
            n += rows.length;
            var tb = el('tbody');
            rows.forEach(function (r) {
              tb.appendChild(el('tr', null,
                el('td', null, el('code', { text: r.method })),
                el('td', { class: 'wrap' }, el('code', { text: r.path }), (r.pathParams || []).length ? el('div', { class: 'apiref-sub', text: r.pathParams.map(function (x) { return '{' + x.name + '}: ' + x.value; }).join('; ') }) : null),
                el('td', { text: r.role }),
                el('td', { class: 'wrap', text: r.summary }),
                el('td', { class: 'wrap', text: params(r) }),
                el('td', { class: 'wrap', text: r.answer + ' - ' + r.applied }),
                el('td', { text: (r.errors || []).join(', ') }),
                el('td', { class: 'wrap', text: (r.audit || []).join(', ') })));
            });
            host.appendChild(el('h3', { text: a }));
            host.appendChild(el('div', { class: 'twrap' }, el('table', { class: 'grid' }, el('thead', null, el('tr', null, ['Method', 'Path', 'Role', 'What it does', 'Parameters', 'Answer', 'Errors', 'Audit'].map(function (h) { return el('th', { text: h }); }))), tb)));
          });
          count.textContent = fmtNum(n) + ' of ' + fmtNum(j.routes.length) + ' routes';
          if (!n) host.appendChild(el('div', { class: 'empty', text: 'No route matches the search.' }));
        };
        search.addEventListener('input', draw);
        draw();
      });
    } },
    { id: 'backups', label: 'Backups / Undo', role: 'Reader', draw: function (p, arg) { return drawBackups(p, arg); } },
    { id: 'run', label: null, role: 'Reader', draw: function (p, id) {
      return api('GET', '/api/runs/' + encodeURIComponent(id || '')).then(function (j) {
        var r = j.run;
        p.appendChild(el('h2', { text: jobName(r.Job) + ' - ' + r.Mode + ' - ' + r.Status }));
        p.appendChild(el('div', { class: 'cards' }, card(r.Objects, 'objects'), card(r.Planned, 'planned'), card(r.Overwrites, 'overwrites'), card(r.Applied, 'applied'), card(r.Failed, 'failed', r.Failed > 0)));
        p.appendChild(el('p', null, 'Started ', timeEl(r.StartedAtUtc), r.EndedAtUtc ? ', ended ' : '', r.EndedAtUtc ? timeEl(r.EndedAtUtc) : null, '. ', el('a', { href: '#changes/' + r.RunId, text: 'Its tag changes' })));
        if (r.HeldReason) p.appendChild(el('div', { class: 'guide', text: 'HELD: ' + r.HeldReason }));
        // UNDO-BACKUP: a tagging run that wrote tags can be undone (a new run puts the old values back)
        if (isRole('Admin') && /^(User|Device)Tagging$/.test(r.Job) && r.Mode === 'Apply' && r.Applied > 0) p.appendChild(el('div', { class: 'toolbar' }, el('button', { type: 'button', class: 'secondary', text: 'Undo this run...', onclick: function () { runUndoDialog(r.RunId); } })));
        if (r.UndoOfRunId) p.appendChild(el('p', null, 'The undo of ', el('a', { href: '#run/' + r.UndoOfRunId, text: 'this run' }), '.'));
        p.appendChild(el('h3', { text: 'Log' }));
        p.appendChild(el('pre', { class: 'log', text: j.log.map(function (l) { return fmtTime(l.AtUtc) + '  ' + l.Level + '  ' + l.Message; }).join('\n') || '(no log lines)' }));
      });
    } }
  ];
  // the tab order (owner 2026-10-31: "rules is core so it must be left in view. tamper is less importantant")
  var NAV_ORDER = ['overview', 'rules', 'identity', 'queue', 'tagtypes', 'jobs', 'runs', 'changes', 'capolicies', 'ca', 'backups', 'settings', 'worker', 'access', 'audit', 'tamper', 'apiref'];
  PAGES.sort(function (a, b) { var x = NAV_ORDER.indexOf(a.id), y = NAV_ORDER.indexOf(b.id); return (x < 0 ? 99 : x) - (y < 0 ? 99 : y); });

  // ---- navigation ------------------------------------------------------------------------------------------------
  function current() { var h = (location.hash || '#overview').substring(1); var i = h.indexOf('/'); return { id: i < 0 ? h : h.substring(0, i), arg: i < 0 ? '' : decodeURIComponent(h.substring(i + 1)) }; }
  // MENU-1 (owner 2026-11-03: "we need to restructure the menus similar to fx PIM as we have too many now"; his choice
  // "6 groups by area"): a few top menus, each a list of pages with a one-line description, as PIM Manager's.
  var NAV_GROUPS = [
    { label: 'Overview', items: [
      { hash: 'overview', label: 'Overview', desc: 'What needs attention: open tag changes, runs, findings.' },
      { hash: 'start', label: 'Get started', desc: 'What Entra Policy Suite needs before it works - checked against your tenant.' },
      { hash: 'v1import', label: 'Import v1', desc: 'Bring a v1 install over: upload its files, see the plan, approve.' }] },
    { label: 'Tagging', items: [
      { hash: 'rules', label: 'Tagging Rules', desc: 'The rules that set the tags on users and devices.' },
      { hash: 'troubleshoot', label: 'Troubleshoot tagging', desc: 'Pick accounts and see why each tag was or was not set.' },
      { hash: 'tagtypes', label: 'Tag types', desc: 'The tags Entra Policy Suite writes, each in its own attribute, with its values.' },
      { hash: 'conditions', label: 'Condition types', desc: 'What a rule can test.' },
      { hash: 'queue', label: 'Commit queue', desc: 'Rule changes waiting for an admin to commit them.' },
      { hash: 'changes', label: 'Tag changes', desc: 'Every tag Entra Policy Suite wrote, when and why.' },
      { hash: 'tamper', label: 'Tamper', desc: 'Changes to watched tags that Entra Policy Suite did not make.' }] },
    { label: 'Conditional Access', items: [
      { hash: 'capolicies', label: 'Policies', desc: 'Your policies against their templates; adopt, stage moves.' },
      { hash: 'capolicies/groups', label: 'Groups', desc: 'The groups the policies use: create, rules, members, administrative units.' },
      { hash: 'capolicies/doc', label: 'Documentation', desc: 'Every policy with its ids resolved, as Excel or CSV.' },
      { hash: 'capolicies/templates', label: 'Templates', desc: 'The template library of this release.' },
      { hash: 'capolicies/updates', label: 'Template updates', desc: 'What a newer template library brings - you decide.' },
      { hash: 'ca', label: 'CA Policy Analyzer', desc: 'Who a policy blocked or challenged in the sign-ins, and why.' }] },
    { label: 'Identity report', items: [
      { hash: 'identity', label: 'Identity report', desc: 'Users and devices, the gaps by severity, follow-up actions.' }] },
    { label: 'Jobs & runs', items: [
      { hash: 'jobs', label: 'Jobs & schedule', desc: 'Each job, its schedule, its last run; run one now.' },
      { hash: 'runs', label: 'Runs', desc: 'Every run with its log.' }] },
    { label: 'Administration', items: [
      { hash: 'settings', label: 'Settings', desc: 'Every setting with what it does.' },
      { hash: 'worker', label: 'Hybrid worker', desc: 'The AD worker: its scheduled task, AD domain, queue, connection test, how to add one.' },
      { hash: 'access', label: 'Access', desc: 'Who may sign in, and their role.' },
      { hash: 'backups', label: 'Backups / Undo', desc: 'The daily backups of your policies and tagging; put something back, undo a change.' },
      { hash: 'audit', label: 'Audit', desc: 'Every change and who made it.' },
      { hash: 'apiref', label: 'API reference', desc: 'The API, route by route.' }] }
  ];
  function pageOf(id) { return PAGES.filter(function (x) { return x.id === id; })[0]; }
  function closeMenus() { Array.prototype.forEach.call(document.querySelectorAll('.nav-grp.open'), function (g) { g.classList.remove('open'); g.firstChild.setAttribute('aria-expanded', 'false'); }); }
  function drawTabs() {
    var nav = clear(document.getElementById('tabs')), c = current(), cur = c.id === 'run' ? 'runs' : c.id, full = cur + (c.arg && cur === 'capolicies' && /^(doc|templates|updates)$/.test(c.arg) ? '/' + c.arg : '');
    NAV_GROUPS.forEach(function (g) {
      var items = g.items.filter(function (it) { var pg = pageOf(it.hash.split('/')[0]); return pg && isRole(pg.role); });
      if (!items.length) return;
      var active = items.some(function (it) { return it.hash.split('/')[0] === cur; });
      var box = el('div', { class: 'nav-grp' + (active ? ' active' : '') });
      var btn = el('button', { type: 'button', class: 'tab nav-grp-btn', 'aria-haspopup': 'true', 'aria-expanded': 'false', 'aria-selected': active ? 'true' : 'false' }, g.label + ' ', el('span', { class: 'nav-caret', text: '▾' }));
      var menu = el('div', { class: 'nav-grp-menu', role: 'menu' });
      items.forEach(function (it) {
        var on = it.hash === full || (it.hash === cur && !(cur === 'capolicies' && full !== 'capolicies'));
        menu.appendChild(el('a', { href: '#' + it.hash, role: 'menuitem', class: 'nav-item' + (on ? ' on' : ''), onclick: closeMenus }, el('span', { class: 'nav-item-l', text: it.label }), el('span', { class: 'nav-item-d', text: it.desc })));
      });
      btn.addEventListener('click', function (ev) { ev.stopPropagation(); var open = box.classList.contains('open'); closeMenus(); if (!open) { box.classList.add('open'); btn.setAttribute('aria-expanded', 'true'); } });
      box.appendChild(btn); box.appendChild(menu); nav.appendChild(box);
    });
  }
  document.addEventListener('click', closeMenus);
  document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') closeMenus(); });
  function render() {
    drawTabs();
    var c = current(), pg = PAGES.filter(function (x) { return x.id === c.id; })[0] || PAGES[0];
    var main = clear(document.getElementById('page'));
    if (!isRole(pg.role)) { main.appendChild(el('div', { class: 'empty', text: 'This page needs the ' + pg.role + ' role.' })); return; }
    if (pg.label) main.appendChild(el('h2', { text: pg.label }));
    pg.draw(main, c.arg).catch(function (e) { main.appendChild(el('div', { class: 'empty', text: 'Could not load: ' + e.message })); });
  }

  // ---- version (BRAND-2.11) --------------------------------------------------------------------------------------
  var dismissed = null;
  function checkVersion(v) {
    if (!v || v === LOADED_VERSION || v === dismissed) return;
    document.getElementById('versionBarText').textContent = 'A new version of Entra Policy Suite is available (v' + v + '; this page v' + LOADED_VERSION + '). Reload when you are ready.';
    document.getElementById('versionBar').hidden = false;
  }
  function pollVersion() { api('GET', '/api/version').then(function (j) { checkVersion(j.version); }).catch(function () { }); }

  // ---- start -----------------------------------------------------------------------------------------------------
  document.addEventListener('DOMContentLoaded', function () {
    var tp = document.getElementById('themePick'); tp.value = store.get('eps.theme', 'auto');
    tp.addEventListener('change', function () { store.set('eps.theme', tp.value); if (tp.value === 'auto') document.documentElement.removeAttribute('data-theme'); else document.documentElement.setAttribute('data-theme', tp.value); });
    var np = document.getElementById('numPick'); np.value = store.get('eps.numbers', 'auto');
    np.addEventListener('change', function () { store.set('eps.numbers', np.value); render(); });
    document.getElementById('versionReload').addEventListener('click', function () { location.reload(); });
    document.getElementById('versionLater').addEventListener('click', function () { dismissed = document.getElementById('versionBarText').textContent.match(/v([^;]+);/)[1]; document.getElementById('versionBar').hidden = true; });
    document.getElementById('sessionReload').addEventListener('click', function () { location.reload(); });
    window.addEventListener('hashchange', render);
    window.addEventListener('focus', pollVersion);
    setInterval(pollVersion, 5 * 60 * 1000);
    api('GET', '/api/me').then(function (m) {
      me = m;
      document.getElementById('whoName').textContent = m.name || m.identity;
      document.getElementById('whoRole').textContent = m.role;
      document.getElementById('envName').textContent = m.environment || '-';
      document.getElementById('tenantName').textContent = m.tenantName || '-';
      document.getElementById('tenantId').textContent = m.tenantId || '';
      document.getElementById('noSuperAdmin').hidden = !m.noSuperAdmin;
      render();
      resumeRequests();
    }).catch(function (e) { status('Could not load: ' + e.message); });
  });
})();
