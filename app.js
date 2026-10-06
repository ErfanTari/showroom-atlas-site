/* Ceramic Showroom Atlas — static site (BRIEF §8). Classic script, no framework, no build step;
   works from file:// (data packs via site/pack.py) and from any static host (site/data/*.json). */
(function () {
  'use strict';

  // ---------- constants ----------
  // the markets are the countries in data/world.json; these eight are only the fallback for an empty file
  const FALLBACK_ISO = ['US', 'DE', 'FR', 'AE', 'PH', 'IL', 'RU', 'KR'];
  let ISO = FALLBACK_ISO.slice();
  const WORLD_VIEW = { center: [40, 30], zoom: 1.75 };
  const METRICS = [['consumption', 'Consumption'], ['production', 'Production'], ['imports', 'Imports'],
                   ['exports', 'Exports'], ['import_share', 'Import share']];
  const KIND = { brand_flagship: 'Flagship', multi_brand: 'Multi-brand', design_centre_suite: 'Design centre', trade_yard: 'Trade yard' };
  const ROLE = { brand_own: 'Brand-owned', master_distributor: 'Distributor', importer: 'Importer', agent: 'Agent',
                 dealer: 'Dealer', design_centre: 'Design centre' };
  const ROLE_ORDER = ['brand_own', 'master_distributor', 'importer', 'agent', 'design_centre', 'dealer'];
  const NUMBER = ['No', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine', 'Ten', 'Eleven', 'Twelve'];
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const dark = matchMedia('(prefers-color-scheme: dark)').matches;
  const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
  const region = (() => { try { return new Intl.DisplayNames(['en'], { type: 'region' }); } catch (e) { return null; } })();
  const regionName = c => (c === 'W00' || c === 'XW') ? 'World' : (region && region.of(c)) || c;
  const nf1 = new Intl.NumberFormat('en', { maximumFractionDigits: 1, minimumFractionDigits: 1 });
  const nf0 = new Intl.NumberFormat('en');

  // ---------- state ----------
  const S = { world: null, countries: {}, geo: {}, route: {}, showCD: false, showDealers: true, hoverIso: null, limit: 120 };
  try { S.showCD = localStorage.getItem('atlas.showCD') === '1'; S.showDealers = localStorage.getItem('atlas.showDealers') !== '0'; } catch (e) { /* storage may be blocked */ }
  const $ = s => document.querySelector(s);
  const panel = $('#panel'), tip = $('#tip'), crumbs = $('#crumbs');

  // ---------- data loading: JSON over http(s), data packs (<script>) on file:// ----------
  const waiters = {};
  window.ATLAS_PUT = function (key, value) { S['_' + key] = value; (waiters[key] || []).forEach(f => f(value)); delete waiters[key]; };
  function load(key, json, js) {
    if (S['_' + key]) return Promise.resolve(S['_' + key]);
    if (location.protocol === 'file:') {
      return new Promise((resolve, reject) => {
        (waiters[key] = waiters[key] || []).push(resolve);
        const s = document.createElement('script');
        s.src = js; s.onerror = () => reject(new Error('Missing ' + js + ' — run python3 site/pack.py after make export.'));
        document.head.appendChild(s);
      });
    }
    if (window.ATLAS_LOCK) {
      // locked build (site/protect.mjs): data files are AES-GCM encrypted; wait for the login, then decrypt
      return unlocked.then(k => fetch(json + '.enc').then(r => { if (!r.ok) throw new Error(json + ': HTTP ' + r.status); return r.arrayBuffer(); })
        .then(buf => decrypt(k, buf))).then(v => (S['_' + key] = v));
    }
    return fetch(json).then(r => { if (!r.ok) throw new Error(json + ': HTTP ' + r.status); return r.json(); })
      .then(v => (S['_' + key] = v));
  }

  // ---------- login for a locked build: the key is derived from user:password, never stored in the files ----------
  const b64 = t => Uint8Array.from(atob(t), c => c.charCodeAt(0));
  const decrypt = (k, buf) => crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(buf, 0, 12) }, k, new Uint8Array(buf, 12))
    .then(pt => JSON.parse(new TextDecoder().decode(pt)));
  let unlock;
  const unlocked = new Promise(r => { unlock = r; });
  async function deriveKey(user, pass) {
    const L = window.ATLAS_LOCK;
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(user.trim().toLowerCase() + ':' + pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64(L.salt), iterations: L.iter, hash: 'SHA-256' }, base,
      { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  }
  async function tryKey(k) { await decrypt(k, b64(window.ATLAS_LOCK.check).buffer); return k; }
  if (window.ATLAS_LOCK) (async () => {
    try { // same tab, already signed in
      const raw = sessionStorage.getItem('atlas.key');
      if (raw) { unlock(await tryKey(await crypto.subtle.importKey('raw', b64(raw), 'AES-GCM', true, ['decrypt']))); return; }
    } catch (e) { /* fall through to the form */ }
    const f = document.createElement('form'); f.className = 'login';
    f.innerHTML = `<h1>Ceramic Showroom Atlas</h1><label>Username <input name="u" autocomplete="username" required></label>
      <label>Password <input name="p" type="password" autocomplete="current-password" required></label>
      <button class="btn" type="submit">Sign in</button><p class="muted" role="alert"></p>`;
    document.body.appendChild(f); f.u.focus();
    f.addEventListener('submit', async ev => {
      ev.preventDefault(); const msg = f.querySelector('[role=alert]'); msg.textContent = 'Checking…';
      try {
        const k = await tryKey(await deriveKey(f.u.value, f.p.value));
        try { sessionStorage.setItem('atlas.key', btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('raw', k))))); } catch (e) { /* ignore */ }
        f.remove(); unlock(k);
      } catch (e) { msg.textContent = 'Wrong username or password.'; }
    });
  })();
  const loadWorld = () => load('world', 'data/world.json', 'data/world.js');
  // a country = core file (<iso>.json) + places parts listed in core.parts (export.py keeps each under 250 KB);
  // parts are fetched in parallel and merged once: arrays concatenate, maps merge
  const merged = {};
  const loadCountry = iso => merged[iso] || (merged[iso] = load('c_' + iso, `data/${iso}.json`, `data/${iso}.js`).then(core =>
    Promise.all((core.parts || []).map(n => { const b = n.replace(/\.json$/, ''); return load('c_' + b, 'data/' + n, 'data/' + b + '.js'); }))
      .then(parts => {
        const d = Object.assign({}, core, { showrooms: (core.showrooms || []).slice(), companies: Object.assign({}, core.companies),
          representations: (core.representations || []).slice(), sources: Object.assign({}, core.sources) });
        parts.forEach(p => {
          if (p.showrooms) d.showrooms.push(...p.showrooms);
          if (p.representations) d.representations.push(...p.representations);
          Object.assign(d.companies, p.companies || {}); Object.assign(d.sources, p.sources || {});
        });
        return load('c_' + iso + '.media', `data/${iso}.media.json`, `data/${iso}.media.js`).catch(() => ({})).then(m => {
          d.showrooms.forEach(x => { const v = m[normKey(x.name) + '|' + normKey(x.address)]; if (v) S.media[x.id] = { img: v[0], page: v[1], scope: v[2] }; });
          return d;
        });
      })));
  const loadGeo = iso => load('g_' + iso, `geo/${iso}.geojson`, `data/${iso}.geo.js`)
    .catch(() => ({ type: 'FeatureCollection', features: [] }));

  // ---------- helpers ----------
  // same as tools/atlas.py norm_name: strip accents, casefold, keep word characters
  const normKey = v => ((String(v || '').normalize('NFKD').replace(/\p{Mn}/gu, '').toLowerCase().match(/[\p{L}\p{N}_]+/gu)) || []).join(' ').replace(/_/g, ' ').trim();
  S.media = {};
  // hover photo: the company's own image (hotlinked, never copied); a company-wide picture is labelled as such
  const photo = id => {
    const m = S.media[id]; if (!m) return '';
    return `<img class="tip-img" src="${esc(m.img)}" alt="" loading="lazy" referrerpolicy="no-referrer" onerror="this.remove()">` +
      `<span class="tip-cap">${m.scope === 'place' ? 'Photo' : 'Company photo, not this branch'} · ${esc(domain(m.page || m.img))}</span>`;
  };
  const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const visible = g => S.showCD || g === 'A' || g === 'B' || g == null;
  const domain = u => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch (e) { return u; } };
  function badge(grade, src, sources) {
    const s = sources && sources[src];
    const g = grade || 'D';
    const title = s ? `${s.title || domain(s.url)} — “${(s.quote || '').slice(0, 160)}” (retrieved ${String(s.retrieved_at || '').slice(0, 10)})` : 'source';
    const href = s && /^https?:/.test(s.url) ? s.url : (s ? s.url : '#');
    return `<a class="badge g-${g}" href="${esc(href)}" target="_blank" rel="noopener" title="${esc(title)}">${g}</a>`;
  }
  const ext = (u, label) => u ? `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(label || domain(u))}</a>` : '';
  const tel = p => p ? `<a href="tel:${esc(p.replace(/[^\d+]/g, ''))}">${esc(p)}</a>` : '';
  // Google Maps link (maps.google URLs API, no key): the place search by name and address
  const gmaps = s => `<a href="https://www.google.com/maps/search/?api=1&query=${encodeURIComponent([s.name, s.address].filter(Boolean).join(', '))}" target="_blank" rel="noopener">Google Maps</a>`;
  const mail = m => m ? `<a href="mailto:${esc(m)}">${esc(m)}</a>` : '';
  function fmtMetric(m) {
    if (!m) return '';
    if (m.unit === 'pct') return nf1.format(m.value) + '<small>%</small>';
    if (m.unit === 'm2') return nf1.format(m.value / 1e6) + '<small>Mm²</small>';
    if (m.unit === 'usd') return nf1.format(m.value / 1e6) + '<small>M USD</small>';
    return nf0.format(m.value) + `<small>${esc(m.unit)}</small>`;
  }
  const byId = (obj, id) => (obj && id != null) ? obj[id] : null;

  // ---------- routing: #/iso/city/district?tab=&q=&brand=&kind=&open= ----------
  function parse() {
    const [path, qs] = location.hash.replace(/^#\/?/, '').split('?');
    const parts = path.split('/').filter(Boolean);
    const q = Object.fromEntries(new URLSearchParams(qs || ''));
    return { iso: (parts[0] || '').toUpperCase() || null, city: parts[1] || null, district: parts[2] || null, q };
  }
  function href(r, q) {
    const p = [r.iso && r.iso.toLowerCase(), r.city, r.district].filter(Boolean).join('/');
    const qs = new URLSearchParams(Object.entries(q || {}).filter(([, v]) => v != null && v !== '')).toString();
    return '#/' + p + (qs ? '?' + qs : '');
  }
  const go = (r, q) => { location.hash = href(r, q); };
  function setQuery(patch) {
    const r = parse(); const q = Object.assign({}, r.q, patch);
    history.replaceState(null, '', href(r, q)); S.limit = 120; render();
  }

  // ---------- map ----------
  // Offline base: Natural Earth land (vendor/world.js) on a water background, so the globe, the markets and the
  // showroom points draw from file:// with no network. Online, OpenFreeMap vector tiles (OpenMapTiles schema) add
  // landcover, water, roads, buildings, boundaries and place/street labels in the same grey scale.
  const W = window.ATLAS_WORLD || { world: { type: 'FeatureCollection', features: [] }, focus: { type: 'FeatureCollection', features: [] } };
  const LAND = W.world.features.concat(W.focus.features); // focus = detailed outlines; world = every other country
  const OFM = 'https://tiles.openfreemap.org';
  const FONT = ['Noto Sans Regular'];
  const C = {}; // map colours from the CSS tokens (light or dark)
  ['bg', 'accent', 'water', 'land', 'border', 'ink', 'ink-2', 'ink-3', 'cover', 'urban', 'building', 'road', 'road-lo',
   'road-hi', 'road-case', 'rail', 'halo'].forEach(k => { C[k] = css('--' + k) || css('--land'); });

  // expression helpers
  const byZoom = (base, stops) => ['interpolate', ['exponential', base], ['zoom']].concat(...stops);
  const byClass = (table, i, dflt) => ['match', ['get', 'class']].concat(...Object.entries(table).map(([k, v]) => [k, v[i]]), [dflt]);
  const isLine = ['match', ['geometry-type'], ['LineString', 'MultiLineString'], true, false];
  const ROAD_Z = [5, 8, 11, 13, 15, 17];
  const ROAD_W = { // line width (px) at ROAD_Z
    motorway: [0.7, 1.2, 2.2, 3.4, 7, 15], trunk: [0.5, 1, 1.9, 3, 6, 13], primary: [0.3, 0.8, 1.6, 2.6, 5.5, 12],
    secondary: [0, 0.4, 1.2, 2.2, 4.6, 10], tertiary: [0, 0, 0.9, 1.8, 4, 9], minor: [0, 0, 0.4, 1, 3, 7.5], service: [0, 0, 0, 0.5, 1.6, 4],
  };
  const CASE_EXTRA = [0, 0, 0.6, 1, 1.6, 2.4];
  const roadWidth = cased => byZoom(1.5, ROAD_Z.map((z, i) => [z, cased ? ['+', byClass(ROAD_W, i, 0), CASE_EXTRA[i]] : byClass(ROAD_W, i, 0)]));
  const ROAD_RANK = ['match', ['get', 'class'], 'motorway', 7, 'trunk', 6, 'primary', 5, 'secondary', 4, 'tertiary', 3, 'minor', 2, 1];
  const placeName = ['coalesce', ['get', 'name:en'], ['get', 'name:latin'], ['get', 'name']];
  const text = (size, color, extra) => ({ layout: Object.assign({ 'text-field': placeName, 'text-font': FONT, 'text-size': size, 'text-max-width': 8, 'text-padding': 3 }, extra),
    paint: { 'text-color': color, 'text-halo-color': C.halo, 'text-halo-width': 1.4, 'text-halo-blur': 0.4 } });
  // a city label moves off a showroom cluster instead of hiding under it (pt-guard reserves the pins' space)
  const NEXT_TO_PIN = { 'text-variable-anchor-offset': ['literal', ['center', [0, 0], 'top', [0, 1.9], 'bottom', [0, -1.9], 'left', [2, 0], 'right', [-2, 0]]] };
  const COUNTRY_TEXT = { 'text-transform': 'uppercase', 'text-letter-spacing': 0.08, 'text-max-width': 7 };
  const place = (id, classes, minzoom, maxzoom, size, color, extra) => Object.assign({ id, type: 'symbol', source: 'ofm', 'source-layer': 'place', minzoom, maxzoom,
    filter: ['match', ['get', 'class'], classes, true, false] }, text(size, color, Object.assign({ 'symbol-sort-key': ['coalesce', ['get', 'rank'], 99] }, extra)));

  const street = (id, minzoom, classes) => ({ id, type: 'symbol', source: 'ofm', 'source-layer': 'transportation_name', minzoom,
    filter: ['all', isLine, ['match', ['get', 'class'], classes, true, false]],
    layout: { 'symbol-placement': 'line', 'text-field': ['coalesce', ['get', 'name:latin'], ['get', 'name']], 'text-font': FONT, 'text-size': 11,
              'text-max-angle': 30, 'symbol-spacing': 320, 'text-padding': 2 },
    paint: { 'text-color': C['ink-2'], 'text-halo-color': C.road, 'text-halo-width': 1.4 } });

  // basemap layers drawn from the vector tiles; ids start with 'b-'. Below the market fill: surfaces and lines.
  const BASE_BELOW = [
    { id: 'b-ice', type: 'fill', source: 'ofm', 'source-layer': 'landcover', filter: ['==', ['get', 'class'], 'ice'], paint: { 'fill-color': C.water, 'fill-opacity': 0.7 } },
    { id: 'b-cover', type: 'fill', source: 'ofm', 'source-layer': 'landcover', minzoom: 4, filter: ['match', ['get', 'class'], ['wood', 'grass', 'wetland'], true, false],
      paint: { 'fill-color': C.cover, 'fill-opacity': byZoom(1, [[4, 0.35], [10, 0.7]]) } },
    { id: 'b-urban', type: 'fill', source: 'ofm', 'source-layer': 'landuse', minzoom: 5,
      filter: ['match', ['get', 'class'], ['residential', 'suburb', 'neighbourhood', 'commercial', 'retail', 'industrial'], true, false],
      paint: { 'fill-color': C.urban, 'fill-opacity': byZoom(1, [[5, 0.9], [13, 0.7], [16, 0.35]]) } },
    { id: 'b-park', type: 'fill', source: 'ofm', 'source-layer': 'park', minzoom: 9, paint: { 'fill-color': C.cover, 'fill-opacity': 0.7 } },
    { id: 'b-water', type: 'fill', source: 'ofm', 'source-layer': 'water', filter: ['!=', ['get', 'brunnel'], 'tunnel'], paint: { 'fill-color': C.water } },
    { id: 'b-waterway', type: 'line', source: 'ofm', 'source-layer': 'waterway', minzoom: 8, filter: ['!=', ['get', 'brunnel'], 'tunnel'],
      paint: { 'line-color': C.water, 'line-width': byZoom(1.4, [[8, 0.5], [13, 1.2], [17, 4]]) } },
    { id: 'b-building', type: 'fill', source: 'ofm', 'source-layer': 'building', minzoom: 14,
      paint: { 'fill-color': C.building, 'fill-opacity': byZoom(1, [[14, 0], [15, 0.9]]) } },
    { id: 'b-rail', type: 'line', source: 'ofm', 'source-layer': 'transportation', minzoom: 10,
      filter: ['all', isLine, ['match', ['get', 'class'], ['rail', 'transit'], true, false], ['!=', ['get', 'brunnel'], 'tunnel'], ['!', ['has', 'service']]],
      paint: { 'line-color': C.rail, 'line-opacity': 0.5, 'line-width': byZoom(1.3, [[10, 0.4], [16, 1.2]]) } },
    { id: 'b-road-case', type: 'line', source: 'ofm', 'source-layer': 'transportation', minzoom: 11,
      filter: ['all', isLine, ['match', ['get', 'class'], Object.keys(ROAD_W), true, false]],
      layout: { 'line-cap': 'round', 'line-join': 'round', 'line-sort-key': ROAD_RANK },
      paint: { 'line-color': C['road-case'], 'line-width': roadWidth(true), 'line-opacity': ['match', ['get', 'brunnel'], 'tunnel', 0.4, 1] } },
    { id: 'b-road', type: 'line', source: 'ofm', 'source-layer': 'transportation', minzoom: 4,
      filter: ['all', isLine, ['match', ['get', 'class'], Object.keys(ROAD_W), true, false]],
      layout: { 'line-cap': 'round', 'line-join': 'round', 'line-sort-key': ROAD_RANK },
      paint: { 'line-color': byZoom(1, [[6, ['match', ['get', 'class'], 'motorway', C['road-hi'], C['road-lo']]], [9, ['match', ['get', 'class'], 'motorway', C['road-hi'], C['road-lo']]], [12, C.road]]),
               'line-width': roadWidth(false), 'line-opacity': ['match', ['get', 'brunnel'], 'tunnel', 0.5, 1] } },
    { id: 'b-bound-4', type: 'line', source: 'ofm', 'source-layer': 'boundary', minzoom: 5,
      filter: ['all', ['==', ['get', 'admin_level'], 4], ['!=', ['get', 'maritime'], 1]],
      paint: { 'line-color': C['ink-3'], 'line-opacity': 0.35, 'line-dasharray': [3, 2], 'line-width': byZoom(1.2, [[5, 0.5], [12, 1]]) } },
    { id: 'b-bound-2', type: 'line', source: 'ofm', 'source-layer': 'boundary',
      filter: ['all', ['==', ['get', 'admin_level'], 2], ['!=', ['get', 'maritime'], 1], ['!=', ['get', 'disputed'], 1]],
      paint: { 'line-color': C['ink-3'], 'line-opacity': 0.6, 'line-width': byZoom(1.2, [[1, 0.4], [6, 0.9], [12, 1.6]]) } },
    { id: 'b-bound-disputed', type: 'line', source: 'ofm', 'source-layer': 'boundary',
      filter: ['all', ['==', ['get', 'admin_level'], 2], ['!=', ['get', 'maritime'], 1], ['==', ['get', 'disputed'], 1]],
      paint: { 'line-color': C['ink-3'], 'line-opacity': 0.6, 'line-dasharray': [2, 2], 'line-width': byZoom(1.2, [[1, 0.4], [6, 0.9], [12, 1.6]]) } },
  ];
  // labels: above the market fill and district polygons, below the showroom points. One font, grey scale, no POIs.
  const BASE_LABELS = [
    street('b-street-major', 13.5, ['motorway', 'trunk', 'primary', 'secondary']),
    street('b-street', 14.5, ['tertiary', 'minor', 'service']),
    place('b-hood', ['suburb', 'quarter', 'neighbourhood'], 11.5, 16.5, 11, C['ink-3'], { 'text-transform': 'uppercase', 'text-letter-spacing': 0.06 }),
    place('b-village', ['village'], 11, 17, 11, C['ink-3']),
    place('b-town', ['town'], 7, 16, ['step', ['zoom'], 11, 11, 13], C['ink-2'], NEXT_TO_PIN),
    place('b-city', ['city'], 3, 15, ['step', ['zoom'], 11, 7, 13, 10, 15], C.ink, NEXT_TO_PIN),
    // country names: the markets from the world view on, the other countries only from zoom 3
    place('b-country', ['country'], 3, 5.5, 11, C['ink-3'], COUNTRY_TEXT),
    place('b-country-mk', ['country'], 1.2, 6, ['step', ['zoom'], 11, 3, 13], C['ink-2'], COUNTRY_TEXT),
  ];
  function countryLabelFilters() { // markets come from data/world.json, so their labels are filtered at run time
    const mk = ['in', ['get', 'iso_a2'], ['literal', ISO]], country = ['==', ['get', 'class'], 'country'];
    if (map.getLayer('b-country')) map.setFilter('b-country', ['all', country, ['!', mk]]);
    if (map.getLayer('b-country-mk')) map.setFilter('b-country-mk', ['all', country, mk]);
  }

  const EMPTY = { type: 'FeatureCollection', features: [] };
  const isCD = ['match', ['get', 'grade'], ['C', 'D'], true, false];
  const map = new maplibregl.Map({
    container: 'map',
    style: {
      version: 8,
      projection: { type: 'globe' },
      glyphs: OFM + '/fonts/{fontstack}/{range}.pbf', // only fetched when the vector tiles draw a label
      sources: {
        land: { type: 'geojson', data: { type: 'FeatureCollection', features: LAND } },
        focus: { type: 'geojson', data: EMPTY, promoteId: 'iso' }, // the markets listed in data/world.json
        pts: { type: 'geojson', data: EMPTY },
        rooms: { type: 'geojson', data: EMPTY, cluster: true, clusterRadius: 38, clusterMaxZoom: 11 },
      },
      layers: [
        { id: 'water', type: 'background', paint: { 'background-color': C.water } },
        { id: 'land', type: 'fill', source: 'land', paint: { 'fill-color': C.land } },
        { id: 'land-line', type: 'line', source: 'land', paint: { 'line-color': C.border, 'line-width': 0.5 } },
        { id: 'focus-fill', type: 'fill', source: 'focus', paint: { 'fill-color': C.accent, 'fill-opacity': 0.35 } },
        { id: 'focus-line', type: 'line', source: 'focus', paint: {
          'line-color': C.accent, 'line-width': ['case', ['boolean', ['feature-state', 'sel'], false], 2, 0.6] } },
        { id: 'dist-fill', type: 'fill', source: 'pts', filter: ['==', ['geometry-type'], 'Polygon'],
          paint: { 'fill-color': C.accent, 'fill-opacity': 0.12 } },
        { id: 'dist-line', type: 'line', source: 'pts', filter: ['==', ['geometry-type'], 'Polygon'],
          paint: { 'line-color': C.accent, 'line-width': 1.5 } },
        // clusters sized by count; the bg-coloured ring keeps every mark readable over roads and labels
        { id: 'cl', type: 'circle', source: 'rooms', filter: ['has', 'point_count'],
          paint: { 'circle-color': C.accent, 'circle-opacity': 0.88, 'circle-stroke-color': C.bg, 'circle-stroke-width': 2,
                   'circle-radius': ['interpolate', ['linear'], ['get', 'point_count'], 2, 7, 10, 10, 50, 14, 200, 19, 600, 24] } },
        // multi-brand and design-centre showrooms hollow; any C/D point hollow and fainter (only drawn when toggled)
        { id: 'pt-hollow', type: 'circle', source: 'rooms',
          filter: ['all', ['!', ['has', 'point_count']], ['==', ['geometry-type'], 'Point'], ['==', ['get', 'layer'], 'showroom'], ['!=', ['get', 'kind'], 'trade_yard'],
                   ['any', ['!=', ['get', 'kind'], 'brand_flagship'], isCD]],
          paint: { 'circle-radius': ['interpolate', ['linear'], ['zoom'], 2, 2.4, 10, 5, 16, 7.5], 'circle-color': C.bg,
                   'circle-stroke-color': C.accent, 'circle-stroke-width': ['interpolate', ['linear'], ['zoom'], 2, 1.2, 12, 1.8],
                   'circle-stroke-opacity': ['case', isCD, 0.55, 1] } },
        { id: 'pt-yard', type: 'symbol', source: 'rooms',
          filter: ['all', ['!', ['has', 'point_count']], ['==', ['get', 'kind'], 'trade_yard']],
          layout: { 'icon-image': ['case', isCD, 'square-hollow', 'square'], 'icon-size': ['interpolate', ['linear'], ['zoom'], 2, 0.5, 10, 0.9, 15, 1.1], 'icon-allow-overlap': true } },
        { id: 'pt-flag', type: 'circle', source: 'rooms',
          filter: ['all', ['!', ['has', 'point_count']], ['==', ['get', 'kind'], 'brand_flagship'], ['!', isCD]],
          paint: { 'circle-radius': ['interpolate', ['linear'], ['zoom'], 2, 3, 10, 6, 16, 8.5], 'circle-color': C.accent,
                   'circle-stroke-color': C.bg, 'circle-stroke-width': 1.5 } },
        { id: 'pt-district', type: 'circle', source: 'pts',
          filter: ['all', ['==', ['geometry-type'], 'Point'], ['==', ['get', 'layer'], 'district']],
          paint: { 'circle-radius': 5, 'circle-color': 'rgba(0,0,0,0)', 'circle-stroke-color': C.accent, 'circle-stroke-width': 2 } },
        // invisible, topmost symbol layer: claims the space of every pin and cluster so basemap labels
        // are placed around them (placement runs top-down) and never sit under a showroom mark
        { id: 'pt-guard', type: 'symbol', source: 'rooms',
          layout: { 'icon-image': 'guard', 'icon-allow-overlap': true, 'icon-ignore-placement': false,
                    'icon-size': ['case', ['has', 'point_count'], ['interpolate', ['linear'], ['get', 'point_count'], 2, 1.15, 10, 1.5, 50, 2, 200, 2.7, 600, 3.3], 0.8] },
          paint: { 'icon-opacity': 0 } },
      ],
    },
    center: WORLD_VIEW.center, zoom: WORLD_VIEW.zoom, minZoom: 0.8, maxZoom: 18,
    attributionControl: { compact: true, customAttribution: 'Natural Earth · MapLibre' },
    dragRotate: false, pitchWithRotate: false,
    fadeDuration: 120,              // labels settle quickly after a flight
    maxTileCacheSize: 1200,         // keep country, city and street tiles for going back and forth
    maxTileCacheZoomLevels: 8,
    refreshExpiredTiles: false,
  });
  map.touchZoomRotate.disableRotation();
  const POINT_LAYERS = ['cl', 'pt-hollow', 'pt-yard', 'pt-flag', 'pt-district', 'dist-fill'];

  function squareIcon(hollow) {
    const n = 14, c = document.createElement('canvas'); c.width = c.height = n;
    const x = c.getContext('2d');
    x.fillStyle = C.bg; x.fillRect(0, 0, n, n);                 // ring in the background colour
    x.fillStyle = C.accent; x.fillRect(1.5, 1.5, n - 3, n - 3);
    if (hollow) { x.fillStyle = C.bg; x.fillRect(3.5, 3.5, n - 7, n - 7); }
    return x.getImageData(0, 0, n, n);
  }

  // Vector basemap: added as soon as the style is up (not on first zoom-in) so its TileJSON, glyphs and first
  // tiles load while the globe is still on the world view. A failed request is ignored: the atlas stays usable.
  let tilesOk = false;
  function addBasemap() {
    try {
      map.addSource('ofm', { type: 'vector', url: OFM + '/planet', maxzoom: 14,
        attribution: '<a href="https://openfreemap.org" target="_blank" rel="noopener">OpenFreeMap</a> © <a href="https://www.openmaptiles.org/" target="_blank" rel="noopener">OpenMapTiles</a> © <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener">OpenStreetMap</a>' });
      BASE_BELOW.forEach(l => map.addLayer(l, 'focus-fill'));
      BASE_LABELS.forEach(l => map.addLayer(l, 'cl'));
      countryLabelFilters();
    } catch (e) { /* the atlas works without the vector basemap */ }
  }
  // once real tiles arrive, the tiles take over coast, borders and land colour from Natural Earth at local zoom
  function onlineLook() {
    map.setPaintProperty('water', 'background-color', byZoom(1, [[5, C.water], [6.5, C.land]]));
    map.setPaintProperty('land-line', 'line-opacity', 0);
    map.setPaintProperty('focus-line', 'line-opacity', byZoom(1, [[7, 1], [9.5, 0]]));
    setSel(selIso);
  }
  map.on('sourcedata', e => { if (!tilesOk && e.sourceId === 'ofm' && e.tile) { tilesOk = true; onlineLook(); } });
  map.on('error', e => {
    const m = String((e.error && e.error.message) || '');
    if (e.sourceId === 'ofm' || /openfreemap|Failed to fetch|NetworkError|AJAXError/i.test(m)) return; // offline: silent
    console.error(e.error || e);
  });
  map.on('load', () => {
    map.addImage('square', squareIcon(false));
    map.addImage('square-hollow', squareIcon(true));
    map.addImage('guard', { width: 16, height: 16, data: new Uint8Array(16 * 16 * 4) });
    if (navigator.onLine !== false) addBasemap();
    // phones: start with the attribution folded behind its (i) button so it does not cover the map
    if (innerWidth <= 760) { const a = map.getContainer().querySelector('.maplibregl-ctrl-attrib'); if (a) a.classList.remove('maplibregl-compact-show'); }
    render();
  });

  function fly(opts) {
    const pad = innerWidth > 760 ? { top: 60, bottom: 30, left: 30, right: 30 } : { top: 50, bottom: 20, left: 20, right: 20 };
    const o = Object.assign({ padding: pad, essential: false }, opts);
    if (o.center && o.zoom != null) prefetch(o.center, o.zoom);
    if (reduced) map.jumpTo(o); else map.flyTo(Object.assign({ curve: 1.3 }, o));
  }
  // Start downloading the destination's vector tiles when a flight starts, not when the camera gets there:
  // the tiles are immutable and cached by the browser (max-age 10 years), so the map's own request for them
  // on arrival is served from the HTTP cache and roads and labels appear as the camera settles.
  const prefetched = new Set();
  function prefetch(center, zoom) {
    const src = tilesOk && map.getSource('ofm'), tpl = src && src.tiles && src.tiles[0];
    if (!tpl) return;
    const c = maplibregl.LngLat.convert(center), lat = Math.max(-85, Math.min(85, c.lat)) * Math.PI / 180;
    const z = Math.max(0, Math.min(14, Math.floor(zoom))), n = 2 ** z, ts = 512 * 2 ** (zoom - z); // tile size on screen, px
    const x = (c.lng + 180) / 360 * n, y = (1 - Math.log(Math.tan(lat) + 1 / Math.cos(lat)) / Math.PI) / 2 * n;
    const el = map.getContainer(), dx = el.clientWidth / 2 / ts + 0.3, dy = el.clientHeight / 2 / ts + 0.3;
    let count = 0;
    for (let j = Math.max(0, Math.floor(y - dy)); j <= Math.min(n - 1, Math.floor(y + dy)); j++) {
      for (let i = Math.floor(x - dx); i <= Math.floor(x + dx) && count < 30; i++) {
        const url = tpl.replace('{z}', z).replace('{x}', ((i % n) + n) % n).replace('{y}', j);
        if (prefetched.has(url)) continue;
        prefetched.add(url); count++;
        fetch(url).catch(() => prefetched.delete(url));
      }
    }
  }

  let selIso = null, hoverIso = null;
  function setSel(iso) {
    if (selIso && selIso !== iso) map.setFeatureState({ source: 'focus', id: selIso }, { sel: false });
    selIso = iso;
    if (iso) map.setFeatureState({ source: 'focus', id: iso }, { sel: true });
    // world: markets at 35 %; inside a country the other markets recede so the open one reads first;
    // at city zoom (with vector tiles) the tint fades out so streets and labels keep their contrast
    const sel = ['boolean', ['feature-state', 'sel'], false], hov = ['boolean', ['feature-state', 'hover'], false];
    const near = ['case', sel, 0.1, hov, iso ? 0.3 : 0.55, iso ? 0.14 : 0.35];
    map.setPaintProperty('focus-fill', 'fill-opacity', tilesOk ? byZoom(1, [[6, near], [9, ['case', sel, 0, hov, 0.12, 0.06]]]) : near);
  }
  function setHover(iso) {
    if (hoverIso === iso) return;
    if (hoverIso) map.setFeatureState({ source: 'focus', id: hoverIso }, { hover: false });
    hoverIso = iso;
    if (iso) map.setFeatureState({ source: 'focus', id: iso }, { hover: true });
    document.querySelectorAll('[data-iso]').forEach(el => el.classList.toggle('hi', el.dataset.iso === iso));
  }
  function showTip(e, html) {
    if (tip.innerHTML !== html) tip.innerHTML = html;
    tip.hidden = false;
    // keep the card on screen: flip left/up near the right and bottom edges
    const x = e.originalEvent.clientX, y = e.originalEvent.clientY, w = tip.offsetWidth, h = tip.offsetHeight;
    tip.style.left = (x + 14 + w > innerWidth ? Math.max(4, x - 14 - w) : x + 14) + 'px';
    tip.style.top = (y + 14 + h > innerHeight ? Math.max(4, y - 14 - h) : y + 14) + 'px';
  }
  const hideTip = () => { tip.hidden = true; };
  panel.addEventListener('mousemove', e => {
    const li = e.target.closest && e.target.closest('li[data-sid]');
    const h = li && photo(li.dataset.sid);
    if (h) showTip({ originalEvent: e }, h); else hideTip();
  });
  panel.addEventListener('mouseleave', hideTip);

  map.on('mousemove', 'focus-fill', e => {
    const iso = e.features[0].properties.iso; setHover(iso); map.getCanvas().style.cursor = 'pointer';
    const c = S._world && S._world.countries.find(x => x.iso2 === iso);
    const m = c && c.metrics.imports;
    showTip(e, `<b>${esc(c ? c.name : e.features[0].properties.name)}</b>` +
      (m ? `Imports ${fmtMetric(m).replace(/<\/?small>/g, ' ')} (${m.year})` : '<span class="muted">no import figure yet</span>') +
      (c && c.status === 'intel_only' ? '<br><span class="muted">intel only, not scored</span>' : ''));
  });
  map.on('mouseleave', 'focus-fill', () => { setHover(null); hideTip(); map.getCanvas().style.cursor = ''; });
  // double-click on a showroom point selects it (instead of the map's zoom-in); single click does the same
  map.on('dblclick', e => {
    const hit = map.queryRenderedFeatures(e.point, { layers: POINT_LAYERS.filter(l => map.getLayer(l)) })
      .find(h => h.properties.layer === 'showroom' && !h.properties.cluster);
    if (!hit) return;
    e.preventDefault();
    const r = parse();
    go(r, Object.assign({}, r.q, { tab: r.district ? undefined : 'showrooms', sel: hit.properties.id }));
  });
  map.on('click', e => {
    const hits = map.queryRenderedFeatures(e.point, { layers: POINT_LAYERS.filter(l => map.getLayer(l)) });
    if (hits.length) {
      const f = hits[0].properties;
      const r = parse();
      if (f.cluster) {
        map.getSource('rooms').getClusterExpansionZoom(f.cluster_id).then(z =>
          fly({ center: hits[0].geometry.coordinates, zoom: Math.min(z + 0.5, 15), duration: 700 }));
        stopSpin(); return;
      }
      if (f.layer === 'district') { go({ iso: r.iso, city: cityOfDistrict(r.iso, f.id), district: f.slug }); return; }
      if (f.layer === 'showroom') { go(r, Object.assign({}, r.q, { tab: r.district ? undefined : 'showrooms', sel: f.id })); return; }
    }
    const c = map.queryRenderedFeatures(e.point, { layers: ['focus-fill'] });
    if (c.length) { const iso = c[0].properties.iso; if (parse().iso !== iso) go({ iso }); }
  });
  POINT_LAYERS.forEach(l => {
    map.on('mousemove', l, e => {
      map.getCanvas().style.cursor = 'pointer';
      const p = e.features[0].properties;
      showTip(e, p.cluster ? `<b>${nf0.format(p.point_count)} showrooms</b>click to zoom in`
        : `<b>${esc(p.name)}</b>${esc(KIND[p.kind] || (p.layer === 'district' ? 'District' : ''))}${p.layer === 'showroom' ? photo(p.id) : ''}`);
    });
    map.on('mouseleave', l, () => { hideTip(); map.getCanvas().style.cursor = ''; });
  });

  function cityOfDistrict(iso, id) {
    const d = S['_c_' + iso]; if (!d) return null;
    const dist = d.districts.find(x => x.id === id); const city = dist && d.cities.find(c => c.id === dist.city);
    return city ? city.slug : null;
  }

  function setPoints(fc, filterFn) {
    const src = map.getSource('pts'), rooms = map.getSource('rooms'); if (!src || !rooms) return [];
    const feats = (fc ? fc.features : []).filter(f => visible(f.properties.grade) && (S.showDealers || !f.properties.dealer) && (!filterFn || filterFn(f)));
    const isRoom = f => f.properties.layer === 'showroom' && f.geometry && f.geometry.type === 'Point';
    src.setData({ type: 'FeatureCollection', features: feats.filter(f => !isRoom(f)) });
    const rs = feats.filter(isRoom);
    rooms.setData({ type: 'FeatureCollection', features: rs });
    return rs;
  }

  // ---------- markets: every country in data/world.json, outlined from vendor/world.js ----------
  let marketsKey = null;
  function setMarkets(world) {
    const rows = ((world && world.countries) || []).filter(c => c && c.iso2);
    // rank by imports in m² only; a market whose import figure is in another unit (e.g. USD) sorts after them
    const imp = c => { const m = c.metrics && c.metrics.imports; return m && m.unit === 'm2' ? m.value : -1; };
    const list = rows.length ? rows.slice().sort((a, b) => (a.status === 'intel_only') - (b.status === 'intel_only') ||
      imp(b) - imp(a) || String(a.name).localeCompare(b.name)).map(c => c.iso2.toUpperCase()) : FALLBACK_ISO.slice();
    if (list.join() === marketsKey) return;
    marketsKey = list.join(); ISO = list; countryLabelFilters();
    map.getSource('focus').setData({ type: 'FeatureCollection', features: LAND.filter(f => list.includes(f.properties.iso)) });
  }
  // country camera from its outline: the largest landmass plus the islands next to it (Corsica, Sakhalin,
  // the Visayas) or nearly as big (Mindanao), so Alaska, Hawaii or French Guiana do not pull the view away.
  // world.js keeps RU, US, CA and Fiji continuous across ±180°, so the bounds never wrap.
  const boundsCache = {};
  function countryBounds(iso) {
    if (boundsCache[iso]) return boundsCache[iso];
    const f = LAND.find(x => x.properties.iso === iso); if (!f) return null;
    const polys = (f.geometry.type === 'Polygon' ? [f.geometry.coordinates] : f.geometry.coordinates).map(p => {
      const ring = p[0], b = [Infinity, Infinity, -Infinity, -Infinity]; let a = 0;
      ring.forEach(([x, y], i) => { b[0] = Math.min(b[0], x); b[1] = Math.min(b[1], y); b[2] = Math.max(b[2], x); b[3] = Math.max(b[3], y);
        const [x2, y2] = ring[(i + 1) % ring.length]; a += (x * y2 - x2 * y); });
      return { b, a: Math.abs(a / 2) * Math.cos((b[1] + b[3]) / 2 * Math.PI / 180) };
    }).sort((p, q) => q.a - p.a);
    const big = polys[0], b = big.b.slice(), used = new Set([big]);
    for (let grew = true; grew;) {
      grew = false;
      polys.forEach(p => {
        if (used.has(p)) return;
        const near = p.b[0] <= b[2] + 3 && p.b[2] >= b[0] - 3 && p.b[1] <= b[3] + 3 && p.b[3] >= b[1] - 3;
        if (p.a >= 0.25 * big.a || (p.a >= 0.02 * big.a && near)) {
          used.add(p); grew = true;
          b[0] = Math.min(b[0], p.b[0]); b[1] = Math.min(b[1], p.b[1]); b[2] = Math.max(b[2], p.b[2]); b[3] = Math.max(b[3], p.b[3]);
        }
      });
    }
    // the high Arctic (Canada's islands, Franz Josef Land) would pull a Mercator-framed camera far north
    return (boundsCache[iso] = [[b[0], Math.max(b[1], -60)], [b[2], Math.min(b[3], 72)]]);
  }
  const framePad = () => innerWidth > 760 ? { top: 70, bottom: 40, left: 40, right: 40 } : { top: 50, bottom: 20, left: 20, right: 20 };
  function countryCamera(iso) {
    const b = countryBounds(iso);
    let cam = null;
    try { cam = b && map.cameraForBounds(b, { padding: framePad(), maxZoom: 6.5 }); } catch (e) { cam = null; }
    if (!cam) return { center: WORLD_VIEW.center, zoom: 3 };
    const c = maplibregl.LngLat.convert(cam.center).wrap();
    return { center: [c.lng, c.lat], zoom: cam.zoom };
  }

  // ---------- camera on the data: frame where the showrooms are ----------
  function robustBounds(pts, trim) {
    if (pts.length < 2) return null;
    const q = (arr, p) => arr[Math.min(arr.length - 1, Math.max(0, Math.round(p * (arr.length - 1))))];
    const xs = pts.map(p => p[0]).sort((a, b) => a - b), ys = pts.map(p => p[1]).sort((a, b) => a - b);
    const t = pts.length >= 20 ? trim : 0;
    return [[q(xs, t), q(ys, t)], [q(xs, 1 - t), q(ys, 1 - t)]];
  }
  function frame(pts, fallback, maxZoom, duration) {
    const b = robustBounds(pts, 0.04);
    if (!b) { if (pts.length === 1) fly({ center: pts[0], zoom: Math.min(maxZoom, 13), duration }); else fly(Object.assign({ duration }, fallback)); return; }
    const cam = map.cameraForBounds(b, { padding: framePad(), maxZoom });
    if (!cam) { fly(Object.assign({ duration }, fallback)); return; }
    fly({ center: cam.center, zoom: cam.zoom, duration });
  }
  // densest areas: a 0.5° grid, each hotspot = a cell plus its 8 neighbours
  function hotspots(pts, n) {
    const cell = 0.5, grid = new Map(), key = (i, j) => i + ':' + j;
    pts.forEach(p => { const k = key(Math.floor(p[0] / cell), Math.floor(p[1] / cell)); (grid.get(k) || grid.set(k, []).get(k)).push(p); });
    const used = new Set(), out = [];
    [...grid.entries()].sort((a, b) => b[1].length - a[1].length).forEach(([k]) => {
      if (out.length >= n || used.has(k)) return;
      const [i, j] = k.split(':').map(Number), members = [];
      for (let a = -1; a <= 1; a++) for (let c = -1; c <= 1; c++) { const kk = key(i + a, j + c); if (!used.has(kk) && grid.has(kk)) { used.add(kk); members.push(...grid.get(kk)); } }
      if (members.length >= 3) out.push(members);
    });
    return out;
  }

  // gentle rotation of the globe at world level while idle (off for reduced motion)
  let spinning = false, lastInteract = Date.now();
  function spin() {
    if (!spinning) return;
    if (Date.now() - lastInteract > 2500 && !map.isMoving()) { const c = map.getCenter(); map.setCenter([c.lng + 0.05, c.lat]); }
    requestAnimationFrame(spin);
  }
  function startSpin() { if (reduced || spinning) return; spinning = true; requestAnimationFrame(spin); }
  function stopSpin() { spinning = false; }
  ['mousedown', 'wheel', 'touchstart', 'keydown'].forEach(ev => addEventListener(ev, () => { lastInteract = Date.now(); }, { passive: true }));

  // ---------- rendering ----------
  function crumbsFor(r, d) {
    const out = [`<a href="#/">World</a>`];
    if (r.iso) out.push(`<span><a href="${href({ iso: r.iso })}">${esc(d ? d.country.name : r.iso)}</a></span>`);
    const city = d && r.city && d.cities.find(c => c.slug === r.city);
    if (r.city) out.push(`<span><a href="${href({ iso: r.iso, city: r.city })}">${esc(city ? city.name : r.city)}</a></span>`);
    const dist = d && r.district && d.districts.find(x => x.slug === r.district);
    if (r.district) out.push(`<span>${esc(dist ? dist.name : r.district)}</span>`);
    crumbs.innerHTML = out.join('');
  }

  let renderToken = 0;
  async function render() {
    const token = ++renderToken;
    const r = parse(); S.route = r;
    try {
      const world = await loadWorld();
      setMarkets(world);
      if (!r.iso) { if (token === renderToken) renderWorld(world); return; }
      if (!ISO.includes(r.iso)) { go({}); return; }
      const [d, geo] = await Promise.all([loadCountry(r.iso.toLowerCase()), loadGeo(r.iso.toLowerCase())]);
      if (token !== renderToken) return;
      if (r.district) renderDistrict(r, d, geo);
      else if (r.city) renderCity(r, d, geo);
      else renderCountry(r, d, geo);
    } catch (err) {
      panel.innerHTML = `<h1>Data not available</h1><p class="sub">${esc(err.message)}</p>` +
        `<p class="muted">From a local folder, run <code>make export</code> then <code>python3 site/pack.py</code>; or serve the site with <code>make serve</code>.</p>`;
    }
  }

  // World level
  let lastLevel = null;
  function renderWorld(world) {
    crumbsFor({}, null); setSel(null); setPoints(null);
    if (lastLevel !== 'world') { fly({ center: WORLD_VIEW.center, zoom: WORLD_VIEW.zoom, duration: 1200 }); lastInteract = Date.now(); }
    startSpin();
    lastLevel = 'world';
    const rows = ISO.map(iso => world.countries.find(c => c.iso2 === iso)).filter(Boolean);
    panel.innerHTML = `
      <h1>${NUMBER[rows.length] || nf0.format(rows.length)} markets</h1>
      <p class="sub">Where Anatolia should be shown: tile markets, showroom districts, showrooms, brands and who runs them.</p>
      <ul class="list">${rows.map(c => {
        const m = c.metrics.imports;
        return `<li data-iso="${c.iso2}"><a class="row-link" href="${href({ iso: c.iso2 })}">
          <div class="row-title"><b>${esc(c.name)}</b>
          <span class="right">${m ? `${fmtMetric(m).replace(/<small>/, ' <small>')} <span class="muted">${m.year}</span>` : '<span class="muted">—</span>'}</span></div>
          <div class="meta">${c.status === 'intel_only' ? 'Intel only, not scored · ' : ''}imports${m && m.derived && /mirror/i.test(m.derived) ? ' (mirror)' : ''}</div></a></li>`;
      }).join('')}</ul>
      <p class="muted" style="margin-top:14px">Hover a country to preview, click to open. Esc goes up a level.</p>`;
    panel.querySelectorAll('[data-iso]').forEach(li => {
      li.addEventListener('mouseenter', () => setHover(li.dataset.iso));
      li.addEventListener('mouseleave', () => setHover(null));
    });
  }

  function countryHead(d, r) {
    const tab = r.q.tab || 'market';
    const t = (id, label) => `<a href="${href({ iso: r.iso }, id === 'market' ? {} : { tab: id })}" ${tab === id ? 'aria-current="page"' : ''}>${label}</a>`;
    return `<h1>${esc(d.country.name)}</h1>
      <p class="sub">${d.country.status === 'intel_only' ? 'Intel only: mapped and verified, excluded from scores and recommendations.' : `${showroomsOf(d).length} showrooms · ${contactsOf(d).length} contacts · ${d.districts.length} districts`}</p>
      <nav class="tabs">${t('market', 'Market')}${t('showrooms', 'Showrooms')}${t('brands', 'Brands')}${t('contacts', 'Contacts')}</nav>`;
  }

  // Country level
  function renderCountry(r, d, geo) {
    crumbsFor(r, d); setSel(r.iso); stopSpin();
    const tab = r.q.tab || 'market';
    const rs = setPoints(geo, tab === 'showrooms' ? f => f.properties.layer !== 'showroom' || matchIds(d, r).has(f.properties.id) : null);
    const coords = rs.map(f => f.geometry.coordinates);
    S.hot = hotspots(coords, 5);
    if (lastLevel !== 'country:' + r.iso) {
      const fb = countryCamera(r.iso);
      // one flight straight to where the showrooms are (the country outline when there are none): a single
      // camera move requests one set of tiles, so roads and labels are in place soon after the camera stops
      if (coords.length) frame(coords, fb, 8.5, 1100);
      else fly(Object.assign({ duration: 900 }, fb));
    }
    lastLevel = 'country:' + r.iso;
    let body = '';
    if (tab === 'market') body = marketCard(d, r);
    else if (tab === 'showrooms') body = showroomList(d, r, showroomsOf(d));
    else if (tab === 'brands') body = brandList(d, r);
    else if (tab === 'contacts') body = contactList(d, r);
    panel.innerHTML = countryHead(d, r) + body;
    wire(d, r);
  }

  function marketCard(d, r) {
    const m = d.country.metrics || {};
    const rows = METRICS.filter(([k]) => m[k] && visible(m[k].grade)).map(([k, label]) =>
      `<div class="k">${label} <span class="muted">${m[k].year}</span>${m[k].derived && /mirror/i.test(m[k].derived) ? ' <span class="muted">mirror</span>' : ''}</div>
       <div class="v">${fmtMetric(m[k])}${badge(m[k].grade, m[k].source, d.sources)}</div>`).join('');
    let html = `<div class="metrics">${rows || '<div class="muted">No market figures yet.</div>'}</div>`;
    if (S.hot && S.hot.length) {
      const named = S.hot.map(h => ({ n: h.length, label: hotLabel(d, h), c: h }));
      html += `<h2>Where the showrooms are</h2><ul class="list">` + named.map((h, i) =>
        `<li class="clickable" data-hot="${i}"><div class="row-title"><b>${esc(h.label)}</b><span class="right">${plural(h.n, 'showroom')} on the map</span></div></li>`).join('') + '</ul>';
    }
    const om = d.origin_mix;
    if (om && om.top && om.top.length) {
      const items = om.top.filter(x => visible(x.grade)).map(x => ({ lab: regionName(x.partner), v: x.qty_m2, g: x.grade, s: x.source }));
      if (om.other_m2) items.push({ lab: 'Other', v: om.other_m2, other: true });
      const max = Math.max(...items.map(i => i.v || 0)) || 1;
      html += `<h2>Where imports come from${om.year ? ' · ' + om.year : ''}${om.mirror ? ' · mirror' : ''}</h2><div class="bars">` + items.map(i =>
        `<div class="lab" title="${esc(i.lab)}">${esc(i.lab)}</div><div class="track"><div class="fill${i.other ? ' other' : ''}" style="width:${Math.max(1, 100 * i.v / max * 0.72)}%"></div>
         <span>${nf1.format(i.v / 1e6)}</span>${i.other ? '' : badge(i.g, i.s, d.sources)}</div>`).join('') + '</div>';
    }
    const tr = (d.imports_trend || []).filter(p => p.qty_m2 != null && visible(p.grade));
    if (tr.length >= 5) html += `<h2>Imports ${tr[0].year}–${tr[tr.length - 1].year}, Mm²</h2>` + trendSvg(tr, d.sources);
    const cities = d.cities || [];
    if (cities.length) {
      html += `<h2>Cities and districts</h2><ul class="list">` + cities.map(c => {
        const ds = d.districts.filter(x => x.city === c.id);
        return `<li><a class="row-link" href="${href({ iso: r.iso, city: c.slug })}"><div class="row-title"><b>${esc(c.name)}</b>
          <span class="right">${ds.length} district${ds.length === 1 ? '' : 's'}</span></div>
          <div class="meta">${ds.slice().sort((a, b) => score(b) - score(a)).map(x => esc(x.name)).join(' · ')}</div></a></li>`;
      }).join('') + '</ul>';
    }
    return html;
  }

  // label a hotspot with the seed city whose name appears most in its showroom addresses
  function hotLabel(d, pts) {
    const inHot = new Set(pts.map(p => p[0].toFixed(5) + ',' + p[1].toFixed(5)));
    const rooms = (d.showrooms || []).filter(s => s.lat != null && inHot.has((+s.lon).toFixed(5) + ',' + (+s.lat).toFixed(5)));
    let best = null, bestN = 0;
    (d.cities || []).forEach(c => c.name.split(/\s*\/\s*/).forEach(nm => {
      const re = new RegExp('(^|[^\\p{L}])' + nm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^\\p{L}]|$)', 'iu');
      const n = rooms.filter(s => re.test(s.address)).length; if (n > bestN) { bestN = n; best = nm; }
    }));
    if (best && bestN >= rooms.length / 4) return best + ' area';
    const counts = {};
    rooms.forEach(s => { const c = cityFromAddress(s.address); if (c) counts[c] = (counts[c] || 0) + 1; });
    const top = Object.entries(counts).sort((x, y) => y[1] - x[1])[0];
    return (top ? top[0] : 'Showroom cluster') + ' area';
  }
  // "…, Williamstown, KY 41097, USA" → Williamstown; "…, 10179 Berlin (Berlin), Germany" → Berlin
  // trailing region words that locators append to the city ("LOS ANGELES CALIFORNIA", "LYON RHONE")
  const REGION_TAIL = /\s+(california|texas|florida|illinois|georgia|new jersey|new york|nevada|arizona|colorado|michigan|ohio|bouches-du-rh[oô]ne|gironde|rh[oô]ne|hauts-de-seine|val-de-marne|essonne|var|loire|ain|seine-saint-denis|seine-et-marne|vaucluse|val-d'oise|is[eè]re|haute-garonne|nord|bavaria|bayern|hesse|hessen)$/i;
  function cityFromAddress(a) {
    const parts = String(a || '').split(',').map(x => x.replace(/\s*\(.*?\)/g, '').trim()).filter(Boolean).reverse();
    for (const p of parts.slice(parts.length > 1 ? 1 : 0)) {
      const c = p.replace(/^\d[\d\s-]*/, '').replace(/\s+[A-Z]{2}\s*\d{5}(-\d{4})?$/, '').replace(/^[A-Z]{2}\s*\d{5}$/, '').trim();
      if (/\b(street|st|road|rd|avenue|ave|blvd|boulevard|drive|dr|way|lane|unit|suite|floor|building|str|straße|strasse|rue|chemin|ул|улица)\b/i.test(c)) continue;
      const cc = c.replace(REGION_TAIL, '').trim();
      if (cc && !/\d/.test(cc) && !/^[A-Z]{2}$/.test(cc) && cc.length > 2) return cc === cc.toUpperCase() && cc.length > 3 ? cc.toLowerCase().replace(/(^|[\s-])\S/g, m => m.toUpperCase()) : cc;
    }
    return '';
  }

  function trendSvg(tr, sources) {
    const w = 340, h = 90, px = 6, py = 16;
    const vs = tr.map(p => p.qty_m2), min = Math.min(...vs), max = Math.max(...vs), span = (max - min) || 1;
    const x = i => px + i * (w - 2 * px) / (tr.length - 1), y = v => py + (h - 2 * py) * (1 - (v - min) / span);
    const path = tr.map((p, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(p.qty_m2).toFixed(1)).join('');
    const dots = tr.map((p, i) => `<a href="${esc(sources[p.source] ? sources[p.source].url : '#')}" target="_blank" rel="noopener"><circle class="${p.mirror || p.derived ? 'hollow' : ''}" cx="${x(i).toFixed(1)}" cy="${y(p.qty_m2).toFixed(1)}" r="2.6"><title>${p.year}: ${nf1.format(p.qty_m2 / 1e6)} Mm²${p.mirror ? ' (mirror)' : ''} · grade ${p.grade}</title></circle></a>`).join('');
    const f = tr[0], l = tr[tr.length - 1];
    return `<svg class="trend" viewBox="0 0 ${w} ${h + 14}" role="img" aria-label="Imports trend"><path d="${path}"/>${dots}
      <text x="${x(0) + 6}" y="${y(f.qty_m2) + 4}">${nf1.format(f.qty_m2 / 1e6)}</text>
      <text x="${x(tr.length - 1)}" y="${y(l.qty_m2) - 7}" text-anchor="end">${nf1.format(l.qty_m2 / 1e6)}</text>
      <text x="${x(0)}" y="${h + 12}">${f.year}</text><text x="${x(tr.length - 1)}" y="${h + 12}" text-anchor="end">${l.year}</text></svg>`;
  }

  const score = x => (x.score && x.score.total) || 0;
  const showroomsOf = d => (d.showrooms || []).filter(s => visible(s.grade) && (S.showDealers || !s.dealer));
  const companiesWithContact = d => Object.entries(d.companies || {}).filter(([, c]) => visible(c.grade) && (c.phone || c.email || c.website));
  // every published contact: each showroom's own phone/email (its branch line), plus each company's line
  function contactsOf(d) {
    const out = [];
    showroomsOf(d).forEach(x => {
      if ((!x.phone && !x.email) || x.status === 'closed') return;
      const co = byId(d.companies, x.company) || {};
      out.push({ sid: x.id, company: x.company, name: x.name, sub: co.name && co.name !== x.name ? co.name : '', role: KIND[x.kind] || '',
        phone: x.phone, email: x.email, website: x.website || co.website, address: x.address, grade: x.grade, source: x.contact_source != null ? x.contact_source : x.source });
    });
    companiesWithContact(d).forEach(([id, c]) => out.push({ company: +id, name: c.name, sub: '', role: ROLE[c.role] || c.role || '',
      phone: c.phone, email: c.email, website: c.website, address: c.address, grade: c.grade, source: c.contact_source != null ? c.contact_source : c.source, co: c }));
    return out;
  }

  function brandSeg(d, id) { const b = byId(d.brands, id); return b && b.segment ? `style="--seg:var(--seg-${b.segment})"` : ''; }
  function matchIds(d, r) { return new Set(filterShowrooms(d, r, showroomsOf(d)).map(s => s.id)); }
  function filterShowrooms(d, r, list) {
    const q = (r.q.q || '').toLowerCase(), brand = byId(d.brands, r.q.brand) ? r.q.brand : null, kind = r.q.kind, open = r.q.open === '1';
    return list.filter(s =>
      (!q || (s.name + ' ' + s.address + ' ' + ((byId(d.companies, s.company) || {}).name || '')).toLowerCase().includes(q)) &&
      (!brand || (s.brands || []).some(b => String(b.brand) === brand)) &&
      (!kind || s.kind === kind) && (!open || s.status === 'open'));
  }

  function showroomList(d, r, base, heading) {
    let list = filterShowrooms(d, r, base).sort((a, b) =>
      (a.status === 'open' ? 0 : 1) - (b.status === 'open' ? 0 : 1) || (a.kind === 'brand_flagship' ? 0 : 1) - (b.kind === 'brand_flagship' ? 0 : 1) || a.name.localeCompare(b.name));
    // the showroom picked on the map goes first, so it is always rendered (even past "Show more" or a filter)
    const picked = r.q.sel != null && (d.showrooms || []).find(s => String(s.id) === String(r.q.sel));
    if (picked) list = [picked].concat(list.filter(s => s !== picked));
    const brandsHere = {};
    base.forEach(s => (s.brands || []).forEach(b => { brandsHere[b.brand] = (brandsHere[b.brand] || 0) + 1; }));
    const opts = Object.keys(brandsHere).map(id => [id, (byId(d.brands, id) || {}).name || id]).sort((a, b) => a[1].localeCompare(b[1]));
    const kinds = [['', 'All'], ['brand_flagship', 'Flagship'], ['multi_brand', 'Multi-brand'], ['trade_yard', 'Trade yard']];
    const shown = list.slice(0, S.limit);
    return `${heading || ''}<div class="controls">
        <input type="search" id="q" placeholder="Search name, address or company" value="${esc(r.q.q || '')}" aria-label="Search showrooms">
        <select id="brand" aria-label="Brand"><option value="">All brands</option>${opts.map(([id, n]) => `<option value="${id}" ${r.q.brand === id ? 'selected' : ''}>${esc(n)} (${brandsHere[id]})</option>`).join('')}</select>
        <div class="seg" role="group" aria-label="Kind">${kinds.map(([k, l]) => `<button type="button" data-kind="${k}" aria-pressed="${(r.q.kind || '') === k}">${l}</button>`).join('')}
          <button type="button" id="openOnly" aria-pressed="${r.q.open === '1'}">Open only</button></div>
      </div>
      <div class="count">${nf0.format(list.length)} of ${nf0.format(base.length)} · ${list.filter(s => s.status === 'open').length} open (two sources agree)
        <button class="btn" id="csvShowrooms" type="button">CSV</button></div>
      <ul class="list">${shown.map(s => showroomRow(d, s, r)).join('') || '<li class="muted">No showroom matches.</li>'}</ul>
      ${list.length > shown.length ? `<button class="btn more" id="more" type="button">Show ${Math.min(120, list.length - shown.length)} more</button>` : ''}`;
  }

  function showroomRow(d, s, r) {
    const co = byId(d.companies, s.company) || {};
    const brands = (s.brands || []).map(b => byId(d.brands, b.brand)).filter(Boolean);
    const phone = s.phone, web = s.website || co.website; // company phone is shown under Contacts, not on each branch
    return `<li class="${visible(s.grade) && (s.grade === 'A' || s.grade === 'B') ? '' : 'hollow'}${String(r.q.sel) === String(s.id) ? ' hi' : ''}" data-sid="${s.id}" ${s.lat != null ? 'data-ll="' + s.lon + ',' + s.lat + '"' : ''}>
      <div class="row-title ${s.lat != null ? 'clickable' : ''}"><span class="pin ${s.lat != null ? s.kind : 'none'}" title="${esc(KIND[s.kind] || '')}${s.lat == null ? ', not on the map yet' : ''}"></span>
        <b>${esc(s.name)}</b><span class="right">${s.status === 'open' ? 'open' : ''}${badge(s.grade, s.source, d.sources)}</span></div>
      <div class="meta">${esc(s.address)}</div>
      <div class="meta">${[KIND[s.kind], co.name && co.name !== s.name ? esc(co.name) + (co.role ? ' (' + (ROLE[co.role] || co.role).toLowerCase() + ')' : '') : '', tel(phone), ext(web), s.hours ? esc(s.hours) : ''].filter(Boolean).join(' · ')}</div>
      ${brands.length ? `<div class="chips">${brands.map(b => `<a class="chip" href="${href({ iso: r.iso }, { tab: 'showrooms', brand: idOf(d, b) })}" ${b.segment ? `style="--seg:var(--seg-${b.segment})"` : ''}>${esc(b.name)}</a>`).join('')}</div>` : ''}
      <div class="meta muted">Last verified ${esc(s.last_verified_at || '—')} · ${gmaps(s)}</div></li>`;
  }
  const plural = (n, one, many) => `${nf0.format(n)} ${n === 1 ? one : (many || one + 's')}`;
  const idOf = (d, b) => Object.keys(d.brands).find(k => d.brands[k] === b);

  function brandList(d, r) {
    const reps = {}, rooms = {};
    (d.representations || []).filter(x => visible(x.grade)).forEach(x => { if (x.brand == null) return; (reps[x.brand] = reps[x.brand] || new Set()); if (x.company != null) reps[x.brand].add(x.company); });
    showroomsOf(d).forEach(s => (s.brands || []).forEach(b => { rooms[b.brand] = (rooms[b.brand] || 0) + 1; }));
    // company-less lines: "no representation shown" = absent; anything else (e.g. a store finder that lists points
    // without operator names) = present, operator not named by the brand
    // a shared source may hold several quotes (" ‖ "): use the one that names this country
    const quoteOf = x => { const segs = String(((d.sources || {})[x.source] || {}).quote || '').split(' ‖ ');
      return segs.find(q => q.toLowerCase().includes(String(d.country.name).toLowerCase())) || (segs.length === 1 ? segs[0] : ''); };
    const noCo = (d.representations || []).filter(x => x.company == null && visible(x.grade));
    const present = x => !/no representation shown/i.test(quoteOf(x)) && /\d+\s+points?|operator (names? )?not|present/i.test(quoteOf(x));
    const unnamed = noCo.filter(present);
    const none = noCo.filter(x => !present(x)).map(x => x.brand);
    const pts = x => { const m = quoteOf(x).match(/lists\s+(\d+)\s+points?/i); return m ? +m[1] : null; };
    const ids = [...new Set([...Object.keys(reps), ...Object.keys(rooms)])].filter(id => byId(d.brands, id));
    const groups = {};
    ids.forEach(id => { const b = d.brands[id]; (groups[b.group || 'Other brands seen at dealers'] = groups[b.group || 'Other brands seen at dealers'] || []).push(id); });
    const gnames = Object.keys(groups).sort((a, b) => (a.startsWith('Other') ? 1 : 0) - (b.startsWith('Other') ? 1 : 0) || a.localeCompare(b));
    return gnames.map(g => `<h2>${esc(g)}</h2><ul class="list">${groups[g].sort((a, b) => (rooms[b] || 0) - (rooms[a] || 0)).map(id => {
      const b = d.brands[id]; const nReps = reps[id] ? [...reps[id]].filter(c => byId(d.companies, c)).length : 0;
      const top = reps[id] ? [...reps[id]].map(c => byId(d.companies, c)).filter(c => c && c.role !== 'dealer').map(c => c.name).slice(0, 3) : [];
      return `<li><a class="row-link" href="${href({ iso: r.iso }, { tab: 'showrooms', brand: id })}"><div class="row-title"><b>${esc(b.name)}</b>
        <span class="right">${plural(rooms[id] || 0, 'showroom')} · ${plural(nReps, 'company', 'companies')}</span></div>
        <div class="meta">${top.length ? 'Represented by ' + top.map(esc).join(', ') : (b.is_peer ? '' : 'Seen on dealer websites')}</div></a></li>`;
    }).join('')}</ul>`).join('') +
      (unnamed.length ? `<h2>Present, operator not named</h2><ul class="list">${unnamed.map(x => {
        const b = byId(d.brands, x.brand) || {}, n = pts(x), src = (d.sources || {})[x.source] || {};
        return `<li><div class="row-title"><b>${esc(b.name || x.brand)}</b><span class="right">${n != null ? plural(n, 'point') : ''}${badge(x.grade, x.source, d.sources)}</span></div>
          <div class="meta">The brand's own locator lists ${n != null ? plural(n, 'point') : 'points'} here by city and type only; it does not name the dealers${src.url ? ' · ' + ext(src.url, 'locator') : ''}.</div></li>`;
      }).join('')}</ul>` : '') +
      (none.length ? `<h2>Not shown in ${esc(d.country.name)}</h2><p class="meta">${[...new Set(none)].map(id => esc((byId(d.brands, id) || {}).name || id)).join(', ')}: the brand's own locator lists no one here.</p>` : '') ||
      '<p class="muted">No brand data yet.</p>';
  }

  function contactList(d, r) {
    const q = (r.q.q || '').toLowerCase();
    const rows = contactsOf(d).filter(c => !q || [c.name, c.sub, c.address, c.email, c.phone].join(' ').toLowerCase().includes(q))
      .sort((a, b) => (a.sid == null) - (b.sid == null) || (a.co ? ROLE_ORDER.indexOf(a.co.role) - ROLE_ORDER.indexOf(b.co.role) : 0) || a.name.localeCompare(b.name));
    const brandsOf = {};
    (d.representations || []).forEach(x => { if (x.company != null && byId(d.brands, x.brand)) (brandsOf[x.company] = brandsOf[x.company] || new Set()).add(d.brands[x.brand].name); });
    const nRooms = rows.filter(c => c.sid != null).length;
    const shown = rows.slice(0, S.limit);
    return `<div class="controls"><input type="search" id="q" placeholder="Search name, address, phone or email" value="${esc(r.q.q || '')}" aria-label="Search contacts"></div>
      <div class="count">${plural(nRooms, 'showroom')} and ${plural(rows.length - nRooms, 'company', 'companies')} with a published contact
        <button class="btn" id="csvContacts" type="button">CSV</button></div>
      <p class="muted">Business contacts only, as published on each company's own website. Showrooms first (their own branch line), then head offices.</p>
      <ul class="list">${shown.map(c => `<li class="${c.grade === 'A' || c.grade === 'B' ? '' : 'hollow'}"${c.sid != null ? ` data-sid="${c.sid}"` : ''}><div class="row-title"><b>${c.sid != null ? `<a href="${href({ iso: r.iso }, { tab: 'showrooms', sel: c.sid })}">${esc(c.name)}</a>` : esc(c.name)}</b><span class="right">${esc(c.role)}${badge(c.grade, c.source, d.sources)}</span></div>
        ${c.sub ? `<div class="meta muted">${esc(c.sub)}</div>` : ''}
        <div class="meta">${[tel(c.phone), mail(c.email), ext(c.website)].filter(Boolean).join(' · ')}</div>
        ${c.address ? `<div class="meta">${esc(c.address)}</div>` : ''}
        ${c.sid == null && brandsOf[c.company] ? `<div class="meta muted">${[...brandsOf[c.company]].map(esc).join(', ')}</div>` : ''}</li>`).join('') || '<li class="muted">No contact matches.</li>'}</ul>
      ${rows.length > shown.length ? `<button class="btn more" id="more" type="button">Show more</button>` : ''}`;
  }

  // City level: districts of the city, ranked by fit score; showrooms whose address names the city
  function renderCity(r, d, geo) {
    crumbsFor(r, d); setSel(r.iso);
    const city = d.cities.find(c => c.slug === r.city);
    if (!city) { go({ iso: r.iso }); return; }
    stopSpin();
    const ds = d.districts.filter(x => x.city === city.id).sort((a, b) => score(b) - score(a));
    const nameRe = new RegExp('(^|[^\\p{L}])' + city.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').split(/\s*\/\s*/).join('|') + '([^\\p{L}]|$)', 'iu');
    const rooms = showroomsOf(d).filter(s => nameRe.test(s.address) || ds.some(x => x.id === s.district));
    const cityPts = rooms.filter(s => s.lat != null).map(s => [s.lon, s.lat]);
    if (lastLevel !== 'city:' + city.id) {
      const fb = city.lat != null ? { center: [city.lon, city.lat], zoom: city.zoom || 10.5 } : countryCamera(r.iso);
      if (cityPts.length) frame(cityPts, fb, 13, 900); else fly(Object.assign({ duration: 700 }, fb));
    }
    lastLevel = 'city:' + city.id;
    panel.innerHTML = `<h1>${esc(city.name)}</h1>
      <p class="sub">${city.lat == null && !cityPts.length ? 'No coordinates for this city yet, so the map stays on the country. ' : ''}${ds.length} candidate district${ds.length === 1 ? '' : 's'}, ranked by fit score.</p>
      <ul class="list">${ds.map(x => `<li><a class="row-link" href="${href({ iso: r.iso, city: city.slug, district: x.slug })}">
        <div class="row-title"><b>${esc(x.name)}</b><span class="right">${d.country.status === 'intel_only' ? 'not scored' : 'score ' + score(x)}${badge(x.grade, x.source, d.sources)}</span></div>
        <div class="meta">${[x.channel, x.status, x.peer_count + ' peer brands', x.anchor ? 'anchor: ' + esc(x.anchor) : ''].filter(Boolean).join(' · ')}</div></a></li>`).join('') || '<li class="muted">No districts yet.</li>'}</ul>
      ${showroomList(d, r, rooms, `<h2>Showrooms in ${esc(city.name)} <span class="muted">(address or district)</span></h2>`)}`;
    wire(d, r);
    const ids = new Set(filterShowrooms(d, r, rooms).map(s => s.id));
    setPoints(geo, f => f.properties.layer === 'district' ? ds.some(x => x.id === f.properties.id) : ids.has(f.properties.id));
  }

  // District level
  function renderDistrict(r, d, geo) {
    crumbsFor(r, d); setSel(r.iso);
    const x = d.districts.find(v => v.slug === r.district);
    if (!x) { go({ iso: r.iso, city: r.city }); return; }
    if (lastLevel !== 'district:' + x.id) {
      const city = d.cities.find(c => c.id === x.city);
      if (x.centroid) fly({ center: [x.centroid.lon != null ? x.centroid.lon : x.centroid[0], x.centroid.lat != null ? x.centroid.lat : x.centroid[1]], zoom: 14.5, pitch: 0, duration: 500 });
      else if (city && city.lat != null) fly({ center: [city.lon, city.lat], zoom: 11, duration: 500 });
      else fly(Object.assign({ duration: 500 }, countryCamera(r.iso)));
    }
    lastLevel = 'district:' + x.id;
    const rooms = showroomsOf(d).filter(s => s.district === x.id);
    const sc = x.score || {};
    panel.innerHTML = `<h1>${esc(x.name)}</h1>
      <p class="sub">${esc([x.channel, x.status, x.anchor ? 'anchor: ' + x.anchor : ''].filter(Boolean).join(' · '))}${badge(x.grade, x.source, d.sources)}</p>
      ${d.country.status === 'intel_only' ? '<p class="note">Intel only: this district is not scored.</p>' : `<div class="metrics">
        ${[['Peer density', sc.peer_density, 40], ['Channel fit', sc.channel_fit, 20], ['Openness', sc.openness, 20], ['Access', sc.access, 10], ['Evidence', sc.evidence, 10]]
          .map(([k, v, m]) => `<div class="k">${k}</div><div class="v">${v == null ? '—' : v}<small>/ ${m}</small></div>`).join('')}
        <div class="k"><b>Fit score</b></div><div class="v"><b>${score(x)}</b><small>/ 100</small></div></div>`}
      ${x.centroid ? '' : '<p class="muted">Polygon not drawn yet (district sweep pending).</p>'}
      ${rooms.length ? showroomList(d, r, rooms, '<h2>Showrooms</h2>') : '<h2>Showrooms</h2><p class="muted">No showroom is assigned to this district yet; the district sweep (WP-C) places them.</p>'}`;
    wire(d, r);
    setPoints(geo, f => f.properties.layer === 'district' ? f.properties.id === x.id : rooms.some(s => s.id === f.properties.id));
  }

  // ---------- panel wiring ----------
  function wire(d, r) {
    const q = $('#q');
    if (q) {
      let t; q.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { setQuery({ q: q.value || undefined }); const n = $('#q'); if (n) { n.focus(); n.setSelectionRange(n.value.length, n.value.length); } }, 250); });
    }
    const b = $('#brand'); if (b) b.addEventListener('change', () => setQuery({ brand: b.value || undefined }));
    panel.querySelectorAll('[data-kind]').forEach(el => el.addEventListener('click', () => setQuery({ kind: el.dataset.kind || undefined })));
    const o = $('#openOnly'); if (o) o.addEventListener('click', () => setQuery({ open: r.q.open === '1' ? undefined : '1' }));
    const m = $('#more'); if (m) m.addEventListener('click', () => { S.limit += 120; render(); });
    panel.querySelectorAll('[data-hot]').forEach(li => li.addEventListener('click', () => {
      const h = S.hot[+li.dataset.hot]; if (h) { frame(h, null, 12.5, 1100); }
    }));
    panel.querySelectorAll('[data-ll]').forEach(li => li.querySelector('.row-title').addEventListener('click', () => {
      const [lon, lat] = li.dataset.ll.split(',').map(Number); fly({ center: [lon, lat], zoom: 13, duration: 700 });
    }));
    const cs = $('#csvShowrooms'); if (cs) cs.addEventListener('click', () => {
      const list = filterShowrooms(d, r, r.city || r.district ? [...panel.querySelectorAll('[data-sid]')].map(li => d.showrooms.find(s => String(s.id) === li.dataset.sid)) : showroomsOf(d));
      download(`${r.iso.toLowerCase()}-showrooms.csv`, [['name', 'kind', 'status', 'address', 'company', 'phone', 'website', 'brands', 'grade', 'last_verified', 'source']]
        .concat(list.map(s => { const co = byId(d.companies, s.company) || {}; const src = byId(d.sources, s.source) || {};
          return [s.name, KIND[s.kind] || s.kind, s.status, s.address, co.name, s.phone || co.phone, s.website || co.website,
            (s.brands || []).map(b => (byId(d.brands, b.brand) || {}).name).filter(Boolean).join('; '), s.grade, s.last_verified_at, src.url]; })));
    });
    const cc = $('#csvContacts'); if (cc) cc.addEventListener('click', () => {
      download(`${r.iso.toLowerCase()}-contacts.csv`, [['name', 'level', 'company', 'type', 'phone', 'email', 'website', 'address', 'grade', 'source']]
        .concat(contactsOf(d).map(c => [c.name, c.sid != null ? 'showroom' : 'company', c.sub, c.role, c.phone, c.email, c.website, c.address, c.grade, (byId(d.sources, c.source) || {}).url])));
    });
    const sel = r.q.sel && panel.querySelector(`[data-sid="${CSS.escape(r.q.sel)}"]`);
    if (sel) sel.scrollIntoView({ block: 'center', behavior: reduced ? 'auto' : 'smooth' });
  }

  function download(name, rows) {
    const text = '﻿' + rows.map(r => r.map(v => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }).join(',')).join('\n');
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'text/csv' })); a.download = name;
    document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  }

  // ---------- keyboard: Esc up one level, ←/→ siblings ----------
  addEventListener('keydown', e => {
    if (e.target.matches('input, select, textarea')) { if (e.key === 'Escape') e.target.blur(); return; }
    const r = parse();
    if (e.key === 'Escape') {
      if (r.district) go({ iso: r.iso, city: r.city }); else if (r.city) go({ iso: r.iso }); else if (r.iso) go({});
    } else if ((e.key === 'ArrowRight' || e.key === 'ArrowLeft') && r.iso && !r.city) {
      const i = ISO.indexOf(r.iso), n = ISO[(i + (e.key === 'ArrowRight' ? 1 : ISO.length - 1)) % ISO.length];
      go({ iso: n }, r.q.tab ? { tab: r.q.tab } : {});
    } else if (e.key === '/' && $('#q')) { e.preventDefault(); $('#q').focus(); }
  });

  const dl = $('#showDealers');
  dl.checked = S.showDealers;
  dl.addEventListener('change', () => { S.showDealers = dl.checked; try { localStorage.setItem('atlas.showDealers', dl.checked ? '1' : '0'); } catch (e) { /* ignore */ } render(); });
  const cd = $('#showCD');
  cd.checked = S.showCD;
  cd.addEventListener('change', () => { S.showCD = cd.checked; try { localStorage.setItem('atlas.showCD', cd.checked ? '1' : '0'); } catch (e) { /* ignore */ } render(); });
  addEventListener('hashchange', () => { S.limit = 120; render(); });
})();
