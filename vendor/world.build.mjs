// Build site/vendor/world.js from world-atlas 2.0.2 (Natural Earth, ISC) with topojson-client 3.1.0.
//   node world.build.mjs <dir with world-atlas-2.0.2/ and topojson-client-3.1.0/> site/vendor/world.js
// Output: window.ATLAS_WORLD = { world, focus }, every feature { iso: <ISO 3166 alpha-2 or ''>, name }.
//   focus = detailed outlines for the atlas markets (50m where the 50m file stays small, 110m for the big
//           countries); world = every other 110m country. The site draws both as land and highlights the
//           countries listed in site/data/world.json, so a market added to the data needs no code change.
import fs from 'fs';
const [dir, dst] = process.argv.slice(2);
const topo = await import(dir + '/topojson-client-3.1.0/package/dist/topojson-client.js');
const read = f => JSON.parse(fs.readFileSync(dir + '/world-atlas-2.0.2/package/' + f));
const t110 = read('countries-110m.json'), t50 = read('countries-50m.json');

// ISO 3166-1 numeric -> alpha-2 for every 110m country (unrecognised areas such as N. Cyprus get '')
const A2 = { '004': 'AF', '008': 'AL', '010': 'AQ', '012': 'DZ', '024': 'AO', '031': 'AZ', '032': 'AR', '036': 'AU', '040': 'AT',
  '044': 'BS', '050': 'BD', '051': 'AM', '056': 'BE', '064': 'BT', '068': 'BO', '070': 'BA', '072': 'BW', '076': 'BR', '084': 'BZ',
  '090': 'SB', '096': 'BN', 100: 'BG', 104: 'MM', 108: 'BI', 112: 'BY', 116: 'KH', 120: 'CM', 124: 'CA', 140: 'CF', 144: 'LK',
  148: 'TD', 152: 'CL', 156: 'CN', 158: 'TW', 170: 'CO', 178: 'CG', 180: 'CD', 188: 'CR', 191: 'HR', 192: 'CU', 196: 'CY',
  203: 'CZ', 204: 'BJ', 208: 'DK', 214: 'DO', 218: 'EC', 222: 'SV', 226: 'GQ', 231: 'ET', 232: 'ER', 233: 'EE', 238: 'FK',
  242: 'FJ', 246: 'FI', 250: 'FR', 260: 'TF', 262: 'DJ', 266: 'GA', 268: 'GE', 270: 'GM', 275: 'PS', 276: 'DE', 288: 'GH',
  300: 'GR', 304: 'GL', 320: 'GT', 324: 'GN', 328: 'GY', 332: 'HT', 340: 'HN', 348: 'HU', 352: 'IS', 356: 'IN', 360: 'ID',
  364: 'IR', 368: 'IQ', 372: 'IE', 376: 'IL', 380: 'IT', 384: 'CI', 388: 'JM', 392: 'JP', 398: 'KZ', 400: 'JO', 404: 'KE',
  408: 'KP', 410: 'KR', 414: 'KW', 417: 'KG', 418: 'LA', 422: 'LB', 426: 'LS', 428: 'LV', 430: 'LR', 434: 'LY', 440: 'LT',
  442: 'LU', 450: 'MG', 454: 'MW', 458: 'MY', 466: 'ML', 478: 'MR', 484: 'MX', 496: 'MN', 498: 'MD', 499: 'ME', 504: 'MA',
  508: 'MZ', 512: 'OM', 516: 'NA', 524: 'NP', 528: 'NL', 540: 'NC', 548: 'VU', 554: 'NZ', 558: 'NI', 562: 'NE', 566: 'NG',
  578: 'NO', 586: 'PK', 591: 'PA', 598: 'PG', 600: 'PY', 604: 'PE', 608: 'PH', 616: 'PL', 620: 'PT', 624: 'GW', 626: 'TL',
  630: 'PR', 634: 'QA', 642: 'RO', 643: 'RU', 646: 'RW', 682: 'SA', 686: 'SN', 688: 'RS', 694: 'SL', 703: 'SK', 704: 'VN',
  705: 'SI', 706: 'SO', 710: 'ZA', 716: 'ZW', 724: 'ES', 728: 'SS', 729: 'SD', 732: 'EH', 740: 'SR', 748: 'SZ', 752: 'SE',
  756: 'CH', 760: 'SY', 762: 'TJ', 764: 'TH', 768: 'TG', 780: 'TT', 784: 'AE', 788: 'TN', 792: 'TR', 795: 'TM', 800: 'UG',
  804: 'UA', 807: 'MK', 818: 'EG', 826: 'GB', 834: 'TZ', 840: 'US', 854: 'BF', 858: 'UY', 860: 'UZ', 862: 'VE', 887: 'YE',
  894: 'ZM' };
const iso = f => f.id === undefined ? (f.properties.name === 'Kosovo' ? 'XK' : '') : (A2[f.id] || '');
// detailed outlines: 50m for the compact markets, 110m for the continental ones (50m would add ~200 KB)
const DETAIL_50 = ['DE', 'FR', 'AE', 'PH', 'IL', 'KR', 'GB'], DETAIL_110 = ['US', 'RU', 'CA'];

// rings that jump across ±180 (RU Chukotka, US Aleutians, Fiji) break the globe; move the minority side
// by 360° so every such country is continuous (bounds then span e.g. 19..190 for RU, -188..-67 for US)
function fixAntimeridian(f) {
  if (f.properties.iso === 'AQ') return f;
  const pts = []; const walk = c => typeof c[0] === 'number' ? pts.push(c[0]) : c.forEach(walk); walk(f.geometry.coordinates);
  if (!(pts.some(x => x > 170) && pts.some(x => x < -170))) return f;
  const east = pts.filter(x => x > 0).length >= pts.length / 2;
  const shift = c => typeof c[0] === 'number' ? [east ? (c[0] < 0 ? c[0] + 360 : c[0]) : (c[0] > 0 ? c[0] - 360 : c[0]), c[1]] : c.map(shift);
  f.geometry = { type: f.geometry.type, coordinates: shift(f.geometry.coordinates) };
  return f;
}
const round = g => JSON.parse(JSON.stringify(g, (k, v) => typeof v === 'number' ? Math.round(v * 1e2) / 1e2 : v));
const feats = t => topo.feature(t, t.objects.countries).features
  .map(f => fixAntimeridian({ type: 'Feature', properties: { iso: iso(f), name: f.properties.name }, geometry: f.geometry }));
const f110 = feats(t110), f50 = feats(t50);
const focus = f50.filter(f => DETAIL_50.includes(f.properties.iso)).concat(f110.filter(f => DETAIL_110.includes(f.properties.iso)));
const inFocus = new Set(focus.map(f => f.properties.iso));
const world = f110.filter(f => !inFocus.has(f.properties.iso));
const out = '/* Natural Earth via world-atlas 2.0.2 (ISC); 110m world + detailed atlas markets; built by world.build.mjs */\n' +
  'window.ATLAS_WORLD=' + JSON.stringify({ world: round({ type: 'FeatureCollection', features: world }), focus: round({ type: 'FeatureCollection', features: focus }) }) + ';\n';
fs.writeFileSync(dst, out);
console.log('bytes', out.length, 'world', world.length, 'focus', focus.map(f => f.properties.iso).join(','));
