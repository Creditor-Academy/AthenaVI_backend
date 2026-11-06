/**
 * Fonts in PowerPoint (Phase 5): the deck's fonts travel inside the PPTX, so PowerPoint draws
 * text with the same font the editor used and wraps it the same way. Without them PowerPoint
 * swaps in another font and headings wrap onto extra lines.
 *
 * - The fonts are Google Fonts (OFL: embedding is allowed). They are downloaded as TrueType
 *   once and kept in a server cache.
 * - PowerPoint stores embedded fonts as EOT (`ppt/fonts/fontN.fntdata`, ECMA-376
 *   `p:embeddedFontLst`). The EOT is a header plus the untouched TrueType data.
 * - Only the faces the editor loads are embedded: regular (400), bold (700) and italic (400).
 *   The editor draws bold italic as synthetic bold on the italic, and PowerPoint does the same
 *   when no bold-italic face is embedded.
 * - Google Slides ignores embedded fonts but picks Google Fonts up by name, which every run
 *   already carries (`latin` / `ea` / `cs`).
 *
 * Never fails an export: a font that can't be fetched is left out (PowerPoint substitutes it,
 * as before) and listed in the export report.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const logger = require('../../shared/utils/logger');
const { isSystemFontFamily } = require('../../shared/fonts/builtinFonts');

/** Fonts every PowerPoint has (or names PowerPoint resolves itself): never embedded. */
const OFFICE_FONTS = new Set(
  [
    'arial',
    'arial black',
    'calibri',
    'calibri light',
    'cambria',
    'candara',
    'consolas',
    'constantia',
    'corbel',
    'courier new',
    'georgia',
    'helvetica',
    'impact',
    'segoe ui',
    'tahoma',
    'times new roman',
    'trebuchet ms',
    'verdana',
  ]
);

/** The faces the editor loads for a family (googleFonts.js: wght 300–700 upright, 400 italic). */
const FACES = {
  regular: { weight: 400, italic: false },
  bold: { weight: 700, italic: false },
  italic: { weight: 400, italic: true },
};
const FACE_ORDER = ['regular', 'bold', 'italic'];

const MAX_FACE_BYTES = 4 * 1024 * 1024;
const MAX_TOTAL_BYTES = 20 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 8000;
const FAILED_RETRY_MS = 10 * 60 * 1000;

/** The first family of a CSS font-family list, unquoted; null for generic families / vars. */
function primaryFamily(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  const first = raw.match(/^\s*(?:"([^"]+)"|'([^']+)'|([^,]+))/);
  const name = String(first?.[1] || first?.[2] || first?.[3] || '').trim();
  if (!name || /^var\(/i.test(name)) return null;
  const generic = ['serif', 'sans-serif', 'monospace', 'cursive', 'fantasy', 'system-ui', 'inherit', 'initial'];
  if (generic.includes(name.toLowerCase())) return null;
  return name;
}

function shouldEmbedFamily(family) {
  const key = String(family || '').trim().toLowerCase();
  if (!key || key.startsWith('+')) return false;
  return !OFFICE_FONTS.has(key) && !isSystemFontFamily(key);
}

// ── TrueType → EOT ───────────────────────────────────────────────────────────

function readTables(ttf) {
  const sfnt = ttf.readUInt32BE(0);
  // 0x00010000 or 'true': TrueType outlines. CFF ('OTTO') fonts can't be embedded in PPTX.
  if (sfnt !== 0x00010000 && sfnt !== 0x74727565) return null;
  const count = ttf.readUInt16BE(4);
  const tables = {};
  for (let i = 0; i < count; i += 1) {
    const at = 12 + i * 16;
    if (at + 16 > ttf.length) return null;
    const tag = ttf.toString('latin1', at, at + 4);
    tables[tag] = { offset: ttf.readUInt32BE(at + 8), length: ttf.readUInt32BE(at + 12) };
  }
  return tables;
}

/** Name-table strings (Windows Unicode, English first) as UTF-16LE buffers. */
function readNames(ttf, table) {
  const names = {};
  if (!table) return names;
  const base = table.offset;
  const count = ttf.readUInt16BE(base + 2);
  const strings = base + ttf.readUInt16BE(base + 4);
  const best = {};
  for (let i = 0; i < count; i += 1) {
    const at = base + 6 + i * 12;
    const platform = ttf.readUInt16BE(at);
    const encoding = ttf.readUInt16BE(at + 2);
    const language = ttf.readUInt16BE(at + 4);
    const id = ttf.readUInt16BE(at + 6);
    if (platform !== 3 || (encoding !== 1 && encoding !== 0) || ![1, 2, 4, 5].includes(id)) continue;
    const rank = language === 0x409 ? 0 : 1;
    if (best[id] && best[id].rank <= rank) continue;
    const length = ttf.readUInt16BE(at + 8);
    const offset = strings + ttf.readUInt16BE(at + 10);
    const be = ttf.subarray(offset, offset + length);
    const le = Buffer.alloc(be.length);
    for (let j = 0; j + 1 < be.length; j += 2) {
      le[j] = be[j + 1];
      le[j + 1] = be[j];
    }
    best[id] = { rank, le };
  }
  for (const [id, v] of Object.entries(best)) names[id] = v.le;
  return names;
}

function nameText(le) {
  return le ? le.toString('utf16le') : '';
}

/**
 * Wrap a TrueType font as EOT (version 0x00020001, no compression, no XOR), the format
 * PowerPoint reads from `.fntdata` parts. Returns null for fonts that can't be embedded:
 * not TrueType, or a "restricted license" fsType.
 */
function ttfToEot(ttf) {
  if (!Buffer.isBuffer(ttf) || ttf.length < 12) return null;
  const tables = readTables(ttf);
  if (!tables || !tables['OS/2'] || !tables.head || !tables.name) return null;
  const os2 = tables['OS/2'].offset;
  const fsType = ttf.readUInt16BE(os2 + 8);
  if ((fsType & 0x000f) === 0x0002) return null; // restricted: the licence forbids embedding
  const os2Version = ttf.readUInt16BE(os2);
  const names = readNames(ttf, tables.name);

  const fixed = Buffer.alloc(82);
  let o = 8; // EOTSize and FontDataSize are written last
  fixed.writeUInt32LE(0x00020001, o);
  o += 4;
  fixed.writeUInt32LE(0, o); // Flags
  o += 4;
  ttf.copy(fixed, o, os2 + 32, os2 + 42); // PANOSE
  o += 10;
  fixed.writeUInt8(1, o); // DEFAULT_CHARSET
  o += 1;
  fixed.writeUInt8(ttf.readUInt16BE(os2 + 62) & 0x01, o); // italic
  o += 1;
  fixed.writeUInt32LE(ttf.readUInt16BE(os2 + 4), o); // weight
  o += 4;
  fixed.writeUInt16LE(fsType, o);
  o += 2;
  fixed.writeUInt16LE(0x504c, o); // magic
  o += 2;
  for (let i = 0; i < 4; i += 1) {
    fixed.writeUInt32LE(ttf.readUInt32BE(os2 + 42 + i * 4), o);
    o += 4;
  }
  for (let i = 0; i < 2; i += 1) {
    fixed.writeUInt32LE(os2Version >= 1 ? ttf.readUInt32BE(os2 + 78 + i * 4) : 0, o);
    o += 4;
  }
  fixed.writeUInt32LE(ttf.readUInt32BE(tables.head.offset + 8), o); // checkSumAdjustment
  o += 4;
  o += 16; // Reserved1–4
  fixed.writeUInt16LE(0, o); // Padding1

  const parts = [fixed];
  const pushName = (le, withPadding = true) => {
    const value = le || Buffer.alloc(0);
    const size = Buffer.alloc(2);
    size.writeUInt16LE(value.length, 0);
    parts.push(size, value);
    if (withPadding) parts.push(Buffer.alloc(2)); // Padding2–5
  };
  pushName(names[1]); // family
  pushName(names[2]); // style
  pushName(names[5]); // version
  pushName(names[4]); // full name
  parts.push(Buffer.alloc(2)); // RootStringSize = 0
  parts.push(ttf);

  const eot = Buffer.concat(parts);
  eot.writeUInt32LE(eot.length, 0);
  eot.writeUInt32LE(ttf.length, 4);
  return eot;
}

/** Family and style names a TrueType font calls itself. */
function fontNames(ttf) {
  const tables = readTables(ttf);
  if (!tables) return null;
  const names = readNames(ttf, tables.name);
  return { family: nameText(names[1]), style: nameText(names[2]) };
}

// ── Google Fonts download, cached ────────────────────────────────────────────

const memoryCache = new Map(); // key → { ttf: Buffer|null, at: number }
/** Downloaded fonts are kept here across exports (PPTX_FONT_CACHE_DIR to move it). */
const cacheDir = () => process.env.PPTX_FONT_CACHE_DIR || path.join(os.tmpdir(), 'athena-pptx-fonts');

function cacheKey(family, face) {
  const safe = String(family).replace(/[^a-z0-9]+/gi, '-').toLowerCase();
  const hash = crypto.createHash('sha1').update(`${family}|${face}`).digest('hex').slice(0, 8);
  return `${safe}-${face}-${hash}`;
}

async function fetchWithTimeout(url, asBuffer) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { 'User-Agent': 'AthenaVI-export' } });
    if (!res.ok) return null;
    return asBuffer ? Buffer.from(await res.arrayBuffer()) : await res.text();
  } finally {
    clearTimeout(timer);
  }
}

/** One face of a Google Font as TrueType, or null when Google doesn't have it. */
async function downloadGoogleFace(family, face) {
  const { weight, italic } = FACES[face];
  const familyParam = encodeURIComponent(family).replace(/%20/g, '+');
  const css = await fetchWithTimeout(
    `https://fonts.googleapis.com/css2?family=${familyParam}:ital,wght@${italic ? 1 : 0},${weight}`,
    false
  );
  const url = css && /url\((https:\/\/fonts\.gstatic\.com\/[^)\s]+\.ttf)\)/.exec(css)?.[1];
  if (!url) return null;
  const ttf = await fetchWithTimeout(url, true);
  if (!ttf || ttf.length > MAX_FACE_BYTES || !readTables(ttf)) return null;
  return ttf;
}

/** A face from the memory cache, the disk cache, or Google (then cached). */
async function loadFace(family, face, download = downloadGoogleFace) {
  const key = cacheKey(family, face);
  const hit = memoryCache.get(key);
  if (hit && (hit.ttf || Date.now() - hit.at < FAILED_RETRY_MS)) return hit.ttf;
  const file = path.join(cacheDir(), `${key}.ttf`);
  try {
    const ttf = await fs.promises.readFile(file);
    memoryCache.set(key, { ttf, at: Date.now() });
    return ttf;
  } catch {
    // not cached yet
  }
  let ttf = null;
  try {
    ttf = await download(family, face);
  } catch (err) {
    logger.warn?.('pptx_font_download_failed', { family, face, error: String(err?.message || err).slice(0, 200) });
  }
  memoryCache.set(key, { ttf, at: Date.now() });
  if (ttf) {
    fs.promises
      .mkdir(cacheDir(), { recursive: true })
      .then(() => fs.promises.writeFile(file, ttf))
      .catch(() => {});
  }
  return ttf;
}

// ── Which fonts the PPTX uses ────────────────────────────────────────────────

/**
 * Families used by the runs in the PPTX parts, with the faces they need: regular always,
 * bold / italic when a run is bold / italic.
 */
function fontUsage(xmlParts) {
  const usage = new Map();
  const runProps = /<a:(rPr|defRPr|endParaRPr)\b([^>]*?)(\/>|>([\s\S]*?)<\/a:\1>)/g;
  for (const xml of xmlParts) {
    let m;
    while ((m = runProps.exec(xml))) {
      const typeface = /<a:latin\b[^>]*\btypeface="([^"]+)"/.exec(m[4] || '')?.[1];
      if (!typeface || !shouldEmbedFamily(typeface)) continue;
      const family = typeface.replace(/&amp;/g, '&').trim();
      if (!usage.has(family)) usage.set(family, new Set(['regular']));
      const attrs = m[2];
      const bold = /\bb="(1|true)"/.test(attrs);
      const italic = /\bi="(1|true)"/.test(attrs);
      if (bold) usage.get(family).add('bold');
      if (italic) usage.get(family).add('italic');
    }
  }
  return usage;
}

// ── Embedding ────────────────────────────────────────────────────────────────

const FONT_REL_TYPE = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/font';

const xmlAttr = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

/**
 * Embed the fonts the PPTX uses (in a JSZip of it). Returns what was embedded and what
 * couldn't be.
 *
 * @param {import('jszip')} zip
 * @param {{ download?: Function }} [opts]  `download(family, face)` → TrueType Buffer|null (tests)
 */
async function embedPptxFonts(zip, { download } = {}) {
  const partNames = Object.keys(zip.files).filter((n) => /^ppt\/(slides\/slide|charts\/chart)\d+\.xml$/.test(n));
  const xmlParts = await Promise.all(partNames.map((n) => zip.file(n).async('string')));
  const usage = fontUsage(xmlParts);
  const result = { embedded: [], unavailable: [], bytes: 0 };
  if (!usage.size) return result;

  const fonts = [];
  for (const [family, faceSet] of usage) {
    const faces = {};
    for (const face of FACE_ORDER) {
      if (!faceSet.has(face)) continue;
      const ttf = await loadFace(family, face, download);
      const eot = ttf && ttfToEot(ttf);
      if (!eot || result.bytes + eot.length > MAX_TOTAL_BYTES) continue;
      faces[face] = eot;
      result.bytes += eot.length;
    }
    if (!faces.regular) {
      result.unavailable.push(family);
      continue;
    }
    fonts.push({ family, faces });
    result.embedded.push(`${family} (${Object.keys(faces).join(', ')})`);
  }
  if (!fonts.length) return result;

  const relsPath = 'ppt/_rels/presentation.xml.rels';
  let rels = await zip.file(relsPath).async('string');
  let presentation = await zip.file('ppt/presentation.xml').async('string');
  let types = await zip.file('[Content_Types].xml').async('string');

  const usedIds = new Set([...rels.matchAll(/Id="rId(\d+)"/g)].map((m) => Number(m[1])));
  let nextId = Math.max(0, ...usedIds) + 1;
  let fontNumber = 0;
  const entries = [];
  const newRels = [];
  for (const { family, faces } of fonts) {
    const refs = [];
    for (const face of ['regular', 'bold', 'italic', 'boldItalic']) {
      if (!faces[face]) continue;
      fontNumber += 1;
      const id = `rId${nextId}`;
      nextId += 1;
      zip.file(`ppt/fonts/font${fontNumber}.fntdata`, faces[face]);
      newRels.push(`<Relationship Id="${id}" Type="${FONT_REL_TYPE}" Target="fonts/font${fontNumber}.fntdata"/>`);
      refs.push(`<p:${face} r:id="${id}"/>`);
    }
    entries.push(`<p:embeddedFont><p:font typeface="${xmlAttr(family)}" charset="0"/>${refs.join('')}</p:embeddedFont>`);
  }

  rels = rels.replace('</Relationships>', `${newRels.join('')}</Relationships>`);
  // Schema order (CT_Presentation): … sldSz, notesSz, smartTags, embeddedFontLst, custShowLst …
  const list = `<p:embeddedFontLst>${entries.join('')}</p:embeddedFontLst>`;
  presentation = presentation.replace(/<p:embeddedFontLst>[\s\S]*?<\/p:embeddedFontLst>/, '');
  if (/<p:notesSz\b[^>]*\/>/.test(presentation)) {
    presentation = presentation.replace(/(<p:notesSz\b[^>]*\/>)/, `$1${list}`);
  } else {
    presentation = presentation.replace(/(<p:defaultTextStyle\b)/, `${list}$1`);
  }
  if (!/xmlns:r=/.test(presentation)) {
    presentation = presentation.replace(
      /<p:presentation\b/,
      '<p:presentation xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
    );
  }
  presentation = presentation.replace(/<p:presentation\b([^>]*)>/, (whole, attrs) =>
    /embedTrueTypeFonts=/.test(attrs) ? whole : `<p:presentation${attrs} embedTrueTypeFonts="1">`
  );
  if (!/Extension="fntdata"/.test(types)) {
    types = types.replace(/(<Types\b[^>]*>)/, '$1<Default Extension="fntdata" ContentType="application/x-fontdata"/>');
  }

  zip.file(relsPath, rels);
  zip.file('ppt/presentation.xml', presentation);
  zip.file('[Content_Types].xml', types);
  return result;
}

/** Embedding is on unless PPTX_EMBED_FONTS=0 (an escape hatch if a font source misbehaves). */
function fontEmbeddingEnabled() {
  return String(process.env.PPTX_EMBED_FONTS ?? '1') !== '0';
}

module.exports = {
  primaryFamily,
  shouldEmbedFamily,
  ttfToEot,
  fontNames,
  fontUsage,
  loadFace,
  embedPptxFonts,
  fontEmbeddingEnabled,
  FACES,
};
