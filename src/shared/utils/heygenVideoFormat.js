function normalizeHeygenOutputFormat(value) {
  const normalized =
    value == null || String(value).trim() === '' ? 'mp4' : String(value).trim().toLowerCase();
  return normalized === 'webm' ? 'webm' : 'mp4';
}

function heygenOutputFileExtension(format) {
  return normalizeHeygenOutputFormat(format) === 'webm' ? 'webm' : 'mp4';
}

function heygenOutputContentType(format) {
  return heygenOutputFileExtension(format) === 'webm' ? 'video/webm' : 'video/mp4';
}

function resolveHeygenOutputFormatFromRecord(record) {
  const ctx = record?.billingContext;
  if (ctx && typeof ctx === 'object' && ctx.outputFormat != null) {
    return normalizeHeygenOutputFormat(ctx.outputFormat);
  }
  if (record?.s3Key && /\.webm$/i.test(String(record.s3Key))) {
    return 'webm';
  }
  return 'mp4';
}

module.exports = {
  normalizeHeygenOutputFormat,
  heygenOutputFileExtension,
  heygenOutputContentType,
  resolveHeygenOutputFormatFromRecord,
};
