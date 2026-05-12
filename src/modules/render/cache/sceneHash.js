const crypto = require('crypto');

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }

  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
      .join(',')}}`;
  }

  return JSON.stringify(value);
}

function stripTransientFields(value) {
  if (Array.isArray(value)) {
    return value.map((item) => stripTransientFields(item));
  }

  if (!value || typeof value !== 'object') {
    return value;
  }

  const output = {};
  for (const [key, child] of Object.entries(value)) {
    if (['src', 'url', 'presignedUrl', 'outputUrl'].includes(key)) {
      continue;
    }
    output[key] = stripTransientFields(child);
  }
  return output;
}

function createSceneHash(sceneManifest) {
  const normalized = stripTransientFields(sceneManifest);
  return crypto.createHash('sha256').update(stableStringify(normalized)).digest('hex');
}

module.exports = {
  stableStringify,
  stripTransientFields,
  createSceneHash,
};
