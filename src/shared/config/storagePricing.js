function envNumber(name, fallback) {
  const raw = process.env[name];
  if (raw == null || String(raw).trim() === '') return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? Math.floor(parsed) : fallback;
}

const STORAGE_TIER_IDS = Object.freeze({
  FREE: 'free',
  PLUS_10GB: 'plus_10gb',
  PRO_50GB: 'pro_50gb',
});

const STORAGE_TIERS = Object.freeze([
  {
    id: STORAGE_TIER_IDS.FREE,
    label: 'Free',
    limitBytes: Math.max(1, envNumber('DEFAULT_STORAGE_LIMIT_BYTES', 1073741824)),
  },
  {
    id: STORAGE_TIER_IDS.PLUS_10GB,
    label: 'Plus 10 GB',
    limitBytes: 10 * 1024 * 1024 * 1024,
  },
  {
    id: STORAGE_TIER_IDS.PRO_50GB,
    label: 'Pro 50 GB',
    limitBytes: 50 * 1024 * 1024 * 1024,
  },
]);

function getDefaultStorageTier() {
  return STORAGE_TIERS[0];
}

function getStorageTierById(tierId) {
  return STORAGE_TIERS.find((tier) => tier.id === tierId) || null;
}

function getMaxStorageLimitBytes() {
  return STORAGE_TIERS.reduce((max, tier) => Math.max(max, tier.limitBytes), 0);
}

module.exports = {
  STORAGE_TIERS,
  STORAGE_TIER_IDS,
  getDefaultStorageTier,
  getStorageTierById,
  getMaxStorageLimitBytes,
};
