function parsePositiveInt(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }
  return Math.floor(parsed);
}

function parsePositiveFloat(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }
  return parsed;
}

const CREDITS_LOW_THRESHOLD_AC = parsePositiveInt(
  process.env.CREDITS_LOW_THRESHOLD_AC,
  100
);

const PLATFORM_HEYGEN_WALLET_THRESHOLD_USD = parsePositiveFloat(
  process.env.PLATFORM_HEYGEN_WALLET_THRESHOLD_USD,
  50
);

const STORAGE_THRESHOLD_PERCENTS = [80, 95, 100];

const PLATFORM_ALERTS_JOB_INTERVAL_MS = parsePositiveInt(
  process.env.PLATFORM_ALERTS_JOB_INTERVAL_MS,
  60 * 60 * 1000
);

module.exports = {
  CREDITS_LOW_THRESHOLD_AC,
  PLATFORM_HEYGEN_WALLET_THRESHOLD_USD,
  STORAGE_THRESHOLD_PERCENTS,
  PLATFORM_ALERTS_JOB_INTERVAL_MS,
};
