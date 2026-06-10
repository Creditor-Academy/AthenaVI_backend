function getSaltRounds() {
  const parsed = Number(process.env.SALT_ROUNDS);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 10;
}

module.exports = { getSaltRounds };
