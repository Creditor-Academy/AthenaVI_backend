const MAX_JSON_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

function toBigInt(value) {
  if (value == null) {
    return 0n;
  }
  if (typeof value === 'bigint') {
    return value;
  }
  const n = Math.floor(Number(value));
  if (!Number.isFinite(n)) {
    return 0n;
  }
  return BigInt(n);
}

function toJsonNumber(value) {
  if (value == null) {
    return 0;
  }
  const asBigInt = typeof value === 'bigint' ? value : toBigInt(value);
  if (
    asBigInt > BigInt(MAX_JSON_SAFE_INTEGER) ||
    asBigInt < BigInt(-MAX_JSON_SAFE_INTEGER)
  ) {
    return asBigInt.toString();
  }
  return Number(asBigInt);
}

function byteAdd(a, b) {
  return toBigInt(a) + toBigInt(b);
}

function byteSub(a, b) {
  return toBigInt(a) - toBigInt(b);
}

function byteGt(a, b) {
  return toBigInt(a) > toBigInt(b);
}

function byteGte(a, b) {
  return toBigInt(a) >= toBigInt(b);
}

function byteLt(a, b) {
  return toBigInt(a) < toBigInt(b);
}

function byteLte(a, b) {
  return toBigInt(a) <= toBigInt(b);
}

function sumNullableByteFields(rows, field) {
  return (rows || []).reduce((sum, row) => sum + toBigInt(row?.[field]), 0n);
}

function sumPrismaAggregate(value) {
  return toJsonNumber(value ?? 0);
}

module.exports = {
  toBigInt,
  toJsonNumber,
  byteAdd,
  byteSub,
  byteGt,
  byteGte,
  byteLt,
  byteLte,
  sumNullableByteFields,
  sumPrismaAggregate,
};
