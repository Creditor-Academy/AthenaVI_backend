const prisma = require('../config/prismaClient');

function toUserSummary(user) {
  if (!user) {
    return null;
  }
  return {
    id: user.id,
    name: user.name,
    email: user.email,
  };
}

async function findUsersByIds(userIds) {
  const uniqueIds = [...new Set(userIds.filter(Boolean))];
  if (!uniqueIds.length) {
    return [];
  }
  return prisma.user.findMany({
    where: { id: { in: uniqueIds } },
    select: { id: true, name: true, email: true },
  });
}

/**
 * Batch-load users and attach summary objects to entities.
 * @param {object[]} entities
 * @param {{ sourceField: string, targetField: string }[]} fieldMap
 */
async function attachUsers(entities, fieldMap) {
  if (!entities.length) {
    return entities;
  }

  const ids = new Set();
  for (const entity of entities) {
    for (const { sourceField } of fieldMap) {
      if (entity[sourceField]) {
        ids.add(entity[sourceField]);
      }
    }
  }

  const users = await findUsersByIds([...ids]);
  const userById = new Map(users.map((u) => [u.id, u]));

  return entities.map((entity) => {
    const enriched = { ...entity };
    for (const { sourceField, targetField } of fieldMap) {
      enriched[targetField] = toUserSummary(userById.get(entity[sourceField]));
    }
    return enriched;
  });
}

module.exports = {
  attachUsers,
  findUsersByIds,
  toUserSummary,
};
