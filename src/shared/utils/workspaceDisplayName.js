/**
 * Admin-facing workspace label. Default PRIVATE workspaces are all named "Personal"
 * in the DB; include the owner so they are distinguishable in reports.
 */
function formatWorkspaceDisplayName({ name, type, owner }) {
  if (type !== 'PRIVATE' || !owner) {
    return name;
  }

  const ownerLabel = owner.name?.trim() || owner.email;
  if (!ownerLabel) {
    return name;
  }

  const trimmedName = (name || '').trim();
  if (/^personal$/i.test(trimmedName)) {
    return `${ownerLabel}'s Personal`;
  }

  return trimmedName || name;
}

module.exports = {
  formatWorkspaceDisplayName,
};
