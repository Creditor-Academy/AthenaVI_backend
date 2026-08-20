function visualRoleFromDeckRhythmEntry(entry) {
  const role = String(entry?.role || '').toLowerCase();
  if (!role) return 'text';
  if (role === 'hero') return 'cover';
  if (role === 'closing') return 'closing';
  if (role === 'visual') return 'visual';
  if (role === 'balanced') return 'balanced';
  return 'text';
}

module.exports = {
  visualRoleFromDeckRhythmEntry,
};

