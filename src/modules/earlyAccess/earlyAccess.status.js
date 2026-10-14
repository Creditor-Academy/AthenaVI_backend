const TERMINAL_STATUSES = new Set(['APPROVED', 'REJECTED']);

const ALL_STATUSES = ['PENDING', 'UNDER_REVIEW', 'IN_DISCUSSION', 'APPROVED', 'REJECTED'];

const OPEN_STATUSES = ['PENDING', 'UNDER_REVIEW', 'IN_DISCUSSION'];

function toApiStatus(dbStatus) {
  return String(dbStatus).toLowerCase();
}

function toDbStatus(apiStatus) {
  return String(apiStatus).trim().toUpperCase().replace(/-/g, '_');
}

function isTerminalStatus(status) {
  return TERMINAL_STATUSES.has(status);
}

function assertValidDbStatus(status) {
  if (!ALL_STATUSES.includes(status)) {
    return false;
  }
  return true;
}

module.exports = {
  TERMINAL_STATUSES,
  ALL_STATUSES,
  OPEN_STATUSES,
  toApiStatus,
  toDbStatus,
  isTerminalStatus,
  assertValidDbStatus,
};
