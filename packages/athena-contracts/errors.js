'use strict';

class ContentContractValidationError extends Error {
  /**
   * @param {string} layoutId
   * @param {Array<{ code: string, message: string, slotId?: string, path?: string }>} errors
   */
  constructor(layoutId, errors = []) {
    const list = Array.isArray(errors) ? errors : [];
    super(
      list.length
        ? `Content contract validation failed for ${layoutId || 'unknown layout'}: ${list.map((e) => e.message).join('; ')}`
        : `Content contract validation failed for ${layoutId || 'unknown layout'}`
    );
    this.name = 'ContentContractValidationError';
    this.layoutId = layoutId || '';
    this.errors = list;
  }
}

module.exports = { ContentContractValidationError };
