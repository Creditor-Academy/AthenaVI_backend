const superadminService = require('./superadmin.service');
const inboxService = require('../inbox/inbox.service');
const inboxDao = require('../inbox/inbox.dao');
const { PLATFORM_HEYGEN_WALLET_THRESHOLD_USD } = require('../../shared/config/notificationThresholds');

async function checkHeygenWalletAlert() {
  try {
    const account = await superadminService.getHeygenAccountBilling();
    const remaining = account?.wallet?.remainingBalanceUsd;

    if (typeof remaining !== 'number') {
      return { checked: true, alerted: false, reason: 'no_wallet_balance' };
    }

    if (remaining < PLATFORM_HEYGEN_WALLET_THRESHOLD_USD) {
      await inboxService.notifyPlatformHeygenWalletLow({
        remainingBalanceUsd: remaining,
        thresholdUsd: PLATFORM_HEYGEN_WALLET_THRESHOLD_USD,
      });
      return { checked: true, alerted: true, remainingBalanceUsd: remaining };
    }

    await inboxService.clearPlatformHeygenWalletLow();
    return { checked: true, alerted: false, remainingBalanceUsd: remaining };
  } catch (error) {
    console.error('HeyGen wallet alert check failed:', error.message);
    return { checked: false, error: error.message };
  }
}

async function getAlertsSummary(userId) {
  const [unreadPlatformCount, heygenResult] = await Promise.all([
    inboxDao.countUnreadPlatformByUserId(userId),
    superadminService.getHeygenAccountBilling().catch(() => null),
  ]);

  return {
    unreadPlatformCount,
    heygenWallet: heygenResult?.wallet
      ? {
          remainingBalanceUsd: heygenResult.wallet.remainingBalanceUsd,
          currency: heygenResult.wallet.currency,
          thresholdUsd: PLATFORM_HEYGEN_WALLET_THRESHOLD_USD,
          isLow:
            typeof heygenResult.wallet.remainingBalanceUsd === 'number' &&
            heygenResult.wallet.remainingBalanceUsd < PLATFORM_HEYGEN_WALLET_THRESHOLD_USD,
        }
      : null,
    fetchedAt: new Date().toISOString(),
  };
}

module.exports = {
  checkHeygenWalletAlert,
  getAlertsSummary,
};
