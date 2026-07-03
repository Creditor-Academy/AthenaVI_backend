const express = require('express');
const earlyAccessController = require('./earlyAccess.controller');

const router = express.Router();

router.post('/request', earlyAccessController.submitEarlyAccessRequest);

module.exports = router;
