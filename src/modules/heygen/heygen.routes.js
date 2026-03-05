const express = require('express');
const router = express.Router();
const heygenController = require('./heygen.controller');

router.post('/generate', heygenController.generateHeygenVideo);



module.exports = router;