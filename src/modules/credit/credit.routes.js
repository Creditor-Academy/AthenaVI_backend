const express = require("express");
const router = express.Router();
const creditController = require("./credit.controller");
const { authMiddleware } = require("../../middlewares/auth.middlware");

router.get("/", authMiddleware, creditController.getCredits);
router.get("/history", authMiddleware, creditController.getCreditHistory);
router.post('/generate')

module.exports = router; 