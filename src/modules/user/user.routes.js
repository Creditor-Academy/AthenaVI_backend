const express = require("express");
const router = express.Router();
const userController = require("./user.controller");
const { authMiddleware } = require("../../middlewares/auth.middlware");

// GET /api/user - Get all users (public route for now)
router.get("/getall",authMiddleware, userController.getAllUsers);

module.exports = router;