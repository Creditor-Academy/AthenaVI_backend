const express = require("express");
const router = express.Router();
const userController = require("./user.controller");

// GET /api/user - Get all users (public route for now)
router.get("/getall", userController.getAllUsers);

module.exports = router;