const express = require("express");
const postsController = require("../controllers/postsController");
const { identifier } = require("../middlewares/identification");
const router = express.Router();

module.exports = router;
