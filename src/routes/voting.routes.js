const express = require('express');
const router = express.Router();
const { veirfyToken } = require("../middleware/auth");
const candidateController = require('../controllers/candidates.controller')
const votingController= require('../controllers/votes.controller');
const verifyToken = require('../middleware/auth');

router.get('/votes',candidateController.vote);

router.post('/vote',verifyToken, votingController.createVote);
router.post('/verifyid',votingController.vertifyId)

module.exports = router;