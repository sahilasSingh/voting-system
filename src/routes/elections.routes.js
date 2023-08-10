const express = require('express');
const router = express.Router();

const electionController = require('../controllers/elections.controller');
const votingController= require('../controllers/candidates.controller');

router.post('/voting', votingController.vote);
router.post('/createElection', electionController.createElection); 
router.get('/viewElection', electionController.getElection);
// router.get('/viewElectionById/:id', electionController.getElectionById);
// router.put('/updateElection/:id', electionController.updateElection);
// router.delete('/deleteElection/:id', electionController.deleteElection);
// router.post('/electionType', electionController.electionType);
// router.get('/pastElection', electionController.pastElection);
// router.get('/upComingElection', electionController.upComingElection);


module.exports = router;