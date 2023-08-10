const express = require('express');
const router = express.Router();
const { veirfyToken } = require("../middleware/auth");
const bodyParser = require('body-parser');
const userValidation=require('../middleware/user')
const usersController=require('../controllers/users.controller');
const verifyToken = require('../middleware/auth');
const Otp = require("../models/otp.model");

router.post('/sign-in', userValidation.signinVerificationMiddleware, usersController.signin);
router.post('/sign-up', userValidation.signupVerificationMiddleware, usersController.signup);
router.get('/profile', verifyToken, usersController.profile);
router.post('/verifyotp',usersController.verifyOtp)
//router.get('/searchLocation', usersController.searchLocation);
//router.post('/updatePassword',verifyToken,  usersController.updatePassword);

router.post('/verifyEmail',  usersController.verifyEmail);
router.post('/verifyOtp',  usersController.verifyOtp);

module.exports = router;    