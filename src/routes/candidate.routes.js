const express = require('express');
const router = express.Router();

console.log('router loaded');

router.use('/users', require('./users.routes'));
router.use('/voting', require('./voting.routes'));

module.exports=router;