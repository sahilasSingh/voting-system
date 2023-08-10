const bcrypt = require("bcryptjs");
const jsonwt = require("jsonwebtoken");
const Candidate = require("../models/candidate.model");

const vote = async (req, res, next) => {
  try {
    
    const candidate = await Candidate.find()
    
      return res.status(200).json({ success: true, data: candidate });
     } catch (error) {
      next(error);
     }
};

module.exports = {vote}