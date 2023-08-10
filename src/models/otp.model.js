const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true
  },
  otp: {
   type: String, 
   required: true 
  },
  userid : {
   type: String 
  },
  created_at: { 
    type: Date, 
    default: Date.now, 
    expires: 300 
  }
});

const Otp = mongoose.model('Otp', otpSchema);

module.exports = Otp;
