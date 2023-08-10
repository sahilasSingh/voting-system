const bcrypt = require("bcryptjs");
const jsonwt = require("jsonwebtoken");
const User = require("../models/user.model");
const Mailsend = require('../utils/mail')
const Otp = require("../models/otp.model");
const ErrorHandler = require("../utils/errorHandler")
// const fast2sms = require('fast-two-sms')
//const GoogleStrategy = require('passport-google-oauth20').Strategy;
require ('dotenv').config();

const securePassword = async (password) => {
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    return passwordHash;
  } catch (error) {
    res.status(400).send(error.message);
  }
};

const signup = async (req, res, next) => {
  const { name, email, area, age, phone, password, gender,voter_id} = req.body
  try {
    if (!name || !email || !area || !age || !phone  || !gender || !password || !voter_id) {
      throw new Error("All the fields should be valid", {
          cause: { status: 400 }
      })
  }
    const userByEmail = await User.findOne({ email: req.body.email });
    if (userByEmail) {
      throw new Error(" Email already registered", 400);
    }

    const newUser = new User(req.body)
    await newUser.save();
   
    //sendWelcomeEmail(req.body.email,Otp)
    return res.json({
      success: true,
      data: "user registered successfully",
      // user:newPerson
    });
  } catch (error) {
    next(error);
  }
};

const verifyEmail = async(req,res,next)=>{
  try{
  const otp = Math.floor(1000 + Math.random() * 9000).toString();
  await new Otp({ email:req.body.email,otp:otp })
  .save()
  const message = `Here is your your otp : ${otp}.If you haven't requested this ignore it.`;
  try {
      await Mailsend({
        email: req.body.email,
        subject: `Voting otp verification mail`,
        message,
      });
    }catch(err){
      console.log('error');
    }
  res.status(200).json({
    success: true,
    data: "Check mail for otp"
})
}catch (error){
   next(error)
}
}

const verifyOtp =  async (req,res,next) =>{
  const otp = req.body.otp;
  const otps = await Otp.findOne({otp:otp}) 
 try{
  if( otps !== null  ){
    if(otps.userid !== undefined){
    const jwtParams = { expiresIn: 3600 };
    const payload={
      id:otps.userid,
      email:otps.email
    }
    const token = jsonwt.sign(payload, process.env.JWT_KEY, jwtParams);
    await Otp.findByIdAndDelete({_id:otps.id})
    return res.status(200).json({
      success: true,
      message:"successfully logged in",
      token: token, 
    });
  }
  else if(otps.userid === undefined){
    await Otp.findByIdAndDelete({_id:otps.id})
    return res.status(200).json({
      success: true,
      message:"Email verified successfully",
    });
  }
  }
  else{
    throw new ErrorHandler
    ("Invalid Otp", 401);
  }
}
catch(error){
  next(error);
}   
}

const signin = async (req, res, next) => {
  try {
   // console.log(req)
    const email = req.body.email;
    const password = req.body.password;
    const otp = Math.floor(1000 + Math.random() * 9000).toString();
   
    const user = await User.findOne({ email });

    if (!user) throw new Error("No user found", 404);
 
    const checkPass = await bcrypt.compare(password, user.password);
  
    if (!checkPass) throw new Error("Incorrect password", 412);

    const payload = {
      email:user.email,
      otp: otp,
      userid: user.id
    };
    const otpCreate = new Otp(payload);
    otpCreate.save();
    // console.log(Otp)
    const message = `Here is your your otp : ${otp}.If you haven't requested this ignore it.`;
  try {
  
      await Mailsend({
        email: user.email,
        subject: `Voting otp verification mail`,
        message,
      });
    }catch(err){
      console.log('error');
    }
  
    return res.status(200).json({
      success: true,
      message: "Check mail for otp",
    });
  } catch (error) {
    next(error);
  }
};

const profile = async (req, res, next) => {
  try {
    //const email = req.body.email;
    const user = await User.findById(req._id);
    return res.status(200).json({ success: true, data: user });
  } catch (error) {
    next(error);
  }
};

const updatePassword = async (req, res, next) => {
  try {
    //const useId = req.body.userId;
    const password = req.body.password;
    console.log(req._id)
    const data = await User.findOne({ _id: req._id });

    if (data) {
      const newPassword = await securePassword(password);

      const userData = await User.findByIdAndUpdate(
        { _id: req._id },

        {
          $set: {
            password: newPassword,
          },
        }
      );

      return res
        .status(200)
        .send({ success: true, data: "password updated"});
    }
  } catch (error) {
    next(error);
  }
};

 module.exports = {signin,signup,securePassword,updatePassword,profile,verifyEmail,verifyOtp }