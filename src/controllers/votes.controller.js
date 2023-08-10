const Vote = require("../models/vote.model");
const Candidate = require("../models/candidate.model");
const ErrorHandler  =require("../utils/errorHandler")
const User = require("../models/user.model")
const Mailsend = require('../utils/mail')
const Otp = require("../models/otp.model");

exports.createVote = async(req,res,next) =>{
    let  user = {}
    const currentDate = new Date();
    const {partyId, electionId, voterId}=req.body
    if(!partyId || !electionId || !voterId){
       return next( new ErrorHandler("please enter the required fields",422));
    }
    user.userId=req._id;
    user.date = currentDate;
    user.partyId =partyId;
    user.electionId = electionId;
    user.voterId =voterId
   
const vote = await Vote.create(user);
    res.status(201).json({
        success:true,
        message:`Vote created!`,
        vote:vote
    })
}

exports.vertifyId= async(req,res,next)=>{
    const voter_id = req.body.voterId
    const users = await User.findOne({ voter_id:voter_id })
  
    if(!users){
        return next( new ErrorHandler("No voter id found",404));
    }
    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    const payload = {
        email:users.email,
        otp: otp,
        
      };
      const otpCreate = new Otp(payload);
      otpCreate.save();
      // console.log(Otp)
      const message = `Here is your your otp : ${otp}.If you haven't requested this ignore it.`;
    try {
    
        await Mailsend({
          email: users.email,
          subject: `Voting otp verification mail`,
          message,

        });
        res.status(201).json({
            success:true,
            message:`check mail for otp`
        })

      }catch(err){
        console.log(err);
      }
}


























// module.exports.toggleLike = async function(req, res){
//     try{
//         let voteable;

//         voteable = await Candidate.findById(req.query.id).populate('vote');

//         let existingVote = await Vote.findOne({
//             voteable: req.query.id,
//             onModel: req.query.type,
//             user: req.user._id
//         });

//         if(!existingVote){
//             let newVote = await Vote.create({
//                 user: req.user._id,
//                 voteable: req.query.id,
//                 onModel: req.query.type
//             });

//             voteable.likes.push(newVote._id);
//             voteable.save();
//         }

//         return res.status(200).json({
//             message: "Request successful",
//             data: {
//             }
//         })

//     }catch(err){
//         console.log(err);
//         return res.json(500, {
//             message: 'Internal server error'
//         });
//     }
// }