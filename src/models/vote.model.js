const mongoose = require('mongoose');


const voteSchema = new mongoose.Schema({
    userId: {
        type: String,
        required:true
    },
    date: {
        type:Date,
        required:true
    },
    partyId:{
        type:String,
        required:true
    },
    electionId:{
        type:String,
        required:true
    },
    voterId:{
        type:String,
        required:true
    }
}, {
    timestamps: true
});

const Vote = mongoose.model('Vote', voteSchema);
module.exports = Vote;