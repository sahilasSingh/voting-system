const mongoose = require('mongoose');

const electionSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
        
    },
    type: {
        type: String,
        enum: ["Assembly", "Lok_Sabha", "Panchayat"],
        required: true,

    },
    date: {
        type: Date,
        required: true,
        unique: true
    },
    startDate: {
        type: Date,
        required: true
    },
    endDate: {
        type: Date,
        required: true
    },
    location:{
        type:String,
        required:true,

    },
    areaId:{
        type:String,
        required:true,
    },
    state:{
        type:String,
        required:true,
    },
    district:{
        type:String,
        required:true,
    },
    area: {
        type: String,
        required: true
    },
    candidate: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }
}, {
    timestamps: true
});

const Election = mongoose.model('Election', electionSchema);

module.exports = Election;