const mongoose = require('mongoose');

const candidateSchema = new mongoose.Schema({
    CandidateName: {
        type: String,
        required: true
    },
    party: {
        type: String,
        required: true
    },
    logo: {
        type: String,
        required: true
    },
    votes: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Vote'
        }
    ]
}, {
    timestamps: true
});

const Candidate = mongoose.model('Candidate', candidateSchema);

module.exports = Candidate;