const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const bcryptSalt = process.env.BCRYPT_SALT;
const jsonwt = require("jsonwebtoken");
// const area = require("../utils/area")

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true,
        required: true
    },
    password: {
        type: String,
        required: true,
        trim:true,
        minLength: [8,"Password should be greater than 8 characters"],
       
        validate(value){
            if(value.toLowerCase().includes('password')){
                throw new Error('password doesnot contain (password )')
            }
        }
    },
    name: {
        type: String,
        required: true
    },
    age: {
        type: Number,
        require: true
    },
    gender:{
        type: String,
        required: true
    },
    voter_id:{
        type:String,
        required:true,
    },
    is_Admin:{
        type:Boolean,
        required:false,
    },
    phone: {
        type: Number,
        require: true
    },
    area: {
        type: String,
        required: true
    },
    token: {
        type: String
    }
}, {
    timestamps: true
});

userSchema.pre('save', async function(){
    const user = this;
    user.password = await bcrypt.hash(user.password, 10);
    return user;
});

userSchema.pre('findOneAndUpdate',async function(){
    const user = this;
    if(user.isModified('password')){
        user.password = await bcrypt.hash(user.password, 10);
    }
    return user;
})

userSchema.methods.toJSON = function (){
   
    const user = this;
    const userObj = user.toObject();
    delete userObj.password;
    return userObj;

}

const User = mongoose.model('User', userSchema);

module.exports = User;