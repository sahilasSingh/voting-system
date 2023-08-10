const jwt = require("jsonwebtoken");
const User=require("../models/user.model")

const key = process.env.JWT_KEY;

const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization.split(" ")[1];
    if (!token) {
      throw(new ErrorHandler("Auth error", 400));
    }
    const decodeToken = await jwt.verify(token, key);
    // console.log("decodeToken -> ", decodeToken);
    // req.user = decodeToken;

    if(!decodeToken)
    throw new ErrorHandler("Invalid token",400)

    const user=User.findById(decodeToken.id)

     if (!user) {
      throw new ErrorHandler("User not found", 404);
     }
     user.password=undefined
     req.user= user;
     req._id = decodeToken.id
     
    next();
  } catch (error) {
    next(error);
  }
};
module.exports = verifyToken;