const {
    signinVerification,
    signupVerification,
  } = require("../validation/user.validation");
  
  const signinVerificationMiddleware = async (req, res, next) => {
    try {
      const userCredentialsVerification = await signinVerification.validateAsync(
        req.body
      );
      next()
    } catch (error) {
      next(error);
    }
  };
  
  const signupVerificationMiddleware = async (req, res, next) => {
    try {
      const userCredentialsVerification = await signupVerification.validateAsync(
        req.body
      );
      next();
    } catch (error) {
      next(error);
    }
  };
  
  module.exports = {
    signinVerificationMiddleware,
    signupVerificationMiddleware,
  };
  