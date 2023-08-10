const Joi = require("joi");
const signupVerification = Joi.object().keys({
  name: Joi.string().min(1).required(),
  email: Joi.string().email(),
  password: Joi.string().min(8).required(),
  phone: Joi.string().min(10).required(),
  age: Joi.string().min(2).required(),
  gender: Joi.string().min(1).required(),
  area: Joi.string().min(3).required(),
  is_Admin : Joi.boolean(),
  voter_id:Joi.string().min(10).max(10).required(),
});

const signinVerification = Joi.object().keys({
  email: Joi.string().required(),
  password: Joi.string().min(8).required(),
});

module.exports = {
  signupVerification,
  signinVerification
};