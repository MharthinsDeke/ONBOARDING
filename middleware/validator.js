const Joi = require('joi');
const joi = require('joi');

exports.signUpValidator = async (req,res,next) => {
  const schema = Joi.object({
    firstName : Joi.string().min(3).max(30).pattern(new RegExp('^[A-Za-z]+$')).required().messages({
        'any.required': 'Firstname is required',
        'string.empty': 'Firstname cannot be empty',
        'string.min': 'Firstname should contain atleast 3 characters',
        'string.max': 'Firstname should not be more than 30 characters long',
        'string.pattern.base': 'Firstname can only contain letters with no spaces'
    }),
    lastName : Joi.string().min(3).max(30).pattern(new RegExp('^[A-Za-z]+$')).required().messages({
         'any.required': 'Lastname is required',
        'string.empty': 'Lastname cannot be empty',
        'string.min': 'Lastname should contain atleast 3 characters',
        'string.max': 'Lastname should not be more than 30 characters long',
        'string.pattern.base': 'Lastname can only contain letters with no spaces'
    }),
    email: Joi.string().email().required().messages({
        'any.required': 'Email is required',
        'string.empty': 'Email cannot be empty',
        'string.email': 'Invalid email format'
        
    }),
    password: Joi.string().min(3).max(30).pattern(new RegExp('^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$'))
    .required().messages({
        'any.required': 'Password is required',
        'string.empty': 'Password cannot be empty',
        'string.pattern.base': 'Password must  be at least 8 characters long, contain at least one Uppercase, Lowercase, Digits and a special character ?=.*?[#?!@$%^&*-]'
    })
  })
  const {error} = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
        message: error.details[0].message
    })
  }
  next()
}
exports.logInValidator = async (req,res,next) => {
  const schema = Joi.object({
    email: Joi.string().email().required().messages({
      'any.required': 'Email is required',
      'string.empty': 'Email cannot be empty.',
      'string.email': 'Invalid email format'
    }),
    password: Joi.string().required().messages({
      'any.required': 'Password is required',
      'string.empty': 'Password cannot be required'
    })

  })
  const {error} = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
        message: error.details[0].message
    })
  }
  next()
}