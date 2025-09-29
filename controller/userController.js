const userModel = require('../Models/userModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { signUpTemplate, verificationTemplate, resetPasswordTemplate } = require('../utils/emailTemplates');
const emailSender = require('../middleware/nodemailer');

exports.signup = async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body
        const userExists = await userModel.findOne({ email: email.toLowerCase() });
        if (userExists) {
            return res.status(404).json({
                message: `User already exists`
            })
        }
        const saltedRounds = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, saltedRounds)

        const user = new userModel({
            firstName,
            lastName,
            email: email.toLowerCase(),
            password: hashedPassword
        })

        await user.save();

        const token = jwt.sign({
            id: user._id,
            email: user.email
        }, process.env.JWT_SECRET, { expiresIn: '1hr' })

        const link = `${req.protocol}://${req.get('host')}/users/verify/${token}`
        console.log('Link', link);

        const emailOption = {
            email: user.email,
            subject: 'Graduation Note',
            html: signUpTemplate(link, user.firstName)
        }
        await emailSender(emailOption)

        res.status(210).json({
            message: `User registered successfully`,
            data: user
        })
    } catch (error) {
        res.status(500).json({
            message: error.message
        });

    }
}
exports.verifyUser = async (req, res) => {
    try {
        const { token } = req.params;
        if (!token) {
            return res.status(400).json({
                message: 'Token not found',
            })
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await userModel.findById(decoded.id)
        if (!user) {
            return res.status(404).json({
                message: `User Not Found`
            })
        }

        if (user.isVerified) {
            return res.status(400).json({
                message: `User already verified, Please proceed to login`
            })
        }

        user.isVerified = true;
        await user.save();

        res.status(200).json({
            message: `User verified successfully`,
            data: user
        })
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(500).json({
                message: `Session expired, please resend verification`
            })
        }
        res.status(500).json({
            message: error.message
        })
    }
}

exports.resendVerification = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await userModel.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({
                message: `User not found`
            })
        }
        if (user.isVerified) {
            return res.status(400).json({
                message: 'User already verified, Please proceed to login'
            })
        }
        const token = jwt.sign({
            email: user.email,
            id: user._id
        }, process.env.JWT_SECRET, { expiresIn: '30mins' });

        const link = `${req.protocol}://${req.get('host')}/users/verify/${token}`
        const option = {
            email: user.email,
            subject: 'Verification Email',
            html: verificationTemplate(link, user.firstName)
        }
        await emailSender(option);
        res.status(200).json({
            message: `verification email sent successfully, please check your email to verify`
        });
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }

}

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body
        const user = await userModel.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({
                message: 'User not found'
            })
        }
        const passwordCorrect = await bcrypt.compare(password, user.password);
        if (passwordCorrect === false) {
            return res.status(404).json({
                message: 'Incorrect Password'
            })
        };
        if (user.isVerified === false) {
            return res.status(401).json({
                message: `User not verified ,please check your email for verification link`
            });
        }
        const token = jwt.sign({
            email: user.email,
            id: user._id
        }, process.env.JWT_SECRET, { expiresIn: '1hr' });

        res.status(200).json({
            message: 'Login successful',
            data: user,
            token
        })



    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}
exports.forgotPassword = async (req,res) => {
    try {
        const { email } = req.body;
        const user = await userModel.findOne({email: email.toLowerCase()});
        if (!user) {
            return res.status(400).json({
                message: `User not found`
            })
        }
        const token = jwt.sign({
            email: user.email,
            id: user._id
        }, process.env.JWT_SECRET,{expiresIn: '10mins'});
        const link = `${req.protocol}://${req.get('host')}/users/reset/password/${token}`;

        const options = {
            email: user.email,
            subject: 'Reset Password',
            html: resetPasswordTemplate(link,user.firstName)
        }

        await emailSender(options);
        res.status(200).json({
            message: 'Reset password request is successful'
        })

    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.resetPassword = async (req,res) => {
    try {
        const { token } = req.params;
        const { newPassword, confirmPassword } = req.body;
       if (newPassword !== confirmPassword) {
        return res.status(400).json({
            message: `Password does not match`
        })
       }
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user =  await userModel.findById(decoded.id)
        if (!user) {
            res.status(404).json({
                message: `User not found`
            })
        }
        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(newPassword,salt);
        user.password = hashedPassword;
        await user.save();
        return res.status(200).json({
            message: `Password reset successful`
        })
    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            return res.status(400).json({
                message: 'Link expired , please request a new link'
            })
        }
        res.status(500).json({
            message: error.message
        })
    }
};

exports.getAll = async (req,res) => {
    try {
        const users = await userModel.find();
        res.status(200).json({
            message: `All users in Database and total is ${users.length}`
        })
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}
exports.changePassword = async (req,res) => {
    try {
        const userId = req.user.id;
        const {oldPassword, newPassword, confirmPassword} = req.body;
        const user = await userModel.findById(userId)
        if (!user) {
            return res.status(404).json({
                message: `User not found`
            })
        }
        if (newPassword !== confirmPassword) {
            returnres.status(400).json({
                message: `Password does not match`
            })
        } 
        const passwordCorrect = await bcrypt.compare(oldPassword, user.password);
        if (!passwordCorrect) {
            return res.status(400).json({
                message: 'Old password incorrect'
            })
        }
        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        await user.save()

        res.status(200).json({
            message: 'Password updated Successfully'
        })

    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}
