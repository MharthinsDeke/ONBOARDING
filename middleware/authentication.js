const jwt = require('jsonwebtoken');
const userModel = require('../Models/userModel');
exports.authenticate = async(req,res,next)=>{
try {
    const auth = req.headers.authorization;
    const token = auth.split(' ')[1]

    const decoded = jwt.verify(token, process.env.JWT_SECRET)

    const user = await userModel.findById(decoded.id)
    if (!user) {
        return res.status(404).json({
            message : `Authentication failed: 'User not found`
        })
    }
    req.user = decoded;

    next()

} catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
        return res.status(500).json({
            message: `session expired, please log in to continue`
        })
    }
 res.status(500).json({
    message: error.message
 })
}
}