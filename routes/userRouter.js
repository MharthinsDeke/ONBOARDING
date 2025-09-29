const router = require ('express').Router();

const { signup, verifyUser, resendVerification, login, forgotPassword, resetPassword, getAll, changePassword } = require('../controller/userController');
const { authenticate } = require('../middleware/authentication');
const { signUpValidator, logInValidator } = require('../middleware/validator');




router.post('/user', signUpValidator, signup);

router.get('/users/verify/:token', verifyUser );

router.post('/users/resend-verification', resendVerification);

router.post('/users/login',logInValidator, login);

router.post('/users/forgot/password', forgotPassword)

router.post('/users/reset/password/:token', resetPassword)

router.get('/users', authenticate, getAll)

router.patch('/users/change/password',authenticate, changePassword)

module.exports = router;