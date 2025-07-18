const express = require('express');
const router = express.Router();

// Import controllers
const {
  register,
  login,
  logout,
  getMe,
  updateDetails,
  updatePassword,
  forgotPassword,
  resetPassword,
  verifyEmail,
  resendVerification
} = require('../controllers/authController');

// Import middleware
const { protect } = require('../middleware/auth');
const {
  registerValidation,
  loginValidation,
  updatePasswordValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
  updateDetailsValidation
} = require('../middleware/validate');

// Public routes
router.post('/register', registerValidation, register);
router.post('/login', loginValidation, login);
router.post('/forgotpassword', forgotPasswordValidation, forgotPassword);
router.put('/resetpassword/:resettoken', resetPasswordValidation, resetPassword);
router.get('/verify-email/:token', verifyEmail);

// Protected routes
router.post('/logout', protect, logout);
router.get('/me', protect, getMe);
router.put('/updatedetails', protect, updateDetailsValidation, updateDetails);
router.put('/updatepassword', protect, updatePasswordValidation, updatePassword);
router.post('/resend-verification', protect, resendVerification);

module.exports = router; 