const express = require('express');
const router = express.Router();
const { googleLogin, googleCallback, verifyGoogleToken } = require('../controllers/googleAuthController');

// Google OAuth routes
router.get('/login', googleLogin);
router.get('/callback', googleCallback);
router.post('/verify-token', verifyGoogleToken);

module.exports = router; 