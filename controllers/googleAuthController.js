const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Generate JWT Token
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE
  });
};

// Google OAuth Login - Redirect to Google
const googleLogin = async (req, res) => {
  try {
    const authUrl = `https://accounts.google.com/o/oauth2/auth?` +
      `client_id=${process.env.GOOGLE_CLIENT_ID}&` +
      `redirect_uri=${process.env.GOOGLE_REDIRECT_URI}&` +
      `scope=email profile&` +
      `response_type=code&` +
      `access_type=offline`;

    res.json({ 
      success: true, 
      authUrl: authUrl 
    });
  } catch (error) {
    console.error('Google login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to initiate Google login' 
    });
  }
};

// Google OAuth Callback
const googleCallback = async (req, res) => {
  try {
    const { code } = req.query;

    if (!code) {
      return res.status(400).json({ 
        success: false, 
        message: 'Authorization code is required' 
      });
    }

    // Exchange code for tokens
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: process.env.GOOGLE_REDIRECT_URI
    });

    const { access_token } = tokenResponse.data;

    // Get user info from Google
    const userInfoResponse = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: {
        Authorization: `Bearer ${access_token}`
      }
    });

    const { email, name, picture, given_name, family_name } = userInfoResponse.data;

    // Check if user exists
    let user = await User.findOne({ email });

    if (!user) {
      // Create new user
      user = new User({
        name: name || `${given_name} ${family_name}`,
        email,
        avatar: picture,
        isEmailVerified: true, // Google emails are verified
        authProvider: 'google',
        googleId: userInfoResponse.data.id
      });

      await user.save();
    } else {
      // Update existing user's Google info
      user.authProvider = 'google';
      user.googleId = userInfoResponse.data.id;
      user.avatar = picture;
      user.isEmailVerified = true;
      await user.save();
    }

    // Generate JWT token
    const token = generateToken(user._id);

    // Set cookie
    res.cookie('token', token, {
      expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    // Redirect to frontend with success
    res.redirect(`${process.env.FRONTEND_URL}/login?success=true&token=${token}`);

  } catch (error) {
    console.error('Google callback error:', error);
    res.redirect(`${process.env.FRONTEND_URL}/login?error=google_auth_failed`);
  }
};

// Verify Google Token (for mobile apps or direct token verification)
const verifyGoogleToken = async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({ 
        success: false, 
        message: 'ID token is required' 
      });
    }

    // Verify the token
    const ticket = await client.verifyIdToken({
      idToken: idToken,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { email, name, picture, sub: googleId } = payload;

    // Check if user exists
    let user = await User.findOne({ email });

    if (!user) {
      // Create new user
      user = new User({
        name,
        email,
        avatar: picture,
        isEmailVerified: true,
        authProvider: 'google',
        googleId
      });

      await user.save();
    } else {
      // Update existing user's Google info
      user.authProvider = 'google';
      user.googleId = googleId;
      user.avatar = picture;
      user.isEmailVerified = true;
      await user.save();
    }

    // Generate JWT token
    const token = generateToken(user._id);

    // Set cookie
    res.cookie('token', token, {
      expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        isEmailVerified: user.isEmailVerified
      }
    });

  } catch (error) {
    console.error('Google token verification error:', error);
    res.status(400).json({ 
      success: false, 
      message: 'Invalid Google token' 
    });
  }
};

module.exports = {
  googleLogin,
  googleCallback,
  verifyGoogleToken
}; 