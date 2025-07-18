// API Configuration
const API_BASE_URL = '/api';

// Authentication API class
class AuthAPI {
  constructor() {
    this.token = localStorage.getItem('token');
    this.user = JSON.parse(localStorage.getItem('user'));
  }

  // Set auth headers
  getHeaders() {
    const headers = {
      'Content-Type': 'application/json',
    };
    
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    
    return headers;
  }

  // Make API request
  async makeRequest(endpoint, options = {}) {
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: this.getHeaders(),
        credentials: 'include',
        ...options
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Something went wrong');
      }

      return data;
    } catch (error) {
      console.error('API Error:', error);
      throw error;
    }
  }

  // Register user
  async register(userData) {
    const response = await this.makeRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData)
    });

    if (response.success) {
      // Store user data (without token for registration)
      localStorage.setItem('user', JSON.stringify(response.user));
    }

    return response;
  }

  // Login user
  async login(credentials) {
    const response = await this.makeRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials)
    });

    if (response.success) {
      // Store token and user data
      this.token = response.token;
      this.user = response.user;
      localStorage.setItem('token', response.token);
      localStorage.setItem('user', JSON.stringify(response.user));
    }

    return response;
  }

  // Logout user
  async logout() {
    try {
      await this.makeRequest('/auth/logout', {
        method: 'POST'
      });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear local storage
      this.token = null;
      this.user = null;
      localStorage.removeItem('token');
      localStorage.removeItem('user');
    }
  }

  // Get current user
  async getCurrentUser() {
    if (!this.token) {
      return null;
    }

    try {
      const response = await this.makeRequest('/auth/me');
      if (response.success) {
        this.user = response.user;
        localStorage.setItem('user', JSON.stringify(response.user));
        return response.user;
      }
    } catch (error) {
      console.error('Get current user error:', error);
      // Token might be invalid, clear storage
      this.logout();
    }

    return null;
  }

  // Update user details
  async updateDetails(details) {
    const response = await this.makeRequest('/auth/updatedetails', {
      method: 'PUT',
      body: JSON.stringify(details)
    });

    if (response.success) {
      this.user = response.user;
      localStorage.setItem('user', JSON.stringify(response.user));
    }

    return response;
  }

  // Update password
  async updatePassword(passwordData) {
    const response = await this.makeRequest('/auth/updatepassword', {
      method: 'PUT',
      body: JSON.stringify(passwordData)
    });

    if (response.success) {
      // Update token if provided
      if (response.token) {
        this.token = response.token;
        localStorage.setItem('token', response.token);
      }
    }

    return response;
  }

  // Forgot password
  async forgotPassword(email) {
    return await this.makeRequest('/auth/forgotpassword', {
      method: 'POST',
      body: JSON.stringify({ email })
    });
  }

  // Reset password
  async resetPassword(token, password) {
    return await this.makeRequest(`/auth/resetpassword/${token}`, {
      method: 'PUT',
      body: JSON.stringify({ password })
    });
  }

  // Resend verification email
  async resendVerification() {
    return await this.makeRequest('/auth/resend-verification', {
      method: 'POST'
    });
  }

  // Google OAuth Login
  async googleLogin() {
    try {
      const response = await this.makeRequest('/auth/google/login');
      if (response.success) {
        // Redirect to Google OAuth
        window.location.href = response.authUrl;
      }
      return response;
    } catch (error) {
      console.error('Google login error:', error);
      throw error;
    }
  }

  // Handle Google OAuth callback
  handleGoogleCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const success = urlParams.get('success');
    const token = urlParams.get('token');
    const error = urlParams.get('error');

    if (success && token) {
      // Store token and redirect
      this.token = token;
      localStorage.setItem('token', token);
      
      // Get user info
      this.getCurrentUser().then(() => {
        // Redirect to dashboard or home
        window.location.href = '/dock.html';
      });
      
      return { success: true, token };
    } else if (error) {
      console.error('Google OAuth error:', error);
      return { success: false, error };
    }

    return null;
  }

  // Check if user is authenticated
  isAuthenticated() {
    return !!this.token && !!this.user;
  }

  // Get current user data
  getCurrentUserData() {
    return this.user;
  }

  // Get token
  getToken() {
    return this.token;
  }
}

// Create global auth instance
const auth = new AuthAPI();

// Export for use in other files
window.auth = auth; 