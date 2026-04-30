const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const API_BASE_URL = process.env.API_BASE_URL || 'https://hngstage3.onrender.com';

app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));

// CORS for backend requests
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', API_BASE_URL);
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'X-API-Version, Content-Type, Authorization');
  next();
});

// Check authentication middleware
app.use(async (req, res, next) => {
  const token = req.cookies?.access_token;
  if (token && req.path !== '/login' && req.path !== '/logout' && !req.path.startsWith('/auth')) {
    try {
      await axios.get(`${API_BASE_URL}/api/profiles?limit=1`, {
        headers: { 'X-API-Version': '1', 'Authorization': `Bearer ${token}` }
      });
      res.locals.authenticated = true;
    } catch (e) {
      res.locals.authenticated = false;
    }
  } else {
    res.locals.authenticated = false;
  }
  next();
});

// Routes
app.get('/', (req, res) => {
  if (req.cookies?.access_token) {
    res.redirect('/dashboard');
  } else {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
  }
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// IMPORTANT: This handles the OAuth callback from GitHub
app.get('/auth/github/callback', async (req, res) => {
  const { code, state } = req.query;
  console.log('📥 Callback received, code:', code ? 'Yes' : 'No');
  
  if (!code) {
    return res.redirect('/login?error=no_code');
  }
  
  try {
    // Forward to backend
    const response = await axios.get(`${API_BASE_URL}/auth/github/callback`, {
      params: { code, state },
      withCredentials: true
    });
    
    // Forward cookies to client
    const cookies = response.headers['set-cookie'];
    if (cookies) {
      cookies.forEach(cookie => {
        res.setHeader('Set-Cookie', cookie);
      });
    }
    
    // Redirect to dashboard
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Callback error:', error.response?.data || error.message);
    res.redirect('/login?error=auth_failed');
  }
});

app.get('/dashboard', (req, res) => {
  if (!req.cookies?.access_token) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/profiles', (req, res) => {
  if (!req.cookies?.access_token) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'profiles.html'));
});

app.get('/profile-detail', (req, res) => {
  if (!req.cookies?.access_token) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'profile-detail.html'));
});

app.get('/search', (req, res) => {
  if (!req.cookies?.access_token) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'search.html'));
});

app.get('/account', (req, res) => {
  if (!req.cookies?.access_token) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'account.html'));
});

app.get('/logout', (req, res) => {
  res.clearCookie('access_token');
  res.clearCookie('refresh_token');
  res.redirect('/login');
});

app.listen(PORT, () => {
  console.log(`✅ Web Portal running on http://localhost:${PORT}`);
});
