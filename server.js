// server.js
const express = require('express');
const cors = require('cors'); // <-- Import CORS
const app = express();
const PORT = process.env.PORT || 5001;

// MIDDLEWARE
app.use(cors()); // <-- Use CORS to allow requests from your React app
app.use(express.json()); // To parse JSON bodies

// ROUTES
app.get('/api/test', (req, res) => {
  res.json({ message: 'Hello from the backend!' });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// src/components/MyComponent.js
import React, { useState, useEffect } from 'react';
import axios from 'axios';

function MyComponent() {
  const [message, setMessage] = useState('');

  useEffect(() => {
    // The URL of your backend's endpoint
    const apiUrl = 'http://localhost:5001/api/test';

    axios.get(apiUrl)
      .then(response => {
        setMessage(response.data.message);
      })
      .catch(error => {
        console.error('There was an error fetching the data!', error);
      });
  }, []); // The empty array means this effect runs once when the component mounts

  return (
    <div>
      <h1>FullStack Connection Test</h1>
      <p>Message from Backend: <strong>{message}</strong></p>
    </div>
  );
}

export default MyComponent;

// In your user routes file
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User'); // Assuming you have a Mongoose User model

// ... inside an async function
// Hashing the password
const salt = await bcrypt.genSalt(10);
const hashedPassword = await bcrypt.hash(req.body.password, salt);

// Create new user
const newUser = new User({
  username: req.body.username,
  password: hashedPassword,
});

const savedUser = await newUser.save();
res.status(201).json(savedUser);

// ... inside an async function
// Check if user exists
const user = await User.findOne({ username: req.body.username });
if (!user) return res.status(400).send('Username not found');

// Check if password is correct
const validPass = await bcrypt.compare(req.body.password, user.password);
if (!validPass) return res.status(400).send('Invalid password');

// Create and assign a token
const token = jwt.sign(
  { _id: user._id, username: user.username }, // Payload
  process.env.JWT_SECRET // Secret key from your .env file
);

res.header('Authorization', `Bearer ${token}`).json({ token });

// middleware/auth.js
const jwt = require('jsonwebtoken');

module.exports = function (req, res, next) {
  const authHeader = req.header('Authorization');
  if (!authHeader) return res.status(401).send('Access Denied');

  const token = authHeader.split(' ')[1]; // Bearer <token>
  if (!token) return res.status(401).send('Access Denied');

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified; // Add user payload to the request object
    next(); // Proceed to the next middleware or route handler
  } catch (err) {
    res.status(400).send('Invalid Token');
  }
};

const verifyToken = require('./middleware/auth');

// This route is now protected
app.get('/api/user/profile', verifyToken, (req, res) => {
    // req.user is available here because of the middleware
    res.send(req.user);
});


const verifyToken = require('./middleware/auth');

// This route is now protected
app.get('/api/user/profile', verifyToken, (req, res) => {
    // req.user is available here because of the middleware
    res.send(req.user);
});

https://www.themoviedb.org/settings/api#:~:text=941c562484a1fba49b62a4894a33b17e

;


// src/services/api.js
import axios from 'axios';

const apiClient = axios.create({
  baseURL: process.env.REACT_APP_API_URL, // e.g., 'http://localhost:5001'
});

apiClient.interceptors.request.use(config => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, error => {
  return Promise.reject(error);
});

export default apiClient;
