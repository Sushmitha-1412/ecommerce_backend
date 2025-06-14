const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../models');
const User = db.User;
require('dotenv').config(); 

const signup = async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' }); 
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      username,
      email,
      password: hashedPassword
    });

    res.status(201).json({ message: 'User created successfully', user }); 
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: err.message }); 
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(400).json({ message: 'User not found' }); 

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET || 'defaultsecret', 
      { expiresIn: '1h' }
    );

    res.status(200).json({ message: 'Login successful', token }); 
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: err.message }); 
  }
};

module.exports = {
  signup,
  login
};
