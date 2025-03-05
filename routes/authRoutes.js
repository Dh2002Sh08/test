const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // 🔐 Encrypt the passphrase
const User = require('../models/User');

const router = express.Router();

// Encryption Key (Should be stored securely)
const ENCRYPTION_KEY = 'your_32_byte_secret_key_1234567890abcd'; // 🔐 Change this
const IV_LENGTH = 16; // AES Block size

// Encrypt Function
function encrypt(text) {
  let iv = crypto.randomBytes(IV_LENGTH);
  let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Decrypt Function
function decrypt(text) {
  let parts = text.split(':');
  let iv = Buffer.from(parts[0], 'hex');
  let encryptedText = Buffer.from(parts[1], 'hex');
  let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// ✅ User Registration Route
router.post('/register', async (req, res) => {
  const { email, password, passphrase } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const encryptedPassphrase = encrypt(passphrase); // 🔒 Encrypt before saving

    const newUser = new User({ email, password: hashedPassword, passphrase: encryptedPassphrase });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error registering user', error: err.message });
  }
});

// ✅ User Login Route
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, 'your_jwt_secret', { expiresIn: '1h' });

    res.json({ 
      token, 
      email: user.email, 
      userId: user._id,
      walletAddress: user.walletAddress || null 
    });

  } catch (err) {
    res.status(500).json({ message: 'Error logging in', error: err.message });
  }
});

// ✅ Recover Wallet by Passphrase
router.post('/recover-wallet', async (req, res) => {
  const { passphrase } = req.body;

  if (!passphrase) {
    return res.status(400).json({ message: 'Passphrase is required' });
  }

  try {
    const users = await User.find();
    let recoveredUser = null;

    // Decrypt all stored passphrases and compare
    for (let user of users) {
      const decryptedPassphrase = decrypt(user.passphrase);
      if (decryptedPassphrase === passphrase) {
        recoveredUser = user;
        break;
      }
    }

    if (!recoveredUser) {
      return res.status(404).json({ message: 'Wallet not found' });
    }

    res.json({ email: recoveredUser.email, walletAddress: recoveredUser.walletAddress });

  } catch (error) {
    console.error('Recovery Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
