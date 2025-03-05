// models/Wallet.js
const mongoose = require('mongoose');

// Wallet Schema
const walletSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', // Reference to the User model
    required: true,
  },
  walletAddress: {
    type: String,
    required: true,
  },
  mnemonic: {
    type: String,
    required: true,
  },
  transactionHistory: {
    type: [Object], // Array to store transaction history objects
    default: [],
  }
});

const Wallet = mongoose.model('Wallet', walletSchema);

module.exports = Wallet;



// #this is my