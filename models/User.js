const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  publicKey: { type: String, required: true },
  privateKey: { type: String, required: true },
  passphrase: { type: String, required: true },  // ✅ Added for wallet recovery
  isSubscribed: { type: Boolean, default: false },  // ✅ Subscription Status
  subscriptionExpiresAt: { type: Date, default: null }, // ✅ Expiry Date
  transactions: [{
    txid: String,
    amount: Number,
    destinationAddress: String,
    date: Date
  }],
});

const User = mongoose.model('User', userSchema);

module.exports = User;
