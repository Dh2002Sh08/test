const mongoose = require('mongoose');

const TransactionSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, index: true }, // Indexed for faster lookups
    txid: { type: String, required: true, unique: true },
    amount: { type: Number, required: true, min: 0 }, // Ensures non-negative values
    destinationAddress: { type: String, required: true },
    date: { type: Date, default: Date.now, required: true },
    status: { type: String, enum: ['pending', 'confirmed', 'failed'], default: 'pending' }, // Added status field
  },
  { collection: 'transactions', timestamps: true } // Adds createdAt & updatedAt
);

const TransactionModel = mongoose.model('Transaction', TransactionSchema);

module.exports = TransactionModel;
