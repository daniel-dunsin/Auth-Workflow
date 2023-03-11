const { default: mongoose } = require("mongoose");

const PasswordResetTokenSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true,
    required: true,
  },
  token: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now(),
    expires: 3000000,
  },
});

module.exports = mongoose.model("PasswordResetToken", PasswordResetTokenSchema);
