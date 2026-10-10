const mongoose = require("mongoose");

const memberSchema = new mongoose.Schema({
  email: { type: String, required: true },
  password: { type: String, required: true },
  resetToken: { type: String, select: false },
});

module.exports = mongoose.model("Member", memberSchema);
