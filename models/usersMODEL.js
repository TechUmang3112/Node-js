const mongoose = require("mongoose");

const userSchema = mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, "Email Is Required!"],
      trim: true,
      unique: [true, "Email Must Be Unique!"],
      minLength: [5, "Email Must Have 5 Characters!"],
      lowercase: true,
    },
    password: {
      type: String,
      required: [true, "Password Must Be Provided!"],
      trim: true,
      select: false,
    },
    verified: {
      type: Boolean,
      default: false,
    },
    verificationCode: {
      type: String,
      select: false,
    },
    lastVerificationCodeSentAt: {
      type: Date,
    },
    failedAttempts: {
      type: Number,
      default: 0,
    },
    lastFailedAttempt: {
      type: Date,
    },
    verificationCodeValidation: {
      type: Number,
      select: false,
    },
    forgotPasswordCode: {
      type: String,
      select: false,
    },
    lastForgotPasswordCodeSentAt: {
      type: Date,
    },
    forgotPasswordCodeValidation: {
      type: Number,
      select: false,
    },
    failedPasswordAttempts: {
      type: Number,
      default: 0,
    },
    lastFailedPasswordAttempt: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("User", userSchema);
