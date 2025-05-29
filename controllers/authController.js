const jwt = require("jsonwebtoken");
const User = require("../models/usersMODEL");
const {
  signupSchema,
  signinSchema,
  acceptCodeSchema,
  changePasswordSchema,
  acceptFPCodeSchema,
} = require("../middlewares/validator");
const { doHash, doHashValidation, hmacProcess } = require("../utils/hashing");
const transport = require("../middlewares/sendMail");

exports.signup = async (req, res) => {
  const { email, password } = req.body;

  try {
    const { error, value } = signupSchema.validate({ email, password });

    if (error) {
      return res
        .status(400)
        .json({ success: false, message: error.details[0].message });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res
        .status(401)
        .json({ success: false, message: "User already exists!" });
    }

    const hashedPassword = await doHash(password, 12);

    const newUser = new User({
      email,
      password: hashedPassword,
    });

    const result = await newUser.save();

    result.password = undefined;
    res.status(201).json({
      success: true,
      message: "Your account has been created successfully",
      result,
    });
  } catch (error) {
    console.log(error);
  }
};

exports.signin = async (req, res) => {
  const { email, password } = req.body;
  try {
    const { error, value } = signinSchema.validate({ email, password });
    if (error) {
      return res
        .status(401)
        .json({ success: false, message: error.details[0].message });
    }

    const existingUser = await User.findOne({ email }).select("+password");
    if (!existingUser) {
      return res
        .status(401)
        .json({ success: false, message: "User does not exists!" });
    }
    const result = await doHashValidation(password, existingUser.password);
    if (!result) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials!" });
    }
    const token = jwt.sign(
      {
        userId: existingUser._id,
        email: existingUser.email,
        verified: existingUser.verified,
      },
      process.env.TOKEN_SECRET,
      {
        expiresIn: "8h",
      }
    );

    res
      .cookie("Authorization", "Bearer " + token, {
        expires: new Date(Date.now() + 8 * 3600000),
        httpOnly: process.env.NODE_ENV === "production",
        secure: process.env.NODE_ENV === "production",
      })
      .json({
        success: true,
        token,
        message: "logged in successfully",
      });
  } catch (error) {
    console.log(error);
  }
};

exports.signout = async (req, res) => {
  res
    .clearCookie("Authorization")
    .status(200)
    .json({ success: true, message: "logged out successfully" });
};

exports.sendVerificationCode = async (req, res) => {
  const { email } = req.body;
  try {
    const existingUser = await User.findOne({ email }).select(
      "+lastVerificationCodeSentAt"
    );

    if (!existingUser) {
      return res
        .status(404)
        .json({ success: false, message: "User does not exist!" });
    }

    if (existingUser.verified) {
      return res
        .status(400)
        .json({ success: false, message: "You are already verified!" });
    }

    if (existingUser.lastVerificationCodeSentAt) {
      const cooldownEndTime = new Date(
        existingUser.lastVerificationCodeSentAt.getTime() + 30 * 1000
      );

      if (new Date() < cooldownEndTime) {
        const remainingSeconds = Math.ceil(
          (cooldownEndTime - new Date()) / 1000
        );
        return res.status(429).json({
          success: false,
          message: `Please wait ${remainingSeconds} seconds before requesting a new code.`,
        });
      }
    }

    const codeValue = Math.floor(100000 + Math.random() * 900000).toString();
    let info = await transport.sendMail({
      from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
      to: existingUser.email,
      subject: "Verification Code",
      html: `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verification Code</title>
      <style>
        body {
            margin: 0;
            padding: 0;
            background: #f5f9ff;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            font-family: 'Arial', sans-serif;
        }
        .verification-code {
            font-size: 48px;
            font-weight: bold;
            color: #0d47a1;
            letter-spacing: 8px;
            text-align: center;
            background: #e3f2fd;
            padding: 25px 40px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(13, 71, 161, 0.15);
            border: 2px dashed #1e88e5;
        }
      </style>
      </head>
      <body>
      <div class="verification-code">${codeValue}</div>
      </body>
    </html>`,
    });

    if (info.accepted[0] === existingUser.email) {
      const hashedCodeValue = hmacProcess(
        codeValue,
        process.env.HMAC_VERIFICATION_CODE_SECRET
      );
      existingUser.verificationCode = hashedCodeValue;
      existingUser.verificationCodeValidation = Date.now();
      existingUser.lastVerificationCodeSentAt = new Date();
      await existingUser.save();
      return res.status(200).json({ success: true, message: "Code sent!" });
    }

    return res
      .status(400)
      .json({ success: false, message: "Failed to send code!" });
  } catch (error) {
    console.error("OTP sending error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

exports.verifyVerificationCode = async (req, res) => {
  const { email, providedCode } = req.body;
  try {
    const { error, value } = acceptCodeSchema.validate({ email, providedCode });
    if (error) {
      return res
        .status(401)
        .json({ success: false, message: error.details[0].message });
    }

    const codeValue = providedCode.toString();
    const existingUser = await User.findOne({ email }).select(
      "+verificationCode +verificationCodeValidation +failedAttempts +lastFailedAttempt"
    );

    if (!existingUser) {
      return res
        .status(401)
        .json({ success: false, message: "User does not exists!" });
    }

    if (existingUser.failedAttempts >= 3) {
      const cooldownEndTime = new Date(
        existingUser.lastFailedAttempt.getTime() + 5 * 60 * 1000
      );
      if (new Date() < cooldownEndTime) {
        const remainingMinutes = Math.ceil(
          (cooldownEndTime - new Date()) / (60 * 1000)
        );
        return res.status(429).json({
          success: false,
          message: `Too many attempts. Try again in ${remainingMinutes} minute(s).`,
        });
      } else {
        existingUser.failedAttempts = 0;
        await existingUser.save();
      }
    }

    if (existingUser.verified) {
      return res
        .status(400)
        .json({ success: false, message: "you are already verified!" });
    }

    if (
      !existingUser.verificationCode ||
      !existingUser.verificationCodeValidation
    ) {
      return res
        .status(400)
        .json({ success: false, message: "something is wrong with the code!" });
    }

    if (Date.now() - existingUser.verificationCodeValidation > 5 * 60 * 1000) {
      return res
        .status(400)
        .json({ success: false, message: "code has been expired!" });
    }

    const hashedCodeValue = hmacProcess(
      codeValue,
      process.env.HMAC_VERIFICATION_CODE_SECRET
    );

    if (hashedCodeValue === existingUser.verificationCode) {
      existingUser.verified = true;
      existingUser.verificationCode = undefined;
      existingUser.verificationCodeValidation = undefined;
      existingUser.failedAttempts = 0;
      existingUser.lastFailedAttempt = undefined;
      await existingUser.save();
      return res
        .status(200)
        .json({ success: true, message: "your account has been verified!" });
    } else {
      existingUser.failedAttempts = (existingUser.failedAttempts || 0) + 1;
      existingUser.lastFailedAttempt = new Date();
      await existingUser.save();

      return res
        .status(400)
        .json({ success: false, message: "Invalid verification code!" });
    }
  } catch (error) {
    console.log(error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

exports.changePassword = async (req, res) => {
  const { userId, verified } = req.user;
  const { oldPassword, newPassword } = req.body;
  try {
    const { error, value } = changePasswordSchema.validate({
      oldPassword,
      newPassword,
    });
    if (error) {
      return res
        .status(401)
        .json({ success: false, message: error.details[0].message });
    }
    if (!verified) {
      return res
        .status(401)
        .json({ success: false, message: "You are not verified user!" });
    }
    const existingUser = await User.findOne({ _id: userId }).select(
      "+password"
    );
    if (!existingUser) {
      return res
        .status(401)
        .json({ success: false, message: "User does not exists!" });
    }
    const result = await doHashValidation(oldPassword, existingUser.password);
    if (!result) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials!" });
    }
    const hashedPassword = await doHash(newPassword, 12);
    existingUser.password = hashedPassword;
    await existingUser.save();
    return res
      .status(200)
      .json({ success: true, message: "Password updated!!" });
  } catch (error) {
    console.log(error);
  }
};

exports.sendForgotPasswordCode = async (req, res) => {
  const { email } = req.body;
  try {
    const existingUser = await User.findOne({ email }).select(
      "+lastForgotPasswordCodeSentAt"
    );

    if (!existingUser) {
      return res
        .status(404)
        .json({ success: false, message: "User does not exist!" });
    }

    if (existingUser.lastForgotPasswordCodeSentAt) {
      const cooldownEndTime = new Date(
        existingUser.lastForgotPasswordCodeSentAt.getTime() + 30 * 1000
      );

      if (new Date() < cooldownEndTime) {
        const remainingSeconds = Math.ceil(
          (cooldownEndTime - new Date()) / 1000
        );
        return res.status(429).json({
          success: false,
          message: `Please wait ${remainingSeconds} seconds before requesting a new password reset code.`,
        });
      }
    }

    const codeValue = Math.floor(100000 + Math.random() * 900000).toString();
    let info = await transport.sendMail({
      from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
      to: existingUser.email,
      subject: "Password Reset Code",
      html: `
      <!DOCTYPE html>
      <html>
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Password Reset Code</title>
          <style>
              body {
                  margin: 0;
                  padding: 0;
                  background: #f5fff9;
                  display: flex;
                  justify-content: center;
                  align-items: center;
                  height: 100vh;
                  font-family: 'Arial', sans-serif;
              }
              .reset-code {
                  font-size: 48px;
                  font-weight: bold;
                  color: #27ae60;
                  letter-spacing: 8px;
                  text-align: center;
                  background: #e8f8f0;
                  padding: 25px 40px;
                  border-radius: 12px;
                  box-shadow: 0 4px 20px rgba(39, 174, 96, 0.15);
                  border: 2px dashed #2ecc71;
              }
          </style>
      </head>
      <body>
          <div class="reset-code">${codeValue}</div>
      </body>
      </html>`,
    });

    if (info.accepted[0] === existingUser.email) {
      const hashedCodeValue = hmacProcess(
        codeValue,
        process.env.HMAC_VERIFICATION_CODE_SECRET
      );
      existingUser.forgotPasswordCode = hashedCodeValue;
      existingUser.forgotPasswordCodeValidation = Date.now();
      existingUser.lastForgotPasswordCodeSentAt = new Date();
      await existingUser.save();
      return res
        .status(200)
        .json({ success: true, message: "Password reset code sent!" });
    }

    return res
      .status(400)
      .json({ success: false, message: "Failed to send password reset code!" });
  } catch (error) {
    console.error("Password reset code sending error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

exports.verifyForgotPasswordCode = async (req, res) => {
  const { email, providedCode, newPassword } = req.body;
  try {
    const { error, value } = acceptFPCodeSchema.validate({
      email,
      providedCode,
      newPassword,
    });
    if (error) {
      return res
        .status(401)
        .json({ success: false, message: error.details[0].message });
    }

    const existingUser = await User.findOne({ email }).select(
      "+forgotPasswordCode +forgotPasswordCodeValidation +failedPasswordAttempts +lastFailedPasswordAttempt"
    );

    if (!existingUser) {
      return res
        .status(401)
        .json({ success: false, message: "User does not exist!" });
    }

    if (existingUser.failedPasswordAttempts >= 3) {
      const cooldownEndTime = new Date(
        existingUser.lastFailedPasswordAttempt.getTime() + 5 * 60 * 1000
      );

      if (new Date() < cooldownEndTime) {
        const remainingMinutes = Math.ceil(
          (cooldownEndTime - new Date()) / (60 * 1000)
        );
        return res.status(429).json({
          success: false,
          message: `Too many attempts. Try again in ${remainingMinutes} minute(s).`,
        });
      } else {
        existingUser.failedPasswordAttempts = 0;
        await existingUser.save();
      }
    }

    if (
      !existingUser.forgotPasswordCode ||
      !existingUser.forgotPasswordCodeValidation
    ) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid password reset request!" });
    }

    if (
      Date.now() - existingUser.forgotPasswordCodeValidation >
      5 * 60 * 1000
    ) {
      return res
        .status(400)
        .json({ success: false, message: "Reset code has expired!" });
    }

    const hashedCodeValue = hmacProcess(
      providedCode.toString(),
      process.env.HMAC_VERIFICATION_CODE_SECRET
    );

    if (hashedCodeValue === existingUser.forgotPasswordCode) {
      const hashedPassword = await doHash(newPassword, 12);
      existingUser.password = hashedPassword;
      existingUser.forgotPasswordCode = undefined;
      existingUser.forgotPasswordCodeValidation = undefined;
      existingUser.failedPasswordAttempts = 0;
      existingUser.lastFailedPasswordAttempt = undefined;
      await existingUser.save();

      return res
        .status(200)
        .json({ success: true, message: "Password updated successfully!" });
    } else {
      existingUser.failedPasswordAttempts =
        (existingUser.failedPasswordAttempts || 0) + 1;
      existingUser.lastFailedPasswordAttempt = new Date();
      await existingUser.save();

      return res
        .status(400)
        .json({ success: false, message: "Invalid verification code!" });
    }
  } catch (error) {
    console.error("Password reset error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};
