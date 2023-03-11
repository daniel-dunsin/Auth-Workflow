const { StatusCodes } = require("http-status-codes");
const asyncHandler = require("../utils/async-handler");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/user.model");
const VerifyEmailToken = require("../models/verify-token.model");
const PasswordResetToken = require("../models/password-reset-token.model");
const CustomError = require("../utils/custom-error");
const sendMail = require("../utils/sendMail");
const generateOTP = require("../utils/generate-otp");
const simplifyUser = require("../utils/simplify-user");
const crypto = require("crypto");
const { findOneAndUpdate } = require("../models/user.model");

const register = asyncHandler(async (req, res, next) => {
  if (!req.body.email || !req.body.username || !req.body.password) {
    throw new CustomError(
      "Please provider email, username and password",
      StatusCodes.BAD_REQUEST
    );
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  const user = await User.create({ ...req.body, password: hashedPassword });
  const token = await user.createJWT();
  const otp = await generateOTP();

  // add otp to the database
  await VerifyEmailToken.create({ email: user.email, token: otp });

  await sendMail(
    req.body.email,
    `Verify your email address`,
    `
    <h1>Hey there ${user.username}</h1>
    <p>This is your OTP: ${otp}</p>
    <p>Your token expires in 5 minutes!!</p>
  `
  );

  res.status(StatusCodes.CREATED).json({
    user: simplifyUser(user),
    msg: "Verification OTP Sent!",
    token,
  });
});

const resendOTP = asyncHandler(async (req, res, next) => {
  const { email } = req.body;
  if (!email) {
    throw new CustomError(
      "Please provide the email for the reset password",
      StatusCodes.BAD_REQUEST
    );
  }
  const user = await User.findOne({ email });
  // if the useris verified, send an error message
  if (!user) {
    throw new CustomError(
      "User with this email address doesn't exist",
      StatusCodes.NOT_FOUND
    );
  } else {
    if (user.verified) {
      const error = new CustomError(
        "User is already verified",
        StatusCodes.NOT_ACCEPTABLE
      );
      return next(error);
    }
  }

  // generate the otp
  const otp = await generateOTP();
  await sendMail(
    email,
    `Verify your email address`,
    `
      <h1>Hey there ${user.username}</h1>
      <p>This is your new OTP: ${otp}</p>
      <p>Your token expires in 5 minutes!!</p>
  `
  );
  // add the token to otp
  const token = await VerifyEmailToken.findOneAndUpdate(
    { email },
    { token: otp },
    {
      new: true,
      runValidators: true,
    }
  );
  if (!token) {
    await VerifyEmailToken.create({ email, token: otp });
  }
  res.status(StatusCodes.CREATED).json({ msg: "Verification OTP sent!" });
});

const verifyOTP = asyncHandler(async (req, res, next) => {
  const { code } = req.body;
  if (!code) {
    throw new CustomError("Kindly provide code", StatusCodes.BAD_REQUEST);
  }
  // check if that code exists in the database and get the email then verify it in the users account
  const token = await VerifyEmailToken.findOneAndDelete({ token: code });
  if (!token) {
    throw new CustomError(
      "Token doesn't exist or has expired",
      StatusCodes.NOT_FOUND
    );
  }
  const user = await User.findOne({ email: token.email });
  if (user.verified) {
    throw new CustomError(
      "User is verified already",
      StatusCodes.NOT_ACCEPTABLE
    );
  }
  user.verified = true;
  await user.save();
  res.status(StatusCodes.OK).send({ msg: "User verified!" });
});

const login = asyncHandler(async (req, res, next) => {
  const { detail, password } = req.body;
  if (!detail || !password) {
    throw new CustomError(
      "Kindly provide password and email/username",
      StatusCodes.BAD_REQUEST
    );
  }

  // check if a user with that email exists
  let user;
  user = await User.findOne({ email: detail });
  if (!user) {
    user = await User.findOne({ username: detail });
  }
  if (!user) {
    throw new CustomError("User doesn't exist", StatusCodes.NOT_FOUND);
  }

  const decodedPasswordMatch = await bcrypt.compare(password, user.password);
  if (!decodedPasswordMatch) {
    throw new CustomError("Password is incorrect", StatusCodes.BAD_REQUEST);
  }
  // do not allow the user to login if they're not verified
  if (!user.verified) {
    throw new CustomError("Account not yet verified", StatusCodes.FORBIDDEN);
  }

  const token = await user.createJWT();

  res.status(StatusCodes.OK).json({
    msg: "Login Successful!",
    user: simplifyUser(user),
    token,
  });
});

const getUser = asyncHandler(async (req, res, next) => {
  const user = await User.findOne({
    username: req.user.username,
    _id: req.user.user_id,
  });

  res.status(StatusCodes.OK).json({
    msg: "Successful",
    user: simplifyUser(user),
  });
});

const updateUser = asyncHandler(async (req, res, next) => {
  if (req.body.password) {
    throw new CustomError(
      "You cannot update password",
      StatusCodes.BAD_REQUEST
    );
  }
  await User.findOneAndUpdate(
    { _id: req.user.user_id, username: req.user.username },
    req.body,
    { new: true, runValidators: true }
  );
  res.status(StatusCodes.OK).json({
    msg: "Successful",
  });
});

const forgotPassword = asyncHandler(async (req, res, next) => {
  const { email } = req.body;

  if (!email) {
    throw new CustomError("Provide account email", StatusCodes.BAD_REQUEST);
  }
  const token = await crypto.randomBytes(10).toString("hex");
  const tokenInDB = await PasswordResetToken.findOneAndUpdate(
    { email },
    { token }
  );
  if (!tokenInDB) {
    await PasswordResetToken.create({ email, token });
  }

  // send the token as a link
  await sendMail(
    email,
    "Password Reset Link",
    `
    <h3>Hello ${email}, you requested a password reset link</h3>
    <p>If you didn't request for this kindly ignore <a href="https://localhost:3000/${token}">Reset Password</a></p>
  `
  );
  res
    .status(StatusCodes.OK)
    .json({ msg: "Password verification link has been sent to your email!" });
});

const resetPasswordFromForgotPassword = asyncHandler(async (req, res, next) => {
  const { token, password, confirm_password } = req.body;
  if (password !== confirm_password) {
    throw new CustomError("Passwords do not match!", StatusCodes.BAD_REQUEST);
  }
  const tokenInDB = await PasswordResetToken.findOneAndDelete({ token });
  if (!tokenInDB) {
    throw new CustomError(
      "Token is invalid or has expired",
      StatusCodes.NOT_FOUND
    );
  }
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  await User.findOneAndUpdate(
    { email: tokenInDB.email },
    { password: hashedPassword }
  );
  res.status(StatusCodes.OK).json({ msg: "Password updated successfully!" });
});

const changePassword = asyncHandler(async (req, res, next) => {
  const { detail, old_password, new_password } = req.body;
  if (!detail) {
    throw new CustomError(
      "Please provide email/username!",
      StatusCodes.BAD_REQUEST
    );
  }
  if (old_password === new_password) {
    throw new CustomError(
      "Your old password cannot be the same as your new password!",
      StatusCodes.BAD_REQUEST
    );
  }
  const hashed_password = await bcrypt.hash(
    new_password,
    await bcrypt.genSalt(10)
  );
  let user = await User.findOne({ email: detail });
  if (!user) {
    user = await User.findOne({ username: detail });
  }
  if (!user) {
    throw new CustomError("User doesn't exist", StatusCodes.NOT_FOUND);
  }
  const comparePasswords = await bcrypt.compare(old_password, user.password);

  if (!comparePasswords) {
    throw new CustomError("Passwords do not match", StatusCodes.NOT_ACCEPTABLE);
  }

  user.password = hashed_password;
  await user.save();

  res.status(200).json({ msg: "Password updated successfully" });
});

module.exports = {
  register,
  login,
  updateUser,
  getUser,
  resendOTP,
  verifyOTP,
  forgotPassword,
  resetPasswordFromForgotPassword,
  changePassword,
};
