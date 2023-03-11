const { Router } = require("express");
const {
  register,
  updateUser,
  login,
  forgotPassword,
  getUser,
  resendOTP,
  verifyOTP,
  resetPasswordFromForgotPassword,
  changePassword,
} = require("../controllers/auth.controller");
const is_auth = require("../middlewares/is_auth");
const router = Router();

router.route("/register").post(register);
router.route("/login").post(login);
router.route("/user").get(is_auth, getUser).patch(is_auth, updateUser);
router.route("/forgot-password").post(forgotPassword);
router.route("/resend-otp").post(resendOTP);
router.route("/verify-otp").post(verifyOTP);
router.route("/change-password").patch(changePassword);
router.route("/reset-password").patch(resetPasswordFromForgotPassword);

module.exports = router;
