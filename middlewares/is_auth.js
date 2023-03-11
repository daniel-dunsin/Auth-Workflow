require("dotenv").config();
const { StatusCodes } = require("http-status-codes");
const jwt = require("jsonwebtoken");
const CustomError = require("../utils/custom-error");

const is_auth = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    const error = new CustomError("Unauthorized!", StatusCodes.UNAUTHORIZED);
    next(error);
  }
  const token = authHeader.split(" ")[1];
  const verified = jwt.verify(token, process.env.JWT_SECRET);
  if (!verified) {
    const error = new CustomError("Invalid token!", StatusCodes.UNAUTHORIZED);
    next(error);
  }
  req.user = verified;
  next();
};

module.exports = is_auth;
