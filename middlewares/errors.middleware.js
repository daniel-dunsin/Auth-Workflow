const { StatusCodes } = require("http-status-codes");
const CustomError = require("../utils/custom-error");

const not_found = (req, res) => {
  return res.status(StatusCodes.NOT_FOUND).send("Resource not found");
};

const errorHandler = (err, req, res, next) => {
  if (err instanceof CustomError) {
    return res.status(err.statusCode).json({ err: err.message });
  }
  return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ err });
};

module.exports = {
  not_found,
  errorHandler,
};
