const asyncHandler = (callback) => {
  return async (req, res, next) => {
    try {
      return await callback(req, res, next);
    } catch (error) {
      return next(error);
    }
  };
};

module.exports = asyncHandler;
