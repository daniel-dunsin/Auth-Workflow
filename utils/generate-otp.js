const otpgenerator = require("otp-generator");

const generateOTP = async () => {
  return await otpgenerator.generate(6, {
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });
};
module.exports = generateOTP;
