require("dotenv").config();
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.NODEMAILER_USERNAME,
    pass: process.env.NODEMAILER_PASS,
  },
});

const sendMail = async (email, subject, html) => {
  transporter.sendMail(
    {
      from: process.env.NODEMAILER_USERNAME,
      to: email,
      subject,
      html,
    },
    (error, info) => {
      if (error) {
        console.log(error);
      }
      console.log(info);
    }
  );
};

module.exports = sendMail;
