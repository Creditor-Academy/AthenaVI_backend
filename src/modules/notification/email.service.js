const nodemailer = require('nodemailer');
const messages = require('../../shared/utils/messages');

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const sendEmail = async ({ email, otp, subject, text }) => {
    try {
    await transporter.sendMail({
    from: process.env.SMTP_USER,
    to: email,
    subject: subject || `OTP Verification`,
    text:
      text ||
      `Hello there \n Your OTP code is ${otp}. It will expire in 5 minutes.`,
  });
    } catch (error) {
        console.error("EMAIL ERROR", error)
        throw new Error(messages.EMAIL_SEND_FAILED)
    }
  
};


module.exports = {sendEmail}