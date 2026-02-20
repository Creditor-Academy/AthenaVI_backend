const nodemailer = require('nodemailer');
const messages = require('../utils/messages');

let transporter;

const getTransporter = () => {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT) || 587,
      secure: process.env.SMTP_PORT == 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }
  return transporter;
};

const sendEmail = async ({ to, subject, text, html }) => {
  try {
    const mailer = getTransporter();

    await mailer.sendMail({
      from: `"Your App" <${process.env.SMTP_USER}>`,
      to,
      subject,
      text,
      html,
    });

  } catch (error) {
    console.error("EMAIL SERVICE ERROR:", error);
    throw new Error(messages.EMAIL_SEND_FAILED);
  }
};

module.exports = { sendEmail };