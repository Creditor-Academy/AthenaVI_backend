const otpTemplate = (otp) => {
  return `
    <div style="font-family: Arial, sans-serif; padding: 20px;">
      <h2 style="color: #333;">OTP Verification</h2>
      <p>Your One-Time Password is:</p>
      <h1 style="color: #4CAF50;">${otp}</h1>
      <p>This OTP will expire in 5 minutes.</p>
      <hr />
      <small>If you did not request this, please ignore this email.</small>
    </div>
  `;
};

module.exports = otpTemplate;