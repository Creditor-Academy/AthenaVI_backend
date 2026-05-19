const resetPasswordTemplate = (resetLink, expiryMinutes = 15) => {
  return `
  <div style="background-color:#f4f6f8;padding:40px 0;font-family:Arial,Helvetica,sans-serif;">
    
    <div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:10px;padding:40px 30px;text-align:center;box-shadow:0 4px 12px rgba(0,0,0,0.08);">

      <h2 style="color:#2d3748;margin-bottom:10px;">
        Reset Your Password
      </h2>

      <p style="color:#4a5568;font-size:15px;margin-bottom:25px;">
        We received a request to reset your password. Click the button below to create a new one.
      </p>

      <a href="${resetLink}" 
        style="
          display:inline-block;
          padding:12px 24px;
          background-color:#2563eb;
          color:#ffffff;
          text-decoration:none;
          font-weight:bold;
          border-radius:6px;
          font-size:14px;
        ">
        Reset Password
      </a>

      <p style="color:#4a5568;font-size:14px;margin-top:25px;">
        This link will expire in <strong>${expiryMinutes} minutes</strong>.
      </p>

      <hr style="border:none;border-top:1px solid #e2e8f0;margin:30px 0;" />

      <p style="color:#718096;font-size:12px;">
        If the button doesn't work, copy and paste this link into your browser:
      </p>

      <p style="word-break:break-all;font-size:12px;color:#2563eb;">
        ${resetLink}
      </p>

      <p style="color:#718096;font-size:12px;margin-top:20px;">
        If you did not request a password reset, you can safely ignore this email.
      </p>

      <p style="color:#a0aec0;font-size:11px;margin-top:10px;">
        © ${new Date().getFullYear()} AthenaVI. All rights reserved.
      </p>

    </div>
  </div>
  `;
};

module.exports = resetPasswordTemplate;