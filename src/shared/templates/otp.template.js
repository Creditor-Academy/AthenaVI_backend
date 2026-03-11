const otpTemplate = (otp) => {
  return `
  <div style="background-color:#f4f6f8;padding:40px 0;font-family:Arial,Helvetica,sans-serif;">
    <div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:10px;padding:40px 30px;text-align:center;box-shadow:0 4px 12px rgba(0,0,0,0.08);">
      
      <h2 style="color:#2d3748;margin-bottom:10px;">Verify Your Email</h2>
      
      <p style="color:#4a5568;font-size:15px;margin-bottom:30px;">
        Use the One-Time Password below to complete your verification.
      </p>

      <div style="background:#f1f5f9;border-radius:8px;padding:20px;margin:20px 0;">
        <span style="font-size:32px;letter-spacing:6px;font-weight:bold;color:#2563eb;">
          ${otp}
        </span>
      </div>

      <p style="color:#4a5568;font-size:14px;margin-top:20px;">
        This OTP will expire in <strong>5 minutes</strong>.
      </p>

      <hr style="border:none;border-top:1px solid #e2e8f0;margin:30px 0;" />

      <p style="color:#718096;font-size:12px;">
        If you did not request this email, you can safely ignore it.
      </p>

      <p style="color:#a0aec0;font-size:11px;margin-top:10px;">
        © ${new Date().getFullYear()} AthenaVI. All rights reserved.
      </p>

    </div>
  </div>
  `;
};

module.exports = otpTemplate;