const resetPassworTemplate = (resetLink) => {
  return `
     <h2>Password Reset</h2>
      <p>Click the link below to reset your password:</p>
      <a href="${resetLink}">${resetLink}</a>
      <p>This link will expire soon.</p>
  `;
};

module.exports = resetPassworTemplate;