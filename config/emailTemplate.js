const getResetPaswEmailContent = (token) => {
	const resetUrl = `https://test.com/reset-password?token=${token}`;

	return `
        <p>You are receiving this email because you ask for reset password.</p>
        <p>Please <a href="${resetUrl}">click here</a> to complete the process within the next hour.</p>
        <p>If you did not request this, you can ignore this email.</p>
    `;
};

module.exports = { getResetPaswEmailContent };