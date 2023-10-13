const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
        user: 'horacio.okuneva@ethereal.email',
        pass: 'jXfn767wMt8FzMM5Tt'
    }
});

const sendEmail = async (options) => {
	const mailOptions = {
		from: "horacio.okuneva@ethereal.email",
		to: options.to,
		subject: options.subject,
		html: options.html,
	};

	return transporter.sendMail(mailOptions);
};

module.exports = { sendEmail };