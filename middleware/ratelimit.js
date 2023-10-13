const rateLimit = require("express-rate-limit");

const LoginLimiter = rateLimit({
	windowMs: 30 * 1000,
	max: 5,
	standardHeaders: "draft-7",
	legacyHeaders: false,
	message: "Too many failed login attempts, please try again after 30 seconds",
});

module.exports = LoginLimiter;
