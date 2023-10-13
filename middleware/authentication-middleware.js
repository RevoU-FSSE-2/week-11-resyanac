const jwt = require("jsonwebtoken");
const { JWT_SIGN } = require("../config/jwt.js");

const authenticationMiddleware = (req, res, next) => {
	const accessToken = req.cookies.accessToken;

	if (!accessToken) {
		return res.status(401).json({ error: "Unauthorized" });
	}

	if (!JWT_SIGN) {
		return res.status(404).json({ error: "No token available" });
	}

	jwt.verify(accessToken, JWT_SIGN, (error, user) => {
		if (error) {
			console.log("JWT verification Error", error);
			return res.status(401).json({ error: "Refresh Token Invalid" });
		}
		req.user = user;
		next();
	});
};

module.exports = authenticationMiddleware;
