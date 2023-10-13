const checkRole = (allowedRoles) => {
	return (req, res, next) => {
		console.log('checkRole middleware triggered');
		if (!req.user) {
			return res.status(401).json({
				message: "Unauthorized. Please log in to access this resource.",
			});
		}

		const { role } = req.user;

		if (!allowedRoles.includes(role)) {
			return res.status(403).json({
				message:
					"Access Denied, you don't have permission to access this data or URL",
			});
		}
	
		next();
	};
};

module.exports = {
  checkRole
};

