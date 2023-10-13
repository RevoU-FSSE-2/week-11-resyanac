const { v4: uuidv4 } = require("uuid");

const generateResetToken = () => {
	return uuidv4();
};

module.exports = {
	generateResetToken,
};
