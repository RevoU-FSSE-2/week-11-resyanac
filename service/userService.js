const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { JWT_SIGN } = require('../config/jwt.js')
const express = require('express');
const { generateResetToken } = require("../middleware/uid.js");
const { getResetPaswEmailContent } = require("../config/emailTemplate.js");
const { sendEmail } = require("../middleware/emailservice.js");
const { error } = require('express-openapi-validator');



// get all users
const getAllUsers = async (req, res) => {
  try {
   const user = await req.db.collection('users').find().toArray()
   res.status(200).json({
    message: 'Users successfully retrieved',
    data: user,
   })
   console.log(user);
   return user
  } catch (error) {
    const standardError = new Error({
      message: error.message || 'Error while registering user',
      status: 500
    })
    next(standardError) 
  }
}

// register

const register = async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const validRoles = ['reviewer', 'approver', 'admin'];
    const usernameValue = username.trim(' ');
    if (password.length < 8) {
    return res.status(400).json({
      message: 'Password minimum length 8'
    });
  }
    const alphanumericRegex = /[0-9a-zA-Z]/;
    if (!alphanumericRegex.test(password)) {
    return res.status(400).json({
      message: 'Password has to be alphanumeric'
    });
    }
    if (usernameValue === '' || usernameValue == null) {
    return res.status(400).json({
      message: 'Username cant be blank'
    });
  } 
    if (!validRoles.includes(role)) {
    return res.status(400).json({
      message: 'Invalid Role'
    });
    }
    const user = await req.db.collection('users').findOne({ username });
    if (user) {
    return res.status(400).json({
      message: 'Username already exists'
    });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await req.db.collection('users').insertOne({
      username,
      password: hashedPassword,
      role,
    });
    console.log(newUser);
    res.status(200).json({
      message: 'User successfully registered',
      data: newUser
    }); 
    return newUser
  } catch (error) {
    res.status(400).json({ error: error.message });
    console.log(error);
  }
}

// login
const login = async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await req.db.collection('users').findOne({ username });
    console.log(user); // For Debugging Purpose
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    
    if (user) {
      if (isPasswordCorrect) {
        const accessToken = jwt.sign(
          { username: user.username, id: user._id, role: user.role },
          JWT_SIGN,
          { expiresIn: '30s' }
        );

        const refreshToken = jwt.sign(
          { username: user.username, id: user._id, role: user.role },
          JWT_SIGN,
          { expiresIn: '7d' }
        );

        const accessTokenExpiration = new Date(Date.now() + 30 * 1000); // 30 seconds from now
  

       console.log(accessToken); // For Debugging Purpose
        res.cookie('accessToken', accessToken, {
          httpOnly: true,
          maxAge: 30 * 1000,
              path: '/'
        });

        console.log(refreshToken); // For debugging purpose
        res.cookie('refreshToken', refreshToken, {
          httpOnly: true,
          maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/'
        });

        res.status(200).json({
          message: 'Successfully Logged In',
          data: {
            accessToken,
            refreshToken,
            accessTokenExpiration,
          },
        });
      } else {
        res.status(401).json({ error: 'Password is incorrect' });
      }
    } else {
      res.status(401).json({ error: 'User not found' });
    }
  } catch (error) {
    console.error('Internal server error:', error);
    return res.status(500).json({ message: 'Internal Server error' });
  }
};

const refreshAccessToken = async (refreshToken) => {
  if (!JWT_SIGN) throw new Error("JWT_SIGN is not defined");

  const decodedRefreshToken = verify(refreshToken, JWT_SIGN);

  if (
    !decodedRefreshToken ||
    !decodedRefreshToken.exp ||
    typeof decodedRefreshToken.exp !== "number"
  ) {
    throw new error({
      success: false,
      status: 401,
      message: "Refresh token is invalid or has expired. Please login again",
    });
  }

  if (decodedRefreshToken.exp < Date.now() / 1000) {
    throw new error({
      success: false,
      status: 401,
      message: "Refresh token has expired. Please login again",
    });
  }

  const accessToken = sign({ userId: decodedRefreshToken.userId }, JWT_SIGN, {
    expiresIn: "10m",
  });

  return { success: true, message: { accessToken } };
};


const requestResetPassword = async (req, res) => {
	const { username } = req.body;

	try {
		const user = await req.db.collection('users').findOne({ username });
      
        if (!user) {
            return res.status(404).json({ message: "No Username Found" });
        }
        const token = generateResetToken();
        await req.db.collection('users').updateOne(
          {username},{ $set: { resetPasswordToken: token , resetPasswordExpires:Date.now() + 3600000} }
        )
        // user.resetPasswordToken = token;
        // user.resetPasswordExpires = Date.now() + 3600000; // 19 : 10 + 60 = 20 : 10
		const emailContent = getResetPaswEmailContent(token);

		await sendEmail({
			to: "test@email.com",
			subject: "Reset Password",
			html: emailContent,
		});

		res.status(200).json({ message: "Password reset link sent to email" });
	} catch (error) {
		console.error("Internal server error:", error);
		return res.status(500).json({ messsage: "Internal Server error" });
	}
};

const resetPassword = async (req, res) => {
	const { token, newPassword } = req.body;

	try {
		const user = await req.db.collection('users').findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() },
      });
if (!user) {
  return res
    .status(400)
    .json({ message: "Invalid or expired reset token" });
}
		const hashedPassword = await bcrypt.hash(newPassword, 8);
		user.password = hashedPassword;
		user.resetPasswordToken = undefined;
		user.resetPasswordExpires = undefined;

		res.status(200).json({ message: "Password successfully reset" });
	} catch (error) {
		console.error("Internal server error", error);
		return res.status(500).json({ message: "Internal Server Error" });
	}
};

const logout = async (req, res) => {
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.status(200).json({ message: 'Successfully log out' });
}

module.exports = {
  getAllUsers,
	register,
	login,
	logout,
  requestResetPassword,
  resetPassword,
  refreshAccessToken
};