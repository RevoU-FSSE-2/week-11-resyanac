const { Router } = require('express')
const { register, login, getAllUsers, logout, requestResetPassword, resetPassword } = require('../service/userService.js')
const LoginLimiter = require("../middleware/ratelimit.js");

const userRouter = Router()

userRouter.post('/register', register)
userRouter.post('/login',LoginLimiter, login)
userRouter.get('/allusers', getAllUsers);
userRouter.post('/logout', logout);
userRouter.post('/reset-password/request', requestResetPassword)
userRouter.post("/reset-password", resetPassword);


module.exports = userRouter 