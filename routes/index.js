const reviewRouter = require('./reviewRouter');
const userRouter = require('./userRouter');
const express = require('express');
const authMiddleware = require('../middleware/authentication-middleware')

const router = express();

router.get('/', (req, res) => {
    const tokenCookie = req.cookies['Access-Token'];
    const tokenCookieRefresh = req.cookies['Refresh-Token'];
    res.status(200).json({
      Access_Token: `${tokenCookie}`,
      Refresh_Token: `${tokenCookieRefresh}`
    });
   

    
});
router.use('/user', userRouter)
router.use('/review', authMiddleware, reviewRouter);

module.exports = router;