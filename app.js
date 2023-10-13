require('dotenv').config();
const cors = require('cors')
const express = require('express');
// const databaseMiddleware = require('./middleware/database-middleware');
// const connectToDB = require('./db/database')
// const authMiddleware = require('./middleware/authentication-middleware')
// const cookieParser = require('cookie-parser');
const useMiddleware = require('./middleware');
const router = require("./routes")

const app = express()
 
// Use Middleware
useMiddleware(app);
app.use(router);

// Error Handler
app.use((err, req, res, next) => {
  console.log(err, `<=================== error ==================`);
  res.status(err.status || 500).json({
    message: err.message,
    errors: err.errors
  })
})

// app.get("/", (req, res) => {
// 	res.send("Its Week 16");
// });

// console.log(process.env.MONGO_DB)
app.listen(5001, () => {
  console.log('Server is running on port 5001')
})
