
const connectToDB  = require('../db/database')

const databaseMiddleware = async (req, res, next) => {
  const db = await connectToDB()
  req.db = db
  next()
}
 
module.exports = databaseMiddleware
 

 
  