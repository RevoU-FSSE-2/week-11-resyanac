const { MongoClient } = require('mongodb')
require('dotenv').config()
const connectToDB = async () => {
    const client = await new MongoClient(process.env.MONGO_DEV).connect();
    try {
        const db = client.db(process.env.MONGO_DB)
        return db
    } catch (error) {
        console.log(error);
        client.close()
    }
}

module.exports = connectToDB

