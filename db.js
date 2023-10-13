const connectToDB = require('./db/database')

async function main() {
    await connectToDB()
}

main()