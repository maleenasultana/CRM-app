const dbConfig = require("./configs/db.config")
const mongoose = require("mongoose")
const authController = require("./controllers/auth.controller")
const express = require('express')
const User = require("./models/user.model")
const app = express()
const bcrypt = require('bcryptjs')
const cors = require('cors')
app.use(cors())
const constants = require("./utils/constants")

const PORT = process.env.PORT || 7500
async function init() {
    let user = await User.findOne({ userId: "admin" })

    if (user) {
        console.log("Admin user already present", user)
        return
    }

    try {
        let user = await User.create({
            name: "Maleena",
            userId: "01",
            email: "admin@gmail.com",
            userType: "ADMIN",
            password: bcrypt.hashSync("12345678", 8),
            userStatus: constants.userStatus.approved
        })
        console.log(user)
    } catch (err) {
        console.log(err.message)
    }
}

mongoose.connect(dbConfig.MONGO_URI)
app.use(express.json())

const db = mongoose.connection
db.on("error", () => console.log("Can't connect to DB"))
db.once("open", () => {
    console.log("Connected to Mongo DB")
    init()
})

require('./routes/auth.routes')(app)
require("./routes/user.routes")(app)
require("./routes/ticket.routes")(app)

app.get("/", (req, res) => res.send("Hello World"))

module.exports = app.listen(`${PORT}`, () => console.log(`Listening at localhost:${PORT}`))








//for testing netconnection
//Test-NetConnection localhost -p 3000
 // "test": "jest --testEnvironment=node --runInBand --detectOpenHandles --coverage./tests"