const request = require('supertest');
const User = require('../../models/user.model')
const app = require('../../app')
var jwt = require("jsonwebtoken")
const config = require('../../configs/auth.config')

const db = require('../db')

beforeAll(async () => {
    await db.clearDatabase();
    await User.create ({
        name: "Maleena",
        userId: "01",
        email: "admin01@gmail.com",
        userType:"ADMIN",
        password:"12345678",
        userStatus:"APPROVED"
    })
})

afterAll(async () => {
    await db.closeDatabase()
    app.close()
})

const api_endpoint ="/crm/api/"

describe("Find By Id Endpoints", () => {
    let token = jwt.sign({ userId: 1}, config.secret, {
        expiresIn: 120
    })

    it('should find by id', async () => {
        const res = await request(app)
            .get(api_endpoint + "users/1")
            .set({ "x-access-token": token })
            .field("userId", 1)
        expect(res.statusCode).toEqual(200)
        expect(res.body).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    'email': "admin01@gmail.com",
                    'name': "Maleena",
                    'userId': "01",
                    'userStatus': "APPROVED",
                    'userType': "ADMIN"
                })
            ])
        )

    })
})

describe("Find all endpoints", () => {
    let token = jwt.sign({ userId: 1 }, config.secret, {
        expiresIn: 120
    })

    it("should Find All", async () => {
        const res = await request(app)
            .get(api_endpoint + "users")
            .set('x-access-token', token)
            .query({ userType: "ADMIN" })
            .field("userId", 1)
        expect(res.statusCode).toEqual(200)
        expect(res.body).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    'email': "admin01@gmail.com",
                    'name': "Maleena",
                    'userId': "01",
                    'userStatus': "APPROVED",
                    'userType': "ADMIN"
                })
            ])
        )
    })
})

describe("PUT Update Endpoints", () => {
    let token = jwt.sign({ userId: 1 }, config.secret, {
        expiresIn: 120
    })

    it('should Update', async () => {
        const res = await request(app)
            .put(api_endpoint + "users/1")
            .set('x-access-token', token)
            .field('userType', "ADMIN")
            .field('userId', 1)
        expect(res.statusCode).toEqual(200)
        expect(res.body).toEqual({
            "message": `User record has been updated successfully`
        })
    })
})