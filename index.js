const express = require("express");
const app = express();
const cors = require('cors');
const mongodb = require("mongodb");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoClient = mongodb.MongoClient;
const dotenv = require("dotenv")
dotenv.config();

const url = process.env.DB;
const PORT = process.env.PORT || 4000;
app.use(cors({
    origin: "*"
}))

app.use(express.json());

function authenticate(req, res, next) {
    try {
        // Check if the token is present
        // if present -> check if it is valid
        if (req.headers.authorization) {
            jwt.verify(req.headers.authorization, process.env.JWT_SECRET, function (error, decoded) {
                if (error) {
                    res.status(500).json({
                        message: "Unauthorized"
                    })
                } else {
                    // console.log(decoded)
                    req.userid = decoded.id;
                    next()
                }

            });

        } else {
            res.status(401).json({
                message: "No Token Present"
            })
        }
    } catch (error) {
        console.log(error)
        res.status(500).json({
            message: "Internal Server Error"
        })
    }

}

app.post("/register", async function (req, res) {
    try {
        // Connect the Database
        let client = await mongoClient.connect(url)

        // Select the DB
        let db = client.db("condo-security-db");

        // Hash the password
        let salt = bcryptjs.genSaltSync(10);
        let hash = bcryptjs.hashSync(req.body.password, salt)
        req.body.password = hash;

        // Select the Collection and perform the action
        let data = await db.collection("users").insertOne(req.body)

        // Close the Connection
        await client.close();

        res.json({
            message: "Condo Owner Registered",
            id: data._id
        })
    } catch (error) {

    }
})

app.post("/add-unit", [authenticate], async function (req, res) {
    try {
        // console.log(req.body)
        // Connect the Database
        let client = await mongoClient.connect(url)

        // Select the DB
        let db = client.db("condo-security-db");

        // Hash the password
        let salt = bcryptjs.genSaltSync(10);
        let hash = bcryptjs.hashSync(req.body.password, salt)
        req.body.password = hash;

        req.body.userid = req.userid;
        // Select the Collection and perform the action
        let data = await db.collection("units").insertOne(req.body)

        // Close the Connection
        await client.close();

        res.json({
            message: "Unit Added"
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({
            message: "Something went wrong!"
        })
    }
})

app.get("/units", [authenticate], async function (req, res) {
    try {
        // Connect the Database
        let client = await mongoClient.connect(url)

        // Select the DB
        let db = client.db("condo-security-db");
        
        // Select the collection and perform operations
        let units =  await db.collection("units").find({userid: req.userid}).toArray();
        res.json(
            units
        )

        // Close connection
        await client.close()

    } catch (error) {
        console.log(error)
    }
})

app.post("/super-admin-register", async function (req, res) {
    try {
        // Connect the Database
        let client = await mongoClient.connect(url)

        // Select the DB
        let db = client.db("condo-security-db");

        // Hash the password
        let salt = bcryptjs.genSaltSync(10);
        let hash = bcryptjs.hashSync(req.body.password, salt)
        req.body.password = hash;

        // Select the Collection and perform the action
        let data = await db.collection("users").insertOne(req.body)

        // Close the Connection
        await client.close();

        res.json({
            message: "Super Admin Registered",
            id: data._id
        })
    } catch (error) {

    }
})


app.post("/login", async function (req, res) {
    try {
        // Connect the Database
        let client = await mongoClient.connect(url)

        // Select the DB
        let db = client.db("condo-security-db");

        // Find the user with email_id
        let user = await db.collection("users").findOne({ email: req.body.email });

        if (user) {
            // Hash the incoming password
            // Compare that password with user's password
            // console.log(req.body)
            // console.log(user.password)
            let matchPassword = bcryptjs.compareSync(req.body.password, user.password)
            if (matchPassword) {
                // Generate JWT token
                let token = jwt.sign({ id: user._id }, process.env.JWT_SECRET)
                res.json({
                    message: true,
                    token,
                    userName: user.username,
                    roleType: user.roleType,
                    approved: user.approved
                })
            } else {
                res.status(404).send({
                    message: "Email/Password is incorrect"
                })
            }
            // if both are correct then allow them
        } else {
            res.status(404).json({
                message: "Email/Password is incorrect"
            })
        }

    } catch (error) {
        console.log(error)
    }
})

app.get("/all-condo-registrations", async function (req, res) {
    try {
        // Connect the Database
        let client = await mongoClient.connect(url)

        // Select the DB
        let db = client.db("condo-security-db");

        // Select the collection and perform operations
        let user = await db.collection("users").find({ roleType: "condoOwner" }).toArray()
        res.send(
            [user]
        )

        // Clos connection
        await client.close()

    } catch (error) {
        console.log(error)
    }
})


app.get("/condo-approval", async function (req, res) {
    try {
        // Connect the Database
        let client = await mongoClient.connect(url)

        // Select the DB
        let db = client.db("condo-security-db");

        // Select the collection and perform operations
        let user = await db.collection("users").find({ roleType: "condoOwner", approved: "no" }).toArray()
        res.send(
            [user]
        )

        // Clos connection
        await client.close()

    } catch (error) {
        console.log(error)
    }
})

app.post("/approve-condo/:id", async function (req, res) {
    try {
        // Connect the Database
        let client = await mongoClient.connect(url)

        // Select the DB
        let db = client.db("condo-security-db");

        // Select the collection and perform operations
        let user = await db.collection("users").findOneAndUpdate({ _id: mongodb.ObjectId(req.params.id) }, { $set: { approved: "yes" } })

        res.send(
            [user]
        )

        // Close connection
        await client.close()

    } catch (error) {
        console.log(error)
    }
})

app.get("/approved-condos", async function (req, res) {
    try {
        // Connect the Database
        let client = await mongoClient.connect(url)

        // Select the DB
        let db = client.db("condo-security-db");

        // Select the collection and perform operations
        let user = await db.collection("users").find({ roleType: "condoOwner", approved: "yes" }).toArray()
        res.send(
            [user]
        )

        // Close connection
        await client.close()

    } catch (error) {
        console.log(error)
    }
})

app.post("/reject-condo/:id", async function (req, res) {
    try {
        // Connect the Database
        let client = await mongoClient.connect(url)

        // Select the DB
        let db = client.db("condo-security-db");

        // Select the collection and perform operations
        let user = await db.collection("users").findOneAndUpdate({ _id: mongodb.ObjectId(req.params.id) }, { $set: { approved: "rejected" } })

        res.send(
            [user]
        )

        // Close connection
        await client.close()

    } catch (error) {
        console.log(error)
    }
})

app.get("/rejected-condos", async function (req, res) {
    try {
        // Connect the Database
        let client = await mongoClient.connect(url)

        // Select the DB
        let db = client.db("condo-security-db");

        // Select the collection and perform operations
        let user = await db.collection("users").find({ roleType: "condoOwner", approved: "rejected" }).toArray()
        res.send(
            [user]
        )

        // Close connection
        await client.close()

    } catch (error) {
        console.log(error)
    }
})

app.get("/dashboard", [authenticate], async (req, res) => {
    res.json({
        message: "Protected Data"
    })
})

app.listen(PORT, function () {
    console.log(`The app is listening in port ${PORT}`)
})