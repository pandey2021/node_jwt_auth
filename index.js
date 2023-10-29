const express = require("express");
const app = express();
const jwt = require('jsonwebtoken');
require('dotenv').config(); // needed to define variable under .env file
app.use(express.json());

//temporarily making users array, otherwise get data from the database
const users = [
    {
        "id": "1",
        "username": "Samir Kumar",
        "password": "samir@123",
        "isAdmin": true
    },
    {
        "id": "2",
        "username": "Samir Kumar 1",
        "password": "samir1@123",
        "isAdmin": false
    },
    {
        "id": "3",
        "username": "Samir Kumar 2",
        "password": "samir2@123",
        "isAdmin": false
    }
];

// //generate accessToken

const generateAccessToken = (payload) => {
    return jwt.sign(
        //Note: not directly pass `payload` here as iat and exp are overwritten. so token are not refreshed
        { id: payload.id, isAdmin: payload.isAdmin },
        process.env.myAccessSecretKey,
        { expiresIn: '1m' });
};
const generateRefreshToken = (payload) => {
    return jwt.sign(
        { id: payload.id, isAdmin: payload.isAdmin },
        process.env.myRefreshSecretKey
    );
};

// to store refreshTokens for now
let refreshTokens = [];

// refresh functionalities
// this will refresh the token
app.post("/api/refresh", (req, res) => {
    // take the refresh token
    const refreshToken = req.body.refreshToken;
    //return err if it is empty or not valid.
    // Note: to check the token is valid or not, we need to store this token in our db
    if (!refreshToken) return res.status(401).send("You are not authenticated 1");
    if (!refreshTokens.includes(refreshToken)) return res.status(403).send("you are not allowed 1");
    jwt.verify(refreshToken, process.env.myRefreshSecretKey, (err, payload) => {
        err && console.log(err);
        //deleting the refresh token
        refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
        const newAccessToken123 = generateAccessToken(payload);
        const newRefreshToken123 = generateRefreshToken(payload);

        refreshTokens.push(newRefreshToken123);
        res.status(200).json({ "newAccessToken": newAccessToken123, "newRefreshToken": newRefreshToken123 })
    })
})


// creating middleware to validate access token
const verify = (req, res, next) => {
    const authHeaders = req.headers.auth;
    if (authHeaders) {
        const token = authHeaders.split(" ")[1];
        jwt.verify(token, process.env.myAccessSecretKey, (err, payload) => {
            if (err) {
                return res.status(403).send({ "Token is not valid": err });
            }
            req.payload = payload; // need to see how can we assing .user to req
            next();
        });
    } else {
        return res.status(401).send("You are not authenticated");
    }
}

//login function

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find((user) => {
        return user.username === username && user.password === password;
    });

    if (user) {
        console.log(user);
        // generate an access token
        const accessToken = generateAccessToken(user);  //expires after 20sec of login
        const refreshToken = generateRefreshToken(user);
        refreshTokens.push(refreshToken);
        res.status(200).send({
            "id": user.id,
            "username": user.username,
            "isAdmin": user.isAdmin,
            accessToken,
            refreshToken
        });
    } else {
        res.status(400).send("incorrect password or username");
    }
})

//logout function
app.post("/api/logout",verify,(req,res)=>{
    const refreshToken = req.body.refreshToken;
    refreshTokens = refreshTokens.filter((token)=> token !== refreshToken);
    res.status(200).send("Logout Successfully");
});

// delete function
app.delete("/api/user/:id", verify, (req, res) => {
    console.log(req.params.id, req.payload.id);
    console.log(typeof (req.params.id), typeof (req.payload.id));
    console.log(req.payload.id === req.params.id, req.payload.isAdmin);
    if (req.payload.id === req.params.id || req.payload.isAdmin) {
        res.status(200).send("user deleted");
    } else {
        res.status(403).send("you are not allowed to delete this user");
    }
});

app.get("/", (req, res) => {
    res.send("our api is runing...");
})
app.listen(8080, () => {
    console.log("port is up...");
})