const express = require('express');
const app = express();
const port = 3000;

const jwt = require('jsonwebtoken');

// Authentication server private key for token generation (tokens to be verified by passport service using paired public key)
const fs = require('fs');
const PRIVATE_KEY = fs.readFileSync('./rsa_private.pem', 'utf8');
const crypto = require('crypto');

// Simulate user database with simple access levels
const authenticationMap = new Map();
// Create users, encrypt stored passwords, grant access permissions
function createUser(username, password, access) {
    let salt = crypto.randomBytes(32).toString('hex');
    let hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    authenticationMap.set(username, { hashedPassword: hashedPassword, salt: salt, access: access });
}
createUser("matthew", "abc123", 0b1111); // Can access all math functions
createUser("christopher", "123456", 0b0100); // Can only access subtraction

app.use(express.json());
app.use((err, req, res, next) => {
    res.status(400).json({ status: 400, message: "Invalid JSON format" })
});

app.post('/login', (req, res) => {
    const username = req.body.username;
    const hashedPassword = crypto.pbkdf2Sync(req.body.password, authenticationMap.get(username).salt, 10000, 64, 'sha512').toString('hex');
    if (hashedPassword !== authenticationMap.get(username).hashedPassword) return res.status(401).json({ status: 401, message: "Login Failure: Invalid credentials" });

    // Token expires in 90 seconds
    const expiresIn = '90000';

    const payload = {
        sub: { username, access: authenticationMap.get(username).access }
    };

    const token = jwt.sign(payload, PRIVATE_KEY, { expiresIn: expiresIn, algorithm: 'RS256' });
    res.status(200).json({ status: 200, username: username, token: token, expiresIn: expiresIn });
});

app.use((req, res) => {
    res.sendStatus(404);
});

app.listen(port, () => console.log('listening on port:' + port));