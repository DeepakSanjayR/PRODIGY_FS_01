const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const User = require('./models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const port = 3000;
const jwtSecret = 'your_jwt_secret_key'; // Replace with your own secret

// Middleware
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost/auth-system', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// User Registration
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check if user already exists
        let user = await User.findOne({ username });
        if (user) return res.status(400).send('User already exists');

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        user = new User({ username, password: hashedPassword });
        await user.save();

        res.status(201).send('User registered');
    } catch (error) {
        res.status(500).send('Server error');
    }
});

// User Login
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user
        const user = await User.findOne({ username });
        if (!user) return res.status(400).send('Invalid credentials');

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid credentials');

        // Create and send JWT
        const token = jwt.sign({ id: user._id }, jwtSecret, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).send('Server error');
    }
});

// Middleware to verify JWT
const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).send('Access denied');

    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) return res.status(403).send('Invalid token');
        req.user = decoded;
        next();
    });
};

// Protected Route
app.get('/protected', authMiddleware, (req, res) => {
    res.send('This is a protected route');
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
