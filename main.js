const express = require('express');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// Endpoint for code submission
app.post('/code', (req, res) => {
    const code = req.body.code;

    // Execute the code and get the results
    const results = executeCode(code);

    // Send the results as a response
    res.json({ results });
});

// Helper function to execute the code (replace with your own implementation)
function executeCode(code) {
    // Implement code execution logic here
    return 'Code execution results';
}

// Start the server
app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});

const { MongoClient } = require('mongodb');

const url = 'mongodb://localhost:27017';
const dbName = 'codeExecutionDB';

let db;

MongoClient.connect(url, { useUnifiedTopology: true })
    .then((client) => {
        console.log('Connected to MongoDB');
        db = client.db(dbName);
    })
    .catch((err) => {
        console.error('Error connecting to MongoDB:', err);
    });

app.post('/code', (req, res) => {
    const code = req.body.code;

    // Save the code submission to the database
    db.collection('submissions').insertOne({ code });

    // Execute the code and get the results
    const results = executeCode(code);

    // Save the execution results to the database
    db.collection('results').insertOne({ results });

    // Send the results as a response
    res.json({ results });
});

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const secretKey = 'your-secret-key';

app.post('/signup', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Generate a hash of the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save the user details to the database (replace with your own logic)
        db.collection('users').insertOne({ username, password: hashedPassword });

        res.json({ message: 'User registered successfully' });
    } catch (err) {
        console.error('Error during signup:', err);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find the user in the database
        const user = await db.collection('users').findOne({ username });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Compare the provided password with the stored hashed password
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Generate a JWT token
        const token = jwt.sign({ username }, secretKey);

        // Send the token as a response
        res.json({ token });
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ error: 'Failed to log in' });
    }
});

function verifyToken(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        req.user = decoded.username;
        next();
    });

}

// Example protected endpoint
app.get('/protected', verifyToken, (req, res) => {
    const username = req.user;
    res.json({ message: `Hello, ${username}! This is a protected endpoint.` });
});

const Joi = require('joi');

// Example request validation using Joi
app.post('/signup', (req, res) => {
    const schema = Joi.object({
        username: Joi.string().required(),
        password: Joi.string().required(),
    });

    const { error } = schema.validate(req.body);
    if (error) {
        return res.status(400).json({ error: error.details[0].message });
    }

    // Handle valid request
});

app.post('/login', async (req, res) => {
    try {
        // Code that may throw an error

        // Handle success case
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.use((err, req, res, next) => {
    console.error('Error:', err);

    // Check if it's a known error with a custom message
    if (err.message) {
        return res.status(500).json({ error: err.message });
    }

    // Otherwise, return a generic error message
    res.status(500).json({ error: 'Internal Server Error' });
});

app.get('/users/:id', (req, res) => {
    const userId = req.params.id;

    // Find the user in the database
    const user = db.collection('users').findOne({ _id: userId });

    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    // Handle found user
});

const WebSocket = require('ws');

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
    // Handle WebSocket connection
});

const executionId = 'unique-execution-id'; // Use the actual execution ID

wss.on('connection', (ws) => {
    ws.on('message', (message) => {
        // Handle incoming WebSocket messages from clients
    });

    // Emit progress notifications to the connected user
    ws.send(JSON.stringify({ event: 'progress', executionId, message: 'Execution started' }));
});

// Emit completion notification with results
ws.send(JSON.stringify({ event: 'completion', executionId, results }));

const socket = new WebSocket('ws://localhost:3000');

socket.addEventListener('message', (event) => {
    const { event: eventType, executionId, message, results } = JSON.parse(event.data);

    if (eventType === 'progress') {
        // Handle progress notification
        console.log(`Execution ID ${executionId}: ${message}`);
    } else if (eventType === 'completion') {
        // Handle completion notification
        console.log(`Execution ID ${executionId} completed with results:`, results);
    }
});
