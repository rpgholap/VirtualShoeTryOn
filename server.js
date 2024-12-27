require('dotenv').config(); // To load environment variables from .env file
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt'); // For password hashing

const app = express();

// Use CORS middleware
app.use(cors());

// Middleware to parse JSON request bodies
app.use(express.json());

// Serve static files from the 'public' folder if needed
app.use(express.static(path.join(__dirname, 'public')));

// Serve the main page from the root directory
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html')); // Serve index.html from the root
});

// Explicit route to handle `/index.html`
app.get('/index.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html')); // Serve index.html at /index.html
});

// Handle the /register POST request
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    // Validate the input
    if (!name || !email || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    // Path to the users JSON file
    const usersFilePath = path.join(__dirname, 'users.json');

    // Read existing users with error handling
    let users = [];
    if (fs.existsSync(usersFilePath)) {
        try {
            const fileContent = fs.readFileSync(usersFilePath, 'utf8');
            if (fileContent) {
                users = JSON.parse(fileContent);
            }
        } catch (err) {
            return res.status(500).json({ success: false, message: 'Error reading user data. File may be corrupted.' });
        }
    }

    // Check if the email is already registered
    if (users.some(user => user.email === email)) {
        return res.status(400).json({ success: false, message: 'Email is already registered.' });
    }

    // Hash the password before saving
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        // Add the new user with hashed password
        users.push({ name, email, password: hashedPassword });

        // Write the updated users array to the users.json file
        fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));

        // Return JSON response
        res.json({ success: true, message: 'Registration successful!' });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Error during password hashing or saving user.' });
    }
});

// Handle the /login POST request
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Path to the users JSON file
    const usersFilePath = path.join(__dirname, 'users.json');

    // Read existing users
    let users = [];
    if (fs.existsSync(usersFilePath)) {
        try {
            const fileContent = fs.readFileSync(usersFilePath, 'utf8');
            if (fileContent) {
                users = JSON.parse(fileContent);
            }
        } catch (err) {
            return res.status(500).json({ success: false, message: 'Error reading user data. File may be corrupted.' });
        }
    }

    // Find the user with the matching email
    const user = users.find(user => user.email === email);
    if (user) {
        // Compare the password with the hashed password in the database
        try {
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (isPasswordValid) {
                return res.json({ success: true, message: 'Login successful!' });
            } else {
                return res.status(401).json({ success: false, message: 'Invalid email or password.' });
            }
        } catch (error) {
            return res.status(500).json({ success: false, message: 'Error comparing passwords.' });
        }
    } else {
        return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }
});

// Start the server
const PORT = process.env.PORT || 3000; // Use environment variable for port
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
