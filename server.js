const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Enhanced CORS configuration
app.use(cors({
    origin: [
        'https://sarvesh-e9i2.onrender.com', // Your frontend domain
        'https://sarveshbackend.onrender.com', // Your backend domain
        'http://localhost:3000', 
        'http://localhost:3001', 
        'http://127.0.0.1:5500'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Handle preflight requests
app.options('*', cors());

app.use(express.json());

// Ensure public directory exists
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
    fs.mkdirSync(publicDir, { recursive: true });
    
    // Create a basic index.html file
    const basicHtml = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Xpress App</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
            h1 { color: #333; }
        </style>
    </head>
    <body>
        <h1>Xpress App Backend</h1>
        <p>Server is running successfully!</p>
        <p>Frontend should be served from a different location.</p>
    </body>
    </html>
    `;
    
    fs.writeFileSync(path.join(publicDir, 'index.html'), basicHtml);
    console.log('Created public directory and basic index.html');
}

// Serve static files from public folder
app.use(express.static(publicDir));

// --- MONGODB SETUP ---

// Connect to MongoDB with better error handling
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => {
        console.error('Could not connect to MongoDB...', err);
        process.exit(1);
    });

// Define User Schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    folders: {
        type: Array,
        default: []
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const User = mongoose.model('User', userSchema);

// Simple token functions
const createToken = (payload) => {
    return Buffer.from(JSON.stringify(payload)).toString('base64');
};

const verifyToken = (token) => {
    try {
        return JSON.parse(Buffer.from(token, 'base64').toString());
    } catch (error) {
        throw new Error('Invalid token');
    }
};

// Middleware to verify token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).send({ message: 'Access token required' });
    }

    try {
        const user = verifyToken(token);
        req.user = user;
        next();
    } catch (err) {
        return res.status(403).send({ message: 'Invalid or expired token' });
    }
};

// --- AUTHENTICATION ENDPOINTS ---

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.status(200).send({ message: 'Server is running' });
});

// User signup endpoint
app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).send({ message: 'Username already exists' });
        }

        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create new user
        const newUser = new User({
            username,
            password: hashedPassword
        });

        await newUser.save();

        // Create a token
        const token = createToken({ userId: newUser._id, username: newUser.username });

        res.status(201).send({ 
            message: 'User created successfully', 
            token,
            user: { username: newUser.username }
        });
    } catch (error) {
        console.error('Error during signup:', error);
        res.status(500).send({ message: 'Failed to create user' });
    }
});

// User login endpoint
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).send({ message: 'Invalid username or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).send({ message: 'Invalid username or password' });
        }

        // Create a token
        const token = createToken({ userId: user._id, username: user.username });

        res.status(200).send({ 
            message: 'Logged in successfully', 
            token,
            user: { username: user.username }
        });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).send({ message: 'Failed to log in' });
    }
});

// Get user data endpoint
app.get('/api/user', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }
        
        res.status(200).send({ user });
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).send({ message: 'Failed to fetch user data' });
    }
});

// Save user data endpoint
app.post('/api/user/data', authenticateToken, async (req, res) => {
    try {
        const { folder } = req.body; // Single folder name

        const user = await User.findByIdAndUpdate(
            req.user.userId,
            { $push: { folders: folder } },
            { new: true }
        ).select('-password');

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        res.status(200).send({ message: 'Folder saved successfully', user });
    } catch (error) {
        console.error('Error saving user data:', error);
        res.status(500).send({ message: 'Failed to save data' });
    }
});

// --- FOLDER ENDPOINTS ---

// Create a new folder
app.post('/api/folders', authenticateToken, async (req, res) => {
    try {
        const { name, parentId } = req.body;
        const userId = req.user.userId;
        
        if (!name || name.trim() === '') {
            return res.status(400).json({ message: 'Folder name is required' });
        }
        
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        const newFolder = {
            id: Date.now().toString(),
            name: name.trim(),
            marks: [],
            subfolders: [],
            createdAt: new Date().toISOString(),
            collapsed: false
        };
        
        if (parentId) {
            const findAndAddToParent = (folders, targetId) => {
                for (const folder of folders) {
                    if (folder.id === targetId) {
                        if (!folder.subfolders) folder.subfolders = [];
                        folder.subfolders.push(newFolder);
                        return true;
                    }
                    if (folder.subfolders && folder.subfolders.length > 0) {
                        if (findAndAddToParent(folder.subfolders, targetId)) {
                            return true;
                        }
                    }
                }
                return false;
            };
            
            const parentFound = findAndAddToParent(user.folders, parentId);
            if (!parentFound) {
                return res.status(404).json({ message: 'Parent folder not found' });
            }
        } else {
            user.folders.push(newFolder);
        }
        
        await user.save();
        
        res.status(201).json({
            message: 'Folder created successfully',
            folder: newFolder
        });
    } catch (error) {
        console.error('Error creating folder:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get all folders for a user
app.get('/api/folders', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        res.status(200).json({ folders: user.folders });
    } catch (error) {
        console.error('Error fetching folders:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update a folder
app.put('/api/folders/:folderId', authenticateToken, async (req, res) => {
    try {
        const { folderId } = req.params;
        const updates = req.body;
        const userId = req.user.userId;
        
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        const findAndUpdateFolder = (folders, targetId) => {
            for (const folder of folders) {
                if (folder.id === targetId) {
                    Object.assign(folder, updates);
                    return true;
                }
                if (folder.subfolders && folder.subfolders.length > 0) {
                    if (findAndUpdateFolder(folder.subfolders, targetId)) {
                        return true;
                    }
                }
            }
            return false;
        };
        
        const folderFound = findAndUpdateFolder(user.folders, folderId);
        if (!folderFound) {
            return res.status(404).json({ message: 'Folder not found' });
        }
        
        await user.save();
        
        res.status(200).json({ message: 'Folder updated successfully' });
    } catch (error) {
        console.error('Error updating folder:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Delete a folder
app.delete('/api/folders/:folderId', authenticateToken, async (req, res) => {
    try {
        const { folderId } = req.params;
        const userId = req.user.userId;
        
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        const findAndDeleteFolder = (folders, targetId) => {
            for (let i = 0; i < folders.length; i++) {
                if (folders[i].id === targetId) {
                    folders.splice(i, 1);
                    return true;
                }
                if (folders[i].subfolders && folders[i].subfolders.length > 0) {
                    if (findAndDeleteFolder(folders[i].subfolders, targetId)) {
                        return true;
                    }
                }
            }
            return false;
        };
        
        const folderFound = findAndDeleteFolder(user.folders, folderId);
        if (!folderFound) {
            return res.status(404).json({ message: 'Folder not found' });
        }
        
        await user.save();
        
        res.status(200).json({ message: 'Folder deleted successfully' });
    } catch (error) {
        console.error('Error deleting folder:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Catch-all -> frontend (must be last)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
    console.log(`Server listening at port ${port}`);
});