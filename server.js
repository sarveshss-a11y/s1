const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// --- CORS CONFIG ---
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

app.options('*', cors());
app.use(express.json());

// Ensure public directory exists
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
    fs.mkdirSync(publicDir, { recursive: true });
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
    </html>`;
    fs.writeFileSync(path.join(publicDir, 'index.html'), basicHtml);
    console.log('Created public directory and basic index.html');
}
app.use(express.static(publicDir));

// --- MONGODB ---
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => {
        console.error('Could not connect to MongoDB...', err);
        process.exit(1);
    });

// --- SCHEMA ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    folders: { type: Array, default: [] },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// --- SIMPLE TOKEN ---
const createToken = (payload) => Buffer.from(JSON.stringify(payload)).toString('base64');
const verifyToken = (token) => JSON.parse(Buffer.from(token, 'base64').toString());

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).send({ message: 'Access token required' });

    try {
        req.user = verifyToken(token);
        next();
    } catch {
        return res.status(403).send({ message: 'Invalid or expired token' });
    }
};

// --- AUTH ENDPOINTS ---
app.get('/api/health', (req, res) => res.status(200).send({ message: 'Server is running' }));

app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;
    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).send({ message: 'Username already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

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

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(401).send({ message: 'Invalid username or password' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).send({ message: 'Invalid username or password' });

        const token = createToken({ userId: user._id, username: user.username });
        res.status(200).send({ message: 'Logged in successfully', token, user: { username: user.username } });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).send({ message: 'Failed to log in' });
    }
});

// --- USER DATA ENDPOINTS ---
app.get('/api/user', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) return res.status(404).send({ message: 'User not found' });

        res.status(200).send({ username: user.username, folders: user.folders });
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).send({ message: 'Failed to fetch user data' });
    }
});

// Save all folders at once
app.post('/api/user/data', authenticateToken, async (req, res) => {
    try {
        const { folders } = req.body;
        const user = await User.findByIdAndUpdate(
            req.user.userId,
            { folders },
            { new: true }
        ).select('-password');

        if (!user) return res.status(404).send({ message: 'User not found' });
        res.status(200).send({ message: 'Folders saved successfully', folders: user.folders });
    } catch (error) {
        console.error('Error saving user data:', error);
        res.status(500).send({ message: 'Failed to save data' });
    }
});

// --- FOLDER ENDPOINTS ---
app.post('/api/folders', authenticateToken, async (req, res) => {
    try {
        const { name, parentId } = req.body;
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });
        if (!name || name.trim() === '') return res.status(400).json({ message: 'Folder name is required' });

        const newFolder = {
            id: Date.now().toString(),
            name: name.trim(),
            marks: [],
            subfolders: [],
            createdAt: new Date().toISOString(),
            collapsed: false
        };

        if (parentId) {
            const addToParent = (folders, targetId) => {
                for (const f of folders) {
                    if (f.id === targetId) {
                        f.subfolders = f.subfolders || [];
                        f.subfolders.push(newFolder);
                        return true;
                    }
                    if (f.subfolders && addToParent(f.subfolders, targetId)) return true;
                }
                return false;
            };
            if (!addToParent(user.folders, parentId)) return res.status(404).json({ message: 'Parent folder not found' });
        } else {
            user.folders.push(newFolder);
        }

        await user.save();
        res.status(201).json({ message: 'Folder created successfully', folder: newFolder });
    } catch (error) {
        console.error('Error creating folder:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/folders', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.status(200).json({ folders: user.folders });
    } catch (error) {
        console.error('Error fetching folders:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.put('/api/folders/:folderId', authenticateToken, async (req, res) => {
    try {
        const { folderId } = req.params;
        const updates = req.body;
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        const updateFolder = (folders, id) => {
            for (const f of folders) {
                if (f.id === id) {
                    Object.assign(f, updates);
                    return true;
                }
                if (f.subfolders && updateFolder(f.subfolders, id)) return true;
            }
            return false;
        };

        if (!updateFolder(user.folders, folderId)) return res.status(404).json({ message: 'Folder not found' });
        await user.save();
        res.status(200).json({ message: 'Folder updated successfully' });
    } catch (error) {
        console.error('Error updating folder:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.delete('/api/folders/:folderId', authenticateToken, async (req, res) => {
    try {
        const { folderId } = req.params;
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        const deleteFolder = (folders, id) => {
            for (let i = 0; i < folders.length; i++) {
                if (folders[i].id === id) {
                    folders.splice(i, 1);
                    return true;
                }
                if (folders[i].subfolders && deleteFolder(folders[i].subfolders, id)) return true;
            }
            return false;
        };

        if (!deleteFolder(user.folders, folderId)) return res.status(404).json({ message: 'Folder not found' });
        await user.save();
        res.status(200).json({ message: 'Folder deleted successfully' });
    } catch (error) {
        console.error('Error deleting folder:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// --- CATCH-ALL ---
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => console.log(`Server listening at port ${port}`));
