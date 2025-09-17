// server.js
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
        'https://sarvesh-e9i2.onrender.com',
        'https://sarveshbackend.onrender.com',
        'http://localhost:3000',
        'http://localhost:3001',
        'http://127.0.0.1:5500',
        'http://localhost:5500'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.options('*', cors());
app.use(express.json());

// Ensure public directory exists (so catch-all can serve an index if needed)
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
    fs.mkdirSync(publicDir, { recursive: true });
    const basicHtml = `
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"><title>Xpress App</title></head>
    <body><h1>Backend</h1><p>Server is running.</p></body>
    </html>`;
    fs.writeFileSync(path.join(publicDir, 'index.html'), basicHtml);
}
app.use(express.static(publicDir));

// --- MONGODB ---
mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/marks_explorer', {
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
    // folders is an array of folder objects; each folder may have subfolders and marks
    folders: { type: Array, default: [] },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// --- SIMPLE TOKEN HELPERS (Base64 JSON) ---
// NOTE: base64 token is NOT secure for production. This keeps your previous approach.
const createToken = (payload) => Buffer.from(JSON.stringify(payload)).toString('base64');
const verifyToken = (token) => JSON.parse(Buffer.from(token, 'base64').toString());

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).send({ message: 'Access token required' });

    try {
        req.user = verifyToken(token);
        next();
    } catch (err) {
        return res.status(403).send({ message: 'Invalid or expired token' });
    }
};

// --- AUTH ENDPOINTS ---
app.get('/api/health', (req, res) => res.status(200).send({ message: 'Server is running' }));

app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send({ message: 'Username and password required' });

    try {
        const existing = await User.findOne({ username });
        if (existing) return res.status(400).send({ message: 'Username already exists' });

        const hashed = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashed, folders: [] });
        await user.save();

        const token = createToken({ userId: user._id, username: user.username });
        res.status(201).send({ message: 'User created successfully', token, user: { username: user.username } });
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).send({ message: 'Failed to create user' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send({ message: 'Username and password required' });

    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(401).send({ message: 'Invalid username or password' });

        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(401).send({ message: 'Invalid username or password' });

        const token = createToken({ userId: user._id, username: user.username });
        // return folders so frontend can initialize without an extra call
        res.status(200).send({ message: 'Logged in successfully', token, user: { username: user.username }, folders: user.folders || [] });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).send({ message: 'Failed to log in' });
    }
});

// --- USER DATA ENDPOINTS ---
app.get('/api/user', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) return res.status(404).send({ message: 'User not found' });
        res.status(200).send({ username: user.username, folders: user.folders || [] });
    } catch (err) {
        console.error('Error fetching user data:', err);
        res.status(500).send({ message: 'Failed to fetch user data' });
    }
});

app.post('/api/user/data', authenticateToken, async (req, res) => {
    try {
        const { folders } = req.body;
        if (!Array.isArray(folders)) return res.status(400).send({ message: 'Folders must be an array' });

        const user = await User.findByIdAndUpdate(req.user.userId, { folders }, { new: true }).select('-password');
        if (!user) return res.status(404).send({ message: 'User not found' });

        res.status(200).send({ message: 'Data saved successfully', folders: user.folders });
    } catch (err) {
        console.error('Error saving user data:', err);
        res.status(500).send({ message: 'Failed to save data' });
    }
});

// --- FOLDER HELPERS (recursive) ---
const addToParent = (folders, targetId, newFolder) => {
    for (const f of folders) {
        if (f.id === targetId) {
            f.subfolders = f.subfolders || [];
            f.subfolders.push(newFolder);
            return true;
        }
        if (f.subfolders && addToParent(f.subfolders, targetId, newFolder)) return true;
    }
    return false;
};

const updateFolderRecursively = (folders, id, updates) => {
    for (const f of folders) {
        if (f.id === id) {
            Object.assign(f, updates);
            return true;
        }
        if (f.subfolders && updateFolderRecursively(f.subfolders, id, updates)) return true;
    }
    return false;
};

const deleteFolderRecursively = (folders, id) => {
    for (let i = 0; i < folders.length; i++) {
        if (folders[i].id === id) {
            folders.splice(i, 1);
            return true;
        }
        if (folders[i].subfolders && deleteFolderRecursively(folders[i].subfolders, id)) return true;
    }
    return false;
};

const findFolderRecursively = (folders, folderId) => {
    for (const folder of folders) {
        if (folder.id === folderId) return folder;
        if (folder.subfolders) {
            const found = findFolderRecursively(folder.subfolders, folderId);
            if (found) return found;
        }
    }
    return null;
};

// --- FOLDER ENDPOINTS ---
app.post('/api/folders', authenticateToken, async (req, res) => {
    try {
        const { name, parentId } = req.body;
        if (!name || !name.trim()) return res.status(400).json({ message: 'Folder name is required' });

        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        const newFolder = {
            id: Date.now().toString(),
            name: name.trim(),
            marks: [],
            subfolders: [],
            createdAt: new Date().toISOString(),
            collapsed: false
        };

        if (parentId) {
            if (!addToParent(user.folders, parentId, newFolder)) {
                return res.status(404).json({ message: 'Parent folder not found' });
            }
        } else {
            user.folders.push(newFolder);
        }

        await user.save();
        res.status(201).json({ message: 'Folder created successfully', folder: newFolder });
    } catch (err) {
        console.error('Error creating folder:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/folders', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.status(200).json({ folders: user.folders || [] });
    } catch (err) {
        console.error('Error fetching folders:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.put('/api/folders/:folderId', authenticateToken, async (req, res) => {
    try {
        const { folderId } = req.params;
        const updates = req.body;

        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        if (!updateFolderRecursively(user.folders, folderId, updates)) {
            return res.status(404).json({ message: 'Folder not found' });
        }

        await user.save();
        res.status(200).json({ message: 'Folder updated successfully' });
    } catch (err) {
        console.error('Error updating folder:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.delete('/api/folders/:folderId', authenticateToken, async (req, res) => {
    try {
        const { folderId } = req.params;

        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        if (!deleteFolderRecursively(user.folders, folderId)) {
            return res.status(404).json({ message: 'Folder not found' });
        }

        await user.save();
        res.status(200).json({ message: 'Folder deleted successfully' });
    } catch (err) {
        console.error('Error deleting folder:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// --- MARKS ENDPOINTS ---
app.post('/api/folders/:folderId/marks', authenticateToken, async (req, res) => {
    try {
        const { folderId } = req.params;
        const { subject, marksObtained, totalMarks, date } = req.body;

        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        const folder = findFolderRecursively(user.folders, folderId);
        if (!folder) return res.status(404).json({ message: 'Folder not found' });

        // Ensure folder.marks exists
        folder.marks = folder.marks || [];

        const newMark = {
            id: Date.now().toString(),
            subject: subject || 'Untitled',
            marksObtained: parseFloat(marksObtained) || 0,
            totalMarks: parseFloat(totalMarks) || 0,
            date: date || new Date().toISOString().split('T')[0],
            createdAt: new Date().toISOString(),
            folderId: folderId
        };

        folder.marks.push(newMark);
        await user.save();

        res.status(201).json({ message: 'Marks added successfully', mark: newMark });
    } catch (err) {
        console.error('Error adding marks:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.put('/api/folders/:folderId/marks/:markId', authenticateToken, async (req, res) => {
    try {
        const { folderId, markId } = req.params;
        const { subject, marksObtained, totalMarks, date } = req.body;

        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        const folder = findFolderRecursively(user.folders, folderId);
        if (!folder) return res.status(404).json({ message: 'Folder not found' });

        folder.marks = folder.marks || [];
        const markIndex = folder.marks.findIndex(m => m.id === markId);
        if (markIndex === -1) return res.status(404).json({ message: 'Mark not found' });

        folder.marks[markIndex] = {
            ...folder.marks[markIndex],
            subject: subject || folder.marks[markIndex].subject,
            marksObtained: isNaN(parseFloat(marksObtained)) ? folder.marks[markIndex].marksObtained : parseFloat(marksObtained),
            totalMarks: isNaN(parseFloat(totalMarks)) ? folder.marks[markIndex].totalMarks : parseFloat(totalMarks),
            date: date || folder.marks[markIndex].date,
            updatedAt: new Date().toISOString()
        };

        await user.save();
        res.status(200).json({ message: 'Marks updated successfully', mark: folder.marks[markIndex] });
    } catch (err) {
        console.error('Error updating marks:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.delete('/api/folders/:folderId/marks/:markId', authenticateToken, async (req, res) => {
    try {
        const { folderId, markId } = req.params;

        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        const folder = findFolderRecursively(user.folders, folderId);
        if (!folder) return res.status(404).json({ message: 'Folder not found' });

        folder.marks = folder.marks || [];
        const idx = folder.marks.findIndex(m => m.id === markId);
        if (idx === -1) return res.status(404).json({ message: 'Mark not found' });

        folder.marks.splice(idx, 1);
        await user.save();
        res.status(200).json({ message: 'Marks deleted successfully' });
    } catch (err) {
        console.error('Error deleting marks:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// --- IMPORT/EXPORT ENDPOINTS ---
app.get('/api/export-data', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) return res.status(404).send({ message: 'User not found' });

        const exportData = {
            username: user.username,
            folders: user.folders,
            exportedAt: new Date().toISOString()
        };

        res.setHeader('Content-Disposition', 'attachment; filename=marks-explorer-data.json');
        res.setHeader('Content-Type', 'application/json');
        res.status(200).send(exportData);
    } catch (err) {
        console.error('Error exporting data:', err);
        res.status(500).send({ message: 'Failed to export data' });
    }
});

app.post('/api/import-data', authenticateToken, async (req, res) => {
    try {
        const { folders } = req.body;
        if (!Array.isArray(folders)) return res.status(400).send({ message: 'Invalid payload: folders must be an array' });

        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).send({ message: 'User not found' });

        user.folders = folders;
        await user.save();

        res.status(200).send({ message: 'Data imported successfully', folders: user.folders });
    } catch (err) {
        console.error('Error importing data:', err);
        res.status(500).send({ message: 'Failed to import data' });
    }
});

// --- USER PROFILE & ACCOUNT MANAGEMENT ---
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) return res.status(404).send({ message: 'User not found' });

        res.status(200).send({ username: user.username, createdAt: user.createdAt });
    } catch (err) {
        console.error('Error fetching profile:', err);
        res.status(500).send({ message: 'Failed to fetch profile' });
    }
});

app.put('/api/user/username', authenticateToken, async (req, res) => {
    try {
        const { username } = req.body;
        if (!username || !username.trim()) return res.status(400).send({ message: 'Username is required' });

        const already = await User.findOne({ username });
        if (already) return res.status(400).send({ message: 'Username already exists' });

        const user = await User.findByIdAndUpdate(req.user.userId, { username: username.trim() }, { new: true }).select('-password');
        if (!user) return res.status(404).send({ message: 'User not found' });

        res.status(200).send({ message: 'Username updated successfully', username: user.username });
    } catch (err) {
        console.error('Error updating username:', err);
        res.status(500).send({ message: 'Failed to update username' });
    }
});

app.put('/api/user/password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) return res.status(400).send({ message: 'Current and new password are required' });

        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).send({ message: 'User not found' });

        const match = await bcrypt.compare(currentPassword, user.password);
        if (!match) return res.status(401).send({ message: 'Current password is incorrect' });

        const hashed = await bcrypt.hash(newPassword, 10);
        user.password = hashed;
        await user.save();

        res.status(200).send({ message: 'Password updated successfully' });
    } catch (err) {
        console.error('Error updating password:', err);
        res.status(500).send({ message: 'Failed to update password' });
    }
});

app.delete('/api/user', authenticateToken, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.user.userId);
        if (!user) return res.status(404).send({ message: 'User not found' });
        res.status(200).send({ message: 'Account deleted successfully' });
    } catch (err) {
        console.error('Error deleting account:', err);
        res.status(500).send({ message: 'Failed to delete account' });
    }
});

// Clear all data for a user (folders)
app.delete('/api/clear-data', authenticateToken, async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.user.userId, { folders: [] }, { new: true });
        if (!user) return res.status(404).send({ message: 'User not found' });
        res.status(200).send({ message: 'All data cleared successfully' });
    } catch (err) {
        console.error('Error clearing data:', err);
        res.status(500).send({ message: 'Failed to clear data' });
    }
});

// --- CATCH-ALL (serve index.html for client-side routing) ---
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(port, () => console.log(`Server listening at port ${port}`));
