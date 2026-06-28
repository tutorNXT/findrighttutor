const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const multer = require('multer');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const JWT_SECRET = 'TutorNxt_Secure_Crypto_Key_2026_Static';

// Secure Local Storage Engine for Profile Pictures
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/profiles/');
    },
    filename: (req, file, cb) => {
        // Enforce structural file containment mapping to authenticated roll number
        const uniqueSuffix = req.user ? req.user.rollNumber : Date.now();
        cb(null, `avatar_${uniqueSuffix}${path.extname(file.originalname)}`);
    }
});
const upload = multer({ 
    storage: storage,
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        if (extname) return cb(null, true);
        cb(new Error('Security Alert: Only image files (jpg/png) are permitted!'));
    }
});

// Mock Database Representation incorporating TutorNxt Core Datasets
let mockStudentsDatabase = [
    {
        rollNumber: "TNXT202601",
        passwordHash: "$2b$10$K7Z26eZpWlX.SBy8YUp/6eeT9bYfX5U9PaeD8nCgXbY9LzH3b5mK2", // Hashed version of: "password123"
        fullName: "Chanda Biswakarma",
        admissionDate: "March 24, 2026",
        assignedTeacher: "Mr. Amrit Kumar (Physics Specialist)",
        feeStatus: "Paid",
        nextDueDate: "N/A",
        profilePictureUrl: ""
    }
];

// Authentication Middleware to isolate and guard user sessions
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: "Access Denied: Session token token missing." });

    jwt.verify(token, JWT_SECRET, (err, decodedStudent) => {
        if (err) return res.status(403).json({ error: "Forbidden: Session verification failed or expired." });
        req.user = decodedStudent;
        next();
    });
}

// 🔐 Secure Login Endpoint
app.post('/api/auth/login', async (req, res) => {
    const { rollNumber, password } = req.body;
    const student = mockStudentsDatabase.find(s => s.rollNumber === rollNumber);

    if (!student) {
        return res.status(400).json({ error: "Invalid roll number or secure login parameters." });
    }

    try {
        const credentialMatch = await bcrypt.compare(password, student.passwordHash);
        if (!credentialMatch) {
            return res.status(400).json({ error: "Invalid roll number or secure login parameters." });
        }

        // Issue Signed Token containment matrix
        const token = jwt.sign({ rollNumber: student.rollNumber }, JWT_SECRET, { expiresIn: '2h' });
        res.json({ success: true, token });
    } catch (e) {
        res.status(500).json({ error: "Internal Gateway Encryption error occurs." });
    }
});

// 📊 Secure Profile Retreival Endpoint
app.get('/api/student/profile', authenticateToken, (req, res) => {
    const studentData = mockStudentsDatabase.find(s => s.rollNumber === req.user.rollNumber);
    if (!studentData) return res.status(404).json({ error: "Student profile record not found." });
    
    // Explicitly exclude internal passwordHash before distribution over network lines
    const { passwordHash, ...safeProfileBundle } = studentData;
    res.json(safeProfileBundle);
});

// 🖼️ Secure Image Upload Endpoint
app.post('/api/student/upload-avatar', authenticateToken, upload.single('avatar'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No target file selected for upload pipelines." });

    const student = mockStudentsDatabase.find(s => s.rollNumber === req.user.rollNumber);
    const localFilePath = `http://localhost:5000/uploads/profiles/${req.file.filename}`;
    
    student.profilePictureUrl = localFilePath; // Mutate database record index reference link
    res.json({ success: true, url: localFilePath });
});

app.listen(5000, () => console.log('TutorNxt Secure Backend Server executing on port 5000'));