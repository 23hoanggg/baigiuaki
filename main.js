const mongoose = require('mongoose');
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = 3000;

mongoose.connect('mongodb://127.0.0.1:27017/fullstack').then(() => {
    console.log('Connect to DB');
});

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    dateOfBirth: String,
    placeOfBirth: String,
    nationality: String,
});

const User = mongoose.model('User', userSchema);

const profileSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    full_name: String,
    date_of_birth: String,
    place_of_birth: String,
    nationality: String,
});

const Profile = mongoose.model('Profile', profileSchema);

app.use(express.json());

//authen
const authenticateUser = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Unauthorized' });
        }
        req.userId = decoded.userId;
        next();
    });
};

//register
app.post('/user/register', async (req, res) => {
    try {
        const { username, password, dateOfBirth, placeOfBirth, nationality } = req.body;
        if (!username || !password || !dateOfBirth || !placeOfBirth || !nationality) {
            throw Error('All fields are required');
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).send('Username already exists');
        }

        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            username,
            password: hashPassword,
            dateOfBirth,
            placeOfBirth,
            nationality,
        });
        await newUser.save();
        const newProfile = new Profile({
            user_id: newUser._id,
            full_name: username, 
            date_of_birth: dateOfBirth,
            place_of_birth: placeOfBirth,
            nationality,
        });
        await newProfile.save();
        return res.status(200).send('Register success!');
    } catch (error) {
        console.error(error);
        res.status(400).send(error.message);
    }
});

//login
app.post('/user/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username) throw Error('Username is required');
        if (!password) throw Error('Password is required');

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).send('Username or password not correct');
        }

        const result = await bcrypt.compare(password, user.password);
        if (!result) {
            return res.status(400).send('Username or password not correct');
        }

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        return res.status(200).send(token)
    } catch (error) {
        console.error(error);
        res.status(400).send(error.message);
    }
});

// Get user profile
app.get('/user/profile', authenticateUser, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const profile = await Profile.findOne({ user_id: req.userId });
        if (!profile) {
            return res.status(404).json({ message: 'Profile not found' });
        }

        return res.status(200).json({ user, profile });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

app.put('/user/profile', authenticateUser, async (req, res) => {
    try {
        const existingProfile = await Profile.findOne({ user_id: req.userId });
        if (!existingProfile) {
            return res.status(404).json({ message: 'Profile not found' });
        }

        if (req.userId.toString() !== existingProfile.user_id.toString()) {
            return res.status(403).json({ message: 'Unauthorized - You do not have permission to access this profile' });
        }

        const updatedUser = await User.findByIdAndUpdate(req.userId, req.body, { new: true });
        await Profile.findOneAndUpdate(
            { user_id: req.userId },
            req.body,
            { new: true }
        );

        return res.status(200).json(updatedUser);
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// Delete user profile
app.delete('/user/profile', authenticateUser, async (req, res) => {
    try {
        const deletedUser = await User.findOneAndDelete({ _id: req.userId });
        if (!deletedUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        await Profile.findOneAndDelete({ user_id: req.userId });

        return res.status(204).send();
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
