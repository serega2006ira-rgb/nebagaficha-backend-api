// server.js

const express = require('express');
const session = require('express-session');
const cors = require('cors');
const mongoose = require('mongoose');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy; 
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

// VERCEL_VERSION_LOGGER_START: Принудительный коммит для чистой сборки
function logAppVersion() {
    console.log("App Version: 1.2.6 - Final Stable Release");
}
logAppVersion();
// VERCEL_VERSION_LOGGER_END

// Загрузка переменных окружения (для локального запуска)
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5001;
const FRONTEND_URL = process.env.FRONTEND_URL;
const MONGODB_URI = process.env.MONGODB_URI;

// --- 1. ПОДКЛЮЧЕНИЕ К MONGODB ---

mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ MongoDB успешно подключен'))
    .catch(err => {
        console.error('❌ Ошибка подключения к MongoDB:', err);
        // При сбое подключения сервер должен упасть, чтобы Vercel показал ошибку
        process.exit(1); 
    });


// --- 2. МОДЕЛЬ ПОЛЬЗОВАТЕЛЯ (Mongoose Schema) ---

const userSchema = new mongoose.Schema({
    githubId: { type: String, unique: true, sparse: true },
    googleId: { type: String, unique: true, sparse: true }, 
    username: String, 
    displayName: String,
    avatarUrl: String,
    bio: String,
});

const User = mongoose.model('User', userSchema);


// --- 3. PASSPORT СТРАТЕГИИ И СЕРИАЛИЗАЦИЯ ---

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// GitHub Strategy
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: `${process.env.BACKEND_URL}/api/auth/github/callback`
},
async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ githubId: profile.id });
        if (!user) {
            user = new User({
                githubId: profile.id,
                username: profile.username,
                displayName: profile.displayName || profile.username,
                avatarUrl: profile.photos && profile.photos.length > 0 ? profile.photos[0].value : null,
                bio: profile._json.bio || 'Без описания',
            });
            await user.save();
        }
        done(null, user);
    } catch (err) {
        done(err, null);
    }
}));


// Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.BACKEND_URL}/api/auth/google/callback`
},
async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
            user = new User({
                googleId: profile.id,
                username: profile.displayName, 
                displayName: profile.displayName,
                avatarUrl: profile.photos && profile.photos.length > 0 ? profile.photos[0].value : null,
            });
            await user.save();
        }
        done(null, user);
    } catch (err) {
        done(err, null);
    }
}));


// --- 4. MIDDLEWARE ---

app.use(cors({
    origin: FRONTEND_URL, 
    credentials: true,
}));

app.use(express.json());

app.use(session({
    secret: process.env.JWT_SECRET, 
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } 
}));

app.use(passport.initialize());
app.use(passport.session());


// Утилита для проверки JWT (Middleware)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authorization header missing or invalid' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        // Сохраняем ID пользователя в запросе для дальнейшего использования
        req.userId = decoded.id; 
        req.username = decoded.username;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};


// --- 5. ROUTES ---

// Главный маршрут для проверки живости
app.get('/', (req, res) => {
    res.send(`Backend API is running. MONGODB_URI: ${!!MONGODB_URI ? 'SET' : 'NOT SET'}`);
});

// GitHub Auth Routes
app.get('/api/auth/github',
    passport.authenticate('github', { scope: ['user:email'] })
);

app.get('/api/auth/github/callback',
    passport.authenticate('github', { failureRedirect: FRONTEND_URL }),
    (req, res) => {
        const token = jwt.sign(
            { id: req.user.id, username: req.user.username }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );
        res.redirect(`${FRONTEND_URL}?token=${token}`);
    }
);

// Google Auth Routes
app.get('/api/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] }) 
);

app.get('/api/auth/google/callback',
    passport.authenticate('google', { failureRedirect: FRONTEND_URL }),
    (req, res) => {
        const token = jwt.sign(
            { id: req.user.id, username: req.user.username }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );
        res.redirect(`${FRONTEND_URL}?token=${token}`);
    }
);


// Защищенный маршрут (ТЕСТ: Проверка токена)
app.get('/api/protected/profile', authenticateToken, (req, res) => {
    res.json({
        secretData: "Access granted! JWT is valid.",
        user: { id: req.userId, username: req.username }
    });
});


// МАРШРУТ: Поиск пары
app.get('/api/find-match', authenticateToken, async (req, res) => {
    try {
        // Находим текущего пользователя (чтобы исключить его из поиска)
        const currentUser = await User.findById(req.userId);

        if (!currentUser) {
            return res.status(404).json({ error: 'Current user not found.' });
        }

        // Ищем первого попавшегося другого пользователя (простейшая логика)
        const potentialMatch = await User.findOne({
            _id: { $ne: req.userId } // Исключаем текущего пользователя
        });

        if (potentialMatch) {
            res.json({
                message: "Match found!",
                match: {
                    displayName: potentialMatch.displayName,
                    username: potentialMatch.username,
                    avatarUrl: potentialMatch.avatarUrl,
                    matchId: potentialMatch._id 
                }
            });
        } else {
            res.status(200).json({ message: "No other users available at the moment." });
        }

    } catch (error) {
        console.error("Error finding match:", error);
        res.status(500).json({ error: "Internal server error during match search." });
    }
});


// --- 6. START SERVER ---

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
