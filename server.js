// server.js

const express = require('express');
const session = require('express-session');
const cors = require('cors');
const mongoose = require('mongoose'); // Mongoose для MongoDB
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

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
        // ВАЖНО: При сбое подключения сервер должен упасть, чтобы Vercel показал ошибку
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
    // Можете добавить другие поля
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
    // ИСПРАВЛЕНИЕ: Мы убираем начальный слеш из строки, чтобы не было двойного слеша, 
    // если BACKEND_URL содержит конечный слеш. 
    // Мы уверены, что '/api/...' начнется сразу после URL.
    callbackURL: `${process.env.BACKEND_URL}/api/auth/github/callback`
},
async (accessToken, refreshToken, profile, done) => {
    try {
        // Логика "upsert": найти или создать пользователя
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


// --- 4. MIDDLEWARE ---

// CORS для разрешения запросов с фронтенда
app.use(cors({
    origin: FRONTEND_URL, 
    credentials: true,
}));

app.use(express.json());

// Session Middleware (Passport требует сессию)
app.use(session({
    secret: process.env.JWT_SECRET, // Используем JWT_SECRET как секрет сессии
    resave: false,
    saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());


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
        // Генерируем JWT после успешного входа
        const token = jwt.sign(
            { id: req.user.id, username: req.user.username }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );
        // Перенаправляем на фронтенд с токеном в URL
        res.redirect(`${FRONTEND_URL}?token=${token}`);
    }
);

// Маршрут для Google (если настроен)
app.get('/api/auth/google', (req, res) => {
    // ВАШ КОД Google Auth
    res.status(501).send('Google Auth not implemented yet.');
});


// Защищенный маршрут (проверка JWT)
app.get('/api/protected/profile', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authorization header missing or invalid' });
    }

    const token = authHeader.split(' ')[1];

    try {
        // Проверяем и декодируем токен
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // В реальном приложении здесь был бы поиск пользователя по decoded.id
        res.json({
            secretData: "Access granted! JWT is valid.",
            user: { id: decoded.id, username: decoded.username }
        });
    } catch (err) {
        // Если токен не прошел верификацию
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
});


// --- 6. START SERVER ---

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});