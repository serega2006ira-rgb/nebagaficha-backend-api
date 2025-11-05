// server.js

const portfinder = require('portfinder');
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const GitHubStrategy = require('passport-github2').Strategy;

// --- КОНСТАНТЫ ИЗ .ENV ---
// Домены из вашего .env
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000'; 
const BACKEND_CALLBACK_URL = process.env.BACKEND_CALLBACK_URL || 'http://localhost:5001/api/auth/github/callback'; 
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 5001; // Используем порт 5001

if (!JWT_SECRET) {
    console.error("FATAL ERROR: JWT_SECRET не определен! Аутентификация невозможна.");
    // Принудительно завершаем процесс, если нет ключа
    process.exit(1);
}

const app = express();


// =======================================================
// 1. БАЗА ДАННЫХ И MIDDLEWARE
// =======================================================

// База данных SQLite 
const db = new sqlite3.Database('./dev.db'); 

// Middleware
app.use(express.json());

// --- НАСТРОЙКА CORS ---
// Разрешаем запросы с фронтенда Vercel и локальных хостов
app.use(cors({ 
    origin: [FRONTEND_URL, 'http://localhost:3000', 'http://localhost:5001'], 
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true 
}));

app.use(passport.initialize());


// =======================================================
// 2. СТРАТЕГИЯ GITHUB
// =======================================================

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    // Используем переменную окружения
    callbackURL: BACKEND_CALLBACK_URL 
}, (accessToken, refreshToken, profile, done) => {
    // --------------------------------------------------------------------------------
    // ЛОГИКА СОХРАНЕНИЯ/ПОИСКА ПОЛЬЗОВАТЕЛЯ В SQLite
    // --------------------------------------------------------------------------------
    db.get('SELECT * FROM users WHERE github_id = ?', [profile.id], (err, user) => {
        if (err) return done(err);
        if (user) {
            return done(null, user); 
        } else {
            // Если пользователь не найден, создаем нового
            const newUser = { 
                github_id: profile.id, 
                username: profile.username 
            };
            // ВАЖНО: убедитесь, что в DB есть таблица users с полями github_id и username
            db.run('INSERT INTO users (github_id, username) VALUES (?, ?)', 
                   [newUser.github_id, newUser.username], function(err) {
                if (err) return done(err);
                // После вставки возвращаем нового пользователя
                return done(null, newUser); 
            });
        }
    });
}));

// Сериализация/Десериализация (Обязательно для Passport.js)
passport.serializeUser((user, done) => { done(null, user.id); });
passport.deserializeUser((id, done) => { 
    db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
        done(err, user);
    });
});


// =======================================================
// 3. MIDDLEWARE ДЛЯ ВЕРИФИКАЦИИ JWT 
// =======================================================
const authenticateToken = (req, res, next) => {
    // 1. Получаем токен из заголовка Authorization: Bearer <token>
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ error: 'Требуется JWT (401)' });

    // 2. Верификация
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Токен недействителен или просрочен (403)' });
        
        // 3. Прикрепляем payload токена к запросу
        req.user = user;
        next(); 
    });
};


// =======================================================
// 4. РОУТЫ
// =======================================================

// Публичный роут
app.get('/', (req, res) => {
    res.send('Backend API is running.');
});

// 1. Начало авторизации GitHub
app.get('/api/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

// 2. Колбэк от GitHub
app.get('/api/auth/github/callback',
  // Если авторизация Passport не удалась, перенаправляем на фронтенд с ошибкой
  passport.authenticate('github', { failureRedirect: `${FRONTEND_URL}/?error=auth_failed` }), 
  (req, res) => {
    const user = req.user;
    // Генерируем токен, используя данные пользователя (из DB)
    const token = jwt.sign({ id: user.id, username: user.username, provider: 'github' }, JWT_SECRET, { expiresIn: '1h' });
    
    // Перенаправляем на домен Vercel с токеном
    res.redirect(`${FRONTEND_URL}/?token=${token}`);
  }
);

// 3. Защищенный маршрут (Проверяет JWT от фронтенда)
// Здесь применяется наш новый Middleware
app.get('/api/protected/profile', authenticateToken, (req, res) => {
    res.json({
        message: 'Добро пожаловать в защищенную зону!',
        user: req.user, // Данные, извлеченные из JWT
        secretData: 'Верификация JWT прошла успешно!'
    });
});


// =======================================================
// 5. ЗАПУСК СЕРВЕРА
// =======================================================

// Используем portfinder для надежного запуска
portfinder.getPort({ port: PORT }, (err, availablePort) => {
  if (err) {
    console.error("Не удалось найти доступный порт:", err);
    return;
  }
  app.listen(availablePort, () => console.log(`🚀 Сервер запущен на http://localhost:${availablePort}`));
});