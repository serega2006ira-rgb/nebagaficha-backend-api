// setup_db.js

const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./dev.db'); // Подключается или создает файл dev.db

db.serialize(() => {
    // Создаем таблицу users, если она еще не существует
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            github_id TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) {
            console.error("❌ Ошибка при создании таблицы users:", err.message);
        } else {
            console.log("✅ Таблица 'users' создана или уже существует.");
        }
    });

    // Дополнительно: создадим таблицу для мэтчинга (например)
    db.run(`
        CREATE TABLE IF NOT EXISTS matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id1 INTEGER NOT NULL,
            user_id2 INTEGER NOT NULL,
            status TEXT NOT NULL, -- 'pending', 'match', 'reject'
            FOREIGN KEY (user_id1) REFERENCES users(id),
            FOREIGN KEY (user_id2) REFERENCES users(id)
        )
    `, (err) => {
        if (err) {
            console.error("❌ Ошибка при создании таблицы matches:", err.message);
        } else {
            console.log("✅ Таблица 'matches' создана или уже существует.");
        }
    });
});

db.close((err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('--- Инициализация базы данных завершена. ---');
});