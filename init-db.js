require("dotenv").config();

const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");

// Проверяем, существует ли файл БД
const dbPath = path.join(__dirname, "database.sqlite");
const dbExists = fs.existsSync(dbPath);

if (dbExists) {
  console.log(
    "База данных уже существует. Удалите файл database.sqlite для пересоздания.",
  );
  process.exit(1);
}

// Создаем новую БД
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  // Таблица пользователей
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT,
      is_active BOOLEAN DEFAULT 1,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Индексы для быстрого поиска
  db.run("CREATE INDEX idx_users_email ON users(email)");
  db.run("CREATE INDEX idx_users_username ON users(username)");

  // Триггер для обновления updated_at
  db.run(`
    CREATE TRIGGER update_users_timestamp
    AFTER UPDATE ON users
    FOR EACH ROW
    BEGIN
      UPDATE users SET updated_at = CURRENT_TIMESTAMP
      WHERE id = OLD.id;
    END
  `);

  // Создаем тестового администратора
  const bcrypt = require("bcrypt");
  const saltRounds = 10;
  const adminPassword = process.env.ADMIN_PASSWORD || null;

  if (!adminPassword) {
    console.error(
      "Пароль администратора не указан. Укажите переменную окружения ADMIN_PASSWORD.",
    );
    db.close();
    return;
  }

  bcrypt.hash(adminPassword, saltRounds, (err, hash) => {
    if (err) {
      console.error("Ошибка при хешировании пароля:", err);
      db.close();
      return;
    }

    db.run(
      `INSERT INTO users (email, username, password_hash, full_name, role)
       VALUES (?, ?, ?, ?, ?)`,
      ["admin@example.com", "admin", hash, "Администратор", "admin"],
      function (err) {
        if (err) {
          console.error("Ошибка при создании администратора:", err);
        } else {
          console.log("Администратор создан.");
        }
        db.close();
      },
    );
  });
});

console.log("База данных успешно создана!");
