const fastify = require("fastify")({ logger: true });
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const path = require("path");

// Плагины Fastify
fastify.register(require("@fastify/cors"), {
  origin: true,
  credentials: true,
});

fastify.register(require("@fastify/jwt"), {
  secret:
    process.env.JWT_SECRET || "ваш-супер-секретный-ключ-минимум-32-символа",
  sign: {
    expiresIn: "24h",
  },
});

// Подключение к базе данных
const db = new sqlite3.Database(
  path.join(__dirname, "database.sqlite"),
  sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE,
  (err) => {
    if (err) {
      console.error("Ошибка подключения к БД:", err);
      process.exit(1);
    }
    console.log("Подключено к SQLite базе данных");
  },
);

// Хелперы для работы с БД
const dbAll = (query, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(query, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

const dbRun = (query, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(query, params, function (err) {
      if (err) reject(err);
      else resolve({ id: this.lastID, changes: this.changes });
    });
  });
};

const dbGet = (query, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(query, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

// Декораторы для проверки аутентификации
fastify.decorate("authenticate", async function (request, reply) {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.code(401).send({ error: "Неавторизованный доступ" });
  }
});

fastify.decorate("requireAdmin", async function (request, reply) {
  try {
    await request.jwtVerify();
    if (request.user.role !== "admin") {
      reply.code(403).send({ error: "Требуются права администратора" });
    }
  } catch (err) {
    reply.code(401).send({ error: "Неавторизованный доступ" });
  }
});

// Регистрация Swagger
fastify.register(require("@fastify/swagger"), {
  openapi: {
    info: {
      title: "Hobby Project API",
      description: "API для хобби проекта",
      version: "1.0.0",
    },
    servers: [
      {
        url: "http://localhost:3000",
        description: "Локальный сервер",
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
    },
  },
});

fastify.register(require("@fastify/swagger-ui"), {
  routePrefix: "/docs",
  uiConfig: {
    docExpansion: "list",
    deepLinking: false,
  },
});

// Плагин с маршрутами
async function routes(fastify, options) {
  // 1. Авторизация
  fastify.post(
    "/api/auth/login",
    {
      schema: {
        tags: ["Auth"],
        summary: "Авторизация пользователя",
        description: "Получение JWT токена для доступа к API",
        body: {
          type: "object",
          required: ["username", "password"],
          properties: {
            username: { type: "string" },
            password: { type: "string" },
          },
        },
        response: {
          200: {
            description: "Успешная авторизация",
            type: "object",
            properties: {
              token: { type: "string" },
              user: {
                type: "object",
                properties: {
                  id: { type: "number" },
                  username: { type: "string" },
                  email: { type: "string" },
                  role: { type: "string" },
                },
              },
            },
          },
          401: {
            description: "Неверные учетные данные",
            type: "object",
            properties: {
              error: { type: "string" },
            },
          },
        },
      },
    },
    async (request, reply) => {
      const { username, password } = request.body;

      try {
        const user = await dbGet(
          "SELECT id, email, username, password_hash, role FROM users WHERE username = ? AND is_active = 1",
          [username],
        );

        if (!user) {
          return reply.code(401).send({ error: "Неверные учетные данные" });
        }

        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
          return reply.code(401).send({ error: "Неверные учетные данные" });
        }

        const token = fastify.jwt.sign({
          id: user.id,
          username: user.username,
          role: user.role,
        });

        delete user.password_hash;

        return { token, user };
      } catch (error) {
        fastify.log.error(error);
        reply.code(500).send({ error: "Ошибка сервера" });
      }
    },
  );

  // 2. Создание пользователя (только для администратора)
  fastify.post(
    "/api/users",
    {
      schema: {
        tags: ["Users"],
        summary: "Создание нового пользователя",
        description: "Требуются права администратора",
        security: [{ bearerAuth: [] }],
        body: {
          type: "object",
          required: ["email", "username", "password"],
          properties: {
            email: { type: "string", format: "email" },
            username: { type: "string" },
            password: { type: "string", minLength: 6 },
            full_name: { type: "string" },
            role: { type: "string", enum: ["user", "admin"], default: "user" },
          },
        },
        response: {
          201: {
            description: "Пользователь успешно создан",
            type: "object",
            properties: {
              id: { type: "number" },
              email: { type: "string" },
              username: { type: "string" },
              full_name: { type: "string" },
              role: { type: "string" },
              created_at: { type: "string" },
            },
          },
        },
      },
      preHandler: fastify.requireAdmin,
    },
    async (request, reply) => {
      const {
        email,
        username,
        password,
        full_name,
        role = "user",
      } = request.body;

      try {
        const existingUser = await dbGet(
          "SELECT id FROM users WHERE email = ? OR username = ?",
          [email, username],
        );

        if (existingUser) {
          return reply.code(409).send({
            error: "Пользователь с таким email или username уже существует",
          });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const result = await dbRun(
          `INSERT INTO users (email, username, password_hash, full_name, role)
         VALUES (?, ?, ?, ?, ?)`,
          [email, username, passwordHash, full_name, role],
        );

        const newUser = await dbGet(
          "SELECT id, email, username, full_name, role, created_at FROM users WHERE id = ?",
          [result.id],
        );

        return reply.code(201).send(newUser);
      } catch (error) {
        fastify.log.error(error);
        reply.code(500).send({ error: "Ошибка при создании пользователя" });
      }
    },
  );

  // 3. Получение списка пользователей
  fastify.get(
    "/api/users",
    {
      schema: {
        tags: ["Users"],
        summary: "Получение списка пользователей",
        description: "Требуется авторизация",
        security: [{ bearerAuth: [] }],
        response: {
          200: {
            description: "Список пользователей",
            type: "array",
            items: {
              type: "object",
              properties: {
                id: { type: "number" },
                email: { type: "string" },
                username: { type: "string" },
                full_name: { type: "string" },
                role: { type: "string" },
                created_at: { type: "string" },
              },
            },
          },
        },
      },
      preHandler: fastify.authenticate,
    },
    async (request, reply) => {
      try {
        const users = await dbAll(
          "SELECT id, email, username, full_name, role, created_at FROM users WHERE is_active = 1",
        );
        return users;
      } catch (error) {
        fastify.log.error(error);
        reply.code(500).send({ error: "Ошибка при получении пользователей" });
      }
    },
  );

  // 4. Обновление пользователя
  fastify.put(
    "/api/users/:id",
    {
      schema: {
        tags: ["Users"],
        summary: "Обновление пользователя",
        description:
          "Пользователь может обновлять только свои данные, администратор - любые",
        security: [{ bearerAuth: [] }],
        params: {
          type: "object",
          required: ["id"],
          properties: {
            id: { type: "number" },
          },
        },
        body: {
          type: "object",
          properties: {
            email: { type: "string", format: "email" },
            username: { type: "string" },
            full_name: { type: "string" },
            password: { type: "string", minLength: 6 },
          },
        },
      },
      preHandler: fastify.authenticate,
    },
    async (request, reply) => {
      const { id } = request.params;
      const updates = request.body;
      const userId = request.user.id;
      const userRole = request.user.role;

      if (userId !== parseInt(id) && userRole !== "admin") {
        return reply
          .code(403)
          .send({ error: "Нет прав для редактирования этого пользователя" });
      }

      try {
        const user = await dbGet(
          "SELECT * FROM users WHERE id = ? AND is_active = 1",
          [id],
        );
        if (!user) {
          return reply.code(404).send({ error: "Пользователь не найден" });
        }

        if (updates.password) {
          updates.password_hash = await bcrypt.hash(updates.password, 10);
          delete updates.password;
        }

        const updateFields = [];
        const updateValues = [];

        Object.keys(updates).forEach((key) => {
          if (key !== "id" && user[key] !== updates[key]) {
            updateFields.push(`${key} = ?`);
            updateValues.push(updates[key]);
          }
        });

        if (updateFields.length === 0) {
          return reply.code(400).send({ error: "Нет данных для обновления" });
        }

        updateValues.push(id);

        await dbRun(
          `UPDATE users SET ${updateFields.join(", ")} WHERE id = ?`,
          updateValues,
        );

        const updatedUser = await dbGet(
          "SELECT id, email, username, full_name, role, created_at FROM users WHERE id = ?",
          [id],
        );

        return updatedUser;
      } catch (error) {
        fastify.log.error(error);
        reply.code(500).send({ error: "Ошибка при обновлении пользователя" });
      }
    },
  );

  // 5. Удаление пользователя (мягкое удаление)
  fastify.delete(
    "/api/users/:id",
    {
      schema: {
        tags: ["Users"],
        summary: "Удаление пользователя",
        description: "Требуются права администратора",
        security: [{ bearerAuth: [] }],
        params: {
          type: "object",
          required: ["id"],
          properties: {
            id: { type: "number" },
          },
        },
      },
      preHandler: fastify.requireAdmin,
    },
    async (request, reply) => {
      const { id } = request.params;

      try {
        const result = await dbRun(
          "UPDATE users SET is_active = 0 WHERE id = ?",
          [id],
        );

        if (result.changes === 0) {
          return reply.code(404).send({ error: "Пользователь не найден" });
        }

        return { message: "Пользователь успешно удален" };
      } catch (error) {
        fastify.log.error(error);
        reply.code(500).send({ error: "Ошибка при удалении пользователя" });
      }
    },
  );

  // 6. Получение текущего пользователя
  fastify.get(
    "/api/me",
    {
      schema: {
        tags: ["Users"],
        summary: "Получение информации о текущем пользователе",
        security: [{ bearerAuth: [] }],
      },
      preHandler: fastify.authenticate,
    },
    async (request, reply) => {
      try {
        const user = await dbGet(
          "SELECT id, email, username, full_name, role, created_at FROM users WHERE id = ? AND is_active = 1",
          [request.user.id],
        );

        if (!user) {
          return reply.code(404).send({ error: "Пользователь не найден" });
        }

        return user;
      } catch (error) {
        fastify.log.error(error);
        reply.code(500).send({ error: "Ошибка сервера" });
      }
    },
  );

  // 7. Пример защищенного эндпоинта
  fastify.get(
    "/api/protected",
    {
      schema: {
        tags: ["Example"],
        summary: "Пример защищенного эндпоинта",
        description: "Требуется авторизация",
        security: [{ bearerAuth: [] }],
        response: {
          200: {
            description: "Успешный доступ",
            type: "object",
            properties: {
              message: { type: "string" },
              user: {
                type: "object",
                properties: {
                  id: { type: "number" },
                  username: { type: "string" },
                  role: { type: "string" },
                },
              },
            },
          },
        },
      },
      preHandler: fastify.authenticate,
    },
    async (request, reply) => {
      return {
        message: "Вы успешно получили доступ к защищенному ресурсу!",
        user: request.user,
      };
    },
  );

  // 8. Пример незащищенного эндпоинта
  fastify.get(
    "/api/public",
    {
      schema: {
        tags: ["Example"],
        summary: "Пример незащищенного эндпоинта",
        description: "Доступен без авторизации",
        response: {
          200: {
            description: "Публичный доступ",
            type: "object",
            properties: {
              message: { type: "string" },
              timestamp: { type: "string" },
              status: { type: "string" },
            },
          },
        },
      },
    },
    async (request, reply) => {
      return {
        message: "Это публичный эндпоинт, доступный без авторизации",
        timestamp: new Date().toISOString(),
        status: "OK",
      };
    },
  );
}

// Регистрируем плагин с маршрутами
fastify.register(routes);

// Запуск сервера
const start = async () => {
  try {
    // Инициализация Swagger
    await fastify.ready();

    await fastify.listen({ port: 3000, host: "0.0.0.0" });
    console.log("Сервер запущен на http://localhost:3000");
    console.log("Документация API доступна на http://localhost:3000/docs");
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();

// Закрытие соединения с БД при завершении работы
process.on("SIGINT", () => {
  db.close((err) => {
    if (err) {
      console.error("Ошибка при закрытии БД:", err);
    }
    process.exit(0);
  });
});
