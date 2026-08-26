const express = require("express");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");

const app = express();

app.set("trust proxy", 1);

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing.");
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error("JWT_SECRET is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api", apiLimiter);
app.use("/api/login", authLimiter);
app.use("/api/register", authLimiter);

const CURRENCIES = [
  "NGN",
  "USD",
  "EUR",
  "GBP",
  "IDR",
  "CAD",
  "AUD"
];

const CURRENCY_INFO = {
  NGN: { symbol: "₦", decimals: 2 },
  USD: { symbol: "$", decimals: 2 },
  EUR: { symbol: "€", decimals: 2 },
  GBP: { symbol: "£", decimals: 2 },
  IDR: { symbol: "Rp", decimals: 0 },
  CAD: { symbol: "CA$", decimals: 2 },
  AUD: { symbol: "A$", decimals: 2 }
};


/* =========================================================
   DATABASE
   ========================================================= */

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      primary_currency VARCHAR(3) NOT NULL DEFAULT 'NGN',
      profile_image TEXT DEFAULT '',
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      status TEXT NOT NULL DEFAULT 'Active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  for (const currency of CURRENCIES) {
    await pool.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS balance_${currency.toLowerCase()}
      NUMERIC(30,2) NOT NULL DEFAULT 0;
    `);
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      kind TEXT NOT NULL CHECK (kind IN ('credit','debit')),
      title TEXT NOT NULL,
      amount NUMERIC(30,2) NOT NULL,
      currency VARCHAR(3) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS support_messages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      sender TEXT NOT NULL CHECK (sender IN ('customer','admin')),
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_requests (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      request_type TEXT NOT NULL,
      message TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'new',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log("Database initialized.");
}


/* =========================================================
   HELPERS
   ========================================================= */

function makeToken(user) {
  return jwt.sign(
    {
      id: user.id,
      isAdmin: user.is_admin
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function getBalanceColumn(currency) {
  if (!CURRENCIES.includes(currency)) {
    return null;
  }

  return `balance_${currency.toLowerCase()}`;
}

function formatDate(date) {
  return new Date(date).toLocaleString();
}

function publicUser(row) {
  const balances = {};

  for (const currency of CURRENCIES) {
    balances[currency] =
      Number(row[`balance_${currency.toLowerCase()}`] || 0);
  }

  return {
    id: String(row.id),
    name: row.name,
    email: row.email,
    status: row.status,
    primaryCurrency: row.primary_currency,
    balances,
    profileImage: row.profile_image || "",
    isAdmin: Boolean(row.is_admin),
    createdAt: formatDate(row.created_at)
  };
}

function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication required."
      });
    }

    const token = header.substring(7);

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    req.user = decoded;

    next();

  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired session."
    });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({
      error: "Administrator access required."
    });
  }

  next();
}

async function getUserById(id) {
  const result = await pool.query(
    `SELECT * FROM users WHERE id = $1`,
    [id]
  );

  return result.rows[0] || null;
}


/* =========================================================
   HEALTH CHECK
   ========================================================= */

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      application: "American Crest Banking",
      mode: "fictional-demo"
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      ok: false
    });
  }
});


/* =========================================================
   REGISTER
   ========================================================= */

app.post("/api/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      primaryCurrency
    } = req.body;

    const cleanName = String(name || "").trim();
    const cleanEmail =
      String(email || "").trim().toLowerCase();

    const currency =
      String(primaryCurrency || "NGN").toUpperCase();

    if (cleanName.length < 2) {
      return res.status(400).json({
        error: "Enter your full name."
      });
    }

    if (!cleanEmail.includes("@")) {
      return res.status(400).json({
        error: "Enter a valid email address."
      });
    }

    if (String(password || "").length < 4) {
      return res.status(400).json({
        error: "Password must contain at least 4 characters."
      });
    }

    if (!CURRENCIES.includes(currency)) {
      return res.status(400).json({
        error: "Invalid currency."
      });
    }

    const existing = await pool.query(
      `SELECT id FROM users WHERE email = $1`,
      [cleanEmail]
    );

    if (existing.rows.length) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const passwordHash =
      await bcrypt.hash(
        String(password),
        12
      );

    const result = await pool.query(
      `
      INSERT INTO users
      (
        name,
        email,
        password_hash,
        primary_currency
      )
      VALUES ($1,$2,$3,$4)
      RETURNING *
      `,
      [
        cleanName,
        cleanEmail,
        passwordHash,
        currency
      ]
    );

    const user = result.rows[0];

    /*
      Notify the administrator that a new customer
      registered.
    */

    await pool.query(
      `
      INSERT INTO admin_requests
      (
        user_id,
        request_type,
        message
      )
      VALUES ($1,$2,$3)
      `,
      [
        user.id,
        "new_customer",
        `New customer registered: ${cleanName} (${cleanEmail})`
      ]
    );

    /*
      Add a notification to the customer as well.
    */

    await pool.query(
      `
      INSERT INTO notifications
      (
        user_id,
        message
      )
      VALUES ($1,$2)
      `,
      [
        user.id,
        "Your fictional American Crest account has been created successfully."
      ]
    );

    const token = makeToken(user);

    res.status(201).json({
      token,
      user: publicUser(user)
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      error: "Unable to create account."
    });
  }
});


/* =========================================================
   LOGIN
   ========================================================= */

app.post("/api/login", async (req, res) => {
  try {
    const email =
      String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password =
      String(req.body.password || "");

    const result = await pool.query(
      `
      SELECT *
      FROM users
      WHERE email = $1
      `,
      [email]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    const valid =
      await bcrypt.compare(
        password,
        user.password_hash
      );

    if (!valid) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    const token = makeToken(user);

    res.json({
      token,
      user: publicUser(user)
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      error: "Unable to sign in."
    });
  }
});


/* =========================================================
   CURRENT ACCOUNT
   ========================================================= */

app.get(
  "/api/me",
  requireAuth,
  async (req, res) => {

    try {

      const user =
        await getUserById(req.user.id);

      if (!user) {
        return res.status(404).json({
          error: "Account not found."
        });
      }

      res.json({
        user: publicUser(user)
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to load account."
      });
    }
  }
);


/* =========================================================
   TRANSACTIONS
   ========================================================= */

app.get(
  "/api/transactions",
  requireAuth,
  async (req, res) => {

    try {

      const result = await pool.query(
        `
        SELECT
          id,
          kind,
          title,
          amount,
          currency,
          created_at
        FROM transactions
        WHERE user_id = $1
        ORDER BY created_at DESC
        `,
        [req.user.id]
      );

      res.json({
        transactions:
          result.rows.map(t => ({
            id: String(t.id),
            kind: t.kind,
            title: t.title,
            amount: Number(t.amount),
            currency: t.currency,
            date: formatDate(t.created_at)
          }))
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to load transactions."
      });
    }
  }
);


/* =========================================================
   CUSTOMER TRANSFER
   ========================================================= */

app.post(
  "/api/transfers",
  requireAuth,
  async (req, res) => {

    const client = await pool.connect();

    try {

      const currency =
        String(req.body.currency || "")
        .toUpperCase();

      const amount =
        Number(req.body.amount);

      const recipient =
        String(req.body.recipient || "")
        .trim();

      if (!CURRENCIES.includes(currency)) {
        return res.status(400).json({
          error: "Invalid currency."
        });
      }

      if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({
          error: "Enter a valid amount."
        });
      }

      if (recipient.length < 2) {
        return res.status(400).json({
          error: "Enter the recipient name."
        });
      }

      const column =
        getBalanceColumn(currency);

      await client.query("BEGIN");

      const userResult =
        await client.query(
          `
          SELECT *
          FROM users
          WHERE id = $1
          FOR UPDATE
          `,
          [req.user.id]
        );

      const user =
        userResult.rows[0];

      if (!user) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Account not found."
        });
      }

      const currentBalance =
        Number(user[column] || 0);

      if (amount > currentBalance) {

        await client.query("ROLLBACK");

        return res.status(400).json({
          error: "Insufficient balance."
        });
      }

      await client.query(
        `
        UPDATE users
        SET ${column} = ${column} - $1
        WHERE id = $2
        `,
        [
          amount,
          req.user.id
        ]
      );

      await client.query(
        `
        INSERT INTO transactions
        (
          user_id,
          kind,
          title,
          amount,
          currency
        )
        VALUES
        ($1,'debit',$2,$3,$4)
        `,
        [
          req.user.id,
          `Transfer to ${recipient}`,
          amount,
          currency
        ]
      );

      /*
        Create an administrator request so the admin
        can see that the customer submitted a transfer.
      */

      await client.query(
        `
        INSERT INTO admin_requests
        (
          user_id,
          request_type,
          message
        )
        VALUES
        ($1,$2,$3)
        `,
        [
          req.user.id,
          "transfer_request",
          `Customer requested a fictional transfer of ${amount} ${currency} to ${recipient}.`
        ]
      );

      /*
        Notify the customer.
      */

      await client.query(
        `
        INSERT INTO notifications
        (
          user_id,
          message
        )
        VALUES
        ($1,$2)
        `,
        [
          req.user.id,
          `Your fictional transfer of ${amount} ${currency} to ${recipient} was recorded as a debit.`
        ]
      );

      await client.query("COMMIT");

      res.json({
        success: true,
        message: "Transfer recorded.",
        amount,
        currency
      });

    } catch (error) {

      await client.query("ROLLBACK");

      console.error("TRANSFER ERROR:", error);

      res.status(500).json({
        error: "Unable to process transfer."
      });

    } finally {

      client.release();
    }
  }
);


/* =========================================================
   NOTIFICATIONS
   ========================================================= */

app.get(
  "/api/notifications",
  requireAuth,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            id,
            message,
            created_at
          FROM notifications
          WHERE user_id = $1
          ORDER BY created_at DESC
          LIMIT 50
          `,
          [req.user.id]
        );

      res.json({
        notifications:
          result.rows.map(n => ({
            id: String(n.id),
            message: n.message,
            date: formatDate(n.created_at)
          }))
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to load notifications."
      });
    }
  }
);


/* =========================================================
   SUPPORT — CUSTOMER SENDS MESSAGE
   ========================================================= */

app.post(
  "/api/support",
  requireAuth,
  async (req, res) => {

    try {

      const message =
        String(req.body.message || "")
        .trim();

      if (!message) {
        return res.status(400).json({
          error: "Write a message first."
        });
      }

      if (message.length > 2000) {
        return res.status(400).json({
          error: "Message is too long."
        });
      }

      const user =
        await getUserById(req.user.id);

      if (!user) {
        return res.status(404).json({
          error: "Account not found."
        });
      }

      await pool.query(
        `
        INSERT INTO support_messages
        (
          user_id,
          sender,
          message
        )
        VALUES
        ($1,'customer',$2)
        `,
        [
          req.user.id,
          message
        ]
      );

      /*
        IMPORTANT:
        Admin also receives a request/notification.
      */

      await pool.query(
        `
        INSERT INTO admin_requests
        (
          user_id,
          request_type,
          message
        )
        VALUES
        ($1,$2,$3)
        `,
        [
          req.user.id,
          "support_request",
          `New support message from ${user.name}: ${message}`
        ]
      );

      /*
        Customer gets confirmation notification.
      */

      await pool.query(
        `
        INSERT INTO notifications
        (
          user_id,
          message
        )
        VALUES
        ($1,$2)
        `,
        [
          req.user.id,
          "Your support request has been sent to the administrator."
        ]
      );

      res.json({
        success: true,
        message: "Support message sent."
      });

    } catch (error) {

      console.error("SUPPORT ERROR:", error);

      res.status(500).json({
        error: "Unable to send support message."
      });
    }
  }
);


/* =========================================================
   SUPPORT — CUSTOMER VIEW
   ========================================================= */

app.get(
  "/api/support",
  requireAuth,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            id,
            sender,
            message,
            created_at
          FROM support_messages
          WHERE user_id = $1
          ORDER BY created_at ASC
          `,
          [req.user.id]
        );

      res.json({
        messages:
          result.rows.map(m => ({
            id: String(m.id),
            sender: m.sender,
            message: m.message,
            date: formatDate(m.created_at)
          }))
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to load support messages."
      });
    }
  }
);


/* =========================================================
   PROFILE
   ========================================================= */

app.put(
  "/api/profile",
  requireAuth,
  async (req, res) => {

    try {

      const name =
        String(req.body.name || "")
        .trim();

      if (name.length < 2) {
        return res.status(400).json({
          error: "Enter a valid name."
        });
      }

      const result =
        await pool.query(
          `
          UPDATE users
          SET name = $1
          WHERE id = $2
          RETURNING *
          `,
          [
            name,
            req.user.id
          ]
        );

      res.json({
        user: publicUser(result.rows[0])
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to update profile."
      });
    }
  }
);


/* =========================================================
   PROFILE IMAGE
   ========================================================= */

app.put(
  "/api/profile-image",
  requireAuth,
  async (req, res) => {

    try {

      const image =
        String(req.body.image || "");

      if (
        image &&
        !image.startsWith("data:image/")
      ) {
        return res.status(400).json({
          error: "Invalid image."
        });
      }

      if (image.length > 3 * 1024 * 1024) {
        return res.status(400).json({
          error: "Image is too large."
        });
      }

      const result =
        await pool.query(
          `
          UPDATE users
          SET profile_image = $1
          WHERE id = $2
          RETURNING *
          `,
          [
            image,
            req.user.id
          ]
        );

      res.json({
        user: publicUser(result.rows[0])
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to update profile picture."
      });
    }
  }
);


/* =========================================================
   ADMIN — CUSTOMER LIST
   ========================================================= */

app.get(
  "/api/admin/customers",
  requireAuth,
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT *
          FROM users
          ORDER BY created_at DESC
          `
        );

      res.json({
        customers:
          result.rows.map(publicUser)
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to load customers."
      });
    }
  }
);


/* =========================================================
   ADMIN — CREDIT CUSTOMER
   ========================================================= */

app.post(
  "/api/admin/credit",
  requireAuth,
  requireAdmin,
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      const customerId =
        Number(req.body.customerId);

      const currency =
        String(req.body.currency || "")
        .toUpperCase();

      const amount =
        Number(req.body.amount);

      if (!Number.isInteger(customerId)) {
        return res.status(400).json({
          error: "Invalid customer."
        });
      }

      if (!CURRENCIES.includes(currency)) {
        return res.status(400).json({
          error: "Invalid currency."
        });
      }

      if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({
          error: "Enter a valid amount."
        });
      }

      const column =
        getBalanceColumn(currency);

      await client.query("BEGIN");

      const customerResult =
        await client.query(
          `
          SELECT *
          FROM users
          WHERE id = $1
          FOR UPDATE
          `,
          [customerId]
        );

      const customer =
        customerResult.rows[0];

      if (!customer) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Customer not found."
        });
      }

      await client.query(
        `
        UPDATE users
        SET ${column} = ${column} + $1
        WHERE id = $2
        `,
        [
          amount,
          customerId
        ]
      );

      await client.query(
        `
        INSERT INTO transactions
        (
          user_id,
          kind,
          title,
          amount,
          currency
        )
        VALUES
        ($1,'credit',$2,$3,$4)
        `,
        [
          customerId,
          "Funds credited in fictional account",
          amount,
          currency
        ]
      );

      /*
        Customer notification.
      */

      await client.query(
        `
        INSERT INTO notifications
        (
          user_id,
          message
        )
        VALUES
        ($1,$2)
        `,
        [
          customerId,
          `Your fictional account was credited with ${amount} ${currency}.`
        ]
      );

      await client.query("COMMIT");

      res.json({
        success: true,
        message: "Customer credited successfully."
      });

    } catch (error) {

      await client.query("ROLLBACK");

      console.error("ADMIN CREDIT ERROR:", error);

      res.status(500).json({
        error: "Unable to credit customer."
      });

    } finally {

      client.release();
    }
  }
);


/* =========================================================
   ADMIN — SEND CUSTOMER NOTIFICATION
   ========================================================= */

app.post(
  "/api/admin/notify",
  requireAuth,
  requireAdmin,
  async (req, res) => {

    try {

      const customerId =
        Number(req.body.customerId);

      const message =
        String(req.body.message || "")
        .trim();

      if (!Number.isInteger(customerId)) {
        return res.status(400).json({
          error: "Invalid customer."
        });
      }

      if (!message) {
        return res.status(400).json({
          error: "Write a notification first."
        });
      }

      const customer =
        await getUserById(customerId);

      if (!customer) {
        return res.status(404).json({
          error: "Customer not found."
        });
      }

      await pool.query(
        `
        INSERT INTO notifications
        (
          user_id,
          message
        )
        VALUES
        ($1,$2)
        `,
        [
          customerId,
          message
        ]
      );

      res.json({
        success: true,
        message: "Notification sent."
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to send notification."
      });
    }
  }
);


/* =========================================================
   ADMIN — SUPPORT MESSAGES
   ========================================================= */

app.get(
  "/api/admin/support/:customerId",
  requireAuth,
  requireAdmin,
  async (req, res) => {

    try {

      const customerId =
        Number(req.params.customerId);

      const result =
        await pool.query(
          `
          SELECT
            id,
            sender,
            message,
            created_at
          FROM support_messages
          WHERE user_id = $1
          ORDER BY created_at ASC
          `,
          [customerId]
        );

      res.json({
        messages:
          result.rows.map(m => ({
            id: String(m.id),
            sender: m.sender,
            message: m.message,
            date: formatDate(m.created_at)
          }))
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to load customer support."
      });
    }
  }
);


/* =========================================================
   ADMIN — REPLY TO CUSTOMER
   ========================================================= */

app.post(
  "/api/admin/support/:customerId",
  requireAuth,
  requireAdmin,
  async (req, res) => {

    try {

      const customerId =
        Number(req.params.customerId);

      const message =
        String(req.body.message || "")
        .trim();

      if (!Number.isInteger(customerId)) {
        return res.status(400).json({
          error: "Invalid customer."
        });
      }

      if (!message) {
        return res.status(400).json({
          error: "Write a reply first."
        });
      }

      const customer =
        await getUserById(customerId);

      if (!customer) {
        return res.status(404).json({
          error: "Customer not found."
        });
      }

      await pool.query(
        `
        INSERT INTO support_messages
        (
          user_id,
          sender,
          message
        )
        VALUES
        ($1,'admin',$2)
        `,
        [
          customerId,
          message
        ]
      );

      await pool.query(
        `
        INSERT INTO notifications
        (
          user_id,
          message
        )
        VALUES
        ($1,$2)
        `,
        [
          customerId,
          "You have received a new support response."
        ]
      );

      res.json({
        success: true,
        message: "Reply sent."
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to send reply."
      });
    }
  }
);


/* =========================================================
   ADMIN — REQUESTS / NOTIFICATIONS
   ========================================================= */

app.get(
  "/api/admin/requests",
  requireAuth,
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            ar.id,
            ar.request_type,
            ar.message,
            ar.status,
            ar.created_at,
            u.name,
            u.email
          FROM admin_requests ar
          LEFT JOIN users u
            ON u.id = ar.user_id
          ORDER BY ar.created_at DESC
          LIMIT 100
          `
        );

      res.json({
        requests:
          result.rows.map(r => ({
            id: String(r.id),
            type: r.request_type,
            message: r.message,
            status: r.status,
            customerName: r.name || "Unknown",
            customerEmail: r.email || "",
            date: formatDate(r.created_at)
          }))
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to load administrator requests."
      });
    }
  }
);


/* =========================================================
   ADMIN — MARK REQUEST AS READ
   ========================================================= */

app.put(
  "/api/admin/requests/:id",
  requireAuth,
  requireAdmin,
  async (req, res) => {

    try {

      const requestId =
        Number(req.params.id);

      const result =
        await pool.query(
          `
          UPDATE admin_requests
          SET status = 'read'
          WHERE id = $1
          RETURNING id
          `,
          [requestId]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error: "Request not found."
        });
      }

      res.json({
        success: true
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to update request."
      });
    }
  }
);


/* =========================================================
   ADMIN — UNREAD REQUEST COUNT
   ========================================================= */

app.get(
  "/api/admin/requests/unread-count",
  requireAuth,
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT COUNT(*)::INTEGER AS count
          FROM admin_requests
          WHERE status = 'new'
          `
        );

      res.json({
        count: result.rows[0].count
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to load notification count."
      });
    }
  }
);


/* =========================================================
   ADMIN — CREATE ADMIN ACCOUNT
   =========================================================

   This endpoint is intentionally protected by an environment
   variable. Set ADMIN_SETUP_KEY in Render before using it.

   Example request body:

   {
     "setupKey": "your-secret-key",
     "name": "Administrator",
     "email": "admin@example.com",
     "password": "strong-password"
   }

*/

app.post(
  "/api/admin/setup",
  async (req, res) => {

    try {

      const setupKey =
        String(req.body.setupKey || "");

      if (
        !process.env.ADMIN_SETUP_KEY ||
        setupKey !== process.env.ADMIN_SETUP_KEY
      ) {
        return res.status(403).json({
          error: "Invalid setup key."
        });
      }

      const name =
        String(req.body.name || "")
        .trim();

      const email =
        String(req.body.email || "")
        .trim()
        .toLowerCase();

      const password =
        String(req.body.password || "");

      if (name.length < 2) {
        return res.status(400).json({
          error: "Invalid administrator name."
        });
      }

      if (!email.includes("@")) {
        return res.status(400).json({
          error: "Invalid administrator email."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error: "Administrator password must contain at least 8 characters."
        });
      }

      const existing =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE email = $1
          `,
          [email]
        );

      if (existing.rows.length) {

        await pool.query(
          `
          UPDATE users
          SET is_admin = TRUE
          WHERE email = $1
          `,
          [email]
        );

        return res.json({
          success: true,
          message: "Existing account promoted to administrator."
        });
      }

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      await pool.query(
        `
        INSERT INTO users
        (
          name,
          email,
          password_hash,
          primary_currency,
          is_admin
        )
        VALUES
        ($1,$2,$3,'NGN',TRUE)
        `,
        [
          name,
          email,
          hash
        ]
      );

      res.status(201).json({
        success: true,
        message: "Administrator account created."
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to create administrator."
      });
    }
  }
);


/* =========================================================
   STATIC WEBSITE
   ========================================================= */

app.use(
  express.static(
    path.join(__dirname)
  )
);

app.get("*", (req, res) => {

  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      error: "API endpoint not found."
    });
  }

  res.sendFile(
    path.join(
      __dirname,
      "index.html"
    )
  );

});


/* =========================================================
   ERROR HANDLER
   ========================================================= */

app.use(
  (error, req, res, next) => {

    console.error(
      "SERVER ERROR:",
      error
    );

    res.status(500).json({
      error: "Internal server error."
    });
  }
);


/* =========================================================
   START
   ========================================================= */

initDatabase()
  .then(() => {

    app.listen(
      PORT,
      () => {

        console.log(
          `American Crest Banking server running on port ${PORT}`
        );

      }
    );

  })
  .catch(error => {

    console.error(
      "DATABASE STARTUP ERROR:",
      error
    );

    process.exit(1);

  });
