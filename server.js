const express = require("express");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();

app.set("trust proxy", 1);

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("DATABASE_URL is missing.");
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error("JWT_SECRET is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(cors());
app.use(express.json({ limit: "4mb" }));
app.use(express.urlencoded({ extended: true }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false
});

const writeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api", apiLimiter);

const CURRENCIES = [
  "NGN",
  "USD",
  "EUR",
  "GBP",
  "IDR",
  "CAD",
  "AUD",
  "CHF",
  "JPY",
  "CNY",
  "INR",
  "MYR",
  "SGD",
  "AED",
  "ZAR",
  "KES",
  "GHS"
];

/* =========================================================
   HELPERS
========================================================= */

function newId() {
  return crypto.randomUUID();
}

function validCurrency(currency) {
  return CURRENCIES.includes(
    String(currency || "").toUpperCase()
  );
}

function formatDate(value) {
  return new Date(value).toLocaleString();
}

function balanceColumn(currency) {
  const c = String(currency || "").toUpperCase();

  if (!validCurrency(c)) {
    return null;
  }

  return `balance_${c.toLowerCase()}`;
}

function signToken(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role,
      isAdmin: user.role === "admin"
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  try {
    const token = header.slice(7);

    req.user = jwt.verify(
      token,
      JWT_SECRET
    );

    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired session."
    });
  }
}

function requireAdmin(req, res, next) {
  if (
    !req.user ||
    (
      req.user.role !== "admin" &&
      req.user.isAdmin !== true
    )
  ) {
    return res.status(403).json({
      error: "Administrator access required."
    });
  }

  next();
}

/* =========================================================
   DATABASE
========================================================= */

async function initDatabase() {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL DEFAULT 'Customer',
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL DEFAULT '',
      primary_currency VARCHAR(3) NOT NULL DEFAULT 'NGN',
      profile_image TEXT DEFAULT '',
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT 'Customer'
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_hash TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS primary_currency VARCHAR(3) NOT NULL DEFAULT 'NGN'
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS profile_image TEXT DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  `);

  for (const currency of CURRENCIES) {
    await pool.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS
      balance_${currency.toLowerCase()}
      NUMERIC(30,2) NOT NULL DEFAULT 0
    `);
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
      kind TEXT NOT NULL
        CHECK (kind IN ('credit','debit')),
      title TEXT NOT NULL,
      amount NUMERIC(30,2) NOT NULL,
      currency VARCHAR(3) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
      title TEXT NOT NULL DEFAULT 'Notification',
      message TEXT NOT NULL,
      is_read BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS support_messages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
      sender TEXT NOT NULL
        CHECK (sender IN ('customer','admin')),
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transfers (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
      amount NUMERIC(30,2) NOT NULL,
      currency VARCHAR(3) NOT NULL,
      recipient TEXT NOT NULL,
      reference TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_requests (
      id SERIAL PRIMARY KEY,
      request_type TEXT NOT NULL DEFAULT 'general',
      message TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  /*
    Optional automatic administrator.
    Set ADMIN_EMAIL and ADMIN_PASSWORD in Render
    if you want the admin created automatically.
  */

  const adminEmail = String(
    process.env.ADMIN_EMAIL || ""
  )
    .trim()
    .toLowerCase();

  const adminPassword = String(
    process.env.ADMIN_PASSWORD || ""
  );

  if (
    adminEmail &&
    adminPassword
  ) {
    const existing = await pool.query(
      `
      SELECT id
      FROM users
      WHERE email = $1
      `,
      [adminEmail]
    );

    const hash = await bcrypt.hash(
      adminPassword,
      12
    );

    if (existing.rows.length) {
      await pool.query(
        `
        UPDATE users
        SET
          is_admin = TRUE,
          name = COALESCE(NULLIF(name,''),'Administrator'),
          password_hash = $1,
          status = 'active'
        WHERE email = $2
        `,
        [
          hash,
          adminEmail
        ]
      );
    } else {
      await pool.query(
        `
        INSERT INTO users
        (
          name,
          email,
          password_hash,
          primary_currency,
          is_admin,
          status
        )
        VALUES
        (
          'Administrator',
          $1,
          $2,
          'USD',
          TRUE,
          'active'
        )
        `,
        [
          adminEmail,
          hash
        ]
      );
    }
  }

  console.log(
    "American Crest demo database initialized."
  );
}

/* =========================================================
   USER DATA
========================================================= */

async function getUserById(id) {
  const result = await pool.query(
    `
    SELECT *
    FROM users
    WHERE id = $1
    `,
    [id]
  );

  return result.rows[0] || null;
}

async function getUser(id) {

  const userResult = await pool.query(
    `
    SELECT
      id,
      name,
      email,
      is_admin,
      status,
      primary_currency,
      profile_image,
      created_at
    FROM users
    WHERE id = $1
    `,
    [id]
  );

  if (!userResult.rows.length) {
    return null;
  }

  const user = userResult.rows[0];

  const [
    transactionsResult,
    notificationsResult,
    supportResult,
    transfersResult
  ] = await Promise.all([

    pool.query(
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
      LIMIT 100
      `,
      [id]
    ),

    pool.query(
      `
      SELECT
        id,
        title,
        message,
        is_read,
        created_at
      FROM notifications
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 100
      `,
      [id]
    ),

    pool.query(
      `
      SELECT
        id,
        sender,
        message,
        created_at
      FROM support_messages
      WHERE user_id = $1
      ORDER BY created_at ASC
      LIMIT 200
      `,
      [id]
    ),

    pool.query(
      `
      SELECT
        id,
        amount,
        currency,
        recipient,
        reference,
        status,
        created_at
      FROM transfers
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 100
      `,
      [id]
    )
  ]);

  const balances = {};

  for (const currency of CURRENCIES) {
    balances[currency] = Number(
      user[
        `balance_${currency.toLowerCase()}`
      ] || 0
    );
  }

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.is_admin
      ? "admin"
      : "customer",
    isAdmin: Boolean(user.is_admin),
    status: user.status,
    primaryCurrency: user.primary_currency,
    primary_currency: user.primary_currency,
    profileImage: user.profile_image || "",
    profile_image: user.profile_image || "",
    createdAt: user.created_at,
    created_at: user.created_at,

    balances,

    transactions:
      transactionsResult.rows.map(row => ({
        id: String(row.id),
        kind: row.kind,
        title: row.title,
        amount: Number(row.amount),
        currency: row.currency,
        date: formatDate(row.created_at),
        created_at: row.created_at
      })),

    notifications:
      notificationsResult.rows.map(row => ({
        id: String(row.id),
        title: row.title,
        message: row.message,
        is_read: row.is_read,
        date: formatDate(row.created_at),
        created_at: row.created_at
      })),

    support:
      supportResult.rows.map(row => ({
        id: String(row.id),
        sender: row.sender,
        message: row.message,
        date: formatDate(row.created_at),
        created_at: row.created_at
      })),

    transfers:
      transfersResult.rows.map(row => ({
        id: String(row.id),
        amount: Number(row.amount),
        currency: row.currency,
        recipient: row.recipient,
        reference: row.reference,
        status: row.status,
        date: formatDate(row.created_at),
        created_at: row.created_at
      }))
  };
}

/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/api/health",
  async (req, res) => {
    try {
      await pool.query("SELECT 1");

      res.json({
        ok: true,
        demo: true,
        application:
          "American Crest Bank — Fictional Demo",
        mode: "fictional-demo"
      });

    } catch (error) {

      console.error(
        "HEALTH ERROR:",
        error
      );

      res.status(500).json({
        ok: false
      });
    }
  }
);

/* =========================================================
   REGISTER
   NEW CUSTOMERS ARE SAVED IN THE SAME DATABASE
   THE ADMIN USES
========================================================= */

async function registerHandler(req, res) {

  try {

    const name = String(
      req.body.name || ""
    ).trim();

    const email = String(
      req.body.email || ""
    )
      .trim()
      .toLowerCase();

    const password = String(
      req.body.password || ""
    );

    const currency = String(
      req.body.currency ||
      req.body.primaryCurrency ||
      "NGN"
    ).toUpperCase();

    if (name.length < 2) {
      return res.status(400).json({
        error:
          "Enter your full name."
      });
    }

    if (
      !/^\S+@\S+\.\S+$/.test(email)
    ) {
      return res.status(400).json({
        error:
          "Enter a valid email address."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error:
          "Password must contain at least 6 characters."
      });
    }

    if (!validCurrency(currency)) {
      return res.status(400).json({
        error:
          "Invalid currency."
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
      return res.status(409).json({
        error:
          "This email is already registered."
      });
    }

    const hash =
      await bcrypt.hash(
        password,
        12
      );

    const result =
      await pool.query(
        `
        INSERT INTO users
        (
          name,
          email,
          password_hash,
          primary_currency,
          is_admin,
          status
        )
        VALUES
        (
          $1,
          $2,
          $3,
          $4,
          FALSE,
          'active'
        )
        RETURNING id
        `,
        [
          name,
          email,
          hash,
          currency
        ]
      );

    const userId =
      result.rows[0].id;

    /*
      Create every currency balance
      so admin credit always works.
    */

    for (const c of CURRENCIES) {

      await pool.query(
        `
        UPDATE users
        SET balance_${c.toLowerCase()} = 0
        WHERE id = $1
        `,
        [userId]
      );

    }

    /*
      Customer notification
    */

    await pool.query(
      `
      INSERT INTO notifications
      (
        user_id,
        title,
        message
      )
      VALUES
      (
        $1,
        'Account created',
        'Your fictional demo account has been created successfully.'
      )
      `,
      [userId]
    );

    /*
      Notify every administrator that
      a new customer registered.
    */

    const admins =
      await pool.query(
        `
        SELECT id
        FROM users
        WHERE is_admin = TRUE
        `
      );

    for (const admin of admins.rows) {

      await pool.query(
        `
        INSERT INTO notifications
        (
          user_id,
          title,
          message
        )
        VALUES
        (
          $1,
          'New customer registered',
          $2
        )
        `,
        [
          admin.id,
          `New demo customer registered: ${name} (${email}).`
        ]
      );

    }

    const user =
      await getUser(userId);

    res.status(201).json({
      token: signToken(user),
      user
    });

  } catch (error) {

    console.error(
      "REGISTER ERROR:",
      error
    );

    res.status(500).json({
      error:
        "Unable to create account."
    });
  }
}

app.post(
  "/api/auth/register",
  authLimiter,
  registerHandler
);

app.post(
  "/api/register",
  authLimiter,
  registerHandler
);

/* =========================================================
   LOGIN
========================================================= */

async function loginHandler(req, res) {

  try {

    const email = String(
      req.body.email || ""
    )
      .trim()
      .toLowerCase();

    const password = String(
      req.body.password || ""
    );

    const result =
      await pool.query(
        `
        SELECT *
        FROM users
        WHERE email = $1
        `,
        [email]
      );

    const row =
      result.rows[0];

    if (!row) {
      return res.status(401).json({
        error:
          "Incorrect email or password."
      });
    }

    const valid =
      await bcrypt.compare(
        password,
        row.password_hash
      );

    if (!valid) {
      return res.status(401).json({
        error:
          "Incorrect email or password."
      });
    }

    const user =
      await getUser(row.id);

    res.json({
      token: signToken(user),
      user
    });

  } catch (error) {

    console.error(
      "LOGIN ERROR:",
      error
    );

    res.status(500).json({
      error:
        "Unable to sign in."
    });
  }
}

app.post(
  "/api/auth/login",
  authLimiter,
  loginHandler
);

app.post(
  "/api/login",
  authLimiter,
  loginHandler
);

/* =========================================================
   ME
========================================================= */

app.get(
  "/api/me",
  requireAuth,
  async (req, res) => {

    try {

      const user =
        await getUser(
          req.user.id
        );

      if (!user) {
        return res.status(404).json({
          error:
            "Account not found."
        });
      }

      res.json({
        user
      });

    } catch (error) {

      console.error(
        "ME ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load account."
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

      const result =
        await pool.query(
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
          result.rows.map(row => ({
            id: String(row.id),
            kind: row.kind,
            title: row.title,
            amount: Number(row.amount),
            currency: row.currency,
            date: formatDate(
              row.created_at
            ),
            created_at:
              row.created_at
          }))
      });

    } catch (error) {

      console.error(
        "TRANSACTIONS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load transactions."
      });
    }
  }
);

/* =========================================================
   CUSTOMER TRANSFER / REQUEST
========================================================= */

async function requestTransfer(
  req,
  res
) {

  const client =
    await pool.connect();

  try {

    const currency =
      String(
        req.body.currency || ""
      ).toUpperCase();

    const amount =
      Number(
        req.body.amount
      );

    const recipient =
      String(
        req.body.recipient || ""
      ).trim();

    const note =
      String(
        req.body.note || ""
      ).trim()
      .slice(0, 500);

    if (!validCurrency(currency)) {
      return res.status(400).json({
        error:
          "Invalid currency."
      });
    }

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        error:
          "Enter a valid amount."
      });
    }

    if (recipient.length < 2) {
      return res.status(400).json({
        error:
          "Enter the recipient name."
      });
    }

    await client.query(
      "BEGIN"
    );

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

      await client.query(
        "ROLLBACK"
      );

      return res.status(404).json({
        error:
          "Account not found."
      });
    }

    const column =
      balanceColumn(currency);

    const currentBalance =
      Number(
        user[column] || 0
      );

    /*
      Keep the existing demo transfer
      balance check.
    */

    if (amount > currentBalance) {

      await client.query(
        "ROLLBACK"
      );

      return res.status(400).json({
        error:
          "Insufficient demo balance."
      });
    }

    /*
      Deduct demo balance.
    */

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

    const reference =
      "DEMO-" +
      Date.now()
        .toString(36)
        .toUpperCase() +
      "-" +
      Math.random()
        .toString(36)
        .slice(2, 7)
        .toUpperCase();

    await client.query(
      `
      INSERT INTO transfers
      (
        user_id,
        amount,
        currency,
        recipient,
        reference,
        status
      )
      VALUES
      (
        $1,
        $2,
        $3,
        $4,
        $5,
        'pending'
      )
      `,
      [
        req.user.id,
        amount,
        currency,
        recipient,
        reference
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
      (
        $1,
        'debit',
        $2,
        $3,
        $4
      )
      `,
      [
        req.user.id,
        `Demo transfer to ${recipient}`,
        amount,
        currency
      ]
    );

    await client.query(
      `
      INSERT INTO notifications
      (
        user_id,
        title,
        message
      )
      VALUES
      (
        $1,
        'Demo transfer',
        $2
      )
      `,
      [
        req.user.id,
        `Your fictional demo transfer of ${amount} ${currency} to ${recipient} is pending.`
      ]
    );

    /*
      Notify admin about transfer.
    */

    const admins =
      await client.query(
        `
        SELECT id
        FROM users
        WHERE is_admin = TRUE
        `
      );

    for (const admin of admins.rows) {

      await client.query(
        `
        INSERT INTO notifications
        (
          user_id,
          title,
          message
        )
        VALUES
        (
          $1,
          'New customer transfer',
          $2
        )
        `,
        [
          admin.id,
          `New demo transfer from ${user.name}: ${amount} ${currency} to ${recipient}. Reference: ${reference}`
        ]
      );

    }

    await client.query(
      "COMMIT"
    );

    res.json({
      success: true,
      message:
        "Demo transfer recorded.",
      amount,
      currency,
      reference,
      status: "pending",
      user:
        await getUser(req.user.id)
    });

  } catch (error) {

    try {
      await client.query(
        "ROLLBACK"
      );
    } catch {}

    console.error(
      "TRANSFER ERROR:",
      error
    );

    res.status(500).json({
      error:
        "Unable to process demo transfer."
    });

  } finally {
    client.release();
  }
}

app.post(
  "/api/requests",
  requireAuth,
  writeLimiter,
  requestTransfer
);

app.post(
  "/api/transfers",
  requireAuth,
  writeLimiter,
  requestTransfer
);

/* =========================================================
   CUSTOMER NOTIFICATIONS
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
            title,
            message,
            is_read,
            created_at
          FROM notifications
          WHERE user_id = $1
          ORDER BY created_at DESC
          LIMIT 100
          `,
          [req.user.id]
        );

      res.json({
        notifications:
          result.rows.map(row => ({
            id: String(row.id),
            title: row.title,
            message: row.message,
            is_read: row.is_read,
            date: formatDate(
              row.created_at
            ),
            created_at:
              row.created_at
          }))
      });

    } catch (error) {

      console.error(
        "NOTIFICATIONS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load notifications."
      });
    }
  }
);

/* =========================================================
   CUSTOMER SUPPORT
========================================================= */

app.post(
  "/api/support",
  requireAuth,
  writeLimiter,
  async (req, res) => {

    try {

      const message =
        String(
          req.body.message || ""
        )
        .trim()
        .slice(0, 2000);

      if (!message) {
        return res.status(400).json({
          error:
            "Write a message first."
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
        (
          $1,
          'customer',
          $2
        )
        `,
        [
          req.user.id,
          message
        ]
      );

      const customer =
        await getUser(
          req.user.id
        );

      const admins =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE is_admin = TRUE
          `
        );

      for (const admin of admins.rows) {

        await pool.query(
          `
          INSERT INTO notifications
          (
            user_id,
            title,
            message
          )
          VALUES
          (
            $1,
            'New support message',
            $2
          )
          `,
          [
            admin.id,
            `New support message from ${customer.name} (${customer.email}).`
          ]
        );
      }

      res.json({
        success: true,
        message:
          "Support message sent.",
        user:
          await getUser(req.user.id)
      });

    } catch (error) {

      console.error(
        "SUPPORT ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to send support message."
      });
    }
  }
);

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
          result.rows.map(row => ({
            id: String(row.id),
            sender: row.sender,
            message: row.message,
            date: formatDate(
              row.created_at
            ),
            created_at:
              row.created_at
          }))
      });

    } catch (error) {

      console.error(
        "SUPPORT LOAD ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load support messages."
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
  writeLimiter,
  async (req, res) => {

    try {

      const name =
        String(
          req.body.name || ""
        ).trim();

      if (name.length < 2) {
        return res.status(400).json({
          error:
            "Enter a valid name."
        });
      }

      const result =
        await pool.query(
          `
          UPDATE users
          SET name = $1
          WHERE id = $2
          RETURNING id
          `,
          [
            name,
            req.user.id
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Account not found."
        });
      }

      res.json({
        user:
          await getUser(
            req.user.id
          )
      });

    } catch (error) {

      console.error(
        "PROFILE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to update profile."
      });
    }
  }
);

async function updateProfileImage(
  req,
  res
) {

  try {

    const image =
      String(
        req.body.profileImage ||
        req.body.image ||
        ""
      );

    if (
      image &&
      !image.startsWith(
        "data:image/"
      )
    ) {
      return res.status(400).json({
        error:
          "Invalid image."
      });
    }

    if (
      image.length >
      3 * 1024 * 1024
    ) {
      return res.status(400).json({
        error:
          "Image is too large."
      });
    }

    await pool.query(
      `
      UPDATE users
      SET profile_image = $1
      WHERE id = $2
      `,
      [
        image,
        req.user.id
      ]
    );

    res.json({
      user:
        await getUser(
          req.user.id
        )
    });

  } catch (error) {

    console.error(
      "PROFILE IMAGE ERROR:",
      error
    );

    res.status(500).json({
      error:
        "Unable to update profile picture."
    });
  }
}

app.post(
  "/api/profile/image",
  requireAuth,
  writeLimiter,
  updateProfileImage
);

app.put(
  "/api/profile-image",
  requireAuth,
  writeLimiter,
  updateProfileImage
);

/* =========================================================
   ADMIN STATE
   CUSTOMERS + REQUESTS + SUPPORT + NOTIFICATIONS
========================================================= */

app.get(
  "/api/admin/state",
  requireAuth,
  requireAdmin,
  async (req, res) => {

    try {

      const customersResult =
        await pool.query(
          `
          SELECT
            id,
            name,
            email,
            status,
            primary_currency,
            profile_image,
            created_at
          FROM users
          WHERE is_admin = FALSE
          ORDER BY created_at DESC
          `
        );

      const requestsResult =
        await pool.query(
          `
          SELECT
            t.id,
            t.user_id,
            u.name,
            u.email,
            t.amount,
            t.currency,
            t.recipient,
            '' AS note,
            t.reference,
            t.status,
            t.created_at,
            t.created_at AS handled_at
          FROM transfers t
          JOIN users u
            ON u.id = t.user_id
          ORDER BY t.created_at DESC
          LIMIT 200
          `
        );

      const supportResult =
        await pool.query(
          `
          SELECT
            s.id,
            s.user_id,
            u.name,
            u.email,
            s.sender,
            s.message,
            s.created_at
          FROM support_messages s
          JOIN users u
            ON u.id = s.user_id
          ORDER BY s.created_at DESC
          LIMIT 500
          `
        );

      const notificationsResult =
        await pool.query(
          `
          SELECT
            n.id,
            n.user_id,
            u.name,
            u.email,
            n.title,
            n.message,
            n.is_read,
            n.created_at
          FROM notifications n
          JOIN users u
            ON u.id = n.user_id
          WHERE u.is_admin = FALSE
          ORDER BY n.created_at DESC
          LIMIT 500
          `
        );

      const customers =
        await Promise.all(
          customersResult.rows.map(
            async row => {

              const balances = {};

              for (
                const currency
                of CURRENCIES
              ) {

                const balanceResult =
                  await pool.query(
                    `
                    SELECT balance_${currency.toLowerCase()}
                    FROM users
                    WHERE id = $1
                    `,
                    [row.id]
                  );

                balances[currency] =
                  Number(
                    balanceResult.rows[0]?.[
                      `balance_${currency.toLowerCase()}`
                    ] || 0
                  );
              }

              return {
                id: String(row.id),
                name: row.name,
                email: row.email,
                status:
                  String(
                    row.status || "active"
                  ).toLowerCase(),
                primary_currency:
                  row.primary_currency,
                primaryCurrency:
                  row.primary_currency,
                profile_image:
                  row.profile_image || "",
                created_at:
                  row.created_at,
                balances
              };
            }
          )
        );

      res.json({

        customers,

        requests:
          requestsResult.rows.map(
            row => ({
              id: String(row.id),
              user_id: String(row.user_id),
              name: row.name,
              email: row.email,
              amount: Number(row.amount),
              currency: row.currency,
              recipient: row.recipient,
              note: row.note || "",
              reference: row.reference,
              status: row.status,
              created_at: row.created_at,
              handled_at: row.handled_at,
              date:
                formatDate(
                  row.created_at
                )
            })
          ),

        support:
          supportResult.rows.map(
            row => ({
              id: String(row.id),
              user_id: String(row.user_id),
              name: row.name,
              email: row.email,
              sender: row.sender,
              message: row.message,
              created_at: row.created_at,
              date:
                formatDate(
                  row.created_at
                )
            })
          ),

        notifications:
          notificationsResult.rows.map(
            row => ({
              id: String(row.id),
              user_id: String(row.user_id),
              name: row.name,
              email: row.email,
              title: row.title,
              message: row.message,
              is_read: row.is_read,
              created_at: row.created_at,
              date:
                formatDate(
                  row.created_at
                )
            })
          )

      });

    } catch (error) {

      console.error(
        "ADMIN STATE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load admin data."
      });
    }
  }
);

/* =========================================================
   ADMIN CUSTOMERS
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
          WHERE is_admin = FALSE
          ORDER BY created_at DESC
          `
        );

      const customers =
        result.rows.map(
          row => {

            const accounts =
              CURRENCIES
                .map(currency => ({
                  currency,
                  balance:
                    Number(
                      row[
                        `balance_${currency.toLowerCase()}`
                      ] || 0
                    )
                }))
                .filter(
                  account =>
                    account.balance !== 0
                );

            const balances = {};

            for (
              const currency
              of CURRENCIES
            ) {
              balances[currency] =
                Number(
                  row[
                    `balance_${currency.toLowerCase()}`
                  ] || 0
                );
            }

            return {
              id: row.id,
              name: row.name,
              full_name: row.name,
              email: row.email,
              status:
                String(
                  row.status || "active"
                ).toLowerCase(),
              primary_currency:
                row.primary_currency,
              primaryCurrency:
                row.primary_currency,
              created_at:
                row.created_at,
              accounts,
              balances
            };
          }
        );

      res.json(
        customers
      );

    } catch (error) {

      console.error(
        "ADMIN CUSTOMERS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load customers."
      });
    }
  }
);

/* =========================================================
   ADMIN CREDIT CUSTOMER
========================================================= */

async function adminCredit(
  req,
  res
) {

  const client =
    await pool.connect();

  try {

    const customerId =
      String(
        req.body.userId ||
        req.body.customerId ||
        ""
      ).trim();

    const currency =
      String(
        req.body.currency || ""
      ).toUpperCase();

    const amount =
      Number(
        req.body.amount
      );

    const description =
      String(
        req.body.description ||
        "Funds credited by demo administrator"
      )
      .trim()
      .slice(0, 500);

    if (!customerId) {
      return res.status(400).json({
        error:
          "Select a customer first."
      });
    }

    if (!validCurrency(currency)) {
      return res.status(400).json({
        error:
          "Invalid currency."
      });
    }

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        error:
          "Enter a valid amount."
      });
    }

    if (
      amount >
      1000000000000
    ) {
      return res.status(400).json({
        error:
          "The amount is too large."
      });
    }

    const column =
      balanceColumn(currency);

    await client.query(
      "BEGIN"
    );

    const customerResult =
      await client.query(
        `
        SELECT *
        FROM users
        WHERE id = $1
        AND is_admin = FALSE
        FOR UPDATE
        `,
        [customerId]
      );

    const customer =
      customerResult.rows[0];

    if (!customer) {

      await client.query(
        "ROLLBACK"
      );

      return res.status(404).json({
        error:
          "Customer not found."
      });
    }

    await client.query(
      `
      UPDATE users
      SET ${column} =
        ${column} + $1
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
      (
        $1,
        'credit',
        $2,
        $3,
        $4
      )
      `,
      [
        customerId,
        description,
        amount,
        currency
      ]
    );

    await client.query(
      `
      INSERT INTO notifications
      (
        user_id,
        title,
        message
      )
      VALUES
      (
        $1,
        'Demo account credit',
        $2
      )
      `,
      [
        customerId,
        `Your fictional demo account was credited with ${amount.toLocaleString()} ${currency}.`
      ]
    );

    await client.query(
      "COMMIT"
    );

    res.json({
      success: true,
      message:
        "Customer demo account funded successfully.",
      customerId,
      amount,
      currency,
      user:
        await getUser(customerId)
    });

  } catch (error) {

    try {
      await client.query(
        "ROLLBACK"
      );
    } catch {}

    console.error(
      "ADMIN CREDIT ERROR:",
      error
    );

    res.status(500).json({
      error:
        "Unable to credit customer."
    });

  } finally {
    client.release();
  }
}

app.post(
  "/api/admin/credit",
  requireAuth,
  requireAdmin,
  writeLimiter,
  adminCredit
);

app.post(
  "/api/admin/customers/:id/funds",
  requireAuth,
  requireAdmin,
  writeLimiter,
  async (req, res) => {

    req.body.userId =
      req.params.id;

    return adminCredit(
      req,
      res
    );
  }
);

/* =========================================================
   ADMIN SEND CUSTOMER NOTIFICATION
========================================================= */

app.post(
  "/api/admin/notify",
  requireAuth,
  requireAdmin,
  writeLimiter,
  async (req, res) => {

    try {

      const customerId =
        String(
          req.body.userId ||
          req.body.customerId ||
          ""
        ).trim();

      const message =
        String(
          req.body.message || ""
        )
        .trim()
        .slice(0, 2000);

      if (!customerId) {
        return res.status(400).json({
          error:
            "Select a customer first."
        });
      }

      if (!message) {
        return res.status(400).json({
          error:
            "Write a notification first."
        });
      }

      const customer =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE id = $1
          AND is_admin = FALSE
          `,
          [customerId]
        );

      if (!customer.rows.length) {
        return res.status(404).json({
          error:
            "Customer not found."
        });
      }

      await pool.query(
        `
        INSERT INTO notifications
        (
          user_id,
          title,
          message
        )
        VALUES
        (
          $1,
          'Administrator notification',
          $2
        )
        `,
        [
          customerId,
          message
        ]
      );

      res.json({
        success: true,
        message:
          "Notification sent."
      });

    } catch (error) {

      console.error(
        "ADMIN NOTIFY ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to send notification."
      });
    }
  }
);

/* =========================================================
   ADMIN VIEW CUSTOMER NOTIFICATIONS
========================================================= */

app.get(
  "/api/admin/notifications",
  requireAuth,
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            n.id,
            n.user_id,
            u.name,
            u.email,
            n.title,
            n.message,
            n.is_read,
            n.created_at
          FROM notifications n
          JOIN users u
            ON u.id = n.user_id
          WHERE u.is_admin = FALSE
          ORDER BY n.created_at DESC
          LIMIT 500
          `
        );

      res.json({
        notifications:
          result.rows.map(
            row => ({
              id: String(row.id),
              user_id: String(row.user_id),
              customerId: String(row.user_id),
              name: row.name,
              email: row.email,
              title: row.title,
              message: row.message,
              is_read: row.is_read,
              created_at: row.created_at,
              date:
                formatDate(
                  row.created_at
                )
            })
          )
      });

    } catch (error) {

      console.error(
        "ADMIN NOTIFICATIONS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load customer notifications."
      });
    }
  }
);

/* =========================================================
   ADMIN CUSTOMER STATUS
========================================================= */

app.patch(
  "/api/admin/customers/:id/status",
  requireAuth,
  requireAdmin,
  writeLimiter,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      const status =
        String(
          req.body.status || ""
        )
        .toLowerCase();

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          error:
            "Invalid customer."
        });
      }

      if (
        ![
          "active",
          "suspended",
          "pending"
        ].includes(status)
      ) {
        return res.status(400).json({
          error:
            "Invalid customer status."
        });
      }

      const result =
        await pool.query(
          `
          UPDATE users
          SET status = $1
          WHERE id = $2
          AND is_admin = FALSE
          RETURNING id,status
          `,
          [
            status,
            id
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Customer not found."
        });
      }

      res.json({
        success: true,
        status
      });

    } catch (error) {

      console.error(
        "STATUS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to update customer status."
      });
    }
  }
);

/* =========================================================
   ADMIN TRANSFERS
========================================================= */

app.get(
  "/api/admin/transfers",
  requireAuth,
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            t.id,
            t.user_id,
            t.amount,
            t.currency,
            t.recipient,
            t.reference,
            t.status,
            t.created_at,
            u.name AS full_name,
            u.name,
            u.email
          FROM transfers t
          JOIN users u
            ON u.id = t.user_id
          ORDER BY
            t.created_at DESC
          `
        );

      res.json(
        result.rows.map(
          row => ({
            id: row.id,
            user_id: row.user_id,
            full_name: row.full_name,
            name: row.name,
            email: row.email,
            amount:
              Number(row.amount),
            currency:
              row.currency,
            recipient:
              row.recipient,
            reference:
              row.reference,
            status:
              row.status,
            created_at:
              row.created_at
          })
        )
      );

    } catch (error) {

      console.error(
        "ADMIN TRANSFERS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load transfers."
      });
    }
  }
);

/* =========================================================
   ADMIN TRANSFER STATUS
========================================================= */

app.patch(
  "/api/admin/transfers/:id/status",
  requireAuth,
  requireAdmin,
  writeLimiter,
  async (req, res) => {

    const client =
      await pool.connect();

    let started = false;

    try {

      const id =
        Number(
          req.params.id
        );

      const status =
        String(
          req.body.status || ""
        ).toLowerCase();

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          error:
            "Invalid transfer."
        });
      }

      if (
        ![
          "successful",
          "declined",
          "pending"
        ].includes(status)
      ) {
        return res.status(400).json({
          error:
            "Invalid transfer status."
        });
      }

      await client.query(
        "BEGIN"
      );

      started = true;

      const result =
        await client.query(
          `
          SELECT *
          FROM transfers
          WHERE id = $1
          FOR UPDATE
          `,
          [id]
        );

      const transfer =
        result.rows[0];

      if (!transfer) {

        await client.query(
          "ROLLBACK"
        );

        started = false;

        return res.status(404).json({
          error:
            "Transfer not found."
        });
      }

      if (
        transfer.status === "pending" &&
        status === "declined"
      ) {

        const column =
          balanceColumn(
            transfer.currency
          );

        await client.query(
          `
          UPDATE users
          SET ${column} =
            ${column} + $1
          WHERE id = $2
          `,
          [
            Number(
              transfer.amount
            ),
            transfer.user_id
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
          (
            $1,
            'credit',
            'Demo transfer reversal',
            $2,
            $3
          )
          `,
          [
            transfer.user_id,
            Number(
              transfer.amount
            ),
            transfer.currency
          ]
        );

        await client.query(
          `
          INSERT INTO notifications
          (
            user_id,
            title,
            message
          )
          VALUES
          (
            $1,
            'Demo transfer declined',
            $2
          )
          `,
          [
            transfer.user_id,
            `Your fictional demo transfer ${transfer.reference} was declined and the demo amount was returned.`
          ]
        );

      } else {

        await client.query(
          `
          INSERT INTO notifications
          (
            user_id,
            title,
            message
          )
          VALUES
          (
            $1,
            'Demo transfer update',
            $2
          )
          `,
          [
            transfer.user_id,
            `Your fictional demo transfer ${transfer.reference} is now ${status}.`
          ]
        );
      }

      await client.query(
        `
        UPDATE transfers
        SET status = $1
        WHERE id = $2
        `,
        [
          status,
          id
        ]
      );

      await client.query(
        "COMMIT"
      );

      started = false;

      res.json({
        success: true,
        status
      });

    } catch (error) {

      if (started) {
        try {
          await client.query(
            "ROLLBACK"
          );
        } catch {}
      }

      console.error(
        "TRANSFER STATUS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to update transfer."
      });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   ADMIN SUPPORT
========================================================= */

app.get(
  "/api/admin/support",
  requireAuth,
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            s.id,
            s.user_id,
            s.sender,
            s.message,
            s.created_at,
            u.name AS full_name,
            u.name,
            u.email
          FROM support_messages s
          JOIN users u
            ON u.id = s.user_id
          WHERE u.is_admin = FALSE
          ORDER BY
            s.created_at DESC
          LIMIT 500
          `
        );

      res.json({
        messages:
          result.rows.map(
            row => ({
              id: String(row.id),
              user_id:
                String(row.user_id),
              customerId:
                String(row.user_id),
              full_name:
                row.full_name,
              name:
                row.name,
              email:
                row.email,
              sender:
                row.sender,
              message:
                row.message,
              created_at:
                row.created_at,
              date:
                formatDate(
                  row.created_at
                )
            })
          )
      });

    } catch (error) {

      console.error(
        "ADMIN SUPPORT ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load support requests."
      });
    }
  }
);

/* =========================================================
   ADMIN SUPPORT REPLY
========================================================= */

app.post(
  "/api/admin/support/reply",
  requireAuth,
  requireAdmin,
  writeLimiter,
  async (req, res) => {

    try {

      const userId =
        String(
          req.body.userId ||
          req.body.customerId ||
          ""
        ).trim();

      const message =
        String(
          req.body.message || ""
        )
        .trim()
        .slice(0, 2000);

      if (!userId) {
        return res.status(400).json({
          error:
            "Select a customer first."
        });
      }

      if (!message) {
        return res.status(400).json({
          error:
            "Write a reply first."
        });
      }

      const customer =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE id = $1
          AND is_admin = FALSE
          `,
          [userId]
        );

      if (!customer.rows.length) {
        return res.status(404).json({
          error:
            "Customer not found."
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
        (
          $1,
          'admin',
          $2
        )
        `,
        [
          userId,
          message
        ]
      );

      await pool.query(
        `
        INSERT INTO notifications
        (
          user_id,
          title,
          message
        )
        VALUES
        (
          $1,
          'Support response',
          'You have received a response from demo support.'
        )
        `,
        [userId]
      );

      res.json({
        success: true,
        message:
          "Response sent.",
        user:
          await getUser(userId)
      });

    } catch (error) {

      console.error(
        "ADMIN SUPPORT REPLY ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to send reply."
      });
    }
  }
);

/* =========================================================
   ADMIN REQUESTS
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
            t.id,
            t.user_id,
            u.name,
            u.email,
            t.amount,
            t.currency,
            t.recipient,
            t.status,
            t.reference,
            t.created_at
          FROM transfers t
          JOIN users u
            ON u.id = t.user_id
          ORDER BY
            t.created_at DESC
          LIMIT 100
          `
        );

      res.json({
        requests:
          result.rows.map(
            row => ({
              id: String(row.id),
              user_id:
                String(row.user_id),
              name: row.name,
              email: row.email,
              amount:
                Number(row.amount),
              currency:
                row.currency,
              recipient:
                row.recipient,
              note: "",
              status:
                row.status,
              reference:
                row.reference,
              date:
                formatDate(
                  row.created_at
                ),
              created_at:
                row.created_at
            })
          )
      });

    } catch (error) {

      console.error(
        "ADMIN REQUESTS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load requests."
      });
    }
  }
);

/* =========================================================
   ADMIN APPROVE REQUEST
========================================================= */

app.post(
  "/api/admin/requests/:id/approve",
  requireAuth,
  requireAdmin,
  writeLimiter,
  async (req, res) => {

    const client =
      await pool.connect();

    let started = false;

    try {

      const id =
        Number(
          req.params.id
        );

      await client.query(
        "BEGIN"
      );

      started = true;

      const result =
        await client.query(
          `
          SELECT *
          FROM transfers
          WHERE id = $1
          FOR UPDATE
          `,
          [id]
        );

      const transfer =
        result.rows[0];

      if (!transfer) {

        await client.query(
          "ROLLBACK"
        );

        started = false;

        return res.status(404).json({
          error:
            "Request not found."
        });
      }

      if (
        transfer.status !==
        "pending"
      ) {

        await client.query(
          "ROLLBACK"
        );

        started = false;

        return res.status(409).json({
          error:
            "This request has already been handled."
        });
      }

      /*
        The request itself represents a
        customer transfer. It has already
        reserved/deducted the demo balance.

        Approval therefore only changes
        its status.
      */

      await client.query(
        `
        UPDATE transfers
        SET status = 'successful'
        WHERE id = $1
        `,
        [id]
      );

      await client.query(
        `
        INSERT INTO notifications
        (
          user_id,
          title,
          message
        )
        VALUES
        (
          $1,
          'Demo transfer approved',
          $2
        )
        `,
        [
          transfer.user_id,
          `Your fictional demo transfer ${transfer.reference} has been approved.`
        ]
      );

      await client.query(
        "COMMIT"
      );

      started = false;

      res.json({
        ok: true,
        success: true,
        user:
          await getUser(
            transfer.user_id
          )
      });

    } catch (error) {

      if (started) {
        try {
          await client.query(
            "ROLLBACK"
          );
        } catch {}
      }

      console.error(
        "APPROVE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to approve request."
      });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   ADMIN REJECT REQUEST
========================================================= */

app.post(
  "/api/admin/requests/:id/reject",
  requireAuth,
  requireAdmin,
  writeLimiter,
  async (req, res) => {

    const client =
      await pool.connect();

    let started = false;

    try {

      const id =
        Number(
          req.params.id
        );

      await client.query(
        "BEGIN"
      );

      started = true;

      const result =
        await client.query(
          `
          SELECT *
          FROM transfers
          WHERE id = $1
          FOR UPDATE
          `,
          [id]
        );

      const transfer =
        result.rows[0];

      if (!transfer) {

        await client.query(
          "ROLLBACK"
        );

        started = false;

        return res.status(404).json({
          error:
            "Request not found."
        });
      }

      if (
        transfer.status !==
        "pending"
      ) {

        await client.query(
          "ROLLBACK"
        );

        started = false;

        return res.status(409).json({
          error:
            "This request has already been handled."
        });
      }

      const column =
        balanceColumn(
          transfer.currency
        );

      /*
        Return the demo amount when
        the transfer is declined.
      */

      await client.query(
        `
        UPDATE users
        SET ${column} =
          ${column} + $1
        WHERE id = $2
        `,
        [
          Number(
            transfer.amount
          ),
          transfer.user_id
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
        (
          $1,
          'credit',
          'Demo transfer reversal',
          $2,
          $3
        )
        `,
        [
          transfer.user_id,
          Number(
            transfer.amount
          ),
          transfer.currency
        ]
      );

      await client.query(
        `
        UPDATE transfers
        SET status = 'declined'
        WHERE id = $1
        `,
        [id]
      );

      await client.query(
        `
        INSERT INTO notifications
        (
          user_id,
          title,
          message
        )
        VALUES
        (
          $1,
          'Demo transfer declined',
          $2
        )
        `,
        [
          transfer.user_id,
          `Your fictional demo transfer ${transfer.reference} was declined and the demo amount was returned.`
        ]
      );

      await client.query(
        "COMMIT"
      );

      started = false;

      res.json({
        ok: true,
        success: true
      });

    } catch (error) {

      if (started) {
        try {
          await client.query(
            "ROLLBACK"
          );
        } catch {}
      }

      console.error(
        "REJECT ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to reject request."
      });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   ADMIN MARK NOTIFICATION READ
========================================================= */

app.patch(
  "/api/admin/notifications/:id/read",
  requireAuth,
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      const result =
        await pool.query(
          `
          UPDATE notifications n
          SET is_read = TRUE
          FROM users u
          WHERE n.id = $1
          AND n.user_id = u.id
          AND u.is_admin = FALSE
          RETURNING n.id
          `,
          [id]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Notification not found."
        });
      }

      res.json({
        success: true
      });

    } catch (error) {

      console.error(
        "ADMIN READ NOTIFICATION ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to mark notification as read."
      });
    }
  }
);

/* =========================================================
   ADMIN SUMMARY
========================================================= */

app.get(
  "/api/admin/summary",
  requireAuth,
  requireAdmin,
  async (req, res) => {

    try {

      const customers =
        await pool.query(
          `
          SELECT COUNT(*)::INTEGER AS count
          FROM users
          WHERE is_admin = FALSE
          `
        );

      const active =
        await pool.query(
          `
          SELECT COUNT(*)::INTEGER AS count
          FROM users
          WHERE is_admin = FALSE
          AND LOWER(status) = 'active'
          `
        );

      const pending =
        await pool.query(
          `
          SELECT COUNT(*)::INTEGER AS count
          FROM transfers
          WHERE status = 'pending'
          `
        );

      const support =
        await pool.query(
          `
          SELECT COUNT(*)::INTEGER AS count
          FROM support_messages
          WHERE sender = 'customer'
          `
        );

      const unread =
        await pool.query(
          `
          SELECT COUNT(*)::INTEGER AS count
          FROM notifications n
          JOIN users u
            ON u.id = n.user_id
          WHERE u.is_admin = FALSE
          AND n.is_read = FALSE
          `
        );

      res.json({
        customers:
          customers.rows[0].count,

        activeCustomers:
          active.rows[0].count,

        pendingTransfers:
          pending.rows[0].count,

        openSupport:
          support.rows[0].count,

        unreadNotifications:
          unread.rows[0].count
      });

    } catch (error) {

      console.error(
        "SUMMARY ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load dashboard."
      });
    }
  }
);

/* =========================================================
   ADMIN SETUP PAGE
========================================================= */

app.get(
  "/admin-setup",
  (req, res) => {

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta
          name="viewport"
          content="width=device-width,initial-scale=1"
        >
        <title>American Crest Admin Setup</title>
        <style>
          body{
            font-family:Arial,sans-serif;
            background:#f3f6fa;
            padding:30px;
          }

          .box{
            max-width:500px;
            margin:auto;
            background:#fff;
            padding:25px;
            border-radius:15px;
          }

          input{
            width:100%;
            padding:13px;
            margin:7px 0;
            box-sizing:border-box;
          }

          button{
            padding:13px 20px;
            margin-top:10px;
          }
        </style>
      </head>

      <body>

        <div class="box">

          <h2>Administrator Setup</h2>

          <form
            method="POST"
            action="/api/admin/setup"
          >

            <input
              name="setupKey"
              placeholder="Admin Setup Key"
              required
            >

            <input
              name="name"
              placeholder="Administrator Name"
              required
            >

            <input
              name="email"
              type="email"
              placeholder="Administrator Email"
              required
            >

            <input
              name="password"
              type="password"
              placeholder="Administrator Password"
              required
            >

            <button type="submit">
              Create / Update Administrator
            </button>

          </form>

        </div>

      </body>
      </html>
    `);
  }
);

/* =========================================================
   ADMIN SETUP
========================================================= */

app.post(
  "/api/admin/setup",
  authLimiter,
  async (req, res) => {

    try {

      const setupKey =
        String(
          req.body.setupKey || ""
        );

      if (
        !process.env.ADMIN_SETUP_KEY ||
        setupKey !==
          process.env.ADMIN_SETUP_KEY
      ) {
        return res.status(403).json({
          error:
            "Invalid setup key."
        });
      }

      const name =
        String(
          req.body.name || ""
        ).trim();

      const email =
        String(
          req.body.email || ""
        )
        .trim()
        .toLowerCase();

      const password =
        String(
          req.body.password || ""
        );

      if (name.length < 2) {
        return res.status(400).json({
          error:
            "Invalid administrator name."
        });
      }

      if (
        !/^\S+@\S+\.\S+$/.test(email)
      ) {
        return res.status(400).json({
          error:
            "Invalid administrator email."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error:
            "Administrator password must contain at least 8 characters."
        });
      }

      const hash =
        await bcrypt.hash(
          password,
          12
        );

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
          SET
            name = $1,
            password_hash = $2,
            is_admin = TRUE,
            status = 'active'
          WHERE email = $3
          `,
          [
            name,
            hash,
            email
          ]
        );

        return res.json({
          success: true,
          message:
            "Administrator account updated."
        });
      }

      await pool.query(
        `
        INSERT INTO users
        (
          name,
          email,
          password_hash,
          primary_currency,
          is_admin,
          status
        )
        VALUES
        (
          $1,
          $2,
          $3,
          'USD',
          TRUE,
          'active'
        )
        `,
        [
          name,
          email,
          hash
        ]
      );

      res.status(201).json({
        success: true,
        message:
          "Administrator account created."
      });

    } catch (error) {

      console.error(
        "ADMIN SETUP ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to create administrator."
      });
    }
  }
);

/* =========================================================
   STATIC FILES
========================================================= */

app.use(
  express.static(
    path.join(__dirname)
  )
);

/*
  Frontend fallback.
  Does NOT use app.get("*").
*/

app.use(
  (req, res, next) => {

    if (
      req.method !== "GET"
    ) {
      return next();
    }

    if (
      req.path.startsWith(
        "/api/"
      )
    ) {
      return res.status(404).json({
        error:
          "API endpoint not found."
      });
    }

    res.sendFile(
      path.join(
        __dirname,
        "index.html"
      ),
      error => {

        if (error) {
          next(error);
        }

      }
    );
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {

    console.error(
      "SERVER ERROR:",
      error
    );

    if (
      res.headersSent
    ) {
      return next(error);
    }

    res.status(500).json({
      error:
        "Internal server error."
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
          `American Crest fictional demo server running on port ${PORT}`
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
