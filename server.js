const express = require('express');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();

app.set('trust proxy', 1);

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 10000;

const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

const ADMIN_EMAIL =
  String(process.env.ADMIN_EMAIL || '')
    .trim()
    .toLowerCase();

const ADMIN_PASSWORD =
  String(process.env.ADMIN_PASSWORD || '');

if (!JWT_SECRET || !DATABASE_URL) {
  console.error(
    'Missing JWT_SECRET or DATABASE_URL environment variable.'
  );
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : undefined
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 80,
  standardHeaders: true,
  legacyHeaders: false
});

const writeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
});

const CURRENCIES = [
  'NGN',
  'USD',
  'EUR',
  'GBP',
  'IDR',
  'CAD',
  'AUD',
  'CHF',
  'JPY',
  'CNY',
  'INR',
  'MYR',
  'SGD',
  'AED',
  'ZAR',
  'KES',
  'GHS'
];

function uuid() {
  return crypto.randomUUID();
}

function signToken(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: '7d'
    }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';

  const token =
    header.startsWith('Bearer ')
      ? header.slice(7)
      : null;

  if (!token) {
    return res.status(401).json({
      error: 'Authentication required.'
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      error: 'Session expired. Please sign in again.'
    });
  }
}

function adminOnly(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      error: 'Authentication required.'
    });
  }

  if (
    String(req.user.role || '').toLowerCase() !== 'admin'
  ) {
    return res.status(403).json({
      error: 'Administrator access required.'
    });
  }

  next();
}

function validCurrency(currency) {
  return CURRENCIES.includes(
    String(currency || '')
      .trim()
      .toUpperCase()
  );
}

function validUUID(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    String(value || '')
  );
}

async function ensureBalances(userId) {
  for (const currency of CURRENCIES) {
    await pool.query(
      `
      INSERT INTO acb_balances
        (user_id, currency, amount)
      VALUES
        ($1, $2, 0)
      ON CONFLICT (user_id, currency)
      DO NOTHING
      `,
      [userId, currency]
    );
  }
}

async function loadAdminCustomers() {
  const result = await pool.query(`
    SELECT
      u.id,
      u.name,
      u.email,
      u.role,
      u.status,
      u.primary_currency,
      u.profile_image,
      u.created_at,

      COALESCE(
        json_agg(
          json_build_object(
            'currency', b.currency,
            'balance', b.amount
          )
          ORDER BY b.currency
        ) FILTER (WHERE b.currency IS NOT NULL),
        '[]'::json
      ) AS accounts

    FROM acb_users u

    LEFT JOIN acb_balances b
      ON b.user_id = u.id

    WHERE LOWER(u.role) = 'customer'

    GROUP BY
      u.id,
      u.name,
      u.email,
      u.role,
      u.status,
      u.primary_currency,
      u.profile_image,
      u.created_at

    ORDER BY u.created_at DESC
  `);

  return result.rows.map(row => ({
    id: String(row.id),
    name: row.name,
    full_name: row.name,
    fullName: row.name,
    email: row.email,
    role: 'customer',
    status: row.status,

    primary_currency: row.primary_currency,
    primaryCurrency: row.primary_currency,

    profile_image: row.profile_image || '',
    profileImage: row.profile_image || '',

    created_at: row.created_at,
    createdAt: row.created_at,

    accounts:
      Array.isArray(row.accounts)
        ? row.accounts.map(account => ({
            currency: account.currency,
            balance: Number(account.balance || 0),
            amount: Number(account.balance || 0)
          }))
        : []
  }));
}

async function getUser(userId) {
  if (!validUUID(userId)) {
    return null;
  }

  const userResult = await pool.query(
    `
    SELECT
      id,
      name,
      email,
      role,
      status,
      primary_currency,
      profile_image,
      created_at
    FROM acb_users
    WHERE id=$1
    `,
    [userId]
  );

  if (!userResult.rowCount) {
    return null;
  }

  const user = userResult.rows[0];

  const [
    balances,
    transactions,
    notifications,
    support,
    requests
  ] = await Promise.all([
    pool.query(
      `
      SELECT
        currency,
        amount
      FROM acb_balances
      WHERE user_id=$1
      ORDER BY currency
      `,
      [userId]
    ),

    pool.query(
      `
      SELECT
        id,
        kind,
        title,
        amount,
        currency,
        created_at
      FROM acb_transactions
      WHERE user_id=$1
      ORDER BY created_at DESC
      LIMIT 100
      `,
      [userId]
    ),

    pool.query(
      `
      SELECT
        id,
        message,
        created_at,
        read_at
      FROM acb_notifications
      WHERE user_id=$1
      ORDER BY created_at DESC
      LIMIT 50
      `,
      [userId]
    ),

    pool.query(
      `
      SELECT
        id,
        sender,
        message,
        created_at
      FROM acb_support
      WHERE user_id=$1
      ORDER BY created_at ASC
      LIMIT 200
      `,
      [userId]
    ),

    pool.query(
      `
      SELECT
        id,
        currency,
        amount,
        recipient,
        note,
        status,
        created_at,
        handled_at
      FROM acb_requests
      WHERE user_id=$1
      ORDER BY created_at DESC
      LIMIT 50
      `,
      [userId]
    )
  ]);

  const balanceObject = {};

  for (const currency of CURRENCIES) {
    balanceObject[currency] = 0;
  }

  for (const row of balances.rows) {
    balanceObject[row.currency] = Number(row.amount);
  }

  return {
    ...user,

    id: String(user.id),

    primaryCurrency: user.primary_currency,

    profileImage: user.profile_image,

    createdAt: user.created_at,

    balances: balanceObject,

    accounts: CURRENCIES.map(currency => ({
      currency,
      balance: Number(balanceObject[currency] || 0),
      amount: Number(balanceObject[currency] || 0)
    })),

    transactions: transactions.rows.map(row => ({
      ...row,
      id: String(row.id),
      amount: Number(row.amount),
      date: row.created_at
    })),

    notifications: notifications.rows.map(row => ({
      ...row,
      id: String(row.id),
      is_read: !!row.read_at,
      date: row.created_at
    })),

    support: support.rows.map(row => ({
      ...row,
      id: String(row.id),
      date: row.created_at
    })),

    requests: requests.rows.map(row => ({
      ...row,
      id: String(row.id),
      amount: Number(row.amount),
      date: row.created_at
    }))
  };
}


/*
=========================================================
DATABASE
=========================================================
*/

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS acb_users (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'customer',
      status TEXT NOT NULL DEFAULT 'Active',
      primary_currency TEXT NOT NULL DEFAULT 'NGN',
      profile_image TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS acb_balances (
      user_id UUID NOT NULL
        REFERENCES acb_users(id)
        ON DELETE CASCADE,

      currency TEXT NOT NULL,

      amount NUMERIC(24,2)
        NOT NULL DEFAULT 0,

      PRIMARY KEY(user_id,currency)
    );

    CREATE TABLE IF NOT EXISTS acb_transactions (
      id UUID PRIMARY KEY,

      user_id UUID NOT NULL
        REFERENCES acb_users(id)
        ON DELETE CASCADE,

      kind TEXT NOT NULL,
      title TEXT NOT NULL,
      amount NUMERIC(24,2) NOT NULL,
      currency TEXT NOT NULL,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS acb_notifications (
      id UUID PRIMARY KEY,

      user_id UUID NOT NULL
        REFERENCES acb_users(id)
        ON DELETE CASCADE,

      message TEXT NOT NULL,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      read_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS acb_requests (
      id UUID PRIMARY KEY,

      user_id UUID NOT NULL
        REFERENCES acb_users(id)
        ON DELETE CASCADE,

      currency TEXT NOT NULL,
      amount NUMERIC(24,2) NOT NULL,
      recipient TEXT NOT NULL,
      note TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      handled_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS acb_support (
      id UUID PRIMARY KEY,

      user_id UUID NOT NULL
        REFERENCES acb_users(id)
        ON DELETE CASCADE,

      sender TEXT NOT NULL,
      message TEXT NOT NULL,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    );
  `);

  /*
  =======================================================
  CREATE OR REPAIR ADMINISTRATOR
  =======================================================
  */

  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const existing = await pool.query(
      `
      SELECT id
      FROM acb_users
      WHERE email=$1
      LIMIT 1
      `,
      [ADMIN_EMAIL]
    );

    const passwordHash = await bcrypt.hash(
      ADMIN_PASSWORD,
      12
    );

    if (existing.rowCount) {
      await pool.query(
        `
        UPDATE acb_users
        SET
          name=$1,
          password_hash=$2,
          role='admin',
          status='Active'
        WHERE email=$3
        `,
        [
          'Administrator',
          passwordHash,
          ADMIN_EMAIL
        ]
      );

      console.log(
        `Administrator account repaired: ${ADMIN_EMAIL}`
      );
    } else {
      await pool.query(
        `
        INSERT INTO acb_users
          (
            id,
            name,
            email,
            password_hash,
            role,
            status,
            primary_currency,
            profile_image
          )
        VALUES
          (
            $1,
            $2,
            $3,
            $4,
            'admin',
            'Active',
            'NGN',
            ''
          )
        `,
        [
          uuid(),
          'Administrator',
          ADMIN_EMAIL,
          passwordHash
        ]
      );

      console.log(
        `Administrator account created: ${ADMIN_EMAIL}`
      );
    }
  } else {
    console.warn(
      'ADMIN_EMAIL or ADMIN_PASSWORD is not configured.'
    );
  }
}


/*
=========================================================
HEALTH
=========================================================
*/

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    demo: true
  });
});


/*
=========================================================
CUSTOMER REGISTRATION
=========================================================
*/

app.post(
  '/api/auth/register',
  authLimiter,
  async (req, res) => {
    try {
      const name =
        String(req.body.name || '').trim();

      const email =
        String(req.body.email || '')
          .trim()
          .toLowerCase();

      const password =
        String(req.body.password || '');

      const currency =
        String(req.body.currency || 'NGN')
          .toUpperCase();

      if (name.length < 2) {
        return res.status(400).json({
          error: 'Enter your full name.'
        });
      }

      if (!/^\S+@\S+\.\S+$/.test(email)) {
        return res.status(400).json({
          error: 'Enter a valid email address.'
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            'Password must contain at least 6 characters.'
        });
      }

      if (!validCurrency(currency)) {
        return res.status(400).json({
          error: 'Invalid currency.'
        });
      }

      const exists = await pool.query(
        `
        SELECT id
        FROM acb_users
        WHERE email=$1
        LIMIT 1
        `,
        [email]
      );

      if (exists.rowCount) {
        return res.status(409).json({
          error: 'This email is already registered.'
        });
      }

      const userId = uuid();

      const passwordHash =
        await bcrypt.hash(password, 12);

      await pool.query(
        `
        INSERT INTO acb_users
          (
            id,
            name,
            email,
            password_hash,
            role,
            status,
            primary_currency
          )
        VALUES
          (
            $1,
            $2,
            $3,
            $4,
            'customer',
            'Active',
            $5
          )
        `,
        [
          userId,
          name,
          email,
          passwordHash,
          currency
        ]
      );

      await ensureBalances(userId);

      await pool.query(
        `
        INSERT INTO acb_notifications
          (
            id,
            user_id,
            message
          )
        VALUES
          (
            $1,
            $2,
            $3
          )
        `,
        [
          uuid(),
          userId,
          'Your fictional demo account was created successfully.'
        ]
      );

      const admin = await pool.query(
        `
        SELECT id
        FROM acb_users
        WHERE role='admin'
        ORDER BY created_at ASC
        LIMIT 1
        `
      );

      if (admin.rowCount) {
        await pool.query(
          `
          INSERT INTO acb_notifications
            (
              id,
              user_id,
              message
            )
          VALUES
            (
              $1,
              $2,
              $3
            )
          `,
          [
            uuid(),
            admin.rows[0].id,
            `New demo customer registered: ${name} (${email}).`
          ]
        );
      }

      const user = await getUser(userId);

      res.status(201).json({
        ok: true,
        token: signToken(user),
        user,
        customer: user
      });
    } catch (error) {
      console.error(
        'Registration error:',
        error
      );

      res.status(500).json({
        error: 'Unable to create account.'
      });
    }
  }
);


/*
=========================================================
CUSTOMER LOGIN
=========================================================
*/

app.post(
  '/api/auth/login',
  authLimiter,
  async (req, res) => {
    try {
      const email =
        String(req.body.email || '')
          .trim()
          .toLowerCase();

      const password =
        String(req.body.password || '');

      const result = await pool.query(
        `
        SELECT *
        FROM acb_users
        WHERE email=$1
        LIMIT 1
        `,
        [email]
      );

      if (!result.rowCount) {
        return res.status(401).json({
          error: 'Incorrect email or password.'
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          result.rows[0].password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error: 'Incorrect email or password.'
        });
      }

      const user =
        await getUser(result.rows[0].id);

      res.json({
        ok: true,
        token: signToken(user),
        user
      });
    } catch (error) {
      console.error(
        'Login error:',
        error
      );

      res.status(500).json({
        error: 'Unable to sign in.'
      });
    }
  }
);


/*
=========================================================
CURRENT USER
=========================================================
*/

app.get(
  '/api/me',
  auth,
  async (req, res) => {
    const user =
      await getUser(req.user.id);

    if (!user) {
      return res.status(404).json({
        error: 'Account not found.'
      });
    }

    res.json({
      ok: true,
      user,
      customer: user
    });
  }
);


/*
=========================================================
PROFILE
=========================================================
*/

app.put(
  '/api/profile',
  auth,
  writeLimiter,
  async (req, res) => {
    try {
      const name =
        String(req.body.name || '').trim();

      if (name.length < 2) {
        return res.status(400).json({
          error: 'Enter a valid name.'
        });
      }

      await pool.query(
        `
        UPDATE acb_users
        SET name=$1
        WHERE id=$2
        `,
        [
          name,
          req.user.id
        ]
      );

      const user =
        await getUser(req.user.id);

      res.json({
        ok: true,
        user,
        customer: user
      });
    } catch (error) {
      console.error(
        'Profile update error:',
        error
      );

      res.status(500).json({
        error: 'Unable to update profile.'
      });
    }
  }
);

app.post(
  '/api/profile/image',
  auth,
  writeLimiter,
  async (req, res) => {
    try {
      const image =
        String(req.body.profileImage || '');

      if (image.length > 700000) {
        return res.status(400).json({
          error: 'Profile image is too large.'
        });
      }

      if (
        image &&
        !/^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(
          image
        )
      ) {
        return res.status(400).json({
          error: 'Invalid image format.'
        });
      }

      await pool.query(
        `
        UPDATE acb_users
        SET profile_image=$1
        WHERE id=$2
        `,
        [
          image,
          req.user.id
        ]
      );

      const user =
        await getUser(req.user.id);

      res.json({
        ok: true,
        user,
        customer: user
      });
    } catch (error) {
      console.error(
        'Profile image error:',
        error
      );

      res.status(500).json({
        error: 'Unable to update profile image.'
      });
    }
  }
);


/*
=========================================================
CUSTOMER REQUEST
=========================================================
*/

app.post(
  '/api/requests',
  auth,
  writeLimiter,
  async (req, res) => {
    try {
      const currency =
        String(req.body.currency || '')
          .toUpperCase();

      const amount =
        Number(req.body.amount);

      const recipient =
        String(req.body.recipient || '')
          .trim();

      const note =
        String(req.body.note || '')
          .trim()
          .slice(0, 500);

      if (
        !validCurrency(currency) ||
        !Number.isFinite(amount) ||
        amount <= 0 ||
        amount > 1000000000000
      ) {
        return res.status(400).json({
          error:
            'Enter a valid amount and currency.'
        });
      }

      if (recipient.length < 2) {
        return res.status(400).json({
          error: 'Enter the recipient name.'
        });
      }

      const requestId = uuid();

      await pool.query(
        `
        INSERT INTO acb_requests
          (
            id,
            user_id,
            currency,
            amount,
            recipient,
            note,
            status
          )
        VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            'pending'
          )
        `,
        [
          requestId,
          req.user.id,
          currency,
          amount,
          recipient,
          note
        ]
      );

      const customer =
        await getUser(req.user.id);

      const admin = await pool.query(
        `
        SELECT id
        FROM acb_users
        WHERE role='admin'
        ORDER BY created_at ASC
        LIMIT 1
        `
      );

      if (admin.rowCount) {
        await pool.query(
          `
          INSERT INTO acb_notifications
            (
              id,
              user_id,
              message
            )
          VALUES
            (
              $1,
              $2,
              $3
            )
          `,
          [
            uuid(),
            admin.rows[0].id,
            `New demo funds request from ${customer.name}: ${amount} ${currency} for ${recipient}.`
          ]
        );
      }

      res.status(201).json({
        ok: true,
        request: {
          id: requestId,
          status: 'pending'
        },
        user: customer,
        customer
      });
    } catch (error) {
      console.error(
        'Request error:',
        error
      );

      res.status(500).json({
        error: 'Unable to send request.'
      });
    }
  }
);


/*
=========================================================
ADMIN LOGIN
=========================================================
*/

app.post(
  '/api/admin/login',
  authLimiter,
  async (req, res) => {
    try {
      const email =
        String(req.body.email || '')
          .trim()
          .toLowerCase();

      const password =
        String(req.body.password || '');

      const result = await pool.query(
        `
        SELECT *
        FROM acb_users
        WHERE email=$1
        AND LOWER(role)='admin'
        LIMIT 1
        `,
        [email]
      );

      if (!result.rowCount) {
        return res.status(401).json({
          error:
            'Invalid administrator email or password.'
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          result.rows[0].password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            'Invalid administrator email or password.'
        });
      }

      const user =
        await getUser(result.rows[0].id);

      if (
        !user ||
        String(user.role).toLowerCase() !== 'admin'
      ) {
        return res.status(403).json({
          error:
            'Administrator access required.'
        });
      }

      res.json({
        ok: true,
        token: signToken(user),
        user
      });
    } catch (error) {
      console.error(
        'Admin login error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to sign in as administrator.'
      });
    }
  }
);


/*
=========================================================
ADMIN SUMMARY
=========================================================
*/

app.get(
  '/api/admin/summary',
  auth,
  adminOnly,
  async (_req, res) => {
    try {
      const customers =
        await pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM acb_users
          WHERE role='customer'
          `
        );

      const pending =
        await pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM acb_requests
          WHERE status='pending'
          `
        );

      const support =
        await pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM acb_support
          WHERE sender='customer'
          `
        );

      const balanceResult =
        await pool.query(
          `
          SELECT
            currency,
            COALESCE(SUM(amount),0) AS total
          FROM acb_balances b
          JOIN acb_users u
            ON u.id=b.user_id
          WHERE u.role='customer'
          GROUP BY currency
          ORDER BY currency
          `
        );

      const customerCount =
        Number(customers.rows[0].count);

      const pendingCount =
        Number(pending.rows[0].count);

      const supportCount =
        Number(support.rows[0].count);

      res.json({
        ok: true,

        customers: customerCount,
        customerCount: customerCount,
        totalCustomers: customerCount,

        pendingTransfers: pendingCount,
        pending_transfers: pendingCount,

        openSupport: supportCount,
        open_support: supportCount,

        balances:
          balanceResult.rows.map(row => ({
            currency: row.currency,
            total: Number(row.total)
          }))
      });
    } catch (error) {
      console.error(
        'Admin summary error:',
        error
      );

      res.status(500).json({
        error: 'Unable to load dashboard.'
      });
    }
  }
);


/*
=========================================================
ADMIN CUSTOMERS
=========================================================
*/

app.get(
  '/api/admin/customers',
  auth,
  adminOnly,
  async (_req, res) => {
    try {
      const customers =
        await loadAdminCustomers();

      console.log(
        `[ADMIN CUSTOMERS] ${customers.length} customer(s) found`
      );

      res.json({
        ok: true,
        customers,
        users: customers,
        data: customers,
        items: customers,
        total: customers.length,
        count: customers.length
      });
    } catch (error) {
      console.error(
        'Admin customers error:',
        error
      );

      res.status(500).json({
        ok: false,
        error: 'Unable to load customers.',
        customers: [],
        users: [],
        data: [],
        items: []
      });
    }
  }
);


/*
=========================================================
ADMIN USERS COMPATIBILITY ENDPOINT
=========================================================
*/

app.get(
  '/api/admin/users',
  auth,
  adminOnly,
  async (_req, res) => {
    try {
      const customers =
        await loadAdminCustomers();

      res.json({
        ok: true,
        users: customers,
        customers: customers,
        data: customers,
        total: customers.length,
        count: customers.length
      });
    } catch (error) {
      console.error(
        'Admin users error:',
        error
      );

      res.status(500).json({
        ok: false,
        error: 'Unable to load users.',
        users: [],
        customers: [],
        data: []
      });
    }
  }
);


/*
=========================================================
ADMIN STATE
=========================================================
*/

app.get(
  '/api/admin/state',
  auth,
  adminOnly,
  async (_req, res) => {
    try {
      const customers =
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
          FROM acb_users
          WHERE role='customer'
          ORDER BY created_at DESC
          `
        );

      const requests =
        await pool.query(
          `
          SELECT
            r.id,
            r.user_id,
            u.name,
            u.email,
            r.currency,
            r.amount,
            r.recipient,
            r.note,
            r.status,
            r.created_at,
            r.handled_at
          FROM acb_requests r
          JOIN acb_users u
            ON u.id=r.user_id
          ORDER BY r.created_at DESC
          LIMIT 100
          `
        );

      const support =
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
          FROM acb_support s
          JOIN acb_users u
            ON u.id=s.user_id
          ORDER BY s.created_at DESC
          LIMIT 200
          `
        );

      res.json({
        ok: true,

        customers:
          customers.rows.map(row => ({
            ...row,
            id: String(row.id),
            full_name: row.name,
            fullName: row.name,
            primaryCurrency: row.primary_currency,
            profileImage: row.profile_image || '',
            createdAt: row.created_at
          })),

        requests:
          requests.rows.map(row => ({
            ...row,
            id: String(row.id),
            user_id: String(row.user_id),
            amount: Number(row.amount),
            date: row.created_at
          })),

        support:
          support.rows.map(row => ({
            ...row,
            id: String(row.id),
            user_id: String(row.user_id),
            date: row.created_at
          }))
      });
    } catch (error) {
      console.error(
        'Admin state error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to load administrator data.'
      });
    }
  }
);


/*
=========================================================
ADMIN NOTIFICATIONS
=========================================================
*/

app.get(
  '/api/admin/notifications',
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            n.id,
            n.user_id,
            n.message,
            n.created_at,
            n.read_at
          FROM acb_notifications n
          JOIN acb_users u
            ON u.id=n.user_id
          WHERE n.user_id=$1
          AND LOWER(u.role)='admin'
          ORDER BY n.created_at DESC
          LIMIT 100
          `,
          [req.user.id]
        );

      res.json({
        ok: true,
        notifications:
          result.rows.map(row => ({
            id: String(row.id),
            user_id: String(row.user_id),
            title: 'Customer Activity',
            message: row.message,
            created_at: row.created_at,
            is_read: !!row.read_at
          }))
      });
    } catch (error) {
      console.error(
        'Admin notification error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to load notifications.'
      });
    }
  }
);


/*
=========================================================
ADMIN MARK NOTIFICATION READ
=========================================================
*/

app.patch(
  '/api/admin/notifications/:id/read',
  auth,
  adminOnly,
  async (req, res) => {
    try {
      if (!validUUID(req.params.id)) {
        return res.status(400).json({
          error: 'Invalid notification ID.'
        });
      }

      await pool.query(
        `
        UPDATE acb_notifications
        SET read_at=NOW()
        WHERE id=$1
        AND user_id=$2
        `,
        [
          req.params.id,
          req.user.id
        ]
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        'Mark notification error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to update notification.'
      });
    }
  }
);


/*
=========================================================
ADMIN CREDIT CUSTOMER
=========================================================

FIXED:
- Accepts userId / customerId / id.
- Accepts currency from multiple frontend field names.
- Accepts amount safely.
- Uses one database transaction.
- Locks the customer while updating.
- Creates balance + transaction + notification together.
- Returns the complete updated customer.
- Provides compatibility response fields.
=========================================================
*/

async function creditCustomerAccount({
  userId,
  currency,
  amount,
  description
}) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const customerResult =
      await client.query(
        `
        SELECT
          id,
          name,
          email,
          status,
          primary_currency
        FROM acb_users
        WHERE id=$1
        AND LOWER(role)='customer'
        FOR UPDATE
        `,
        [userId]
      );

    if (!customerResult.rowCount) {
      throw Object.assign(
        new Error('Customer not found.'),
        {
          code: 'CUSTOMER_NOT_FOUND'
        }
      );
    }

    const customer =
      customerResult.rows[0];

    await client.query(
      `
      INSERT INTO acb_balances
        (
          user_id,
          currency,
          amount
        )
      VALUES
        (
          $1,
          $2,
          $3
        )
      ON CONFLICT(user_id,currency)
      DO UPDATE SET
        amount =
          acb_balances.amount +
          EXCLUDED.amount
      `,
      [
        userId,
        currency,
        amount
      ]
    );

    const transactionId = uuid();

    await client.query(
      `
      INSERT INTO acb_transactions
        (
          id,
          user_id,
          kind,
          title,
          amount,
          currency
        )
      VALUES
        (
          $1,
          $2,
          'credit',
          $3,
          $4,
          $5
        )
      `,
      [
        transactionId,
        userId,
        description ||
          'Funds credited by demo administrator',
        amount,
        currency
      ]
    );

    const notificationId = uuid();

    await client.query(
      `
      INSERT INTO acb_notifications
        (
          id,
          user_id,
          message
        )
      VALUES
        (
          $1,
          $2,
          $3
        )
      `,
      [
        notificationId,
        userId,
        `A demo credit of ${amount.toLocaleString()} ${currency} was added to your account.`
      ]
    );

    const balanceResult =
      await client.query(
        `
        SELECT amount
        FROM acb_balances
        WHERE user_id=$1
        AND currency=$2
        `,
        [
          userId,
          currency
        ]
      );

    const newBalance =
      Number(
        balanceResult.rows[0]?.amount || 0
      );

    await client.query('COMMIT');

    return {
      customer,
      newBalance,
      transactionId,
      notificationId
    };
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {}

    throw error;
  } finally {
    client.release();
  }
}

app.post(
  '/api/admin/customers/:id/funds',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    try {
      const userId =
        String(
          req.params.id ||
          req.body.userId ||
          req.body.customerId ||
          req.body.customer_id ||
          req.body.id ||
          ''
        ).trim();

      const currency =
        String(
          req.body.currency ||
          req.body.currencyCode ||
          req.body.currency_code ||
          ''
        )
          .trim()
          .toUpperCase();

      const amount =
        Number(
          req.body.amount ??
          req.body.value ??
          req.body.funds
        );

      const description =
        String(
          req.body.description ||
          req.body.note ||
          req.body.title ||
          'Administrator account funding'
        )
          .trim()
          .slice(0, 500);

      if (!validUUID(userId)) {
        return res.status(400).json({
          ok: false,
          error: 'Invalid customer ID.'
        });
      }

      if (
        !validCurrency(currency) ||
        !Number.isFinite(amount) ||
        amount <= 0 ||
        amount > 1000000000000
      ) {
        return res.status(400).json({
          ok: false,
          error:
            'Enter a valid customer, currency and amount.'
        });
      }

      const result =
        await creditCustomerAccount({
          userId,
          currency,
          amount,
          description
        });

      const updatedUser =
        await getUser(userId);

      if (!updatedUser) {
        return res.status(404).json({
          ok: false,
          error: 'Customer not found.'
        });
      }

      res.json({
        ok: true,

        success: true,

        message:
          `Customer account funded successfully. ${amount.toLocaleString()} ${currency} added.`,

        user: updatedUser,

        customer: updatedUser,

        updatedCustomer: updatedUser,

        balance:
          Number(
            updatedUser.balances?.[currency] || 0
          ),

        balances:
          updatedUser.balances,

        currency,

        amount
      });
    } catch (error) {
      console.error(
        'Admin credit customer error:',
        error
      );

      if (
        error.code ===
        'CUSTOMER_NOT_FOUND'
      ) {
        return res.status(404).json({
          ok: false,
          error: 'Customer not found.'
        });
      }

      res.status(500).json({
        ok: false,
        error:
          'Unable to credit customer.'
      });
    }
  }
);


/*
=========================================================
OLD ADMIN CREDIT ENDPOINT
=========================================================
*/

app.post(
  '/api/admin/credit',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    try {
      const userId =
        String(
          req.body.userId ||
          req.body.customerId ||
          req.body.customer_id ||
          req.body.id ||
          ''
        ).trim();

      const currency =
        String(
          req.body.currency ||
          req.body.currencyCode ||
          req.body.currency_code ||
          ''
        )
          .trim()
          .toUpperCase();

      const amount =
        Number(
          req.body.amount ??
          req.body.value ??
          req.body.funds
        );

      const description =
        String(
          req.body.description ||
          req.body.note ||
          'Funds credited by demo administrator'
        )
          .trim()
          .slice(0, 500);

      if (!validUUID(userId)) {
        return res.status(400).json({
          ok: false,
          error: 'Invalid customer ID.'
        });
      }

      if (
        !validCurrency(currency) ||
        !Number.isFinite(amount) ||
        amount <= 0 ||
        amount > 1000000000000
      ) {
        return res.status(400).json({
          ok: false,
          error:
            'Enter a valid customer, currency and amount.'
        });
      }

      const result =
        await creditCustomerAccount({
          userId,
          currency,
          amount,
          description
        });

      const updatedUser =
        await getUser(userId);

      res.json({
        ok: true,
        success: true,

        message:
          `Customer account funded successfully. ${amount.toLocaleString()} ${currency} added.`,

        user: updatedUser,
        customer: updatedUser,
        updatedCustomer: updatedUser,

        balance:
          Number(
            updatedUser?.balances?.[currency] || 0
          ),

        balances:
          updatedUser?.balances || {},

        currency,
        amount,

        transactionId:
          result.transactionId
      });
    } catch (error) {
      console.error(
        'Admin credit error:',
        error
      );

      if (
        error.code ===
        'CUSTOMER_NOT_FOUND'
      ) {
        return res.status(404).json({
          ok: false,
          error: 'Customer not found.'
        });
      }

      res.status(500).json({
        ok: false,
        error:
          'Unable to credit customer.'
      });
    }
  }
);


/*
=========================================================
ADMIN SEND CUSTOMER NOTIFICATION
=========================================================
*/

app.post(
  '/api/admin/notify',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    try {
      const userId =
        String(
          req.body.userId ||
          req.body.customerId ||
          req.body.customer_id ||
          ''
        );

      const message =
        String(req.body.message || '')
          .trim()
          .slice(0, 1000);

      if (!validUUID(userId)) {
        return res.status(400).json({
          error: 'Invalid customer ID.'
        });
      }

      if (!message) {
        return res.status(400).json({
          error:
            'Select a customer and write a notification.'
        });
      }

      const customer =
        await pool.query(
          `
          SELECT id
          FROM acb_users
          WHERE id=$1
          AND role='customer'
          `,
          [userId]
        );

      if (!customer.rowCount) {
        return res.status(404).json({
          error: 'Customer not found.'
        });
      }

      await pool.query(
        `
        INSERT INTO acb_notifications
          (
            id,
            user_id,
            message
          )
        VALUES
          (
            $1,$2,$3
          )
        `,
        [
          uuid(),
          userId,
          message
        ]
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        'Admin notify error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to send notification.'
      });
    }
  }
);


/*
=========================================================
ADMIN CUSTOMER STATUS
=========================================================
*/

app.patch(
  '/api/admin/customers/:id/status',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    try {
      if (!validUUID(req.params.id)) {
        return res.status(400).json({
          error: 'Invalid customer ID.'
        });
      }

      const status =
        String(req.body.status || '')
          .trim();

      if (
        ![
          'active',
          'Active',
          'suspended',
          'Suspended',
          'pending',
          'Pending'
        ].includes(status)
      ) {
        return res.status(400).json({
          error: 'Invalid account status.'
        });
      }

      const normalized =
        status.toLowerCase() === 'active'
          ? 'Active'
          : status.toLowerCase() === 'suspended'
            ? 'Suspended'
            : 'Pending';

      const result =
        await pool.query(
          `
          UPDATE acb_users
          SET status=$1
          WHERE id=$2
          AND role='customer'
          RETURNING id
          `,
          [
            normalized,
            req.params.id
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          error: 'Customer not found.'
        });
      }

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        'Customer status error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to change account status.'
      });
    }
  }
);


/*
=========================================================
ADMIN SUPPORT
=========================================================
*/

app.get(
  '/api/admin/support',
  auth,
  adminOnly,
  async (_req, res) => {
    try {
      const result =
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
          FROM acb_support s
          JOIN acb_users u
            ON u.id=s.user_id
          WHERE LOWER(u.role)='customer'
          ORDER BY s.created_at ASC
          LIMIT 200
          `
        );

      const grouped = {};

      for (const row of result.rows) {
        const userId =
          String(row.user_id);

        if (!grouped[userId]) {
          grouped[userId] = {
            id: String(row.id),
            user_id: userId,

            customerId: userId,

            full_name: row.name,
            fullName: row.name,
            name: row.name,

            email: row.email,

            subject: 'Customer Support',

            message: row.message,

            status:
              row.sender === 'admin'
                ? 'answered'
                : 'pending',

            created_at: row.created_at,

            messages: []
          };
        }

        grouped[userId].messages.push({
          id: String(row.id),
          user_id: userId,
          sender: row.sender,
          message: row.message,
          created_at: row.created_at,
          date: row.created_at
        });
      }

      res.json({
        ok: true,
        tickets: Object.values(grouped),

        support: Object.values(grouped),

        data: Object.values(grouped)
      });
    } catch (error) {
      console.error(
        'Admin support error:',
        error
      );

      res.status(500).json({
        ok: false,
        error:
          'Unable to load support requests.',
        tickets: [],
        support: [],
        data: []
      });
    }
  }
);


/*
=========================================================
CUSTOMER SUPPORT
=========================================================
*/

app.post(
  '/api/support',
  auth,
  writeLimiter,
  async (req, res) => {
    try {
      const message =
        String(req.body.message || '')
          .trim()
          .slice(0, 2000);

      if (!message) {
        return res.status(400).json({
          error: 'Write a message first.'
        });
      }

      const supportId = uuid();

      await pool.query(
        `
        INSERT INTO acb_support
          (
            id,
            user_id,
            sender,
            message
          )
        VALUES
          (
            $1,
            $2,
            'customer',
            $3
          )
        `,
        [
          supportId,
          req.user.id,
          message
        ]
      );

      const customer =
        await getUser(req.user.id);

      const admin =
        await pool.query(
          `
          SELECT id
          FROM acb_users
          WHERE LOWER(role)='admin'
          ORDER BY created_at ASC
          LIMIT 1
          `
        );

      if (admin.rowCount) {
        await pool.query(
          `
          INSERT INTO acb_notifications
            (
              id,
              user_id,
              message
            )
          VALUES
            (
              $1,
              $2,
              $3
            )
          `,
          [
            uuid(),
            admin.rows[0].id,
            `New support message from ${customer.name} (${customer.email}).`
          ]
        );
      }

      res.status(201).json({
        ok: true,
        supportId,
        user: customer,
        customer
      });
    } catch (error) {
      console.error(
        'Customer support error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to send support message.'
      });
    }
  }
);


/*
=========================================================
ADMIN SUPPORT REPLY
=========================================================

FIXED:
- Accepts either a support message ID or customer ID.
- Correctly resolves the customer.
- Saves the admin reply.
- Sends customer notification.
- Returns the complete updated customer.
- Returns support conversation.
- Supports both old and new frontend payload formats.
=========================================================
*/

async function sendAdminSupportReply({
  userId,
  message
}) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const customerResult =
      await client.query(
        `
        SELECT
          id,
          name,
          email
        FROM acb_users
        WHERE id=$1
        AND LOWER(role)='customer'
        FOR UPDATE
        `,
        [userId]
      );

    if (!customerResult.rowCount) {
      throw Object.assign(
        new Error('Customer not found.'),
        {
          code: 'CUSTOMER_NOT_FOUND'
        }
      );
    }

    const supportId = uuid();

    await client.query(
      `
      INSERT INTO acb_support
        (
          id,
          user_id,
          sender,
          message
        )
      VALUES
        (
          $1,
          $2,
          'admin',
          $3
        )
      `,
      [
        supportId,
        userId,
        message
      ]
    );

    const notificationId = uuid();

    await client.query(
      `
      INSERT INTO acb_notifications
        (
          id,
          user_id,
          message
        )
      VALUES
        (
          $1,
          $2,
          $3
        )
      `,
      [
        notificationId,
        userId,
        'You received a new support reply from the administrator.'
      ]
    );

    await client.query('COMMIT');

    return {
      supportId,
      notificationId,
      customer:
        customerResult.rows[0]
    };
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {}

    throw error;
  } finally {
    client.release();
  }
}

async function resolveSupportCustomerId(identifier) {
  if (!identifier) {
    return null;
  }

  const value =
    String(identifier).trim();

  /*
  First: treat it as a customer UUID.
  */
  if (validUUID(value)) {
    const customer =
      await pool.query(
        `
        SELECT id
        FROM acb_users
        WHERE id=$1
        AND LOWER(role)='customer'
        LIMIT 1
        `,
        [value]
      );

    if (customer.rowCount) {
      return String(customer.rows[0].id);
    }

    /*
    Otherwise treat the UUID as a support-message ID.
    */
    const support =
      await pool.query(
        `
        SELECT user_id
        FROM acb_support
        WHERE id=$1
        LIMIT 1
        `,
        [value]
      );

    if (support.rowCount) {
      return String(support.rows[0].user_id);
    }
  }

  return null;
}


/*
---------------------------------------------------------
PRIMARY SUPPORT REPLY ENDPOINT
---------------------------------------------------------
*/

app.post(
  '/api/admin/support/:id/reply',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    try {
      const identifier =
        String(
          req.params.id ||
          req.body.userId ||
          req.body.customerId ||
          req.body.customer_id ||
          req.body.ticketId ||
          req.body.ticket_id ||
          ''
        ).trim();

      const message =
        String(
          req.body.message ||
          req.body.reply ||
          req.body.text ||
          ''
        )
          .trim()
          .slice(0, 2000);

      if (!identifier) {
        return res.status(400).json({
          ok: false,
          error:
            'Select a customer support request.'
        });
      }

      if (!message) {
        return res.status(400).json({
          ok: false,
          error:
            'Write a reply first.'
        });
      }

      const userId =
        await resolveSupportCustomerId(
          identifier
        );

      if (!userId) {
        return res.status(404).json({
          ok: false,
          error:
            'Customer support request not found.'
        });
      }

      const result =
        await sendAdminSupportReply({
          userId,
          message
        });

      const updatedUser =
        await getUser(userId);

      res.json({
        ok: true,
        success: true,

        message:
          'Support reply sent successfully.',

        supportId:
          result.supportId,

        notificationId:
          result.notificationId,

        user: updatedUser,

        customer: updatedUser,

        updatedCustomer: updatedUser,

        support:
          updatedUser?.support || []
      });
    } catch (error) {
      console.error(
        'Support reply error:',
        error
      );

      if (
        error.code ===
        'CUSTOMER_NOT_FOUND'
      ) {
        return res.status(404).json({
          ok: false,
          error: 'Customer not found.'
        });
      }

      res.status(500).json({
        ok: false,
        error:
          'Unable to send response.'
      });
    }
  }
);


/*
---------------------------------------------------------
OLD ADMIN SUPPORT REPLY
---------------------------------------------------------
*/

app.post(
  '/api/admin/support/reply',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    try {
      const identifier =
        String(
          req.body.userId ||
          req.body.customerId ||
          req.body.customer_id ||
          req.body.ticketId ||
          req.body.ticket_id ||
          req.body.id ||
          ''
        ).trim();

      const message =
        String(
          req.body.message ||
          req.body.reply ||
          req.body.text ||
          ''
        )
          .trim()
          .slice(0, 2000);

      if (!identifier) {
        return res.status(400).json({
          ok: false,
          error:
            'Select a customer support request.'
        });
      }

      if (!message) {
        return res.status(400).json({
          ok: false,
          error:
            'Write a reply first.'
        });
      }

      const userId =
        await resolveSupportCustomerId(
          identifier
        );

      if (!userId) {
        return res.status(404).json({
          ok: false,
          error:
            'Customer support request not found.'
        });
      }

      const result =
        await sendAdminSupportReply({
          userId,
          message
        });

      const updatedUser =
        await getUser(userId);

      res.json({
        ok: true,
        success: true,

        message:
          'Support reply sent successfully.',

        supportId:
          result.supportId,

        notificationId:
          result.notificationId,

        user: updatedUser,

        customer: updatedUser,

        updatedCustomer: updatedUser,

        support:
          updatedUser?.support || []
      });
    } catch (error) {
      console.error(
        'Support reply error:',
        error
      );

      if (
        error.code ===
        'CUSTOMER_NOT_FOUND'
      ) {
        return res.status(404).json({
          ok: false,
          error: 'Customer not found.'
        });
      }

      res.status(500).json({
        ok: false,
        error:
          'Unable to send response.'
      });
    }
  }
);


/*
=========================================================
ADMIN TRANSFERS
=========================================================
*/

app.get(
  '/api/admin/transfers',
  auth,
  adminOnly,
  async (_req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            r.id,
            r.user_id,
            u.name,
            u.email,
            r.currency,
            r.amount,
            r.recipient,
            r.note,
            r.status,
            r.created_at,
            r.handled_at
          FROM acb_requests r
          JOIN acb_users u
            ON u.id=r.user_id
          ORDER BY r.created_at DESC
          LIMIT 200
          `
        );

      res.json({
        ok: true,

        transfers:
          result.rows.map(row => ({
            id: String(row.id),

            user_id:
              String(row.user_id),

            customerId:
              String(row.user_id),

            full_name:
              row.name,

            fullName:
              row.name,

            name:
              row.name,

            email:
              row.email,

            currency:
              row.currency,

            amount:
              Number(row.amount),

            recipient:
              row.recipient,

            reference:
              String(row.id),

            note:
              row.note,

            status:
              row.status,

            created_at:
              row.created_at,

            handled_at:
              row.handled_at
          }))
      });
    } catch (error) {
      console.error(
        'Admin transfers error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to load transfers.'
      });
    }
  }
);


/*
=========================================================
ADMIN TRANSFER STATUS
=========================================================
*/

app.patch(
  '/api/admin/transfers/:id/status',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      if (!validUUID(req.params.id)) {
        return res.status(400).json({
          error: 'Invalid transfer ID.'
        });
      }

      const status =
        String(req.body.status || '')
          .trim()
          .toLowerCase();

      if (
        ![
          'successful',
          'approved',
          'declined'
        ].includes(status)
      ) {
        return res.status(400).json({
          error:
            'Invalid transfer status.'
        });
      }

      await client.query('BEGIN');

      const requestResult =
        await client.query(
          `
          SELECT
            r.*,
            u.name,
            u.email
          FROM acb_requests r
          JOIN acb_users u
            ON u.id=r.user_id
          WHERE r.id=$1
          FOR UPDATE
          `,
          [req.params.id]
        );

      if (!requestResult.rowCount) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          error: 'Transfer not found.'
        });
      }

      const request =
        requestResult.rows[0];

      if (request.status !== 'pending') {
        await client.query('ROLLBACK');

        return res.status(409).json({
          error:
            'This transfer has already been handled.'
        });
      }

      if (status === 'declined') {
        await client.query(
          `
          UPDATE acb_requests
          SET
            status='declined',
            handled_at=NOW()
          WHERE id=$1
          `,
          [request.id]
        );

        await client.query(
          `
          INSERT INTO acb_notifications
            (
              id,
              user_id,
              message
            )
          VALUES
            (
              $1,
              $2,
              $3
            )
          `,
          [
            uuid(),
            request.user_id,
            `Your demo transfer request for ${Number(request.amount).toLocaleString()} ${request.currency} was declined.`
          ]
        );

        await client.query('COMMIT');

        const updatedUser =
          await getUser(
            String(request.user_id)
          );

        return res.json({
          ok: true,
          status: 'declined',
          user: updatedUser,
          customer: updatedUser
        });
      }

      await client.query(
        `
        INSERT INTO acb_balances
          (
            user_id,
            currency,
            amount
          )
        VALUES
          (
            $1,
            $2,
            $3
          )
        ON CONFLICT(user_id,currency)
        DO UPDATE SET
          amount =
            acb_balances.amount +
            EXCLUDED.amount
        `,
        [
          request.user_id,
          request.currency,
          request.amount
        ]
      );

      await client.query(
        `
        INSERT INTO acb_transactions
          (
            id,
            user_id,
            kind,
            title,
            amount,
            currency
          )
        VALUES
          (
            $1,
            $2,
            'credit',
            $3,
            $4,
            $5
          )
        `,
        [
          uuid(),
          request.user_id,
          'Funds received from administrator',
          request.amount,
          request.currency
        ]
      );

      await client.query(
        `
        INSERT INTO acb_notifications
          (
            id,
            user_id,
            message
          )
        VALUES
          (
            $1,
            $2,
            $3
          )
        `,
        [
          uuid(),
          request.user_id,
          `You received ${Number(request.amount).toLocaleString()} ${request.currency}. Your demo account balance has been updated.`
        ]
      );

      await client.query(
        `
        UPDATE acb_requests
        SET
          status=$1,
          handled_at=NOW()
        WHERE id=$2
        AND status='pending'
        `,
        [
          status,
          request.id
        ]
      );

      await client.query('COMMIT');

      const updatedUser =
        await getUser(
          String(request.user_id)
        );

      res.json({
        ok: true,

        status,

        message:
          `Customer received ${Number(request.amount).toLocaleString()} ${request.currency}.`,

        user: updatedUser,

        customer: updatedUser,

        balance:
          updatedUser?.balances?.[request.currency] ?? 0
      });
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {}

      console.error(
        'Transfer status error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to update transfer.'
      });
    } finally {
      client.release();
    }
  }
);


/*
=========================================================
OLD REQUEST APPROVE
=========================================================
*/

app.post(
  '/api/admin/requests/:id/approve',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      if (!validUUID(req.params.id)) {
        return res.status(400).json({
          error: 'Invalid request ID.'
        });
      }

      await client.query('BEGIN');

      const result =
        await client.query(
          `
          SELECT *
          FROM acb_requests
          WHERE id=$1
          FOR UPDATE
          `,
          [req.params.id]
        );

      if (!result.rowCount) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          error: 'Request not found.'
        });
      }

      const request =
        result.rows[0];

      if (request.status !== 'pending') {
        await client.query('ROLLBACK');

        return res.status(409).json({
          error:
            'This request has already been handled.'
        });
      }

      await client.query(
        `
        INSERT INTO acb_balances
          (
            user_id,
            currency,
            amount
          )
        VALUES
          ($1,$2,$3)
        ON CONFLICT(user_id,currency)
        DO UPDATE SET
          amount =
            acb_balances.amount +
            EXCLUDED.amount
        `,
        [
          request.user_id,
          request.currency,
          request.amount
        ]
      );

      await client.query(
        `
        INSERT INTO acb_transactions
          (
            id,
            user_id,
            kind,
            title,
            amount,
            currency
          )
        VALUES
          (
            $1,
            $2,
            'credit',
            'Funds received from administrator',
            $3,
            $4
          )
        `,
        [
          uuid(),
          request.user_id,
          request.amount,
          request.currency
        ]
      );

      await client.query(
        `
        INSERT INTO acb_notifications
          (
            id,
            user_id,
            message
          )
        VALUES
          (
            $1,
            $2,
            $3
          )
        `,
        [
          uuid(),
          request.user_id,
          `You received ${Number(request.amount).toLocaleString()} ${request.currency}. Your demo account balance has been updated.`
        ]
      );

      await client.query(
        `
        UPDATE acb_requests
        SET
          status='approved',
          handled_at=NOW()
        WHERE id=$1
        `,
        [request.id]
      );

      await client.query('COMMIT');

      const updatedUser =
        await getUser(
          String(request.user_id)
        );

      res.json({
        ok: true,

        user: updatedUser,

        customer: updatedUser,

        balance:
          updatedUser?.balances?.[request.currency] ?? 0
      });
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {}

      console.error(
        'Approve request error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to approve request.'
      });
    } finally {
      client.release();
    }
  }
);


/*
=========================================================
OLD REQUEST REJECT
=========================================================
*/

app.post(
  '/api/admin/requests/:id/reject',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    try {
      if (!validUUID(req.params.id)) {
        return res.status(400).json({
          error: 'Invalid request ID.'
        });
      }

      const result =
        await pool.query(
          `
          UPDATE acb_requests
          SET
            status='rejected',
            handled_at=NOW()
          WHERE id=$1
          AND status='pending'
          RETURNING
            user_id,
            amount,
            currency
          `,
          [req.params.id]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          error:
            'Pending request not found.'
        });
      }

      const row =
        result.rows[0];

      await pool.query(
        `
        INSERT INTO acb_notifications
          (
            id,
            user_id,
            message
          )
        VALUES
          (
            $1,
            $2,
            $3
          )
        `,
        [
          uuid(),
          row.user_id,
          `Your demo request for ${Number(row.amount).toLocaleString()} ${row.currency} was not approved.`
        ]
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        'Reject request error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to reject request.'
      });
    }
  }
);


/*
=========================================================
SPA FALLBACK
=========================================================
*/

app.get(
  '/{*splat}',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'index.html'
      )
    );
  }
);


/*
=========================================================
START SERVER
=========================================================
*/

initDb()
  .then(() => {
    app.listen(
      PORT,
      () => {
        console.log(
          `American Crest demo server listening on ${PORT}`
        );
      }
    );
  })
  .catch(error => {
    console.error(
      'Database initialization failed:',
      error
    );

    process.exit(1);
  });
