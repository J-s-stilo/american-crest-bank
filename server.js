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
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

if (!JWT_SECRET || !DATABASE_URL) {
  console.error('Missing JWT_SECRET or DATABASE_URL environment variable.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
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
  'NGN','USD','EUR','GBP','IDR','CAD','AUD',
  'CHF','JPY','CNY','INR','MYR','SGD','AED',
  'ZAR','KES','GHS'
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
    { expiresIn: '7d' }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';

  const token = header.startsWith('Bearer ')
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
  } catch {
    return res.status(401).json({
      error: 'Session expired. Please sign in again.'
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({
      error: 'Administrator access required.'
    });
  }

  next();
}

function validCurrency(currency) {
  return CURRENCIES.includes(
    String(currency || '').toUpperCase()
  );
}

async function ensureBalances(userId) {
  for (const currency of CURRENCIES) {
    await pool.query(
      `
      INSERT INTO acb_balances
        (user_id,currency,amount)
      VALUES
        ($1,$2,0)
      ON CONFLICT (user_id,currency)
      DO NOTHING
      `,
      [userId, currency]
    );
  }
}

async function getUser(userId) {
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
      SELECT currency,amount
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

    primaryCurrency: user.primary_currency,
    profileImage: user.profile_image,
    createdAt: user.created_at,

    balances: balanceObject,

    transactions: transactions.rows.map(row => ({
      ...row,
      amount: Number(row.amount),
      date: row.created_at
    })),

    notifications: notifications.rows.map(row => ({
      ...row,
      is_read: !!row.read_at,
      date: row.created_at
    })),

    support: support.rows.map(row => ({
      ...row,
      date: row.created_at
    })),

    requests: requests.rows.map(row => ({
      ...row,
      amount: Number(row.amount),
      date: row.created_at
    }))
  };
}


/* =========================================================
   DATABASE
========================================================= */

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
      user_id UUID NOT NULL REFERENCES acb_users(id) ON DELETE CASCADE,
      currency TEXT NOT NULL,
      amount NUMERIC(24,2) NOT NULL DEFAULT 0,
      PRIMARY KEY(user_id,currency)
    );

    CREATE TABLE IF NOT EXISTS acb_transactions (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES acb_users(id) ON DELETE CASCADE,
      kind TEXT NOT NULL,
      title TEXT NOT NULL,
      amount NUMERIC(24,2) NOT NULL,
      currency TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS acb_notifications (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES acb_users(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      read_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS acb_requests (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES acb_users(id) ON DELETE CASCADE,
      currency TEXT NOT NULL,
      amount NUMERIC(24,2) NOT NULL,
      recipient TEXT NOT NULL,
      note TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      handled_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS acb_support (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES acb_users(id) ON DELETE CASCADE,
      sender TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);


  /* Create administrator if configured */

  if (ADMIN_EMAIL && ADMIN_PASSWORD) {

    const existing = await pool.query(
      `
      SELECT id
      FROM acb_users
      WHERE email=$1
      `,
      [ADMIN_EMAIL]
    );

    if (!existing.rowCount) {

      const passwordHash =
        await bcrypt.hash(
          ADMIN_PASSWORD,
          12
        );

      await pool.query(
        `
        INSERT INTO acb_users
          (
            id,
            name,
            email,
            password_hash,
            role,
            status
          )
        VALUES
          ($1,$2,$3,$4,'admin','Active')
        `,
        [
          uuid(),
          'Administrator',
          ADMIN_EMAIL,
          passwordHash
        ]
      );

    }
  }
}


/* =========================================================
   HEALTH
========================================================= */

app.get('/api/health', (_req, res) => {

  res.json({
    ok: true,
    demo: true
  });

});


/* =========================================================
   CUSTOMER REGISTRATION
========================================================= */

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
        String(
          req.body.currency || 'NGN'
        ).toUpperCase();


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
        `,
        [email]
      );


      if (exists.rowCount) {
        return res.status(409).json({
          error:
            'This email is already registered.'
        });
      }


      const userId = uuid();

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );


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


      /*
        Customer gets account-created notification.
      */

      await pool.query(
        `
        INSERT INTO acb_notifications
          (id,user_id,message)
        VALUES
          ($1,$2,$3)
        `,
        [
          uuid(),
          userId,
          'Your fictional demo account was created successfully.'
        ]
      );


      /*
        IMPORTANT:
        Send registration notification to the
        administrator account.
      */

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
            (id,user_id,message)
          VALUES
            ($1,$2,$3)
          `,
          [
            uuid(),
            admin.rows[0].id,
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
        'Registration error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to create account.'
      });

    }

  }
);


/* =========================================================
   CUSTOMER LOGIN
========================================================= */

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
        `,
        [email]
      );


      if (
        !result.rowCount ||
        !(await bcrypt.compare(
          password,
          result.rows[0].password_hash
        ))
      ) {

        return res.status(401).json({
          error:
            'Incorrect email or password.'
        });

      }


      const user =
        await getUser(
          result.rows[0].id
        );


      res.json({
        token: signToken(user),
        user
      });


    } catch (error) {

      console.error(
        'Login error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to sign in.'
      });

    }

  }
);


/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  '/api/me',
  auth,
  async (req, res) => {

    const user =
      await getUser(
        req.user.id
      );


    if (!user) {

      return res.status(404).json({
        error:
          'Account not found.'
      });

    }


    res.json({
      user
    });

  }
);


/* =========================================================
   PROFILE
========================================================= */

app.put(
  '/api/profile',
  auth,
  writeLimiter,
  async (req, res) => {

    const name =
      String(
        req.body.name || ''
      ).trim();


    if (name.length < 2) {

      return res.status(400).json({
        error:
          'Enter a valid name.'
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


    res.json({
      user:
        await getUser(
          req.user.id
        )
    });

  }
);


app.post(
  '/api/profile/image',
  auth,
  writeLimiter,
  async (req, res) => {

    const image =
      String(
        req.body.profileImage || ''
      );


    if (image.length > 700000) {

      return res.status(400).json({
        error:
          'Profile image is too large.'
      });

    }


    if (
      image &&
      !/^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(image)
    ) {

      return res.status(400).json({
        error:
          'Invalid image format.'
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


    res.json({
      user:
        await getUser(
          req.user.id
        )
    });

  }
);


/* =========================================================
   CUSTOMER REQUEST
========================================================= */

app.post(
  '/api/requests',
  auth,
  writeLimiter,
  async (req, res) => {

    try {

      const currency =
        String(
          req.body.currency || ''
        ).toUpperCase();

      const amount =
        Number(
          req.body.amount
        );

      const recipient =
        String(
          req.body.recipient || ''
        ).trim();

      const note =
        String(
          req.body.note || ''
        ).trim()
        .slice(0,500);


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
          error:
            'Enter the recipient name.'
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
            $1,$2,$3,$4,$5,$6,'pending'
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
        await getUser(
          req.user.id
        );


      const admin =
        await pool.query(
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
            (id,user_id,message)
          VALUES
            ($1,$2,$3)
          `,
          [
            uuid(),
            admin.rows[0].id,
            `New demo funds request from ${customer.name}: ${amount} ${currency} for ${recipient}.`
          ]
        );

      }


      res.status(201).json({
        request: {
          id: requestId,
          status: 'pending'
        },
        user: customer
      });


    } catch (error) {

      console.error(
        'Request error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to send request.'
      });

    }

  }
);


/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
  '/api/admin/login',
  authLimiter,
  async (req, res) => {

    try {

      const email =
        String(
          req.body.email || ''
        ).trim()
        .toLowerCase();

      const password =
        String(
          req.body.password || ''
        );


      const result =
        await pool.query(
          `
          SELECT *
          FROM acb_users
          WHERE email=$1
          AND role='admin'
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
        await getUser(
          result.rows[0].id
        );


      res.json({
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


/* =========================================================
   ADMIN SUMMARY
========================================================= */

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


      res.json({
        customers:
          customers.rows[0].count,

        customerCount:
          customers.rows[0].count,

        totalCustomers:
          customers.rows[0].count,

        pendingTransfers:
          pending.rows[0].count,

        pending_transfers:
          pending.rows[0].count,

        openSupport:
          support.rows[0].count,

        open_support:
          support.rows[0].count,

        balances:
          balanceResult.rows.map(row => ({
            currency:
              row.currency,
            total:
              Number(row.total)
          }))
      });


    } catch (error) {

      console.error(
        'Admin summary error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to load dashboard.'
      });

    }

  }
);


/* =========================================================
   ADMIN CUSTOMERS
   THIS IS THE IMPORTANT FIX
========================================================= */

app.get(
  '/api/admin/customers',
  auth,
  adminOnly,
  async (_req, res) => {

    try {

      /*
        Read ALL customer registrations
        directly from acb_users.
      */

      const customerResult =
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


      const customers = [];


      for (
        const customer
        of customerResult.rows
      ) {

        const balanceResult =
          await pool.query(
            `
            SELECT
              currency,
              amount
            FROM acb_balances
            WHERE user_id=$1
            ORDER BY currency
            `,
            [customer.id]
          );


        customers.push({

          id:
            customer.id,

          name:
            customer.name,

          full_name:
            customer.name,

          email:
            customer.email,

          status:
            customer.status,

          primary_currency:
            customer.primary_currency,

          profile_image:
            customer.profile_image,

          created_at:
            customer.created_at,

          accounts:
            balanceResult.rows.map(
              balance => ({
                currency:
                  balance.currency,

                balance:
                  Number(
                    balance.amount
                  )
              })
            )

        });

      }


      res.json({
        customers
      });


    } catch (error) {

      console.error(
        'Admin customers error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to load customers.'
      });

    }

  }
);


/* =========================================================
   ADMIN STATE
========================================================= */

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

        customers:
          customers.rows,

        requests:
          requests.rows.map(row => ({
            ...row,
            amount:
              Number(row.amount),
            date:
              row.created_at
          })),

        support:
          support.rows.map(row => ({
            ...row,
            date:
              row.created_at
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


/* =========================================================
   ADMIN NOTIFICATIONS
========================================================= */

app.get(
  '/api/admin/notifications',
  auth,
  adminOnly,
  async (_req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            n.id,
            n.user_id,
            n.message,
            n.created_at,
            n.read_at,
            u.name AS customer_name,
            u.email AS customer_email
          FROM acb_notifications n
          JOIN acb_users u
            ON u.id=n.user_id
          WHERE u.role='admin'
          ORDER BY n.created_at DESC
          LIMIT 100
          `
        );


      res.json({

        notifications:
          result.rows.map(row => ({

            id:
              row.id,

            user_id:
              row.user_id,

            title:
              'Customer Activity',

            message:
              row.message,

            customer_name:
              row.customer_name,

            customer_email:
              row.customer_email,

            created_at:
              row.created_at,

            is_read:
              !!row.read_at

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


/* =========================================================
   ADMIN MARK NOTIFICATION READ
========================================================= */

app.patch(
  '/api/admin/notifications/:id/read',
  auth,
  adminOnly,
  async (req, res) => {

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

  }
);


/* =========================================================
   ADMIN CREDIT CUSTOMER
========================================================= */

app.post(
  '/api/admin/customers/:id/funds',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {

    const client =
      await pool.connect();


    try {

      const userId =
        String(
          req.params.id || ''
        );

      const currency =
        String(
          req.body.currency || ''
        ).toUpperCase();

      const amount =
        Number(
          req.body.amount
        );

      const description =
        String(
          req.body.description ||
          'Administrator account funding'
        )
        .trim()
        .slice(0,500);


      if (
        !userId ||
        !validCurrency(currency) ||
        !Number.isFinite(amount) ||
        amount <= 0
      ) {

        return res.status(400).json({
          error:
            'Enter a valid customer, currency and amount.'
        });

      }


      await client.query(
        'BEGIN'
      );


      const customer =
        await client.query(
          `
          SELECT
            id,
            name,
            email
          FROM acb_users
          WHERE id=$1
          AND role='customer'
          FOR UPDATE
          `,
          [userId]
        );


      if (!customer.rowCount) {

        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error:
            'Customer not found.'
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
          userId,
          currency,
          amount
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
          userId,
          description ||
            'Funds credited by demo administrator',
          amount,
          currency
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
          userId,
          `A demo credit of ${amount.toLocaleString()} ${currency} was added to your account.`
        ]
      );


      await client.query(
        'COMMIT'
      );


      res.json({
        message:
          'Customer account funded successfully.',
        user:
          await getUser(userId)
      });


    } catch (error) {

      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'Admin credit error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to credit customer.'
      });

    } finally {

      client.release();

    }

  }
);


/* =========================================================
   OLD ADMIN CREDIT ENDPOINT — PRESERVED
========================================================= */

app.post(
  '/api/admin/credit',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {

    try {

      const userId =
        String(
          req.body.userId || ''
        );

      const currency =
        String(
          req.body.currency || ''
        ).toUpperCase();

      const amount =
        Number(
          req.body.amount
        );


      if (
        !userId ||
        !validCurrency(currency) ||
        !Number.isFinite(amount) ||
        amount <= 0
      ) {

        return res.status(400).json({
          error:
            'Enter a valid customer, currency and amount.'
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
          error:
            'Customer not found.'
        });

      }


      await pool.query(
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
          userId,
          currency,
          amount
        ]
      );


      await pool.query(
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
            'Funds credited by demo administrator',
            $3,
            $4
          )
        `,
        [
          uuid(),
          userId,
          amount,
          currency
        ]
      );


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
          `A demo credit of ${amount.toLocaleString()} ${currency} was added to your account.`
        ]
      );


      res.json({
        user:
          await getUser(userId)
      });


    } catch (error) {

      console.error(
        'Admin credit error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to credit customer.'
      });

    }

  }
);


/* =========================================================
   ADMIN SEND CUSTOMER NOTIFICATION
========================================================= */

app.post(
  '/api/admin/notify',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {

    const userId =
      String(
        req.body.userId || ''
      );

    const message =
      String(
        req.body.message || ''
      )
      .trim()
      .slice(0,1000);


    if (!userId || !message) {

      return res.status(400).json({
        error:
          'Select a customer and write a notification.'
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
        ($1,$2,$3)
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

  }
);


/* =========================================================
   ADMIN CUSTOMER STATUS
========================================================= */

app.patch(
  '/api/admin/customers/:id/status',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {

    const status =
      String(
        req.body.status || ''
      )
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
        error:
          'Invalid account status.'
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
        error:
          'Customer not found.'
      });

    }


    res.json({
      ok: true
    });

  }
);


/* =========================================================
   ADMIN SUPPORT
========================================================= */

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
          ORDER BY s.created_at DESC
          LIMIT 200
          `
        );


      const grouped = {};


      for (const row of result.rows) {

        if (!grouped[row.user_id]) {

          grouped[row.user_id] = {
            id:
              row.id,

            user_id:
              row.user_id,

            full_name:
              row.name,

            name:
              row.name,

            email:
              row.email,

            subject:
              'Customer Support',

            message:
              row.message,

            status:
              row.sender === 'admin'
                ? 'answered'
                : 'pending',

            created_at:
              row.created_at
          };

        }

      }


      res.json({
        tickets:
          Object.values(grouped)
      });


    } catch (error) {

      console.error(
        'Admin support error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to load support requests.'
      });

    }

  }
);


/* =========================================================
   CUSTOMER SUPPORT
========================================================= */

app.post(
  '/api/support',
  auth,
  writeLimiter,
  async (req, res) => {

    const message =
      String(
        req.body.message || ''
      )
      .trim()
      .slice(0,2000);


    if (!message) {

      return res.status(400).json({
        error:
          'Write a message first.'
      });

    }


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
        uuid(),
        req.user.id,
        message
      ]
    );


    const customer =
      await getUser(
        req.user.id
      );


    const admin =
      await pool.query(
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
          `New support message from ${customer.name} (${customer.email}).`
        ]
      );

    }


    res.json({
      user: customer
    });

  }
);


/* =========================================================
   ADMIN SUPPORT REPLY
   NEW ROUTE + OLD ROUTE PRESERVED
========================================================= */

async function handleSupportReply(
  userId,
  message,
  res
) {

  if (!userId || !message) {

    return res.status(400).json({
      error:
        'Select a customer and write a reply.'
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
      error:
        'Customer not found.'
    });

  }


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
        'admin',
        $3
      )
    `,
    [
      uuid(),
      userId,
      message
    ]
  );


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
      'You received a new support reply.'
    ]
  );


  res.json({
    user:
      await getUser(userId)
  });

}


app.post(
  '/api/admin/support/:id/reply',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {

    const message =
      String(
        req.body.message || ''
      )
      .trim()
      .slice(0,2000);


    try {

      const ticket =
        await pool.query(
          `
          SELECT user_id
          FROM acb_support
          WHERE id=$1
          LIMIT 1
          `,
          [req.params.id]
        );


      if (!ticket.rowCount) {

        return res.status(404).json({
          error:
            'Support request not found.'
        });

      }


      return handleSupportReply(
        ticket.rows[0].user_id,
        message,
        res
      );


    } catch (error) {

      console.error(
        'Support reply error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to send response.'
      });

    }

  }
);


/* Preserve previous reply endpoint */

app.post(
  '/api/admin/support/reply',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {

    const userId =
      String(
        req.body.userId || ''
      );

    const message =
      String(
        req.body.message || ''
      )
      .trim()
      .slice(0,2000);


    try {

      return handleSupportReply(
        userId,
        message,
        res
      );

    } catch (error) {

      console.error(
        'Support reply error:',
        error
      );

      res.status(500).json({
        error:
          'Unable to send response.'
      });

    }

  }
);


/* =========================================================
   ADMIN TRANSFERS
========================================================= */

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
        transfers:
          result.rows.map(row => ({
            id:
              row.id,

            user_id:
              row.user_id,

            full_name:
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
              row.id,

            note:
              row.note,

            status:
              row.status,

            created_at:
              row.created_at
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


/* =========================================================
   ADMIN TRANSFER STATUS
========================================================= */

app.patch(
  '/api/admin/transfers/:id/status',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {

    const status =
      String(
        req.body.status || ''
      )
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


    const result =
      await pool.query(
        `
        UPDATE acb_requests
        SET
          status=$1,
          handled_at=NOW()
        WHERE id=$2
        AND status='pending'
        RETURNING
          user_id,
          amount,
          currency
        `,
        [
          status,
          req.params.id
        ]
      );


    if (!result.rowCount) {

      return res.status(404).json({
        error:
          'Pending transfer not found.'
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
        `Your demo transfer request for ${Number(row.amount).toLocaleString()} ${row.currency} is ${status}.`
      ]
    );


    res.json({
      ok: true
    });

  }
);


/* =========================================================
   OLD REQUEST APPROVE
========================================================= */

app.post(
  '/api/admin/requests/:id/approve',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {

    const client =
      await pool.connect();


    try {

      await client.query(
        'BEGIN'
      );


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

        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error:
            'Request not found.'
        });

      }


      const request =
        result.rows[0];


      if (
        request.status !== 'pending'
      ) {

        await client.query(
          'ROLLBACK'
        );

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
            'Funds credited after demo request approval',
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
          `Your demo request for ${Number(request.amount).toLocaleString()} ${request.currency} has been approved and credited.`
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


      await client.query(
        'COMMIT'
      );


      res.json({
        ok: true,
        user:
          await getUser(
            request.user_id
          )
      });


    } catch (error) {

      try {
        await client.query(
          'ROLLBACK'
        );
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


/* =========================================================
   OLD REQUEST REJECT
========================================================= */

app.post(
  '/api/admin/requests/:id/reject',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {

    try {

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


/* =========================================================
   START SERVER
========================================================= */

app.get(
  '*',
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        'index.html'
      )
    );

  }
);


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
