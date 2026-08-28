
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

app.use(cors({
  origin: true,
  credentials: false
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 10000;

const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || '')
  .trim()
  .toLowerCase();

const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || '');

if (!JWT_SECRET || !DATABASE_URL) {
  console.error('Missing JWT_SECRET or DATABASE_URL environment variable.');
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
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

const writeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

const CURRENCIES = [
  'NGN', 'USD', 'EUR', 'GBP', 'IDR', 'CAD', 'AUD', 'CHF', 'JPY',
  'CNY', 'INR', 'MYR', 'SGD', 'AED', 'ZAR', 'KES', 'GHS'
];

function uuid() {
  return crypto.randomUUID();
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizeText(value) {
  return String(value ?? '').trim();
}

function normalizePhone(value) {
  return String(value || '')
    .trim()
    .replace(/[\s().-]/g, '');
}

function validCurrency(value) {
  return CURRENCIES.includes(
    String(value || '').trim().toUpperCase()
  );
}

function validUUID(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    String(value || '')
  );
}

function validEmail(value) {
  return /^\S+@\S+\.\S+$/.test(String(value || ''));
}

function validPhone(value) {
  return /^\+?[0-9]{7,15}$/.test(normalizePhone(value));
}

function signToken(user) {
  return jwt.sign(
    {
      id: String(user.id),
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

  const token = header.startsWith('Bearer ')
    ? header.slice(7).trim()
    : null;

  if (!token) {
    return res.status(401).json({
      ok: false,
      error: 'Authentication required.'
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      ok: false,
      error: 'Session expired. Please sign in again.'
    });
  }
}

function adminOnly(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      ok: false,
      error: 'Authentication required.'
    });
  }

  if (
    String(req.user.role || '').toLowerCase() !== 'admin'
  ) {
    return res.status(403).json({
      ok: false,
      error: 'Administrator access required.'
    });
  }

  next();
}

async function ensureBalances(userId, client = pool) {
  for (const currency of CURRENCIES) {
    await client.query(
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

async function getUser(userId) {
  if (!validUUID(userId)) {
    return null;
  }

  const result = await pool.query(
    `
    SELECT
      id,
      name,
      email,
      phone,
      role,
      status,
      primary_currency,
      profile_image,
      verified,
      created_at
    FROM acb_users
    WHERE id=$1
    LIMIT 1
    `,
    [userId]
  );

  if (!result.rowCount) {
    return null;
  }

  const user = result.rows[0];

  await ensureBalances(user.id);

  const [
    balances,
    transactions,
    notifications,
    support,
    requests
  ] = await Promise.all([
    pool.query(
      `
      SELECT currency, amount
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
      LIMIT 100
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
      LIMIT 100
      `,
      [userId]
    )
  ]);

  const balanceObject = {};

  for (const currency of CURRENCIES) {
    balanceObject[currency] = 0;
  }

  for (const row of balances.rows) {
    balanceObject[row.currency] = Number(row.amount || 0);
  }

  return {
    id: String(user.id),

    name: user.name,
    email: user.email || '',
    phone: user.phone || '',

    role: user.role,
    status: user.status,

    verified: !!user.verified,

    primary_currency: user.primary_currency,
    primaryCurrency: user.primary_currency,

    profile_image: user.profile_image || '',
    profileImage: user.profile_image || '',

    created_at: user.created_at,
    createdAt: user.created_at,

    balances: balanceObject,

    accounts: CURRENCIES.map(currency => ({
      currency,
      balance: Number(balanceObject[currency] || 0),
      amount: Number(balanceObject[currency] || 0)
    })),

    transactions: transactions.rows.map(row => ({
      id: String(row.id),
      kind: row.kind,
      title: row.title,
      amount: Number(row.amount || 0),
      currency: row.currency,
      created_at: row.created_at,
      date: row.created_at
    })),

    notifications: notifications.rows.map(row => ({
      id: String(row.id),
      message: row.message,
      created_at: row.created_at,
      read_at: row.read_at,
      is_read: !!row.read_at,
      date: row.created_at
    })),

    support: support.rows.map(row => ({
      id: String(row.id),
      sender: row.sender,
      message: row.message,
      created_at: row.created_at,
      date: row.created_at
    })),

    requests: requests.rows.map(row => ({
      id: String(row.id),
      currency: row.currency,
      amount: Number(row.amount || 0),
      recipient: row.recipient,
      note: row.note,
      status: row.status,
      created_at: row.created_at,
      handled_at: row.handled_at,
      date: row.created_at
    }))
  };
}

async function loadAdminCustomers() {
  const result = await pool.query(
    `
    SELECT
      u.id,
      u.name,
      u.email,
      u.phone,
      u.role,
      u.status,
      u.primary_currency,
      u.profile_image,
      u.verified,
      u.created_at,

      COALESCE(
        json_agg(
          json_build_object(
            'currency', b.currency,
            'balance', b.amount,
            'amount', b.amount
          )
          ORDER BY b.currency
        ) FILTER (WHERE b.currency IS NOT NULL),
        '[]'::json
      ) AS accounts

    FROM acb_users u

    LEFT JOIN acb_balances b
      ON b.user_id=u.id

    WHERE LOWER(u.role)='customer'

    GROUP BY
      u.id,
      u.name,
      u.email,
      u.phone,
      u.role,
      u.status,
      u.primary_currency,
      u.profile_image,
      u.verified,
      u.created_at

    ORDER BY u.created_at DESC
    `
  );

  return result.rows.map(row => ({
    id: String(row.id),

    userId: String(row.id),
    user_id: String(row.id),

    customerId: String(row.id),
    customer_id: String(row.id),

    name: row.name,
    full_name: row.name,
    fullName: row.name,

    email: row.email || '',
    phone: row.phone || '',

    role: 'customer',

    status: row.status,

    verified: !!row.verified,

    primary_currency: row.primary_currency,
    primaryCurrency: row.primary_currency,

    profile_image: row.profile_image || '',
    profileImage: row.profile_image || '',

    created_at: row.created_at,
    createdAt: row.created_at,

    accounts: Array.isArray(row.accounts)
      ? row.accounts.map(account => ({
          currency: account.currency,
          balance: Number(account.balance || 0),
          amount: Number(
            account.amount || account.balance || 0
          )
        }))
      : []
  }));
}

function collectIdentifiers(value, output = []) {
  if (value === undefined || value === null) {
    return output;
  }

  if (
    typeof value === 'string' ||
    typeof value === 'number'
  ) {
    const text = String(value).trim();

    if (text) {
      output.push(text);
    }

    return output;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      collectIdentifiers(item, output);
    }

    return output;
  }

  if (typeof value === 'object') {
    const keys = [
      'id',
      'userId',
      'user_id',
      'customerId',
      'customer_id',
      'email',
      'emailAddress',
      'email_address',
      'phone',
      'phoneNumber',
      'phone_number',
      'name',
      'fullName',
      'full_name',
      'username',
      'customer',
      'user',
      'account',
      'recipient',
      'selectedCustomer',
      'selected_customer',
      'selectedUser',
      'selected_user',
      'supportId',
      'support_id',
      'ticketId',
      'ticket_id'
    ];

    for (const key of keys) {
      if (
        Object.prototype.hasOwnProperty.call(value, key)
      ) {
        collectIdentifiers(value[key], output);
      }
    }
  }

  return output;
}

async function resolveCustomer(identifier) {
  if (
    identifier &&
    typeof identifier === 'object' &&
    !Array.isArray(identifier)
  ) {
    const identifiers = collectIdentifiers(identifier);

    for (const item of identifiers) {
      const found = await resolveCustomer(item);

      if (found) {
        return found;
      }
    }

    return null;
  }

  const value = normalizeText(identifier);

  if (!value) {
    return null;
  }

  if (validUUID(value)) {
    const result = await pool.query(
      `
      SELECT id
      FROM acb_users
      WHERE id=$1
      AND LOWER(role)='customer'
      LIMIT 1
      `,
      [value]
    );

    if (result.rowCount) {
      return String(result.rows[0].id);
    }
  }

  const email = normalizeEmail(value);

  if (validEmail(email)) {
    const emailResult = await pool.query(
      `
      SELECT id
      FROM acb_users
      WHERE LOWER(email)=LOWER($1)
      AND LOWER(role)='customer'
      LIMIT 1
      `,
      [email]
    );

    if (emailResult.rowCount) {
      return String(emailResult.rows[0].id);
    }
  }

  const phone = normalizePhone(value);

  if (validPhone(phone)) {
    const phoneResult = await pool.query(
      `
      SELECT id
      FROM acb_users
      WHERE phone=$1
      AND LOWER(role)='customer'
      LIMIT 1
      `,
      [phone]
    );

    if (phoneResult.rowCount) {
      return String(phoneResult.rows[0].id);
    }
  }

  const nameResult = await pool.query(
    `
    SELECT id
    FROM acb_users
    WHERE LOWER(TRIM(name))=LOWER(TRIM($1))
    AND LOWER(role)='customer'
    ORDER BY created_at DESC
    LIMIT 1
    `,
    [value]
  );

  if (nameResult.rowCount) {
    return String(nameResult.rows[0].id);
  }

  return null;
}

async function resolveCustomerFromRequest(req) {
  const candidates = [];

  const fields = [
    req.params?.id,

    req.body?.userId,
    req.body?.user_id,

    req.body?.customerId,
    req.body?.customer_id,

    req.body?.id,

    req.body?.email,
    req.body?.emailAddress,
    req.body?.email_address,

    req.body?.phone,
    req.body?.phoneNumber,
    req.body?.phone_number,

    req.body?.name,
    req.body?.fullName,
    req.body?.full_name,

    req.body?.customer,
    req.body?.user,
    req.body?.account,

    req.body?.selectedCustomer,
    req.body?.selected_customer,

    req.body?.selectedUser,
    req.body?.selected_user,

    req.body?.data
  ];

  for (const field of fields) {
    collectIdentifiers(field, candidates);
  }

  collectIdentifiers(req.body, candidates);

  const unique = [
    ...new Set(
      candidates
        .map(value => String(value).trim())
        .filter(Boolean)
    )
  ];

  const ordered = [
    ...unique.filter(validUUID),
    ...unique.filter(value => validEmail(value)),
    ...unique.filter(value => validPhone(value)),
    ...unique
  ];

  for (const candidate of ordered) {
    const resolved = await resolveCustomer(candidate);

    if (resolved) {
      return resolved;
    }
  }

  return null;
}

async function resolveSupportCustomerId(identifier) {
  const customer = await resolveCustomer(identifier);

  if (customer) {
    return customer;
  }

  let value = identifier;

  if (
    identifier &&
    typeof identifier === 'object' &&
    !Array.isArray(identifier)
  ) {
    value =
      identifier.id ||
      identifier.supportId ||
      identifier.support_id ||
      identifier.ticketId ||
      identifier.ticket_id ||
      identifier.userId ||
      identifier.user_id ||
      identifier.customerId ||
      identifier.customer_id ||
      identifier.email ||
      identifier.phone ||
      identifier.name ||
      '';
  }

  value = normalizeText(value);

  if (!validUUID(value)) {
    return null;
  }

  const support = await pool.query(
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

  const request = await pool.query(
    `
    SELECT user_id
    FROM acb_requests
    WHERE id=$1
    LIMIT 1
    `,
    [value]
  );

  if (request.rowCount) {
    return String(request.rows[0].user_id);
  }

  return null;
}

async function resolveSupportCustomerFromRequest(req) {
  const identifiers = [];

  collectIdentifiers(req.params, identifiers);
  collectIdentifiers(req.body, identifiers);

  const unique = [
    ...new Set(
      identifiers
        .map(value => String(value).trim())
        .filter(Boolean)
    )
  ];

  for (const identifier of unique) {
    const customer =
      await resolveSupportCustomerId(identifier);

    if (customer) {
      return customer;
    }
  }

  return null;
}

/*
=========================================================
DATABASE INITIALIZATION
=========================================================
*/

async function initDb() {
  await pool.query(
    `
    CREATE TABLE IF NOT EXISTS acb_users (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'customer',
      status TEXT NOT NULL DEFAULT 'Active',
      primary_currency TEXT NOT NULL DEFAULT 'NGN',
      profile_image TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    `
  );

  await pool.query(
    `
    ALTER TABLE acb_users
    ALTER COLUMN email DROP NOT NULL
    `
  );

  await pool.query(
    `
    ALTER TABLE acb_users
    ADD COLUMN IF NOT EXISTS phone TEXT
    `
  );

  await pool.query(
    `
    ALTER TABLE acb_users
    ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT TRUE
    `
  );

  await pool.query(
    `
    CREATE UNIQUE INDEX IF NOT EXISTS
      acb_users_phone_unique
    ON acb_users(phone)
    WHERE phone IS NOT NULL
    AND phone <> ''
    `
  );

  await pool.query(
    `
    CREATE TABLE IF NOT EXISTS acb_verifications (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL
        REFERENCES acb_users(id)
        ON DELETE CASCADE,
      code TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    `
  );

  await pool.query(
    `
    CREATE TABLE IF NOT EXISTS acb_balances (
      user_id UUID NOT NULL
        REFERENCES acb_users(id)
        ON DELETE CASCADE,
      currency TEXT NOT NULL,
      amount NUMERIC(24,2) NOT NULL DEFAULT 0,
      PRIMARY KEY(user_id,currency)
    )
    `
  );

  await pool.query(
    `
    CREATE TABLE IF NOT EXISTS acb_transactions (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL
        REFERENCES acb_users(id)
        ON DELETE CASCADE,
      kind TEXT NOT NULL,
      title TEXT NOT NULL,
      amount NUMERIC(24,2) NOT NULL,
      currency TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    `
  );

  await pool.query(
    `
    CREATE TABLE IF NOT EXISTS acb_notifications (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL
        REFERENCES acb_users(id)
        ON DELETE CASCADE,
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      read_at TIMESTAMPTZ
    )
    `
  );

  await pool.query(
    `
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
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      handled_at TIMESTAMPTZ
    )
    `
  );

  await pool.query(
    `
    CREATE TABLE IF NOT EXISTS acb_support (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL
        REFERENCES acb_users(id)
        ON DELETE CASCADE,
      sender TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    `
  );

  const existingUsers = await pool.query(
    `
    SELECT id
    FROM acb_users
    `
  );

  for (const row of existingUsers.rows) {
    await ensureBalances(row.id);
  }

  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const existing = await pool.query(
      `
      SELECT id
      FROM acb_users
      WHERE LOWER(email)=LOWER($1)
      LIMIT 1
      `,
      [ADMIN_EMAIL]
    );

    const passwordHash =
      await bcrypt.hash(ADMIN_PASSWORD, 12);

    if (existing.rowCount) {
      await pool.query(
        `
        UPDATE acb_users
        SET
          name=$1,
          password_hash=$2,
          role='admin',
          status='Active',
          verified=TRUE
        WHERE id=$3
        `,
        [
          'Administrator',
          passwordHash,
          existing.rows[0].id
        ]
      );

      await ensureBalances(
        existing.rows[0].id
      );
    } else {
      const adminId = uuid();

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
            profile_image,
            verified
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
            '',
            TRUE
          )
        `,
        [
          adminId,
          'Administrator',
          ADMIN_EMAIL,
          passwordHash
        ]
      );

      await ensureBalances(adminId);
    }
  }

  console.log(
    'Database initialization completed successfully.'
  );
}

/*
=========================================================
HEALTH
=========================================================
*/

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    demo: true,
    service: 'American Crest Demo Banking Platform'
  });
});

/*
=========================================================
VERIFICATION
=========================================================
*/

async function createVerification(userId) {
  const code = String(
    crypto.randomInt(100000, 1000000)
  );

  await pool.query(
    `
    UPDATE acb_verifications
    SET used_at=NOW()
    WHERE user_id=$1
    AND used_at IS NULL
    `,
    [userId]
  );

  await pool.query(
    `
    INSERT INTO acb_verifications
      (
        id,
        user_id,
        code,
        expires_at
      )
    VALUES
      (
        $1,
        $2,
        $3,
        NOW() + INTERVAL '10 minutes'
      )
    `,
    [
      uuid(),
      userId,
      code
    ]
  );

  return code;
}

/*
=========================================================
REGISTER
=========================================================
*/

async function registerHandler(req, res) {
  const client = await pool.connect();

  try {
    const name = normalizeText(
      req.body.name ||
      req.body.fullName ||
      req.body.full_name ||
      req.body.username ||
      req.body.displayName ||
      req.body.display_name
    );

    const email = normalizeEmail(
      req.body.email ||
      req.body.emailAddress ||
      req.body.email_address
    );

    const phone = normalizePhone(
      req.body.phone ||
      req.body.phoneNumber ||
      req.body.phone_number ||
      req.body.mobile
    );

    const password =
      typeof req.body.password === 'string'
        ? req.body.password
        : typeof req.body.passcode === 'string'
          ? req.body.passcode
          : typeof req.body.passwordValue === 'string'
            ? req.body.passwordValue
            : '';

    const currency = String(
      req.body.currency ||
      req.body.primaryCurrency ||
      req.body.primary_currency ||
      'NGN'
    )
      .trim()
      .toUpperCase();

    if (name.length < 2) {
      return res.status(400).json({
        ok: false,
        error: 'Enter your full name.'
      });
    }

    if (!email && !phone) {
      return res.status(400).json({
        ok: false,
        error:
          'Enter an email address or phone number.'
      });
    }

    if (email && !validEmail(email)) {
      return res.status(400).json({
        ok: false,
        error: 'Enter a valid email address.'
      });
    }

    if (phone && !validPhone(phone)) {
      return res.status(400).json({
        ok: false,
        error: 'Enter a valid phone number.'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        ok: false,
        error:
          'Password must contain at least 6 characters.'
      });
    }

    if (!validCurrency(currency)) {
      return res.status(400).json({
        ok: false,
        error: 'Invalid currency.'
      });
    }

    await client.query('BEGIN');

    const exists = await client.query(
      `
      SELECT id
      FROM acb_users
      WHERE
        (
          $1 <> ''
          AND LOWER(COALESCE(email,''))=LOWER($1)
        )
        OR
        (
          $2 <> ''
          AND phone=$2
        )
      LIMIT 1
      `,
      [
        email,
        phone
      ]
    );

    if (exists.rowCount) {
      await client.query('ROLLBACK');

      return res.status(409).json({
        ok: false,
        success: false,
        error:
          'An account already exists with that email or phone number.'
      });
    }

    const userId = uuid();

    const passwordHash =
      await bcrypt.hash(password, 12);

    await client.query(
      `
      INSERT INTO acb_users
        (
          id,
          name,
          email,
          phone,
          password_hash,
          role,
          status,
          primary_currency,
          profile_image,
          verified
        )
      VALUES
        (
          $1,
          $2,
          $3,
          $4,
          $5,
          'customer',
          'Active',
          $6,
          '',
          FALSE
        )
      `,
      [
        userId,
        name,
        email || null,
        phone || null,
        passwordHash,
        currency
      ]
    );

    await ensureBalances(
      userId,
      client
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
        'Your American Crest demo account was created. Verify your account before signing in.'
      ]
    );

    const admin = await client.query(
      `
      SELECT id
      FROM acb_users
      WHERE LOWER(role)='admin'
      ORDER BY created_at ASC
      LIMIT 1
      `
    );

    if (admin.rowCount) {
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
          admin.rows[0].id,
          `New demo customer registered: ${name}.`
        ]
      );
    }

    await client.query('COMMIT');

    const code =
      await createVerification(userId);

    return res.status(201).json({
      ok: true,
      success: true,

      verificationRequired: true,
      requiresVerification: true,

      userId,
      customerId: userId,

      message:
        'Account created. Enter the verification code before signing in.',

      /*
       * Demo-only verification response.
       * The frontend can display this code for testing.
       */
      demoVerificationCode: code,
      verificationCode: code
    });

  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {}

    console.error(
      'Registration error:',
      error
    );

    return res.status(500).json({
      ok: false,
      success: false,
      error: 'Unable to create account.'
    });

  } finally {
    client.release();
  }
}

app.post(
  '/api/auth/register',
  authLimiter,
  registerHandler
);

app.post(
  '/api/register',
  authLimiter,
  registerHandler
);

app.post(
  '/api/signup',
  authLimiter,
  registerHandler
);

app.post(
  '/api/auth/signup',
  authLimiter,
  registerHandler
);

/*
=========================================================
VERIFY ACCOUNT
=========================================================
*/

async function verifyHandler(req, res) {
  try {
    const identifier = normalizeText(
      req.body.userId ||
      req.body.user_id ||
      req.body.customerId ||
      req.body.customer_id ||
      req.body.email ||
      req.body.phone ||
      req.body.identifier
    );

    const code = normalizeText(
      req.body.code ||
      req.body.verificationCode ||
      req.body.verification_code ||
      req.body.otp
    );

    if (!identifier || !code) {
      return res.status(400).json({
        ok: false,
        error:
          'Enter your verification code.'
      });
    }

    const userId =
      await resolveCustomer(identifier);

    if (!userId) {
      return res.status(404).json({
        ok: false,
        error: 'Account not found.'
      });
    }

    const result = await pool.query(
      `
      SELECT id
      FROM acb_verifications
      WHERE user_id=$1
      AND code=$2
      AND used_at IS NULL
      AND expires_at>NOW()
      ORDER BY created_at DESC
      LIMIT 1
      `,
      [
        userId,
        code
      ]
    );

    if (!result.rowCount) {
      return res.status(400).json({
        ok: false,
        error:
          'Invalid or expired verification code.'
      });
    }

    await pool.query(
      `
      UPDATE acb_verifications
      SET used_at=NOW()
      WHERE id=$1
      `,
      [result.rows[0].id]
    );

    await pool.query(
      `
      UPDATE acb_users
      SET verified=TRUE
      WHERE id=$1
      `,
      [userId]
    );

    const user =
      await getUser(userId);

    const token =
      signToken(user);

    return res.json({
      ok: true,
      success: true,

      message:
        'Account verified successfully.',

      token,
      accessToken: token,

      user,
      customer: user,
      account: user,

      redirect: 'dashboard'
    });

  } catch (error) {
    console.error(
      'Verification error:',
      error
    );

    return res.status(500).json({
      ok: false,
      error: 'Unable to verify account.'
    });
  }
}

app.post(
  '/api/auth/verify',
  authLimiter,
  verifyHandler
);

app.post(
  '/api/verify',
  authLimiter,
  verifyHandler
);

app.post(
  '/api/verify-code',
  authLimiter,
  verifyHandler
);

app.post(
  '/api/auth/verify-code',
  authLimiter,
  verifyHandler
);

/*
=========================================================
RESEND VERIFICATION
=========================================================
*/

async function resendVerificationHandler(
  req,
  res
) {
  try {
    const identifier = normalizeText(
      req.body.userId ||
      req.body.user_id ||
      req.body.customerId ||
      req.body.customer_id ||
      req.body.email ||
      req.body.phone ||
      req.body.identifier
    );

    const userId =
      await resolveCustomer(identifier);

    if (!userId) {
      return res.status(404).json({
        ok: false,
        error: 'Account not found.'
      });
    }

    const user =
      await pool.query(
        `
        SELECT verified
        FROM acb_users
        WHERE id=$1
        AND LOWER(role)='customer'
        LIMIT 1
        `,
        [userId]
      );

    if (!user.rowCount) {
      return res.status(404).json({
        ok: false,
        error: 'Account not found.'
      });
    }

    if (user.rows[0].verified) {
      return res.json({
        ok: true,
        success: true,
        alreadyVerified: true,
        message:
          'Account is already verified.'
      });
    }

    const code =
      await createVerification(userId);

    return res.json({
      ok: true,
      success: true,

      verificationRequired: true,

      userId,

      demoVerificationCode: code,
      verificationCode: code,

      message:
        'A new verification code was generated.'
    });

  } catch (error) {
    console.error(
      'Resend verification error:',
      error
    );

    return res.status(500).json({
      ok: false,
      error:
        'Unable to generate verification code.'
    });
  }
}

app.post(
  '/api/auth/resend-verification',
  authLimiter,
  resendVerificationHandler
);

app.post(
  '/api/resend-verification',
  authLimiter,
  resendVerificationHandler
);

/*
=========================================================
LOGIN
=========================================================
*/

async function loginHandler(req, res) {
  try {
    const identifier = normalizeText(
      req.body.identifier ||
      req.body.login ||
      req.body.username ||
      req.body.email ||
      req.body.emailAddress ||
      req.body.phone ||
      req.body.phoneNumber
    );

    const password =
      typeof req.body.password === 'string'
        ? req.body.password
        : typeof req.body.passcode === 'string'
          ? req.body.passcode
          : typeof req.body.passwordValue === 'string'
            ? req.body.passwordValue
            : '';

    if (!identifier || !password) {
      return res.status(400).json({
        ok: false,
        error:
          'Enter your email/phone and password.'
      });
    }

    const email =
      normalizeEmail(identifier);

    const phone =
      normalizePhone(identifier);

    const result = await pool.query(
      `
      SELECT
        id,
        name,
        email,
        phone,
        password_hash,
        role,
        status,
        primary_currency,
        profile_image,
        verified,
        created_at
      FROM acb_users
      WHERE
        LOWER(COALESCE(email,''))=LOWER($1)
        OR phone=$2
      LIMIT 1
      `,
      [
        email,
        phone
      ]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        ok: false,
        success: false,
        error:
          'Incorrect email/phone or password.'
      });
    }

    const databaseUser =
      result.rows[0];

    const passwordValid =
      await bcrypt.compare(
        password,
        databaseUser.password_hash
      );

    if (!passwordValid) {
      return res.status(401).json({
        ok: false,
        success: false,
        error:
          'Incorrect email/phone or password.'
      });
    }

    if (
      String(databaseUser.status || '')
        .toLowerCase() === 'suspended'
    ) {
      return res.status(403).json({
        ok: false,
        success: false,
        error:
          'This account is currently suspended.'
      });
    }

    /*
     * Customer accounts cannot enter the dashboard
     * until verification is completed.
     */
    if (
      String(databaseUser.role || '')
        .toLowerCase() === 'customer' &&
      !databaseUser.verified
    ) {
      const code =
        await createVerification(
          databaseUser.id
        );

      return res.status(403).json({
        ok: false,

        verificationRequired: true,
        requiresVerification: true,

        userId: String(databaseUser.id),
        customerId: String(databaseUser.id),

        demoVerificationCode: code,
        verificationCode: code,

        error:
          'Verify your account before entering it.'
      });
    }

    await ensureBalances(
      databaseUser.id
    );

    const user =
      await getUser(
        String(databaseUser.id)
      );

    const token =
      signToken(user);

    return res.json({
      ok: true,
      success: true,

      message:
        'Signed in successfully.',

      token,
      accessToken: token,

      user,
      customer: user,
      account: user,

      id: user.id,
      userId: user.id,
      customerId: user.id,

      redirect:
        String(user.role).toLowerCase() ===
        'admin'
          ? 'admin'
          : 'dashboard'
    });

  } catch (error) {
    console.error(
      'Login error:',
      error
    );

    return res.status(500).json({
      ok: false,
      success: false,
      error: 'Unable to sign in.'
    });
  }
}

app.post(
  '/api/auth/login',
  authLimiter,
  loginHandler
);

app.post(
  '/api/login',
  authLimiter,
  loginHandler
);

app.post(
  '/api/signin',
  authLimiter,
  loginHandler
);

app.post(
  '/api/auth/signin',
  authLimiter,
  loginHandler
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
    try {
      const user =
        await getUser(req.user.id);

      if (!user) {
        return res.status(404).json({
          ok: false,
          error: 'Account not found.'
        });
      }

      return res.json({
        ok: true,
        user,
        customer: user,
        account: user
      });

    } catch (error) {
      console.error(
        'ME error:',
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          'Unable to load account.'
      });
    }
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
        normalizeText(
          req.body.name ||
          req.body.fullName ||
          req.body.full_name
        );

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

      const user =
        await getUser(req.user.id);

      return res.json({
        ok: true,
        user,
        customer: user
      });

    } catch (error) {
      console.error(
        'Profile update error:',
        error
      );

      return res.status(500).json({
        error:
          'Unable to update profile.'
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
        String(
          req.body.profileImage ||
          req.body.profile_image ||
          ''
        );

      if (image.length > 700000) {
        return res.status(400).json({
          error:
            'Profile image is too large.'
        });
      }

      if (
        image &&
        !/^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(
          image
        )
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

      const user =
        await getUser(req.user.id);

      return res.json({
        ok: true,
        user,
        customer: user
      });

    } catch (error) {
      console.error(
        'Profile image error:',
        error
      );

      return res.status(500).json({
        error:
          'Unable to update profile image.'
      });
    }
  }
);

/*
=========================================================
CUSTOMER FUNDS REQUEST
=========================================================
*/

app.post(
  '/api/requests',
  auth,
  writeLimiter,
  async (req, res) => {
    try {
      const currency =
        String(
          req.body.currency || ''
        )
          .trim()
          .toUpperCase();

      const amount =
        Number(req.body.amount);

      const recipient =
        normalizeText(
          req.body.recipient ||
          req.body.recipientName
        );

      const note =
        normalizeText(
          req.body.note
        ).slice(0, 500);

      if (!validCurrency(currency)) {
        return res.status(400).json({
          error:
            'Invalid currency.'
        });
      }

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          error:
            'Enter a valid amount.'
        });
      }

      if (!recipient) {
        return res.status(400).json({
          error:
            'Enter a recipient.'
        });
      }

      const requestId =
        uuid();

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
            `New demo funds request from ${customer.name}: ${amount} ${currency} for ${recipient}.`
          ]
        );
      }

      return res.status(201).json({
        ok: true,
        success: true,

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

      return res.status(500).json({
        error:
          'Unable to send request.'
      });
    }
  }
);

/*
=========================================================
ADMIN LOGIN
=========================================================
*/

async function adminLoginHandler(req, res) {
  try {
    const email =
      normalizeEmail(
        req.body.email ||
        req.body.emailAddress ||
        req.body.email_address ||
        req.body.identifier
      );

    const password =
      String(
        req.body.password ||
        req.body.passcode ||
        ''
      );

    const result =
      await pool.query(
        `
        SELECT *
        FROM acb_users
        WHERE LOWER(email)=LOWER($1)
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

    await ensureBalances(
      result.rows[0].id
    );

    const user =
      await getUser(
        result.rows[0].id
      );

    const token =
      signToken(user);

    return res.json({
      ok: true,
      success: true,

      token,
      accessToken: token,

      user
    });

  } catch (error) {
    console.error(
      'Admin login error:',
      error
    );

    return res.status(500).json({
      error:
        'Unable to sign in as administrator.'
    });
  }
}

app.post(
  '/api/admin/login',
  authLimiter,
  adminLoginHandler
);

app.post(
  '/api/auth/admin/login',
  authLimiter,
  adminLoginHandler
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
      const [
        customers,
        transactions,
        support,
        requests
      ] = await Promise.all([
        pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM acb_users
          WHERE LOWER(role)='customer'
          `
        ),

        pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM acb_transactions
          `
        ),

        pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM acb_support s
          JOIN acb_users u
            ON u.id=s.user_id
          WHERE LOWER(s.sender)='customer'
          AND LOWER(u.role)='customer'
          `
        ),

        pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM acb_requests
          WHERE status='pending'
          `
        )
      ]);

      return res.json({
        ok: true,

        customers:
          Number(customers.rows[0].count),

        customerCount:
          Number(customers.rows[0].count),

        transactions:
          Number(transactions.rows[0].count),

        support:
          Number(support.rows[0].count),

        openSupport:
          Number(support.rows[0].count),

        pendingRequests:
          Number(requests.rows[0].count)
      });

    } catch (error) {
      console.error(
        'Admin summary error:',
        error
      );

      return res.status(500).json({
        error:
          'Unable to load summary.'
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

      return res.json({
        ok: true,
        customers,
        users: customers,
        data: customers
      });

    } catch (error) {
      console.error(
        'Admin customers error:',
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          'Unable to load customers.',
        customers: []
      });
    }
  }
);

app.get(
  '/api/admin/users',
  auth,
  adminOnly,
  async (_req, res) => {
    try {
      const customers =
        await loadAdminCustomers();

      return res.json({
        ok: true,
        users: customers,
        customers,
        data: customers
      });

    } catch (error) {
      console.error(
        'Admin users error:',
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          'Unable to load users.',
        users: []
      });
    }
  }
);

app.get(
  '/api/admin/state',
  auth,
  adminOnly,
  async (_req, res) => {
    try {
      const customers =
        await loadAdminCustomers();

      return res.json({
        ok: true,
        customers,
        users: customers
      });

    } catch (error) {
      console.error(
        'Admin state error:',
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          'Unable to load admin state.'
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
            id,
            message,
            created_at,
            read_at
          FROM acb_notifications
          WHERE user_id=$1
          ORDER BY created_at DESC
          LIMIT 100
          `,
          [req.user.id]
        );

      return res.json({
        ok: true,

        notifications:
          result.rows.map(row => ({
            id: String(row.id),
            message: row.message,
            created_at: row.created_at,
            read_at: row.read_at,
            is_read: !!row.read_at
          }))
      });

    } catch (error) {
      console.error(
        'Admin notifications error:',
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          'Unable to load notifications.'
      });
    }
  }
);

app.patch(
  '/api/admin/notifications/:id/read',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    try {
      if (!validUUID(req.params.id)) {
        return res.status(400).json({
          error:
            'Invalid notification ID.'
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

      return res.json({
        ok: true
      });

    } catch (error) {
      console.error(
        'Notification update error:',
        error
      );

      return res.status(500).json({
        error:
          'Unable to update notification.'
      });
    }
  }
);

/*
=========================================================
ADMIN ADD FUNDS
=========================================================
*/

async function handleAdminCredit(
  req,
  res,
  routeId = null
) {
  const client =
    await pool.connect();

  try {
    /*
     * Resolve the customer by UUID, email,
     * phone, name, or nested customer object.
     */
    const userId =
      routeId
        ? await resolveCustomer(routeId)
        : await resolveCustomerFromRequest(req);

    const amount =
      Number(
        req.body.amount ||
        req.body.value ||
        req.body.funds
      );

    const currency =
      String(
        req.body.currency ||
        req.body.accountCurrency ||
        req.body.account_currency ||
        ''
      )
        .trim()
        .toUpperCase();

    if (!userId) {
      return res.status(404).json({
        ok: false,
        success: false,
        error:
          'Customer information cannot be found.'
      });
    }

    if (!validCurrency(currency)) {
      return res.status(400).json({
        ok: false,
        error:
          'Invalid currency.'
      });
    }

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        ok: false,
        error:
          'Enter a valid amount.'
      });
    }

    await client.query('BEGIN');

    /*
     * The important fix:
     * customer IDs are UUID strings and are never
     * converted to numbers.
     */
    const customer =
      await client.query(
        `
        SELECT
          id,
          name,
          email,
          phone
        FROM acb_users
        WHERE id=$1
        AND LOWER(role)='customer'
        FOR UPDATE
        `,
        [userId]
      );

    if (!customer.rowCount) {
      await client.query('ROLLBACK');

      return res.status(404).json({
        ok: false,
        success: false,
        error:
          'Customer information cannot be found.'
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
        userId,
        currency,
        amount
      ]
    );

    const transactionId =
      uuid();

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
        transactionId,
        userId,
        amount,
        currency
      ]
    );

    const notificationId =
      uuid();

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
        `You received ${amount.toLocaleString()} ${currency}. Your demo account balance has been updated.`
      ]
    );

    await client.query('COMMIT');

    const user =
      await getUser(userId);

    return res.json({
      ok: true,
      success: true,

      message:
        `Customer account funded successfully. ${amount.toLocaleString()} ${currency} added.`,

      user,
      customer: user,
      updatedCustomer: user,

      customerId: userId,
      userId,

      balance:
        Number(
          user.balances[currency] || 0
        ),

      balances:
        user.balances,

      accounts:
        user.accounts,

      currency,
      amount,

      transactionId,
      notificationId
    });

  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {}

    console.error(
      'Admin credit error:',
      error
    );

    return res.status(500).json({
      ok: false,
      success: false,
      error:
        'Unable to credit customer.'
    });

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
    await handleAdminCredit(
      req,
      res,
      req.params.id
    );
  }
);

app.post(
  '/api/admin/customers/:id/add-funds',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    await handleAdminCredit(
      req,
      res,
      req.params.id
    );
  }
);

app.post(
  '/api/admin/credit',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    await handleAdminCredit(
      req,
      res
    );
  }
);

app.post(
  '/api/admin/add-funds',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    await handleAdminCredit(
      req,
      res
    );
  }
);

app.post(
  '/api/admin/customers/add-funds',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    await handleAdminCredit(
      req,
      res
    );
  }
);

/*
=========================================================
ADMIN NOTIFY
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
        await resolveCustomerFromRequest(req);

      const message =
        normalizeText(
          req.body.message
        ).slice(0, 1000);

      if (!userId) {
        return res.status(404).json({
          error:
            'Customer not found.'
        });
      }

      if (!message) {
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
          (
            $1,
            $2,
            $3
          )
        `,
        [
          uuid(),
          userId,
          message
        ]
      );

      return res.json({
        ok: true,
        success: true
      });

    } catch (error) {
      console.error(
        'Admin notify error:',
        error
<
