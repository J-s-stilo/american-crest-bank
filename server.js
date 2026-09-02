const express = require('express');

const path = require('path');

const cors = require('cors');

const bcrypt = require('bcryptjs');

const jwt = require('jsonwebtoken');

const { Pool } = require('pg');

const rateLimit = require('express-rate-limit');

const crypto = require('crypto');
let nodemailer = null;
try { nodemailer = require('nodemailer'); } catch {}

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

const BANK_NAME = String(process.env.BANK_NAME || 'American Crest Demo Banking').trim();
const BANK_EMAIL = String(process.env.BANK_EMAIL || 'americancrestbank@gmail.com').trim();
const SMTP_HOST = String(process.env.SMTP_HOST || '').trim();
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_USER = String(process.env.SMTP_USER || BANK_EMAIL).trim();
const SMTP_PASSWORD = String(process.env.SMTP_PASSWORD || '').trim();

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

  'NGN','USD','EUR','GBP','IDR','CAD','AUD','CHF','JPY',

  'CNY','INR','MYR','SGD','AED','ZAR','KES','GHS'

];

// Demo FX rates expressed as units of each currency per 1 USD.
// These are fixed demonstration rates, not live market rates.
const DEMO_EXCHANGE_RATES = {USD:1,EUR:0.92,GBP:0.78,NGN:1535,IDR:16600,CAD:1.37,AUD:1.53,CHF:0.80,JPY:147,CNY:7.18,INR:83.5,MYR:4.68,SGD:1.35,AED:3.6725,ZAR:18.1,KES:129,GHS:15.2};
const DEMO_TRANSFER_FEE_RATE = 0.01;
function convertDemoAmount(amount, from, to) {
  const f=DEMO_EXCHANGE_RATES[String(from).toUpperCase()];
  const t=DEMO_EXCHANGE_RATES[String(to).toUpperCase()];
  if(!f||!t) throw new Error('Unsupported demo currency.');
  return Number(amount) * (t/f);
}

function uuid() {

  return crypto.randomUUID();

}

function makeReference(prefix = 'ACB') {
  const stamp = Date.now().toString(36).toUpperCase();
  const random = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `${prefix}-${stamp}-${random}`;
}

async function generateAccountNumber(client = pool) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const value = String(1000000000 + crypto.randomInt(0, 9000000000));
    const exists = await client.query(
      `SELECT 1 FROM acb_users WHERE account_number=$1 LIMIT 1`,
      [value]
    );
    if (!exists.rowCount) return value;
  }
  throw new Error('Unable to generate account number.');
}

function receiptSvg({
  reference,
  amount,
  currency,
  recipient,
  recipientEmail,
  bankName,
  status,
  date,
  senderName,
  senderEmail,
  senderAccountNumber,
  fee,
  fundingCurrency,
  debitAmount,
  exchangeRate
}) {
  const escSvg = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&apos;'}[c]));
  const rawAccount = String(senderAccountNumber || '').replace(/\s+/g, '');
  const maskedAccount = rawAccount
    ? (rawAccount.length > 4 ? `${'*'.repeat(Math.max(0, rawAccount.length - 4))}${rawAccount.slice(-4)}` : rawAccount)
    : 'Not available';
  const transferAmount = `${escSvg(Number(amount || 0).toFixed(2))} ${escSvg(currency)}`;
  const feeAmount = Number(fee || 0);
  const hasConversion = fundingCurrency && String(fundingCurrency).toUpperCase() !== String(currency).toUpperCase();
  const rateText = Number.isFinite(Number(exchangeRate))
    ? `1 ${escSvg(String(fundingCurrency || currency).toUpperCase())} = ${escSvg(Number(exchangeRate).toFixed(6))} ${escSvg(currency)}`
    : 'Not available';
  const debitText = Number.isFinite(Number(debitAmount))
    ? `${escSvg(Number(debitAmount).toFixed(2))} ${escSvg(String(fundingCurrency || currency).toUpperCase())}`
    : transferAmount;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="900" height="1320" viewBox="0 0 900 1320">
    <rect width="900" height="1320" fill="#f4f7fb"/>
    <rect x="60" y="40" width="780" height="1240" rx="28" fill="#fff" stroke="#d9e2ef" stroke-width="3"/>
    <text x="100" y="112" font-family="Arial" font-size="30" font-weight="700" fill="#071a35">${escSvg(BANK_NAME)}</text>
    <text x="100" y="147" font-family="Arial" font-size="18" fill="#64748b">DIGITAL BANKING DEMO</text>
    <rect x="635" y="78" width="145" height="48" rx="24" fill="#e8f7ee"/>
    <text x="707" y="109" text-anchor="middle" font-family="Arial" font-size="15" font-weight="700" fill="#17633a">${escSvg(String(status || 'successful').toUpperCase())}</text>
    <line x1="100" y1="182" x2="800" y2="182" stroke="#e2e8f0"/>

    <text x="100" y="235" font-family="Arial" font-size="15" fill="#64748b">TRANSFER AMOUNT</text>
    <text x="100" y="282" font-family="Arial" font-size="40" font-weight="700" fill="#071a35">${transferAmount}</text>

    <rect x="100" y="325" width="700" height="205" rx="18" fill="#f7f9fc"/>
    <text x="130" y="365" font-family="Arial" font-size="15" font-weight="700" fill="#64748b">SENDER / CUSTOMER</text>
    <text x="130" y="400" font-family="Arial" font-size="21" font-weight="700" fill="#1e293b">${escSvg(senderName || 'Customer')}</text>
    <text x="130" y="430" font-family="Arial" font-size="17" fill="#475569">${escSvg(senderEmail || 'Email not available')}</text>
    <text x="130" y="470" font-family="Arial" font-size="15" fill="#64748b">ACCOUNT</text>
    <text x="130" y="500" font-family="Arial" font-size="19" font-weight="700" fill="#1e293b">${escSvg(maskedAccount)}</text>

    <text x="100" y="580" font-family="Arial" font-size="15" font-weight="700" fill="#64748b">RECIPIENT</text>
    <text x="100" y="612" font-family="Arial" font-size="21" font-weight="700" fill="#1e293b">${escSvg(recipient)}</text>
    <text x="100" y="640" font-family="Arial" font-size="17" fill="#475569">${escSvg(recipientEmail || 'Email not provided')}</text>

    <text x="100" y="700" font-family="Arial" font-size="15" fill="#64748b">BANK</text>
    <text x="100" y="732" font-family="Arial" font-size="20" font-weight="700" fill="#1e293b">${escSvg(bankName || 'External bank')}</text>

    <text x="100" y="790" font-family="Arial" font-size="15" fill="#64748b">REFERENCE / TRANSFER NUMBER</text>
    <text x="100" y="822" font-family="Arial" font-size="19" font-weight="700" fill="#1e293b">${escSvg(reference)}</text>

    <text x="100" y="880" font-family="Arial" font-size="15" fill="#64748b">DATE &amp; TIME</text>
    <text x="100" y="912" font-family="Arial" font-size="18" font-weight="700" fill="#1e293b">${escSvg(date)}</text>

    <rect x="100" y="950" width="700" height="170" rx="18" fill="#f7f9fc"/>
    <text x="130" y="988" font-family="Arial" font-size="15" font-weight="700" fill="#071a35">CONVERSION &amp; FEES</text>
    <text x="130" y="1022" font-family="Arial" font-size="16" fill="#475569">Amount debited: ${debitText}</text>
    <text x="130" y="1052" font-family="Arial" font-size="16" fill="#475569">Exchange rate: ${rateText}</text>
    <text x="130" y="1082" font-family="Arial" font-size="16" fill="#475569">Demo transfer fee: ${escSvg(feeAmount.toFixed(2))} ${escSvg(currency)}</text>

    <text x="100" y="1170" font-family="Arial" font-size="15" fill="#64748b">${hasConversion ? 'Currency conversion applied using fixed demo rates.' : 'No currency conversion was required.'}</text>
    <text x="100" y="1202" font-family="Arial" font-size="15" fill="#94a3b8">Fictional / simulated transaction — no real funds were moved.</text>
    <text x="100" y="1235" font-family="Arial" font-size="15" fill="#94a3b8">American Crest Demo Banking • ${escSvg(BANK_EMAIL)}</text>
  </svg>`;
}

async function sendDemoEmail({ to, subject, html, receipt }) {
  const recipient = String(to || '').trim();
  console.log(`[DEMO EMAIL] requested recipient=${recipient || '(missing)'}`);
  console.log(`[DEMO EMAIL] smtp configured host=${SMTP_HOST ? 'yes' : 'no'} port=${SMTP_PORT || '(missing)'} user=${SMTP_USER ? 'yes' : 'no'} password=${SMTP_PASSWORD ? 'yes' : 'no'}`);

  if (!recipient || !/^\S+@\S+\.\S+$/.test(recipient)) {
    console.warn(`[DEMO EMAIL] skipped: invalid recipient email (${recipient || '(missing)'})`);
    return false;
  }
  if (!nodemailer) {
    console.error('[DEMO EMAIL] skipped: nodemailer is not available.');
    return false;
  }
  if (!SMTP_HOST || !SMTP_PASSWORD) {
    console.warn('[DEMO EMAIL] skipped: SMTP is not configured.');
    return false;
  }

  try {
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_PORT === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASSWORD },
      connectionTimeout: 15000,
      greetingTimeout: 15000,
      socketTimeout: 20000
    });

    console.log(`[DEMO EMAIL] attempting SMTP verify host=${SMTP_HOST} port=${SMTP_PORT} secure=${SMTP_PORT === 465}`);
    await transporter.verify();
    console.log('[DEMO EMAIL] SMTP verify succeeded.');

    const info = await transporter.sendMail({
      from: `${BANK_NAME} <${BANK_EMAIL}>`,
      to: recipient,
      subject,
      html,
      attachments: receipt ? [{ filename: 'american-crest-demo-transfer-receipt.svg', content: receipt, contentType: 'image/svg+xml' }] : []
    });

    console.log(`[DEMO EMAIL] sendMail accepted messageId=${info.messageId || '(none)'} response=${info.response || '(none)'}`);
    return true;
  } catch (error) {
    console.error(`[DEMO EMAIL] error name=${error?.name || '(unknown)'} code=${error?.code || '(none)'} command=${error?.command || '(none)'} message=${error?.message || error}`);
    return false;
  }
}

function normalizeEmail(value) {

  return String(value || '').trim().toLowerCase();

}

function normalizePhone(value) {
  return String(value || '').replace(/[^0-9+]/g, '').replace(/(?!^)\+/g, '');
}

function validPhone(value) {
  const phone = normalizePhone(value);
  return /^\+?[0-9]{7,15}$/.test(phone);
}

function normalizeText(value) {

  return String(value ?? '').trim();

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

function signToken(user) {

  return jwt.sign(

    {

      id: String(user.id),

      role: user.role

    },

    JWT_SECRET,

    { expiresIn: '7d' }

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

  if (String(req.user.role || '').toLowerCase() !== 'admin') {

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

  if (!validUUID(userId)) return null;

  const userResult = await pool.query(

    `

    SELECT

      id,name,email,phone,phone_verified,role,status,primary_currency,

      account_number,profile_image,created_at

    FROM acb_users

    WHERE id=$1

    LIMIT 1

    `,

    [userId]

  );

  if (!userResult.rowCount) return null;

  const user = userResult.rows[0];

  await ensureBalances(user.id);

  const [balances, transactions, notifications, support, requests] =

    await Promise.all([

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

        SELECT id,kind,title,amount,currency,created_at,reference,status,metadata

        FROM acb_transactions

        WHERE user_id=$1

        ORDER BY created_at DESC

        LIMIT 100

        `,

        [userId]

      ),

      pool.query(

        `

        SELECT id,message,created_at,read_at

        FROM acb_notifications

        WHERE user_id=$1

        ORDER BY created_at DESC

        LIMIT 100

        `,

        [userId]

      ),

      pool.query(

        `

        SELECT id,sender,message,created_at

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

          id,currency,amount,recipient,note,status,

          recipient_bank,recipient_account,recipient_email,recipient_country,swift_bic,reference,

          created_at,handled_at

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

    accountNumber: user.account_number || '',

    account_number: user.account_number || '',

    phone: user.phone || '',

    phoneVerified: !!user.phone_verified,

    role: user.role,

    status: user.status,

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

      date: row.created_at,

      reference: row.reference || String(row.id),

      status: row.status || 'completed',

      metadata: row.metadata || {}

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

      recipientBank: row.recipient_bank || '',

      recipientAccount: row.recipient_account || '',

      recipientEmail: row.recipient_email || '',

      recipientCountry: row.recipient_country || '',

      swiftBic: row.swift_bic || '',

      reference: row.reference || String(row.id),

      created_at: row.created_at,

      handled_at: row.handled_at,

      date: row.created_at

    }))

  };

}

async function loadAdminCustomers() {

  const result = await pool.query(`

    SELECT

      u.id,u.name,u.email,u.phone,u.role,u.status,

      u.primary_currency,u.profile_image,u.created_at,

      COALESCE(

        json_agg(

          json_build_object(

            'currency',b.currency,

            'balance',b.amount,

            'amount',b.amount

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

      u.id,u.name,u.email,u.role,u.status,

      u.primary_currency,u.profile_image,u.created_at

    ORDER BY u.created_at DESC

  `);

  return result.rows.map(row => ({

    id: String(row.id),

    userId: String(row.id),

    user_id: String(row.id),

    customerId: String(row.id),

    customer_id: String(row.id),

    name: row.name,

    full_name: row.name,

    fullName: row.name,

    email: row.email,
    phone: row.phone || '',

    role: 'customer',

    status: row.status,

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

          amount: Number(account.amount || account.balance || 0)

        }))

      : []

  }));

}

/*

\=========================================================

ROBUST CUSTOMER RESOLUTION

\=========================================================

*/

function collectIdentifiers(value, output = []) {

  if (value === undefined || value === null) {

    return output;

  }

  if (

    typeof value === 'string' ||

    typeof value === 'number'

  ) {

    const text = String(value).trim();

    if (text) output.push(text);

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

      'selected_user'

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

    /*

    Try the strongest identifiers first.

    */

    const identifiers = [];

    collectIdentifiers(identifier, identifiers);

    for (const item of identifiers) {

      const found = await resolveCustomer(item);

      if (found) return found;

    }

    return null;

  }

  const value = normalizeText(identifier);

  if (!value) return null;

  /*

  UUID

  */

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

  /*

  EMAIL

  */

  if (value.includes('@')) {

    const emailResult = await pool.query(

      `

      SELECT id

      FROM acb_users

      WHERE LOWER(email)=LOWER($1)

      AND LOWER(role)='customer'

      LIMIT 1

      `,

      [value]

    );

    if (emailResult.rowCount) {

      return String(emailResult.rows[0].id);

    }

  }

  /*

  PHONE

  */

  const normalizedPhone = normalizePhone(value);

  if (validPhone(normalizedPhone)) {
    const phoneResult = await pool.query(
      `
      SELECT id
      FROM acb_users
      WHERE phone=$1
      AND LOWER(role)='customer'
      LIMIT 1
      `,
      [normalizedPhone]
    );

    if (phoneResult.rowCount) {
      return String(phoneResult.rows[0].id);
    }
  }

  /*

  EXACT NAME

  */

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

  /*

  Explicit fields first.

  */

  const fields = [

    req.body?.userId,

    req.body?.user_id,

    req.body?.customerId,

    req.body?.customer_id,

    req.body?.id,

    req.body?.email,

    req.body?.emailAddress,

    req.body?.email_address,

    req.body?.name,

    req.body?.fullName,

    req.body?.full_name,

    req.body?.username,

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

  /*

  Also inspect the entire body.

  */

  collectIdentifiers(req.body, candidates);

  const unique = [

    ...new Set(

      candidates

        .map(value => String(value).trim())

        .filter(Boolean)

    )

  ];

  /*

  Strongest identifiers first.

  */

  const ordered = [

    ...unique.filter(validUUID),

    ...unique.filter(value => value.includes('@')),

    ...unique.filter(value => !validUUID(value) && !value.includes('@'))

  ];

  for (const candidate of ordered) {

    const resolved =

      await resolveCustomer(candidate);

    if (resolved) {

      return resolved;

    }

  }

  return null;

}

/*

\=========================================================

SUPPORT RESOLUTION

\=========================================================

*/

async function resolveSupportCustomerId(identifier) {

  if (!identifier) return null;

  const customer =

    await resolveCustomer(identifier);

  if (customer) return customer;

  let value = identifier;

  if (

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

      identifier.name ||

      '';

  }

  value = normalizeText(value);

  if (!value) return null;

  if (validUUID(value)) {

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

  }

  return null;

}

async function resolveSupportCustomerFromRequest(req) {

  const identifiers = [];

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

      await resolveCustomer(identifier);

    if (customer) return customer;

  }

  for (const identifier of unique) {

    const customer =

      await resolveSupportCustomerId(identifier);

    if (customer) return customer;

  }

  return null;

}

/*

\=========================================================

DATABASE INITIALIZATION

\=========================================================

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

    )

  `);

  await pool.query(`

    ALTER TABLE acb_users ALTER COLUMN email DROP NOT NULL

  `);

  await pool.query(`ALTER TABLE acb_users ADD COLUMN IF NOT EXISTS account_number TEXT`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS acb_users_account_number_unique ON acb_users(account_number) WHERE account_number IS NOT NULL AND account_number <> ''`);

  await pool.query(`

    ALTER TABLE acb_users ADD COLUMN IF NOT EXISTS phone TEXT

  `);

  await pool.query(`

    ALTER TABLE acb_users ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN NOT NULL DEFAULT FALSE

  `);

  await pool.query(`

    CREATE UNIQUE INDEX IF NOT EXISTS acb_users_phone_unique
    ON acb_users(phone)
    WHERE phone IS NOT NULL AND phone <> ''

  `);

  await pool.query(`

    CREATE TABLE IF NOT EXISTS acb_verification_codes (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES acb_users(id) ON DELETE CASCADE,
      purpose TEXT NOT NULL,
      identifier TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      payload JSONB,
      expires_at TIMESTAMPTZ NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      verified_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )

  `);

  await pool.query(`

    CREATE INDEX IF NOT EXISTS acb_verification_codes_lookup
    ON acb_verification_codes(identifier,purpose,created_at DESC)

  `);

  await pool.query(`

    CREATE TABLE IF NOT EXISTS acb_balances (

      user_id UUID NOT NULL

        REFERENCES acb_users(id)

        ON DELETE CASCADE,

      currency TEXT NOT NULL,

      amount NUMERIC(24,2) NOT NULL DEFAULT 0,

      PRIMARY KEY(user_id,currency)

    )

  `);


  await pool.query(`

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

  `);

  await pool.query(`

    CREATE TABLE IF NOT EXISTS acb_notifications (

      id UUID PRIMARY KEY,

      user_id UUID NOT NULL

        REFERENCES acb_users(id)

        ON DELETE CASCADE,

      message TEXT NOT NULL,

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

      read_at TIMESTAMPTZ

    )

  `);

  await pool.query(`

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

  `);

  await pool.query(`ALTER TABLE acb_users ADD COLUMN IF NOT EXISTS account_number TEXT`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS acb_users_account_number_unique ON acb_users(account_number) WHERE account_number IS NOT NULL AND account_number <> ''`);
  await pool.query(`ALTER TABLE acb_transactions ADD COLUMN IF NOT EXISTS reference TEXT`);
  await pool.query(`ALTER TABLE acb_transactions ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'completed'`);
  await pool.query(`ALTER TABLE acb_transactions ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb`);
  await pool.query(`ALTER TABLE acb_requests ADD COLUMN IF NOT EXISTS recipient_bank TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE acb_requests ADD COLUMN IF NOT EXISTS recipient_account TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE acb_requests ADD COLUMN IF NOT EXISTS recipient_email TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE acb_requests ADD COLUMN IF NOT EXISTS recipient_country TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE acb_requests ADD COLUMN IF NOT EXISTS swift_bic TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE acb_requests ADD COLUMN IF NOT EXISTS reference TEXT`);
  await pool.query(`ALTER TABLE acb_requests ADD COLUMN IF NOT EXISTS debit_transaction_id UUID`);
  await pool.query(`ALTER TABLE acb_requests ADD COLUMN IF NOT EXISTS email_sent_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE acb_requests ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS acb_demo_service_requests (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES acb_users(id) ON DELETE CASCADE,
      service TEXT NOT NULL,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      status TEXT NOT NULL DEFAULT 'received',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      handled_at TIMESTAMPTZ
    )
  `);

  await pool.query(`

    CREATE TABLE IF NOT EXISTS acb_support (

      id UUID PRIMARY KEY,

      user_id UUID NOT NULL

        REFERENCES acb_users(id)

        ON DELETE CASCADE,

      sender TEXT NOT NULL,

      message TEXT NOT NULL,

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()

    )

  `);

  const existingUsers =

    await pool.query(`

      SELECT id

      FROM acb_users

    `);

  for (const row of existingUsers.rows) {

    await ensureBalances(row.id);

  }

  if (ADMIN_EMAIL && ADMIN_PASSWORD) {

    const existing =

      await pool.query(

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

          status='Active'

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

            id,name,email,password_hash,role,

            status,primary_currency,profile_image

          )

        VALUES

          (

            $1,$2,$3,$4,'admin',

            'Active','NGN',''

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

  console.log('Database initialization completed successfully.');

}

/*

\=========================================================

HEALTH

\=========================================================

*/

app.get('/api/health', (_req, res) => {

  res.json({

    ok: true,

    demo: true,

    service: 'American Crest Demo Banking Platform'

  });

});

/*

\=========================================================

REGISTER

\=========================================================

*/

async function registerHandler(req, res) {
  try {
    const name = normalizeText(
      req.body.name || req.body.fullName || req.body.full_name ||
      req.body.username || req.body.displayName || req.body.display_name
    );
    const email = normalizeEmail(
      req.body.email || req.body.emailAddress || req.body.email_address || req.body.usernameEmail
    );
    const phone = normalizePhone(
      req.body.phone || req.body.phoneNumber || req.body.phone_number || req.body.mobile
    );
    const password = typeof req.body.password === 'string' ? req.body.password :
      typeof req.body.passcode === 'string' ? req.body.passcode :
      typeof req.body.passwordValue === 'string' ? req.body.passwordValue : '';
    const currency = String(req.body.currency || req.body.primaryCurrency || req.body.primary_currency || 'NGN').trim().toUpperCase();

    if (name.length < 2) return res.status(400).json({ ok:false, error:'Enter your full name.' });
    if (!email && !phone) return res.status(400).json({ ok:false, error:'Enter an email address or phone number.' });
    if (email && !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ ok:false, error:'Enter a valid email address.' });
    if (phone && !validPhone(phone)) return res.status(400).json({ ok:false, error:'Enter a valid phone number.' });
    if (password.length < 6) return res.status(400).json({ ok:false, error:'Password must contain at least 6 characters.' });
    if (!validCurrency(currency)) return res.status(400).json({ ok:false, error:'Invalid currency.' });

    const duplicate = await pool.query(
      `SELECT id FROM acb_users WHERE ($1 <> '' AND LOWER(email)=LOWER($1)) OR ($2 <> '' AND phone=$2) LIMIT 1`,
      [email, phone]
    );
    if (duplicate.rowCount) return res.status(409).json({ ok:false, success:false, error:'That email address or phone number is already registered.' });

    const pendingPayload = {
      name, email: email || null, phone: phone || null,
      passwordHash: await bcrypt.hash(password, 12), currency
    };
    const identifier = email || phone;
    const code = String(crypto.randomInt(100000, 1000000));
    const verificationId = uuid();
    const codeHash = await bcrypt.hash(code, 10);

    await pool.query(`DELETE FROM acb_verification_codes WHERE identifier=$1 AND purpose='registration' AND verified_at IS NULL`, [identifier]);
    await pool.query(
      `INSERT INTO acb_verification_codes (id,purpose,identifier,code_hash,payload,expires_at) VALUES ($1,'registration',$2,$3,$4,NOW()+INTERVAL '10 minutes')`,
      [verificationId, identifier, codeHash, JSON.stringify(pendingPayload)]
    );

    return res.status(202).json({
      ok:true, success:true, verificationRequired:true, verificationId,
      destination: email || phone, channel: email ? 'email' : 'phone',
      message:'Verification code generated for this demo. Enter the code before accessing the account.',
      demoVerificationCode: code
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ ok:false, success:false, error:'Unable to create account.' });
  }
}

async function verifyRegistrationHandler(req, res) {
  const verificationId = normalizeText(req.body.verificationId || req.body.verification_id || req.body.id);
  const code = normalizeText(req.body.code || req.body.verificationCode || req.body.verification_code);
  if (!validUUID(verificationId) || !/^\d{6}$/.test(code)) return res.status(400).json({ok:false,error:'Enter the 6-digit verification code.'});
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(`SELECT * FROM acb_verification_codes WHERE id=$1 AND purpose='registration' AND verified_at IS NULL AND expires_at>NOW() FOR UPDATE`, [verificationId]);
    if (!result.rowCount) { await client.query('ROLLBACK'); return res.status(400).json({ok:false,error:'Verification code is invalid or expired.'}); }
    const row = result.rows[0];
    if (row.attempts >= 5) { await client.query('ROLLBACK'); return res.status(429).json({ok:false,error:'Too many verification attempts. Start registration again.'}); }
    const valid = await bcrypt.compare(code, row.code_hash);
    if (!valid) { await client.query(`UPDATE acb_verification_codes SET attempts=attempts+1 WHERE id=$1`, [verificationId]); await client.query('COMMIT'); return res.status(400).json({ok:false,error:'Incorrect verification code.'}); }
    const payload = row.payload || {};
    const duplicate = await client.query(`SELECT id FROM acb_users WHERE ($1::text IS NOT NULL AND LOWER(email)=LOWER($1::text)) OR ($2::text IS NOT NULL AND phone=$2::text) LIMIT 1`, [payload.email || null, payload.phone || null]);
    if (duplicate.rowCount) { await client.query('ROLLBACK'); return res.status(409).json({ok:false,error:'That email address or phone number is already registered.'}); }
    const userId = uuid();
    const accountNumber = await generateAccountNumber(client);
    await client.query(`INSERT INTO acb_users (id,name,email,phone,password_hash,role,status,primary_currency,account_number,profile_image,phone_verified) VALUES ($1,$2,$3,$4,$5,'customer','Active',$6,$7,'',$8)`, [userId,payload.name,payload.email,payload.phone,payload.passwordHash,payload.currency,accountNumber,!!payload.phone]);
    await ensureBalances(userId, client);
    await client.query(`INSERT INTO acb_notifications (id,user_id,message) VALUES ($1,$2,$3)`, [uuid(),userId,'Your American Crest demo account was created successfully.']);
    const admin = await client.query(`SELECT id FROM acb_users WHERE LOWER(role)='admin' ORDER BY created_at ASC LIMIT 1`);
    if (admin.rowCount) await client.query(`INSERT INTO acb_notifications (id,user_id,message) VALUES ($1,$2,$3)`, [uuid(),admin.rows[0].id,`New demo customer registered: ${payload.name} (${payload.email || payload.phone}).`]);
    await client.query(`UPDATE acb_verification_codes SET verified_at=NOW(),user_id=$1 WHERE id=$2`, [userId,verificationId]);
    await client.query('COMMIT');
    const user = await getUser(userId);
    const token = signToken(user);
    return res.status(201).json({ok:true,success:true,message:'Account verified and created successfully.',token,accessToken:token,user,customer:user,account:user,id:user.id,userId:user.id,customerId:user.id,redirect:'dashboard'});
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('Verification registration error:',error);
    return res.status(500).json({ok:false,error:'Unable to verify and create the account.'});
  } finally { client.release(); }
}

app.post('/api/auth/register', authLimiter, registerHandler);
app.post('/api/register', authLimiter, registerHandler);
app.post('/api/signup', authLimiter, registerHandler);
app.post('/api/auth/signup', authLimiter, registerHandler);
app.post('/api/auth/verify-registration', authLimiter, verifyRegistrationHandler);
app.post('/api/verify-registration', authLimiter, verifyRegistrationHandler);


/*

\=========================================================

LOGIN

\=========================================================

*/

async function loginHandler(req, res) {
  try {
    const identifier = normalizeText(req.body.identifier || req.body.login || req.body.email || req.body.emailAddress || req.body.email_address || req.body.phone || req.body.phoneNumber || req.body.phone_number);
    const password = typeof req.body.password === 'string' ? req.body.password : typeof req.body.passcode === 'string' ? req.body.passcode : '';
    if (!identifier || !password) return res.status(400).json({ok:false,error:'Enter your email/phone and password.'});
    const email = normalizeEmail(identifier);
    const phone = normalizePhone(identifier);
    const result = await pool.query(`SELECT id,name,email,phone,password_hash,role,status,primary_currency,profile_image,created_at,phone_verified FROM acb_users WHERE (LOWER(email)=LOWER($1) AND $1<>'') OR (phone=$2 AND $2<>'') LIMIT 1`, [email,phone]);
    if (!result.rowCount) return res.status(401).json({ok:false,success:false,error:'Incorrect email/phone or password.'});
    const databaseUser=result.rows[0];
    if (!(await bcrypt.compare(password,databaseUser.password_hash))) return res.status(401).json({ok:false,success:false,error:'Incorrect email/phone or password.'});
    if (String(databaseUser.status||'').toLowerCase()==='suspended') return res.status(403).json({ok:false,success:false,error:'This account is currently suspended.'});
    if (String(databaseUser.role||'').toLowerCase()==='admin') {
      const user=await getUser(String(databaseUser.id)); const token=signToken(user);
      return res.json({ok:true,success:true,message:'Signed in successfully.',token,accessToken:token,user,customer:user,account:user,id:user.id,userId:user.id,customerId:user.id,redirect:'admin'});
    }
    const verificationId=uuid(); const code=String(crypto.randomInt(100000,1000000)); const codeHash=await bcrypt.hash(code,10); const loginIdentifier=databaseUser.email || databaseUser.phone;
    await pool.query(`DELETE FROM acb_verification_codes WHERE user_id=$1 AND purpose='login' AND verified_at IS NULL`,[databaseUser.id]);
    await pool.query(`INSERT INTO acb_verification_codes (id,user_id,purpose,identifier,code_hash,expires_at) VALUES ($1,$2,'login',$3,$4,NOW()+INTERVAL '10 minutes')`,[verificationId,databaseUser.id,loginIdentifier,codeHash]);
    return res.status(202).json({ok:true,success:true,verificationRequired:true,verificationId,destination:loginIdentifier,channel:databaseUser.email?'email':'phone',message:'Verification code generated for this demo. Enter the code before accessing the account.',demoVerificationCode:code});
  } catch(error){ console.error('Login error:',error); return res.status(500).json({ok:false,success:false,error:'Unable to sign in.'}); }
}

async function verifyLoginHandler(req,res){
  const verificationId=normalizeText(req.body.verificationId||req.body.verification_id||req.body.id); const code=normalizeText(req.body.code||req.body.verificationCode||req.body.verification_code);
  if(!validUUID(verificationId)||!/^[0-9]{6}$/.test(code)) return res.status(400).json({ok:false,error:'Enter the 6-digit verification code.'});
  const rowResult=await pool.query(`SELECT * FROM acb_verification_codes WHERE id=$1 AND purpose='login' AND verified_at IS NULL AND expires_at>NOW() LIMIT 1`,[verificationId]);
  if(!rowResult.rowCount) return res.status(400).json({ok:false,error:'Verification code is invalid or expired.'});
  const row=rowResult.rows[0]; if(row.attempts>=5) return res.status(429).json({ok:false,error:'Too many verification attempts. Start login again.'});
  if(!(await bcrypt.compare(code,row.code_hash))){ await pool.query(`UPDATE acb_verification_codes SET attempts=attempts+1 WHERE id=$1`,[verificationId]); return res.status(400).json({ok:false,error:'Incorrect verification code.'}); }
  await pool.query(`UPDATE acb_verification_codes SET verified_at=NOW() WHERE id=$1`,[verificationId]);
  const user=await getUser(String(row.user_id)); if(!user) return res.status(404).json({ok:false,error:'Account not found.'});
  const token=signToken(user); return res.json({ok:true,success:true,message:'Verification successful. Signed in successfully.',token,accessToken:token,user,customer:user,account:user,id:user.id,userId:user.id,customerId:user.id,redirect:'dashboard'});
}

app.post('/api/auth/login', authLimiter, loginHandler);
app.post('/api/login', authLimiter, loginHandler);
app.post('/api/signin', authLimiter, loginHandler);
app.post('/api/auth/signin', authLimiter, loginHandler);
app.post('/api/auth/verify-login', authLimiter, verifyLoginHandler);
app.post('/api/verify-login', authLimiter, verifyLoginHandler);


/*

\=========================================================

CURRENT USER

\=========================================================

*/

app.get('/api/me', auth, async (req, res) => {

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

    console.error('ME error:', error);

    return res.status(500).json({

      ok: false,

      error: 'Unable to load account.'

    });

  }

});

/*

\=========================================================

PROFILE

\=========================================================

*/

app.put('/api/profile', auth, writeLimiter, async (req, res) => {

  try {

    const name =

      normalizeText(

        req.body.name ||

        req.body.fullName ||

        req.body.full_name

      );

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

      [name, req.user.id]

    );

    const user =

      await getUser(req.user.id);

    return res.json({

      ok: true,

      user,

      customer: user

    });

  } catch (error) {

    console.error('Profile update error:', error);

    return res.status(500).json({

      error: 'Unable to update profile.'

    });

  }

});

app.post('/api/profile/image', auth, writeLimiter, async (req, res) => {

  try {

    const image =

      String(

        req.body.profileImage ||

        req.body.profile_image ||

        ''

      );

    if (image.length > 700000) {

      return res.status(400).json({

        error: 'Profile image is too large.'

      });

    }

    if (

      image &&

      !/^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(image)

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

      [image, req.user.id]

    );

    const user =

      await getUser(req.user.id);

    return res.json({

      ok: true,

      user,

      customer: user

    });

  } catch (error) {

    console.error('Profile image error:', error);

    return res.status(500).json({

      error: 'Unable to update profile image.'

    });

  }

});

/*

\=========================================================

CUSTOMER FUNDS REQUEST

\=========================================================

*/

app.post('/api/requests', auth, writeLimiter, async (req, res) => {
  const client = await pool.connect();
  try {
    const currency = String(req.body.currency || '').trim().toUpperCase();
    const amount = Number(req.body.amount);
    const recipient = normalizeText(req.body.recipient || req.body.recipientName).slice(0, 120);
    const recipientBank = normalizeText(req.body.recipientBank || req.body.bankName).slice(0, 160);
    const recipientAccount = normalizeText(req.body.recipientAccount || req.body.accountNumber).slice(0, 80);
    const recipientEmail = normalizeEmail(req.body.recipientEmail || req.body.email);
    const recipientCountry = normalizeText(req.body.recipientCountry || req.body.country).slice(0, 80);
    const swiftBic = normalizeText(req.body.swiftBic || req.body.swift || req.body.bic).toUpperCase().slice(0, 20);
    const note = normalizeText(req.body.note).slice(0, 500);

    if (!validCurrency(currency) || !Number.isFinite(amount) || amount <= 0 || amount > 1000000000000) {
      return res.status(400).json({ ok:false, error:'Enter a valid amount and currency.' });
    }
    if (recipient.length < 2) return res.status(400).json({ ok:false, error:'Enter the recipient name.' });
    if (recipientBank.length < 2) return res.status(400).json({ ok:false, error:'Enter the recipient bank name.' });
    if (recipientAccount.length < 3) return res.status(400).json({ ok:false, error:'Enter the recipient account number.' });
    if (recipientEmail && !/^\S+@\S+\.\S+$/.test(recipientEmail)) return res.status(400).json({ok:false,error:'Enter a valid recipient email.'});

    await client.query('BEGIN');
    const userResult = await client.query(`SELECT id,name,email,status,primary_currency,account_number FROM acb_users WHERE id=$1 AND LOWER(role)='customer' FOR UPDATE`, [req.user.id]);
    if (!userResult.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ok:false,error:'Customer account not found.'}); }
    const customer = userResult.rows[0];
    if (String(customer.status).toLowerCase() === 'suspended') { await client.query('ROLLBACK'); return res.status(403).json({ok:false,error:'This account is suspended.'}); }

    await client.query(`INSERT INTO acb_balances(user_id,currency,amount) VALUES($1,$2,0) ON CONFLICT(user_id,currency) DO NOTHING`, [req.user.id,currency]);
    const balancesResult = await client.query(`SELECT currency,amount FROM acb_balances WHERE user_id=$1 FOR UPDATE`, [req.user.id]);
    const balances = Object.fromEntries(balancesResult.rows.map(r=>[String(r.currency).toUpperCase(),Number(r.amount||0)]));
    const fee = amount * DEMO_TRANSFER_FEE_RATE;
    const targetTotal = amount + fee;
    let fundingCurrency = currency;
    let debitAmount = targetTotal;
    if ((balances[currency] || 0) < targetTotal) {
      const primary = String(customer.primary_currency || 'NGN').toUpperCase();
      const candidates = [primary,...Object.keys(balances).filter(c=>c!==primary)];
      let found = null;
      for (const candidate of candidates) {
        const converted = convertDemoAmount(targetTotal, currency, candidate);
        if ((balances[candidate] || 0) >= converted) { found={currency:candidate,amount:converted}; break; }
      }
      if (!found) { await client.query('ROLLBACK'); return res.status(400).json({ok:false,error:`Insufficient demo funds. Required ${targetTotal.toLocaleString()} ${currency}, including a ${DEMO_TRANSFER_FEE_RATE*100}% demo transfer fee.`}); }
      fundingCurrency=found.currency;
      debitAmount=found.amount;
    }
    const exchangeRate = convertDemoAmount(1, fundingCurrency, currency);

    const requestId = uuid();
    const reference = makeReference('ACBTRF');
    const debitTransactionId = uuid();

    await client.query(`UPDATE acb_balances SET amount=amount-$1 WHERE user_id=$2 AND currency=$3`, [debitAmount,req.user.id,fundingCurrency]);
    await client.query(`INSERT INTO acb_transactions(id,user_id,kind,title,amount,currency,reference,status,metadata) VALUES($1,$2,'debit',$3,$4,$5,$6,'pending',$7)`, [debitTransactionId,req.user.id,`Transfer to ${recipient}`,debitAmount,fundingCurrency,reference,JSON.stringify({recipient,recipientBank,recipientAccount,recipientEmail,recipientCountry,swiftBic,requestId,requestedAmount:amount,requestedCurrency:currency,fee,fundingCurrency,exchangeRate})]);
    await client.query(`INSERT INTO acb_requests(id,user_id,currency,amount,recipient,note,status,recipient_bank,recipient_account,recipient_email,recipient_country,swift_bic,reference,debit_transaction_id,metadata) VALUES($1,$2,$3,$4,$5,$6,'pending',$7,$8,$9,$10,$11,$12,$13,$14)`, [requestId,req.user.id,currency,amount,recipient,note,recipientBank,recipientAccount,recipientEmail,recipientCountry,swiftBic,reference,debitTransactionId,JSON.stringify({demo:true,fee,fundingCurrency,debitAmount,exchangeRate})]);
    await client.query(`INSERT INTO acb_notifications(id,user_id,message) VALUES($1,$2,$3)`, [uuid(),req.user.id,`Transfer ${reference}: your account was debited ${debitAmount.toLocaleString()} ${fundingCurrency} for ${amount.toLocaleString()} ${currency}. Status: PENDING.`]);
    const admin = await client.query(`SELECT id FROM acb_users WHERE LOWER(role)='admin' ORDER BY created_at ASC LIMIT 1`);
    if (admin.rowCount) await client.query(`INSERT INTO acb_notifications(id,user_id,message) VALUES($1,$2,$3)`, [uuid(),admin.rows[0].id,`Pending demo transfer ${reference}: ${customer.name} → ${recipient}, ${amount.toLocaleString()} ${currency} (debit ${debitAmount.toLocaleString()} ${fundingCurrency}).`]);
    await client.query('COMMIT');

    const user = await getUser(String(req.user.id));
    const date = new Date().toISOString();
    const receipt = receiptSvg({
      reference,
      amount: amount.toFixed(2),
      currency,
      recipient,
      recipientEmail,
      bankName: recipientBank,
      status: 'pending',
      date,
      senderName: customer.name,
      senderEmail: customer.email,
      senderAccountNumber: customer.account_number,
      fee,
      fundingCurrency,
      debitAmount,
      exchangeRate
    });
    let emailSent = false;
    console.log(`[DEMO EMAIL] transfer ${reference} recipientEmail=${recipientEmail || '(missing)'}`);
    if (recipientEmail) {
      emailSent = await sendDemoEmail({
        to: recipientEmail,
        subject: `Transfer pending — ${reference}`,
        receipt,
        html: `<div style="font-family:Arial,sans-serif;max-width:640px;margin:auto;color:#172033"><h2>${BANK_NAME}</h2><p><b>A simulated transfer is pending.</b></p><p>A demo transfer has been initiated for you and is awaiting processing.</p><div style="padding:18px;background:#f4f7fb;border-radius:14px"><p><b>Amount:</b> ${amount.toLocaleString()} ${currency}</p><p><b>Reference:</b> ${reference}</p><p><b>Recipient bank:</b> ${recipientBank}</p><p><b>Status:</b> PENDING</p></div><p style="color:#64748b">This is a fictional/demo banking notification. No real funds were transferred.</p></div>`
      });
      console.log(`[DEMO EMAIL] transfer ${reference} result=${emailSent ? 'sent' : 'not-sent'}`);
      if (emailSent) await pool.query(`UPDATE acb_requests SET email_sent_at=NOW() WHERE id=$1`, [requestId]);
    }

    return res.status(201).json({ok:true,success:true,message:'Demo transfer submitted and the account was debited.',emailSent,request:{id:requestId,status:'pending',reference,created_at:date,recipient,recipientBank,recipientAccount,recipientEmail,recipientCountry,swiftBic,amount,currency,note,fee,fundingCurrency,debitAmount,exchangeRate,totalDebited:debitAmount},user,customer:user});
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('Transfer request error:', error);
    return res.status(500).json({ok:false,error:'Unable to submit transfer.'});
  } finally { client.release(); }
});

/*

=========================================================

ADMIN LOGIN

=========================================================
*/


app.post('/api/admin/login', authLimiter, async (req, res) => {

  try {

    const email =

      normalizeEmail(

        req.body.email ||

        req.body.emailAddress ||

        req.body.email_address

      );

    const password =

      typeof req.body.password === 'string'

        ? req.body.password

        : typeof req.body.passcode === 'string'

          ? req.body.passcode

          : '';

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

        error: 'Invalid administrator email or password.'

      });

    }

    const valid =

      await bcrypt.compare(

        password,

        result.rows[0].password_hash

      );

    if (!valid) {

      return res.status(401).json({

        error: 'Invalid administrator email or password.'

      });

    }

    await ensureBalances(result.rows[0].id);

    const user =

      await getUser(result.rows[0].id);

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

    console.error('Admin login error:', error);

    return res.status(500).json({

      error: 'Unable to sign in as administrator.'

    });

  }

});

/*

\=========================================================

ADMIN SUMMARY

\=========================================================

*/

app.get('/api/admin/summary', auth, adminOnly, async (_req, res) => {

  try {

    const customers =

      await pool.query(`

        SELECT COUNT(*)::int AS count

        FROM acb_users

        WHERE LOWER(role)='customer'

      `);

    const pending =

      await pool.query(`

        SELECT COUNT(*)::int AS count

        FROM acb_requests

        WHERE status='pending'

      `);

    const support =

      await pool.query(`

        SELECT COUNT(*)::int AS count

        FROM acb_support

        WHERE sender='customer'

      `);

    const balanceResult =

      await pool.query(`

        SELECT

          currency,

          COALESCE(SUM(amount),0) AS total

        FROM acb_balances b

        JOIN acb_users u

          ON u.id=b.user_id

        WHERE LOWER(u.role)='customer'

        GROUP BY currency

        ORDER BY currency

      `);

    const customerCount =

      Number(customers.rows[0].count);

    const pendingCount =

      Number(pending.rows[0].count);

    const supportCount =

      Number(support.rows[0].count);

    return res.json({

      ok: true,

      customers: customerCount,

      customerCount,

      totalCustomers: customerCount,

      pendingTransfers: pendingCount,

      pending_transfers: pendingCount,

      openSupport: supportCount,

      open_support: supportCount,

      balances:

        balanceResult.rows.map(row => ({

          currency: row.currency,

          total: Number(row.total || 0)

        }))

    });

  } catch (error) {

    console.error('Admin summary error:', error);

    return res.status(500).json({

      error: 'Unable to load dashboard.'

    });

  }

});

/*

\=========================================================

ADMIN CUSTOMERS

\=========================================================

*/

app.get('/api/admin/customers', auth, adminOnly, async (_req, res) => {

  try {

    const customers =

      await loadAdminCustomers();

    return res.json({

      ok: true,

      customers,

      users: customers,

      data: customers,

      items: customers,

      total: customers.length,

      count: customers.length

    });

  } catch (error) {

    console.error('Admin customers error:', error);

    return res.status(500).json({

      ok: false,

      error: 'Unable to load customers.',

      customers: [],

      users: [],

      data: [],

      items: []

    });

  }

});

app.get('/api/admin/users', auth, adminOnly, async (_req, res) => {

  try {

    const customers =

      await loadAdminCustomers();

    return res.json({

      ok: true,

      users: customers,

      customers,

      data: customers,

      total: customers.length,

      count: customers.length

    });

  } catch (error) {

    console.error('Admin users error:', error);

    return res.status(500).json({

      ok: false,

      error: 'Unable to load users.',

      users: [],

      customers: [],

      data: []

    });

  }

});

/*

\=========================================================

ADMIN STATE

\=========================================================

*/

app.get('/api/admin/state', auth, adminOnly, async (_req, res) => {

  try {

    const customers =

      await pool.query(`

        SELECT

          u.id,u.name,u.email,u.status,u.primary_currency,

          u.profile_image,u.created_at,

          COALESCE(

            json_agg(

              json_build_object(

                'currency',b.currency,

                'balance',b.amount,

                'amount',b.amount

              ) ORDER BY b.currency

            ) FILTER (WHERE b.currency IS NOT NULL),

            '[]'::json

          ) AS accounts

        FROM acb_users u

        LEFT JOIN acb_balances b

          ON b.user_id=u.id

        WHERE LOWER(u.role)='customer'

        GROUP BY

          u.id,u.name,u.email,u.status,u.primary_currency,

          u.profile_image,u.created_at

        ORDER BY u.created_at DESC

      `);

    const requests =

      await pool.query(`

        SELECT

          r.id,r.user_id,u.name,u.email,

          r.currency,r.amount,r.recipient,r.note,

          r.status,r.created_at,r.handled_at

        FROM acb_requests r

        JOIN acb_users u

          ON u.id=r.user_id

        ORDER BY r.created_at DESC

        LIMIT 200

      `);

    const support =

      await pool.query(`

        SELECT

          s.id,s.user_id,u.name,u.email,

          s.sender,s.message,s.created_at

        FROM acb_support s

        JOIN acb_users u

          ON u.id=s.user_id

        ORDER BY s.created_at DESC

        LIMIT 200

      `);

    return res.json({

      ok: true,

      customers:

        customers.rows.map(row => ({

          ...row,

          id: String(row.id),

          userId: String(row.id),

          customerId: String(row.id),

          customer_id: String(row.id),

          full_name: row.name,

          fullName: row.name,

          primaryCurrency: row.primary_currency,

          profileImage: row.profile_image || '',

          accounts: Array.isArray(row.accounts)

            ? row.accounts.map(account => ({

                currency: account.currency,

                balance: Number(account.balance || 0),

                amount: Number(account.amount || account.balance || 0)

              }))

            : [],

          balances: (Array.isArray(row.accounts) ? row.accounts : []).reduce((map, account) => {

            map[account.currency] = Number(account.amount || account.balance || 0);

            return map;

          }, {}),

          createdAt: row.created_at

        })),

      requests:

        requests.rows.map(row => ({

          ...row,

          id: String(row.id),

          user_id: String(row.user_id),

          userId: String(row.user_id),

          customerId: String(row.user_id),

          customer_id: String(row.user_id),

          amount: Number(row.amount),

          date: row.created_at

        })),

      support:

        support.rows.map(row => ({

          ...row,

          id: String(row.id),

          user_id: String(row.user_id),

          userId: String(row.user_id),

          customerId: String(row.user_id),

          customer_id: String(row.user_id),

          date: row.created_at

        }))

    });

  } catch (error) {

    console.error('Admin state error:', error);

    return res.status(500).json({

      error: 'Unable to load administrator data.'

    });

  }

});

/* CUSTOMER NOTIFICATION DELETE — customer can delete only their own notification. */
app.delete('/api/notifications/:id', auth, writeLimiter, async (req, res) => {
  try {
    if (!validUUID(req.params.id)) {
      return res.status(400).json({ ok: false, error: 'Invalid notification ID.' });
    }

    const result = await pool.query(
      `DELETE FROM acb_notifications
       WHERE id=$1 AND user_id=$2
       RETURNING id`,
      [req.params.id, req.user.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ ok: false, error: 'Notification not found.' });
    }

    return res.json({
      ok: true,
      success: true,
      deleted: true,
      notificationId: String(result.rows[0].id)
    });
  } catch (error) {
    console.error('Customer notification delete error:', error);
    return res.status(500).json({ ok: false, error: 'Unable to delete notification.' });
  }
});

/*

\=========================================================

ADMIN NOTIFICATIONS

\=========================================================

*/

app.get('/api/admin/notifications', auth, adminOnly, async (req, res) => {

  try {

    const result =

      await pool.query(

        `

        SELECT

          n.id,n.user_id,n.message,

          n.created_at,n.read_at

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

    return res.json({

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

    console.error('Admin notification error:', error);

    return res.status(500).json({

      error: 'Unable to load notifications.'

    });

  }

});

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

        [req.params.id, req.user.id]

      );

      return res.json({ ok: true });

    } catch (error) {

      console.error('Mark notification error:', error);

      return res.status(500).json({

        error: 'Unable to update notification.'

      });

    }

  }

);

/*

\=========================================================

ADMIN ADD FUNDS

FIXED:

\- Accepts customer UUID

\- Accepts customer email

\- Accepts customer name

\- Accepts nested customer objects

\- Accepts JSON-string customer objects

\- Uses transaction

\- Updates actual customer balance

\- Creates transaction

\- Creates notification

\- Returns updated customer/balance

\=========================================================

*/

async function creditCustomerAccount({

  userId,

  currency,

  amount,

  description

}) {

  const client =

    await pool.connect();

  try {

    await client.query('BEGIN');

    const customerResult =

      await client.query(

        `

        SELECT

          id,name,email,status,primary_currency

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

        { code: 'CUSTOMER_NOT_FOUND' }

      );

    }

    await client.query(

      `

      INSERT INTO acb_balances

        (user_id,currency,amount)

      VALUES

        ($1,$2,0)

      ON CONFLICT(user_id,currency)

      DO NOTHING

      `,

      [userId, currency]

    );

    await client.query(

      `

      UPDATE acb_balances

      SET amount=amount+$1

      WHERE user_id=$2

      AND currency=$3

      `,

      [amount, userId, currency]

    );

    const transactionId = uuid();

    await client.query(

      `

      INSERT INTO acb_transactions

        (

          id,user_id,kind,title,

          amount,currency

        )

      VALUES

        (

          $1,$2,'credit',$3,

          $4,$5

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

        (id,user_id,message)

      VALUES

        ($1,$2,$3)

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

        [userId, currency]

      );

    const newBalance =

      Number(

        balanceResult.rows[0]?.amount || 0

      );

    await client.query('COMMIT');

    return {

      customer: customerResult.rows[0],

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

async function handleAdminCredit(req, res, fixedId) {

  try {

    let userId = null;

    /*

    1. Route customer ID.

    */

    if (fixedId) {

      userId =

        await resolveCustomer(fixedId);

    }

    /*

    2. Explicit customer ID fields.

    */

    if (!userId) {

      const directIdentifiers = [

        req.body?.customerId,

        req.body?.customer_id,

        req.body?.userId,

        req.body?.user_id,

        req.body?.customer?.id,

        req.body?.customer?.userId,

        req.body?.customer?.user_id,

        req.body?.customer?.customerId,

        req.body?.customer?.customer_id,

        req.body?.user?.id,

        req.body?.user?.userId,

        req.body?.account?.id,

        req.body?.account?.userId

      ];

      for (const identifier of directIdentifiers) {

        if (!identifier) continue;

        userId =

          await resolveCustomer(identifier);

        if (userId) break;

      }

    }

    /*

    3. Entire request body.

    */

    if (!userId) {

      userId =

        await resolveCustomerFromRequest(req);

    }

    /*

    4. Frontends sometimes send the selected

       customer as a JSON string.

    */

    if (!userId) {

      const possibleObjects = [

        req.body?.customer,

        req.body?.user,

        req.body?.account,

        req.body?.selectedCustomer,

        req.body?.selected_customer,

        req.body?.selectedUser,

        req.body?.selected_user,

        req.body?.data

      ];

      for (const item of possibleObjects) {

        if (typeof item !== 'string') continue;

        try {

          const parsed =

            JSON.parse(item);

          userId =

            await resolveCustomer(parsed);

          if (userId) break;

        } catch {

          /*

          If it isn't JSON, also try it directly

          as email/name/UUID.

          */

          userId =

            await resolveCustomer(item);

          if (userId) break;

        }

      }

    }

    const currency =

      String(

        req.body.currency ||

        req.body.currencyCode ||

        req.body.currency_code ||

        req.body.selectedCurrency ||

        req.body.accountCurrency ||

        req.body.selected_currency ||

        'NGN'

      )

        .trim()

        .toUpperCase();

    const amount =

      Number(

        req.body.amount ??

        req.body.value ??

        req.body.funds ??

        req.body.balance ??

        req.body.creditAmount ??

        req.body.credit_amount

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

    if (!userId) {

      return res.status(404).json({

        ok: false,

        success: false,

        error: 'Customer information cannot be found.',

        message: 'Customer information cannot be found.'

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

        success: false,

        error: 'Enter a valid currency and amount.'

      });

    }

    const result =

      await creditCustomerAccount({

        userId,

        currency,

        amount,

        description

      });

    /*

    IMPORTANT:

    Reload the customer directly from PostgreSQL

    after the committed balance update.

    */

    const updatedUser =

      await getUser(userId);

    if (!updatedUser) {

      return res.status(500).json({

        ok: false,

        success: false,

        error:

          'Funds were credited but the updated customer could not be loaded.'

      });

    }

    return res.json({

      ok: true,

      success: true,

      message:

        `Customer account funded successfully. ${amount.toLocaleString()} ${currency} added.`,

      user: updatedUser,

      customer: updatedUser,

      updatedCustomer: updatedUser,

      customerId: userId,

      userId,

      balance:

        Number(

          updatedUser.balances?.[currency] || 0

        ),

      balances:

        updatedUser.balances || {},

      accounts:

        updatedUser.accounts || [],

      currency,

      amount,

      transactionId:

        result.transactionId,

      notificationId:

        result.notificationId

    });

  } catch (error) {

    console.error('Admin credit error:', error);

    if (error.code === 'CUSTOMER_NOT_FOUND') {

      return res.status(404).json({

        ok: false,

        success: false,

        error: 'Customer information cannot be found.'

      });

    }

    return res.status(500).json({

      ok: false,

      success: false,

      error: 'Unable to credit customer.'

    });

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

      res,

      null

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

      res,

      null

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

      res,

      null

    );

  }

);

/*

\=========================================================

ADMIN NOTIFY

\=========================================================

*/

app.post('/api/admin/notify', auth, adminOnly, writeLimiter, async (req, res) => {

  try {

    const userId =

      await resolveCustomerFromRequest(req);

    const message =

      String(req.body.message || '')

        .trim()

        .slice(0, 1000);

    if (!userId) {

      return res.status(404).json({

        error: 'Customer not found.'

      });

    }

    if (!message) {

      return res.status(400).json({

        error: 'Select a customer and write a notification.'

      });

    }

    await pool.query(

      `

      INSERT INTO acb_notifications

        (id,user_id,message)

      VALUES

        ($1,$2,$3)

      `,

      [uuid(), userId, message]

    );

    return res.json({

      ok: true,

      success: true

    });

  } catch (error) {

    console.error('Admin notify error:', error);

    return res.status(500).json({

      error: 'Unable to send notification.'

    });

  }

});

/*

\=========================================================

CUSTOMER STATUS

\=========================================================

*/

app.patch(

  '/api/admin/customers/:id/status',

  auth,

  adminOnly,

  writeLimiter,

  async (req, res) => {

    try {

      const userId =

        await resolveCustomer(req.params.id);

      if (!userId) {

        return res.status(404).json({

          error: 'Customer not found.'

        });

      }

      const status =

        String(req.body.status || '')

          .trim()

          .toLowerCase();

      if (

        !['active','suspended','pending'].includes(status)

      ) {

        return res.status(400).json({

          error: 'Invalid account status.'

        });

      }

      const normalized =

        status === 'active'

          ? 'Active'

          : status === 'suspended'

            ? 'Suspended'

            : 'Pending';

      await pool.query(

        `

        UPDATE acb_users

        SET status=$1

        WHERE id=$2

        AND LOWER(role)='customer'

        `,

        [normalized, userId]

      );

      return res.json({

        ok: true,

        status: normalized

      });

    } catch (error) {

      console.error('Customer status error:', error);

      return res.status(500).json({

        error: 'Unable to change account status.'

      });

    }

  }

);

/*

\=========================================================

ADMIN SUPPORT

\=========================================================

*/

app.get('/api/admin/support', auth, adminOnly, async (_req, res) => {

  try {

    const result =

      await pool.query(

        `

        SELECT

          s.id,s.user_id,u.name,u.email,

          s.sender,s.message,s.created_at

        FROM acb_support s

        JOIN acb_users u

          ON u.id=s.user_id

        WHERE LOWER(u.role)='customer'

        ORDER BY s.created_at ASC

        LIMIT 500

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

          userId,

          customerId: userId,

          customer_id: userId,

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

        userId,

        customerId: userId,

        customer_id: userId,

        sender: row.sender,

        message: row.message,

        created_at: row.created_at,

        date: row.created_at

      });

      grouped[userId].message =

        row.message;

      grouped[userId].status =

        row.sender === 'admin'

          ? 'answered'

          : 'pending';

    }

    const tickets =

      Object.values(grouped);

    return res.json({

      ok: true,

      tickets,

      support: tickets,

      data: tickets

    });

  } catch (error) {

    console.error('Admin support error:', error);

    return res.status(500).json({

      ok: false,

      error: 'Unable to load support requests.',

      tickets: [],

      support: [],

      data: []

    });

  }

});

/*

\=========================================================

CUSTOMER SUPPORT

\=========================================================

*/

app.post('/api/support', auth, writeLimiter, async (req, res) => {

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

        (id,user_id,sender,message)

      VALUES

        ($1,$2,'customer',$3)

      `,

      [supportId, req.user.id, message]

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

          (id,user_id,message)

        VALUES

          ($1,$2,$3)

        `,

        [

          uuid(),

          admin.rows[0].id,

          `New support message from ${customer.name} (${customer.email}).`

        ]

      );

    }

    return res.status(201).json({

      ok: true,

      success: true,

      supportId,

      user: customer,

      customer

    });

  } catch (error) {

    console.error('Customer support error:', error);

    return res.status(500).json({

      error: 'Unable to send support message.'

    });

  }

});

/*

\=========================================================

ADMIN SUPPORT REPLY

\=========================================================

*/

async function sendAdminSupportReply({

  userId,

  message

}) {

  const client =

    await pool.connect();

  try {

    await client.query('BEGIN');

    const customer =

      await client.query(

        `

        SELECT id,name,email

        FROM acb_users

        WHERE id=$1

        AND LOWER(role)='customer'

        FOR UPDATE

        `,

        [userId]

      );

    if (!customer.rowCount) {

      throw Object.assign(

        new Error('Customer not found.'),

        { code: 'CUSTOMER_NOT_FOUND' }

      );

    }

    const supportId = uuid();

    await client.query(

      `

      INSERT INTO acb_support

        (id,user_id,sender,message)

      VALUES

        ($1,$2,'admin',$3)

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

        (id,user_id,message)

      VALUES

        ($1,$2,$3)

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

      customer: customer.rows[0]

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

async function handleSupportReply(req, res, routeId) {

  try {

    let userId = null;

    /*

    Route ID may be either:

    - customer UUID

    - support message UUID

    */

    if (routeId) {

      userId =

        await resolveSupportCustomerId(routeId);

    }

    /*

    Direct customer identifiers.

    */

    if (!userId) {

      const direct = [

        req.body?.customerId,

        req.body?.customer_id,

        req.body?.userId,

        req.body?.user_id,

        req.body?.customer?.id,

        req.body?.customer?.userId,

        req.body?.customer?.user_id,

        req.body?.user?.id,

        req.body?.user?.userId

      ];

      for (const identifier of direct) {

        if (!identifier) continue;

        userId =

          await resolveSupportCustomerId(

            identifier

          );

        if (userId) break;

      }

    }

    /*

    Entire body.

    */

    if (!userId) {

      userId =

        await resolveSupportCustomerFromRequest(req);

    }

    const message =

      String(

        req.body.message ||

        req.body.reply ||

        req.body.text ||

        req.body.replyMessage ||

        req.body.reply_message ||

        ''

      )

        .trim()

        .slice(0, 2000);

    if (!message) {

      return res.status(400).json({

        ok: false,

        error: 'Write a reply first.'

      });

    }

    if (!userId) {

      return res.status(404).json({

        ok: false,

        error: 'Customer support request not found.'

      });

    }

    const result =

      await sendAdminSupportReply({

        userId,

        message

      });

    const updatedUser =

      await getUser(userId);

    return res.json({

      ok: true,

      success: true,

      message:

        'Support reply sent successfully.',

      supportId:

        result.supportId,

      notificationId:

        result.notificationId,

      user:

        updatedUser,

      customer:

        updatedUser,

      updatedCustomer:

        updatedUser,

      support:

        updatedUser?.support || []

    });

  } catch (error) {

    console.error('Support reply error:', error);

    if (error.code === 'CUSTOMER_NOT_FOUND') {

      return res.status(404).json({

        ok: false,

        error: 'Customer not found.'

      });

    }

    return res.status(500).json({

      ok: false,

      error: 'Unable to send response.'

    });

  }

}

app.post(

  '/api/admin/support/:id/reply',

  auth,

  adminOnly,

  writeLimiter,

  async (req, res) => {

    await handleSupportReply(

      req,

      res,

      req.params.id

    );

  }

);

app.post(

  '/api/admin/support/reply',

  auth,

  adminOnly,

  writeLimiter,

  async (req, res) => {

    await handleSupportReply(

      req,

      res,

      null

    );

  }

);

app.post(

  '/api/admin/support/respond',

  auth,

  adminOnly,

  writeLimiter,

  async (req, res) => {

    await handleSupportReply(

      req,

      res,

      null

    );

  }

);

app.post(

  '/api/admin/support/:id/respond',

  auth,

  adminOnly,

  writeLimiter,

  async (req, res) => {

    await handleSupportReply(

      req,

      res,

      req.params.id

    );

  }

);

/*

\=========================================================

ADMIN TRANSFERS

\=========================================================

*/

app.get('/api/admin/transfers', auth, adminOnly, async (_req, res) => {

  try {

    const result =

      await pool.query(

        `

        SELECT

          r.id,r.user_id,u.name,u.email,

          r.currency,r.amount,r.recipient,

          r.note,r.status,r.created_at,r.handled_at

        FROM acb_requests r

        JOIN acb_users u

          ON u.id=r.user_id

        ORDER BY r.created_at DESC

        LIMIT 200

        `

      );

    return res.json({

      ok: true,

      transfers:

        result.rows.map(row => ({

          id: String(row.id),

          user_id: String(row.user_id),

          userId: String(row.user_id),

          customerId: String(row.user_id),

          customer_id: String(row.user_id),

          full_name: row.name,

          fullName: row.name,

          name: row.name,

          email: row.email,

          currency: row.currency,

          amount: Number(row.amount),

          recipient: row.recipient,

          reference: String(row.id),

          note: row.note,

          status: row.status,

          created_at: row.created_at,

          handled_at: row.handled_at

        }))

    });

  } catch (error) {

    console.error('Admin transfers error:', error);

    return res.status(500).json({

      error: 'Unable to load transfers.'

    });

  }

});

/*

\=========================================================

ADMIN TRANSFER STATUS

\=========================================================

*/

async function updateTransferStatus(req, res) {
  const client = await pool.connect();
  try {
    if (!validUUID(req.params.id)) return res.status(400).json({error:'Invalid transfer ID.'});
    const requested = String(req.body.status || '').trim().toLowerCase();
    const status = requested === 'successful' || requested === 'approved' ? 'approved' : requested === 'declined' || requested === 'rejected' ? 'rejected' : '';
    if (!status) return res.status(400).json({error:'Invalid transfer status.'});

    await client.query('BEGIN');
    const result = await client.query(`SELECT r.*,u.name,u.email,u.account_number FROM acb_requests r JOIN acb_users u ON u.id=r.user_id WHERE r.id=$1 FOR UPDATE`, [req.params.id]);
    if (!result.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({error:'Transfer not found.'}); }
    const request = result.rows[0];
    if (String(request.status).toLowerCase() !== 'pending') { await client.query('ROLLBACK'); return res.status(409).json({error:'This transfer has already been handled.'}); }

    if (status === 'rejected') {
      const transferMeta = request.metadata && typeof request.metadata === 'object' ? request.metadata : {};
      const fundingCurrency = String(transferMeta.fundingCurrency || request.currency).toUpperCase();
      const debitAmount = Number(transferMeta.debitAmount ?? request.amount);
      await client.query(`INSERT INTO acb_balances(user_id,currency,amount) VALUES($1,$2,$3) ON CONFLICT(user_id,currency) DO UPDATE SET amount=acb_balances.amount+EXCLUDED.amount`, [request.user_id,fundingCurrency,debitAmount]);
      const reversalReference = makeReference('ACBRVS');
      await client.query(`INSERT INTO acb_transactions(id,user_id,kind,title,amount,currency,reference,status,metadata) VALUES($1,$2,'credit',$3,$4,$5,$6,'completed',$7)`, [uuid(),request.user_id,`Transfer reversal — ${request.recipient}`,debitAmount,fundingCurrency,reversalReference,JSON.stringify({transferReference:request.reference,requestId:request.id,requestedAmount:request.amount,requestedCurrency:request.currency})]);
      await client.query(`UPDATE acb_transactions SET status='rejected' WHERE id=$1`, [request.debit_transaction_id]);
      await client.query(`UPDATE acb_requests SET status='rejected',handled_at=NOW() WHERE id=$1`, [request.id]);
      await client.query(`INSERT INTO acb_notifications(id,user_id,message) VALUES($1,$2,$3)`, [uuid(),request.user_id,`Transfer ${request.reference || request.id} was rejected. ${request.amount.toLocaleString()} ${request.currency} has been returned to your demo balance.`]);
      await client.query('COMMIT');
      const updatedUser = await getUser(String(request.user_id));
      const receipt = receiptSvg({
        reference: request.reference || String(request.id),
        amount: Number(request.amount).toFixed(2),
        currency: request.currency,
        recipient: request.recipient,
        recipientEmail: request.recipient_email,
        bankName: request.recipient_bank,
        status: 'rejected',
        date: new Date().toISOString(),
        senderName: request.name,
        senderEmail: request.email,
        senderAccountNumber: request.account_number,
        fee: Number(transferMeta.fee || 0),
        fundingCurrency: transferMeta.fundingCurrency || request.currency,
        debitAmount: Number(transferMeta.debitAmount ?? request.amount),
        exchangeRate: Number(transferMeta.exchangeRate || 1)
      });
      let emailSent = false;
      if (request.recipient_email) emailSent = await sendDemoEmail({to:request.recipient_email,subject:`Transfer rejected — ${request.reference || request.id}`,receipt,html:`<div style="font-family:Arial"><h2>${BANK_NAME}</h2><p>The simulated transfer <b>${request.reference || request.id}</b> was rejected.</p><p>No real funds were moved. The sender's demo balance was restored.</p></div>`});
      if (emailSent) await pool.query(`UPDATE acb_requests SET email_sent_at=NOW() WHERE id=$1`, [request.id]);
      return res.json({ok:true,status:'rejected',emailSent,user:updatedUser,customer:updatedUser});
    }

    await client.query(`UPDATE acb_requests SET status='approved',handled_at=NOW() WHERE id=$1`, [request.id]);
    await client.query(`UPDATE acb_transactions SET status='completed',title=$1 WHERE id=$2`, [`Transfer to ${request.recipient}`,request.debit_transaction_id]);
    await client.query(`INSERT INTO acb_notifications(id,user_id,message) VALUES($1,$2,$3)`, [uuid(),request.user_id,`Transfer ${request.reference || request.id} was approved and marked successful.`]);
    await client.query('COMMIT');
    const updatedUser = await getUser(String(request.user_id));
    const transferMeta = request.metadata && typeof request.metadata === 'object' ? request.metadata : {};
    const receipt = receiptSvg({
      reference: request.reference || String(request.id),
      amount: Number(request.amount).toFixed(2),
      currency: request.currency,
      recipient: request.recipient,
      recipientEmail: request.recipient_email,
      bankName: request.recipient_bank,
      status: 'approved',
      date: new Date().toISOString(),
      senderName: request.name,
      senderEmail: request.email,
      senderAccountNumber: request.account_number,
      fee: Number(transferMeta.fee || 0),
      fundingCurrency: transferMeta.fundingCurrency || request.currency,
      debitAmount: Number(transferMeta.debitAmount ?? request.amount),
      exchangeRate: Number(transferMeta.exchangeRate || 1)
    });
    let emailSent = false;
    if (request.recipient_email) emailSent = await sendDemoEmail({to:request.recipient_email,subject:`Transfer approved — ${request.reference || request.id}`,receipt,html:`<div style="font-family:Arial,sans-serif;max-width:640px;margin:auto;color:#172033"><h2>${BANK_NAME}</h2><p><b>Your simulated transfer is successful.</b></p><p>Reference: <b>${request.reference || request.id}</b></p><p>Amount: <b>${Number(request.amount).toLocaleString()} ${request.currency}</b></p><p>Recipient: <b>${request.recipient}</b></p><p>Bank: <b>${request.recipient_bank}</b></p><p>Status: <b>SUCCESSFUL</b></p><p style="color:#64748b">This is a fictional/demo banking notification. No real funds were transferred.</p></div>`});
    if (emailSent) await pool.query(`UPDATE acb_requests SET email_sent_at=NOW() WHERE id=$1`, [request.id]);
    return res.json({ok:true,status:'approved',message:'Demo transfer approved.',emailSent,user:updatedUser,customer:updatedUser,balance:updatedUser?.balances?.[request.currency] ?? 0});
  } catch(error) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('Transfer status error:',error);
    return res.status(500).json({error:'Unable to update transfer.'});
  } finally { client.release(); }
}

app.patch(

  '/api/admin/transfers/:id/status',

  auth,

  adminOnly,

  writeLimiter,

  updateTransferStatus

);

/*

\=========================================================

OLD APPROVE ROUTE

\=========================================================

*/

app.post(

  '/api/admin/requests/:id/approve',

  auth,

  adminOnly,

  writeLimiter,

  async (req, res) => {

    req.body.status = 'approved';

    await updateTransferStatus(

      req,

      res

    );

  }

);

/*

\=========================================================

OLD REJECT ROUTE

\=========================================================

*/

app.post(
  '/api/admin/requests/:id/reject',
  auth,
  adminOnly,
  writeLimiter,
  async (req, res) => {
    req.body.status = 'rejected';
    await updateTransferStatus(req, res);
  }
);

/*
=========================================================
DEMO SERVICE WORKFLOWS
=========================================================
*/
app.get('/api/demo/services', auth, async (req,res) => {
  try {
    const result = await pool.query(`SELECT id,service,details,status,created_at,handled_at FROM acb_demo_service_requests WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`, [req.user.id]);
    return res.json({ok:true,requests:result.rows.map(row=>({...row,id:String(row.id)}))});
  } catch(error) { console.error('Demo services load error:',error); return res.status(500).json({ok:false,error:'Unable to load demo service requests.'}); }
});

app.post('/api/demo/services', auth, writeLimiter, async (req,res) => {
  try {
    const service = normalizeText(req.body.service).slice(0,80);
    const details = req.body.details && typeof req.body.details === 'object' ? req.body.details : {note:normalizeText(req.body.details).slice(0,500)};
    const allowed = ['Add Money','Buy Data','Airtime','Pay Bills','Cards','Loans','Savings','Referral','Settings','Gift Cards'];
    if (!allowed.includes(service)) return res.status(400).json({ok:false,error:'Unknown demo service.'});
    const id=uuid();
    await pool.query(`INSERT INTO acb_demo_service_requests(id,user_id,service,details) VALUES($1,$2,$3,$4)`, [id,req.user.id,service,JSON.stringify(details)]);
    const admin=await pool.query(`SELECT id FROM acb_users WHERE LOWER(role)='admin' ORDER BY created_at ASC LIMIT 1`);
    if(admin.rowCount) await pool.query(`INSERT INTO acb_notifications(id,user_id,message) VALUES($1,$2,$3)`,[uuid(),admin.rows[0].id,`Demo ${service} request received from customer ${req.user.id}.`]);
    await pool.query(`INSERT INTO acb_notifications(id,user_id,message) VALUES($1,$2,$3)`,[uuid(),req.user.id,`${service}: your demo request was received. No real payment, purchase, loan or card issuance occurs.`]);
    return res.status(201).json({ok:true,id,service,status:'received',message:`${service} demo request received.`});
  } catch(error) { console.error('Demo service error:',error); return res.status(500).json({ok:false,error:'Unable to submit demo service request.'}); }
});

app.get('/api/bank-directory', auth, async (_req,res) => {
  return res.json({ok:true,banks:[
    {name:'American Crest Demo Banking',country:'United States',swift:'ACBDUS00'},
    {name:'Northstar Demo Bank',country:'Canada',swift:'NSDBCA00'},
    {name:'Harborline Demo Bank',country:'United Kingdom',swift:'HLDBGB00'},
    {name:'Summit Demo Bank',country:'Nigeria',swift:'SUMDNG00'},
    {name:'Pacific Demo Bank',country:'Australia',swift:'PDBAAU00'},
    {name:'Global Union Demo Bank',country:'Singapore',swift:'GUDBSG00'}
  ]});
});

/*

\=========================================================

SPA FALLBACK

\=========================================================

*/

app.get('/*', (req, res) => {

  res.sendFile(

    path.join(__dirname, 'index.html')

  );

});

/*

\=========================================================

START SERVER

\=========================================================

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
