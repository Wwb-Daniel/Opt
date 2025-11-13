const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');
const fs = require('fs');

// ----- Env vars required -----
// GMAIL_USER: Gmail address
// GMAIL_PASS: Gmail App Password (16 chars)
// FIREBASE_SERVICE_ACCOUNT_JSON: JSON string of a Firebase service account key
// or FIREBASE_SERVICE_ACCOUNT_BASE64: base64 of the JSON
// Optional: PORT

function getServiceAccount() {
  const file = process.env.FIREBASE_SERVICE_ACCOUNT_FILE;
  if (file && fs.existsSync(file)) {
    const json = fs.readFileSync(file, 'utf8');
    return JSON.parse(json);
  }
  const b64 = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;
  if (b64) {
    const json = Buffer.from(b64, 'base64').toString('utf8');
    return JSON.parse(json);
  }
  const inline = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (inline) return JSON.parse(inline);
  throw new Error('Missing FIREBASE_SERVICE_ACCOUNT_JSON or FIREBASE_SERVICE_ACCOUNT_BASE64');
}

if (!admin.apps.length) {
  const sa = getServiceAccount();
  admin.initializeApp({
    credential: admin.credential.cert(sa),
  });
}

const db = admin.firestore();

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

const smtpHost = process.env.SMTP_HOST || 'smtp.gmail.com';
const smtpPort = Number(process.env.SMTP_PORT || 587);
const smtpSecure = String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true';
const smtpUser = process.env.SMTP_USER || process.env.GMAIL_USER;
const smtpPass = process.env.SMTP_PASS || process.env.GMAIL_PASS;
const smtpFrom = process.env.SMTP_FROM || (smtpUser ? `Whisp OTP <${smtpUser}>` : undefined);

if (!smtpUser || !smtpPass) {
  console.warn('SMTP_USER/SMTP_PASS not set. Emails will fail.');
}

const transporter = nodemailer.createTransport({
  host: smtpHost,
  port: smtpPort,
  secure: smtpSecure,
  auth: { user: smtpUser, pass: smtpPass },
});

function genOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/sendOtp', async (req, res) => {
  try {
    const email = (req.body?.email || '').toString().trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'email_required' });

    const now = admin.firestore.Timestamp.now();
    const ref = db.collection('email_otps').doc(email);
    const snap = await ref.get();
    if (snap.exists) {
      const data = snap.data();
      const createdAt = data?.createdAt;
      if (createdAt && now.toMillis() - createdAt.toMillis() < 10 * 1000) {
        return res.status(429).json({ error: 'rate_limited' });
      }
    }

    const otp = genOtp();
    const codeHash = await bcrypt.hash(otp, 10);
    const expiresAt = admin.firestore.Timestamp.fromMillis(now.toMillis() + 5 * 60 * 1000);

    await ref.set({
      email,
      codeHash,
      createdAt: now,
      expiresAt,
      attempts: 0,
    });

    await transporter.sendMail({
      from: smtpFrom,
      to: email,
      subject: 'Tu código de verificación',
      text: `Tu código es: ${otp} (expira en 5 minutos)`,
      html: `<p>Tu código es: <b>${otp}</b></p><p>Expira en 5 minutos.</p>`,
    });

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    const code = e && e.code ? String(e.code) : 'send_failed';
    return res.status(500).json({ error: code });
  }
});

app.post('/verifyOtp', async (req, res) => {
  try {
    const email = (req.body?.email || '').toString().trim().toLowerCase();
    const code = (req.body?.code || '').toString().trim();
    if (!email || !code) return res.status(400).json({ error: 'missing_fields' });

    const ref = db.collection('email_otps').doc(email);
    const snap = await ref.get();
    if (!snap.exists) return res.status(400).json({ error: 'otp_not_found' });

    const data = snap.data();
    const expMs = data?.expiresAt?.toMillis?.() ?? 0;
    if (!expMs || Date.now() > expMs) {
      await ref.delete().catch(() => {});
      return res.status(400).json({ error: 'otp_expired' });
    }

    const attempts = (data?.attempts ?? 0) + 1;
    if (attempts > 5) {
      await ref.delete().catch(() => {});
      return res.status(429).json({ error: 'too_many_attempts' });
    }

    const ok = await bcrypt.compare(code, data.codeHash);
    if (!ok) {
      await ref.update({ attempts });
      return res.status(400).json({ error: 'invalid_code' });
    }

    await ref.delete().catch(() => {});

    // Ensure user exists and return custom token
    let uid;
    try {
      const user = await admin.auth().getUserByEmail(email);
      uid = user.uid;
    } catch {
      const user = await admin.auth().createUser({ email });
      uid = user.uid;
    }
    const customToken = await admin.auth().createCustomToken(uid);
    return res.json({ customToken });
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error(e);
    return res.status(500).json({ error: 'verify_failed' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`OTP server listening on :${port}`);
});
