const functions = require('firebase-functions');
const admin = require('firebase-admin');
const sgMail = require('@sendgrid/mail');
const crypto = require('crypto');

admin.initializeApp();
const db = admin.firestore();

const cfg = functions.config().sendgrid || {};
if (!cfg.key || !cfg.from) {
  console.warn('SendGrid config missing. Set sendgrid.key and sendgrid.from via firebase functions:config:set');
} else {
  sgMail.setApiKey(cfg.key);
}

// Helper: hash code
function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

exports.sendResetCode = functions.https.onCall(async (data, context) => {
  const email = String((data && data.email) || '').trim().toLowerCase();
  if (!email) throw new functions.https.HttpsError('invalid-argument', 'Missing email');

  // Basic rate limit: deny if a code sent in last 60s for same email
  const oneMinuteAgo = admin.firestore.Timestamp.fromMillis(Date.now() - 60 * 1000);
  const recent = await db.collection('password_resets')
    .where('email', '==', email)
    .where('createdAt', '>=', oneMinuteAgo)
    .limit(1).get();
  if (!recent.empty) {
    throw new functions.https.HttpsError('resource-exhausted', 'Try again later');
  }

  // Generate 6-digit numeric code
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const codeHash = hashCode(code);
  const ttlMinutes = 15;
  const now = admin.firestore.Timestamp.now();
  const expiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + ttlMinutes * 60 * 1000);

  // Store hashed code
  await db.collection('password_resets').add({
    email,
    codeHash,
    createdAt: now,
    expiresAt,
    used: false
  });

  // Send email via SendGrid (requires functions config)
  if (!cfg.key || !cfg.from) {
    // In dev you can log code to functions log (do not log in production)
    console.warn(`Reset code for ${email}: ${code}`);
    return { success: true, debug: true, message: 'Code created (not emailed in dev)' };
  }

  const msg = {
    to: email,
    from: cfg.from,
    subject: 'Your password reset code',
    text: `Your Skyward password reset code is ${code}. It expires in ${ttlMinutes} minutes.`,
    html: `<p>Your Skyward password reset code is <strong>${code}</strong>. It expires in ${ttlMinutes} minutes.</p>`
  };

  try {
    await sgMail.send(msg);
    return { success: true };
  } catch (err) {
    console.error('SendGrid error', err);
    throw new functions.https.HttpsError('internal', 'Failed to send email');
  }
});

exports.verifyResetCode = functions.https.onCall(async (data, context) => {
  const email = String((data && data.email) || '').trim().toLowerCase();
  const code = String((data && data.code) || '').trim();
  const newPassword = String((data && data.newPassword) || '');

  if (!email || !code || !newPassword) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing parameters');
  }
  if (newPassword.length < 8) {
    throw new functions.https.HttpsError('invalid-argument', 'Password must be at least 8 characters');
  }

  const codeHash = hashCode(code);
  // Find the most recent unused non-expired entry for this email
  const now = admin.firestore.Timestamp.now();
  const snaps = await db.collection('password_resets')
    .where('email', '==', email)
    .where('used', '==', false)
    .orderBy('createdAt', 'desc')
    .limit(10)
    .get();

  let docToUse = null;
  for (const d of snaps.docs) {
    const dataDoc = d.data();
    if (dataDoc.expiresAt && dataDoc.expiresAt.toMillis && dataDoc.expiresAt.toMillis() < Date.now()) {
      continue; // expired
    }
    if (dataDoc.codeHash === codeHash) {
      docToUse = d;
      break;
    }
  }

  if (!docToUse) {
    throw new functions.https.HttpsError('invalid-argument', 'Invalid or expired code');
  }

  // Mark used
  await docToUse.ref.update({ used: true, usedAt: admin.firestore.Timestamp.now() });

  // Update user's password via Admin SDK
  try {
    const user = await admin.auth().getUserByEmail(email);
    await admin.auth().updateUser(user.uid, { password: newPassword });
    return { success: true };
  } catch (err) {
    console.error('Auth update error', err);
    throw new functions.https.HttpsError('internal', 'Failed to update password');
  }
});