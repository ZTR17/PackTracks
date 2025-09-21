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
  if (!email) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing email');
  }
  try {
    // rate-limit check
    const oneMinuteAgo = admin.firestore.Timestamp.fromMillis(Date.now() - 60 * 1000);
    const recent = await db.collection('password_resets')
      .where('email', '==', email)
      .where('createdAt', '>=', oneMinuteAgo)
      .limit(1).get();
    if (!recent.empty) {
      throw new functions.https.HttpsError('resource-exhausted', 'Try again later');
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const codeHash = crypto.createHash('sha256').update(code).digest('hex');
    const ttlMinutes = 15;
    const now = admin.firestore.Timestamp.now();
    const expiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + ttlMinutes * 60 * 1000);

    await db.collection('password_resets').add({
      email,
      codeHash,
      createdAt: now,
      expiresAt,
      used: false
    });

    if (!cfg.key || !cfg.from) {
      console.warn(`SendGrid not configured. Reset code for ${email}: ${code}`);
      return { success: true, debug: true, message: 'Code created (logged on server)' };
    }

    const msg = {
      to: email,
      from: cfg.from,
      subject: 'Your password reset code',
      text: `Your Skyward password reset code is ${code}. It expires in ${ttlMinutes} minutes.`,
      html: `<p>Your Skyward password reset code is <strong>${code}</strong>. It expires in ${ttlMinutes} minutes.</p>`
    };

    await sgMail.send(msg);
    return { success: true };
  } catch (err) {
    console.error('sendResetCode error:', err);
    // Prefer returning explicit HttpsError so client sees code/message
    if (err instanceof functions.https.HttpsError) throw err;
    throw new functions.https.HttpsError('internal', err.message || 'Internal server error');
  }
});

exports.verifyResetCode = functions.https.onCall(async (data, context) => {
  const email = String((data && data.email) || '').trim().toLowerCase();
  const code = String((data && data.code) || '').trim();
  const newPassword = String((data && data.newPassword) || '');
  if (!email || !code || !newPassword) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing parameters');
  }
  try {
    const codeHash = crypto.createHash('sha256').update(code).digest('hex');
    const snaps = await db.collection('password_resets')
      .where('email', '==', email)
      .where('used', '==', false)
      .orderBy('createdAt', 'desc')
      .limit(10)
      .get();

    let docToUse = null;
    for (const d of snaps.docs) {
      const dataDoc = d.data();
      if (dataDoc.expiresAt && dataDoc.expiresAt.toMillis && dataDoc.expiresAt.toMillis() < Date.now()) continue;
      if (dataDoc.codeHash === codeHash) { docToUse = d; break; }
    }
    if (!docToUse) {
      throw new functions.https.HttpsError('invalid-argument', 'Invalid or expired code');
    }

    await docToUse.ref.update({ used: true, usedAt: admin.firestore.Timestamp.now() });

    const user = await admin.auth().getUserByEmail(email).catch(e => {
      console.error('getUserByEmail failed:', e);
      throw new functions.https.HttpsError('not-found', 'No user with that email');
    });

    await admin.auth().updateUser(user.uid, { password: newPassword });
    return { success: true };
  } catch (err) {
    console.error('verifyResetCode error:', err);
    if (err instanceof functions.https.HttpsError) throw err;
    throw new functions.https.HttpsError('internal', err.message || 'Internal server error');
  }
});