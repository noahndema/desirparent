const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const https = require('https');
const http = require('http');

const app = express();
const port = process.env.PORT || 3000;

// ── Database ──────────────────────────────────────────────
if (!process.env.DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is required');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false }
});

// ── Redirect old subdomain to new one ──────────────────────
const OLD_SUBDOMAIN = 'familien';
const NEW_SUBDOMAIN = 'desirparent';

app.use((req, res, next) => {
  const host = req.headers.host || '';
  const subdomain = host.split('.')[0];
  if (subdomain === OLD_SUBDOMAIN) {
    const newHost = host.replace(`${OLD_SUBDOMAIN}.`, `${NEW_SUBDOMAIN}.`);
    return res.redirect(301, `${req.protocol}://${newHost}${req.originalUrl}`);
  }
  next();
});

// ── Subscription Plans ────────────────────────────────────
const PLAN_CONFIG = {
  'standard_1m':  { type: 'standard', months: 1,  price: 9.99  },
  'standard_3m':  { type: 'standard', months: 3,  price: 24.99 },
  'standard_6m':  { type: 'standard', months: 6,  price: 39.99 },
  'standard_12m': { type: 'standard', months: 12, price: 59.99 },
  'premium_1m':   { type: 'premium',  months: 1,  price: 19.99 },
  'premium_3m':   { type: 'premium',  months: 3,  price: 49.99 },
  'premium_6m':   { type: 'premium',  months: 6,  price: 79.99 },
  'premium_12m':  { type: 'premium',  months: 12, price: 119.99 },
  // Recurring monthly subscriptions (auto-billed via Stripe).
  // 12-month DB expiry is a safety cutoff — active Stripe subscribers renew automatically.
  'standard_recurring': { type: 'standard', months: 12, price: 9,  recurring: true },
  'premium_recurring':  { type: 'premium',  months: 12, price: 19, recurring: true },
};

// Stripe payment link URLs (created via Polsia platform)
// Each link is configured with success_url → /compte?plan=X&status=success
// Updated 2026-05-03: added recurring subscription links
const STRIPE_LINKS = {
  
  'standard_1m': 'https://buy.stripe.com/bJe7sM9e11gY2aI8sefUQ00',
  'standard_3m': 'https://buy.stripe.com/dRm5kEeylf7OaHegYKfUQ01',
  'standard_6m': 'https://buy.stripe.com/5kQ8wQ0Hv7FmeXu37UfUQ02',
  'standard_12m': 'https://buy.stripe.com/00w6oIbm92l2bLi6k6fUQ03',
  'premium_1m': 'https://buy.stripe.com/6oUbJ23TH9Nu6qY4bYfUQ04',
  'premium_3m': 'https://buy.stripe.com/7sYfZibm91gYaHefUGfUQ05',
};
  // ── Middleware ─────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ── Cookie Parser (built-in, zero deps) ───────────────────
function parseCookies(req) {
  const cookies = {};
  const header = req.headers.cookie;
  if (header) {
    header.split(';').forEach(cookie => {
      const [name, ...rest] = cookie.split('=');
      cookies[name.trim()] = decodeURIComponent(rest.join('=').trim());
    });
  }
  return cookies;
}

// ── Password Hashing (Node.js crypto — scrypt) ────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [salt, hash] = stored.split(':');
    const computed = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(computed, 'hex'));
  } catch {
    return false;
  }
}

// ── Category Normalization ─────────────────────────────────
// Maps legacy unaccented category names to their canonical accented forms.
// Prevents duplicates in admin stats when users register via old paths.
const CATEGORY_ALIASES = {
  'Coparentalite':     'Coparentalité',
  'Homoparentalite':   'Homoparentalité',
  'Geniteur':          'Géniteur',
  'Famille Recomposee':'Famille Recomposée',
};

function normalizeCategories(cats) {
  if (!Array.isArray(cats)) return [];
  return cats.map(c => CATEGORY_ALIASES[c] || c);
}

// ── Session Middleware ─────────────────────────────────────
async function authMiddleware(req, res, next) {
  const cookies = parseCookies(req);
  const token = cookies['dp_session'];

  if (!token) {
    req.user = null;
    return next();
  }

  try {
    const result = await pool.query(
      `SELECT u.id, u.email, u.name, u.age, u.city, u.photo_url,
              u.categories, u.bio, u.registration_order, u.created_at,
              u.gender, u.country, u.region,
              COALESCE(u.plan, 'free') AS plan,
              COALESCE(u.email_verified, TRUE) AS email_verified,
              COALESCE(u.subscription_type, 'free') AS subscription_type,
              u.subscription_expires_at
       FROM sessions s
       JOIN users u ON s.user_id = u.id
       WHERE s.token = $1 AND s.expires_at > NOW()`,
      [token]
    );

    req.user = result.rows.length > 0 ? result.rows[0] : null;

    // Update session activity (non-blocking)
    if (req.user) {
      pool.query(
        `UPDATE sessions SET last_activity_at = NOW()
         WHERE token = $1 AND last_activity_at < NOW() - INTERVAL '1 second'`,
        [token]
      ).catch(() => {});
    }
  } catch (err) {
    console.error('[auth] Session lookup error:', err.message);
    req.user = null;
  }

  next();
}

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Non authentifié' });
  }
  next();
}

// Returns the effective subscription tier ('free' | 'standard' | 'premium'),
// accounting for expiry. Auto-downgrades in DB if expired.
function getEffectiveTier(user) {
  const sub = user.subscription_type || user.plan || 'free';
  if (sub === 'free') return 'free';
  const exp = user.subscription_expires_at;
  if (exp && new Date(exp) < new Date()) {
    // Expired — async downgrade (fire and forget)
    pool.query(`UPDATE users SET subscription_type = 'free', plan = 'free' WHERE id = $1`, [user.id]).catch(() => {});
    return 'free';
  }
  return sub;
}

app.use(authMiddleware);

// ── Health Check ──────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// ── Transparent Logo (removes white JPEG background) ─────
let cachedLogoPng = null;
app.get('/images/logo-transparent.png', async (req, res) => {
  try {
    if (cachedLogoPng) {
      res.set({ 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400' });
      return res.send(cachedLogoPng);
    }
    const logoUrl = 'https://pub-629428d185ca4960a0a73c850d32294b.r2.dev/company_85746/images/7c223727-f7cb-43ae-b237-dc8a4f578078.jpeg';
    const sharp = require('sharp');
    const buf = await new Promise((resolve, reject) => {
      https.get(logoUrl, (resp) => {
        const chunks = [];
        resp.on('data', c => chunks.push(c));
        resp.on('end', () => resolve(Buffer.concat(chunks)));
        resp.on('error', reject);
      }).on('error', reject);
    });
    const { data, info } = await sharp(buf).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
    // Replace white/near-white pixels with transparent
    const threshold = 235;
    for (let i = 0; i < data.length; i += 4) {
      if (data[i] >= threshold && data[i + 1] >= threshold && data[i + 2] >= threshold) {
        data[i + 3] = 0; // set alpha to 0
      }
    }
    cachedLogoPng = await sharp(data, { raw: { width: info.width, height: info.height, channels: 4 } }).png().toBuffer();
    res.set({ 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400' });
    res.send(cachedLogoPng);
  } catch (err) {
    console.error('Logo processing error:', err.message);
    // Fallback: redirect to original JPEG
    res.redirect('https://pub-629428d185ca4960a0a73c850d32294b.r2.dev/company_85746/images/7c223727-f7cb-43ae-b237-dc8a4f578078.jpeg');
  }
});

// ── Static Files ──────────────────────────────────────────
app.use('/css', express.static(path.join(__dirname, 'public', 'css')));
app.use('/js', express.static(path.join(__dirname, 'public', 'js')));
app.use('/images', express.static(path.join(__dirname, 'public', 'images')));

// ── SEO Files ─────────────────────────────────────────────
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').sendFile(path.join(__dirname, 'public', 'robots.txt'));
});
app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml').sendFile(path.join(__dirname, 'public', 'sitemap.xml'));
});

// ── Page Routes ───────────────────────────────────────────
app.get('/', (req, res) => {
  const slug = process.env.POLSIA_ANALYTICS_SLUG || '';
  const htmlPath = path.join(__dirname, 'public', 'index.html');

  if (fs.existsSync(htmlPath)) {
    let html = fs.readFileSync(htmlPath, 'utf8');
    html = html.replace('__POLSIA_SLUG__', slug);
    res.type('html').send(html);
  } else {
    res.json({ message: 'DésirParent' });
  }
});

app.get('/inscription', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'inscription.html'));
});

app.get('/connexion', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'connexion.html'));
});

app.get('/profil', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profil.html'));
});

app.get('/profil/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profil.html'));
});

app.get('/decouvrir', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'decouvrir.html'));
});

app.get('/recherche', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'recherche.html'));
});

app.get('/notifications', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'notifications.html'));
});

app.get('/messages', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'messages.html'));
});

app.get('/verifier-email', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'verifier-email.html'));
});

// Server-side subscription activation on Stripe redirect.
// Stripe redirects to /compte?plan=X&status=success (one-time) or
// /compte?plan=X&status=success&checkout_session_id=xxx (recurring) —
// we activate here so the subscription writes to DB even if client-side POST fails.
app.get('/compte', async (req, res) => {
  const { plan, status, checkout_session_id } = req.query;
  if (status === 'success' && plan && PLAN_CONFIG[plan]) {
    if (checkout_session_id) {
      // Recurring subscription: log session ID for audit trail
      console.log(`[subscription] Recurring redirect — plan=${plan}, session=${checkout_session_id}`);
    }
    if (req.user) {
      const config = PLAN_CONFIG[plan];
      try {
        const now = new Date();
        let baseDate = now;
        const existing = await pool.query(
          `SELECT subscription_type, subscription_expires_at FROM users WHERE id = $1`,
          [req.user.id]
        );
        const ex = existing.rows[0];
        if (ex && ex.subscription_expires_at && new Date(ex.subscription_expires_at) > now) {
          if (ex.subscription_type === config.type) {
            baseDate = new Date(ex.subscription_expires_at);
          }
        }
        const expiresAt = new Date(baseDate);
        expiresAt.setMonth(expiresAt.getMonth() + config.months);

        await pool.query(
          `UPDATE users SET subscription_type = $1, plan = $1, subscription_expires_at = $2 WHERE id = $3`,
          [config.type, expiresAt.toISOString(), req.user.id]
        );
        console.log(`[subscription] Server-side activated ${plan} for user ${req.user.id}, expires ${expiresAt.toISOString()}`);

        // Send emails (non-blocking, same as the POST endpoint)
        const userResult = await pool.query(`SELECT name, email FROM users WHERE id = $1`, [req.user.id]);
        const user = userResult.rows[0];
        if (user && user.email) {
          sendPaymentConfirmationEmail(user.email, user.name, config, plan, expiresAt).catch(() => {});
        }
        sendAdminSaleNotification(user?.name, user?.email, config, plan, expiresAt).catch(() => {});
      } catch (err) {
        console.error(`[subscription] Server-side activation error for user ${req.user.id}:`, err.message);
      }
    } else {
      // CRITICAL: User returned from Stripe payment but session is missing.
      // Subscription will NOT be activated. The frontend POST fallback in
      // compte.html may still catch it if the user logs in on that page.
      console.error(`[subscription] FAILED: Stripe redirect with plan=${plan} but no authenticated session. Subscription NOT activated. User must re-login and revisit /compte?plan=${plan}&status=success`);
    }
  }
  res.sendFile(path.join(__dirname, 'public', 'compte.html'));
});

app.get('/tarifs', (req, res) => {
  const slug = process.env.POLSIA_ANALYTICS_SLUG || '';
  const htmlPath = path.join(__dirname, 'public', 'tarifs.html');
  if (fs.existsSync(htmlPath)) {
    let html = fs.readFileSync(htmlPath, 'utf8');
    html = html.replace('__POLSIA_SLUG__', slug);
    res.type('html').send(html);
  } else {
    res.status(404).json({ message: 'Page non trouvée' });
  }
});

// ── API: Stats ────────────────────────────────────────────
app.get('/api/stats', async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT COUNT(*) as count FROM users WHERE name IS NOT NULL AND name != '' AND COALESCE(email_verified, TRUE) = TRUE"
    );
    res.json({ registered: parseInt(result.rows[0].count) });
  } catch (err) {
    console.error('[stats] Error:', err.message);
    res.json({ registered: 0 });
  }
});

// ── API: Register ─────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name, age, city, country, gender, categories, bio, photo_url } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Email, mot de passe et prénom sont requis.' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères.' });
  }

  // Email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Adresse email invalide.' });
  }

  // Disposable email domain check
  if (isDisposableEmail(email)) {
    return res.status(400).json({ error: 'Les adresses email temporaires ne sont pas acceptées. Utilisez une adresse email permanente.' });
  }

  // IP rate limiting
  const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown')
    .split(',')[0].trim();
  const rateCheck = await checkRegistrationRateLimit(clientIp);
  if (rateCheck.limited) {
    return res.status(429).json({ error: rateCheck.reason });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Check if email exists
    const existing = await client.query(
      'SELECT id FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );
    if (existing.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Cet email est déjà utilisé.' });
    }

    const passwordHash = hashPassword(password);

    // Get next registration order (atomic)
    const orderResult = await client.query("SELECT nextval('user_registration_seq') as next_order");
    const registrationOrder = parseInt(orderResult.rows[0].next_order);

    // Generate email verification token
    const verifyToken = crypto.randomBytes(32).toString('hex');
    const verifyExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

    const result = await client.query(
      `INSERT INTO users (email, password_hash, name, age, city, country, gender, categories, bio, photo_url, registration_order,
                          email_verified, email_verify_token, email_verify_expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, FALSE, $12, $13)
       RETURNING id, email, name, age, city, country, gender, categories, bio, photo_url, registration_order, created_at, email_verified`,
      [
        email.trim().toLowerCase(),
        passwordHash,
        name.trim(),
        age ? parseInt(age) : null,
        city ? city.trim() : null,
        country ? country.trim() : null,
        gender || null,
        JSON.stringify(normalizeCategories(categories || [])),
        bio ? bio.trim() : null,
        photo_url || null,
        registrationOrder,
        verifyToken,
        verifyExpires
      ]
    );

    const user = result.rows[0];

    // Create session (user can browse but profile is invisible until verified)
    const token = crypto.randomBytes(32).toString('hex');
    await client.query(
      'INSERT INTO sessions (user_id, token) VALUES ($1, $2)',
      [user.id, token]
    );

    await client.query('COMMIT');

    // Record the registration attempt for rate limiting (after commit, non-blocking)
    recordRegistrationAttempt(clientIp);

    // Send verification email (non-blocking — don't fail registration if email fails)
    const appUrl = process.env.APP_URL || 'https://www.desirparent.com';
    const verifyUrl = `${appUrl}/verifier-email?token=${verifyToken}`;
    sendVerificationEmail(user.email, verifyUrl, user.name).catch(() => {});

    res.cookie('dp_session', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000,
      path: '/'
    });

    console.log(`[auth] New user registered: ${user.email} (order #${registrationOrder}, verify token sent)`);

    res.status(201).json({
      user: formatUser(user),
      email_verification_required: true
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[auth] Registration error:', err.message);
    res.status(500).json({ error: "Erreur lors de l'inscription. Réessayez." });
  } finally {
    client.release();
  }
});

// ── API: Verify Email ─────────────────────────────────────
app.post('/api/auth/verify-email', async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'Token manquant.' });
  }

  try {
    const result = await pool.query(
      `UPDATE users
       SET email_verified = TRUE, email_verify_token = NULL, email_verify_expires_at = NULL
       WHERE email_verify_token = $1
         AND email_verify_expires_at > NOW()
         AND email_verified = FALSE
       RETURNING id, email, name`,
      [token]
    );

    if (result.rows.length === 0) {
      // Check if token exists but expired or already used
      const check = await pool.query(
        `SELECT id, email_verified, email_verify_expires_at
         FROM users WHERE email_verify_token = $1`,
        [token]
      );
      if (check.rows.length === 0) {
        return res.status(400).json({ error: 'Lien de vérification invalide.' });
      }
      if (check.rows[0].email_verified) {
        return res.json({ success: true, already_verified: true });
      }
      return res.status(400).json({ error: 'Ce lien a expiré. Demandez un nouveau lien de vérification.' });
    }

    const verifiedUser = result.rows[0];
    console.log(`[auth] Email verified: ${verifiedUser.email}`);

    // Send welcome email non-blocking — don't fail verification if email fails
    sendWelcomeEmail(verifiedUser.email, verifiedUser.name)
      .then(sent => {
        if (sent) {
          return pool.query(
            `UPDATE users SET welcome_email_sent_at = NOW() WHERE id = $1`,
            [verifiedUser.id]
          );
        }
      })
      .catch(e => console.error(`[auth] Welcome email error for ${verifiedUser.email}: ${e.message}`));

    res.json({ success: true });
  } catch (err) {
    console.error('[auth] Verify email error:', err.message);
    res.status(500).json({ error: 'Erreur lors de la vérification.' });
  }
});

// ── API: Resend Verification Email ────────────────────────
app.post('/api/auth/resend-verification', requireAuth, async (req, res) => {
  const userId = req.user.id;

  try {
    // Check if already verified
    const check = await pool.query(
      'SELECT email_verified, email FROM users WHERE id = $1',
      [userId]
    );
    if (!check.rows.length || check.rows[0].email_verified) {
      return res.json({ success: true, already_verified: true });
    }

    // Generate a fresh token
    const verifyToken = crypto.randomBytes(32).toString('hex');
    const verifyExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await pool.query(
      `UPDATE users SET email_verify_token = $1, email_verify_expires_at = $2 WHERE id = $3`,
      [verifyToken, verifyExpires, userId]
    );

    const appUrl = process.env.APP_URL || 'https://www.desirparent.com';
    const verifyUrl = `${appUrl}/verifier-email?token=${verifyToken}`;
    const sent = await sendVerificationEmail(check.rows[0].email, verifyUrl, req.user.name);

    // Return success with delivery status so frontend can show appropriate message
    res.json({ success: true, delivered: sent, queued: !sent });
  } catch (err) {
    console.error('[auth] Resend verification error:', err.message);
    res.status(500).json({ error: 'Erreur lors du renvoi.' });
  }
});

// ── Internal: Send Email (via Resend) ──────────────────────
app.post('/internal/email/send', async (req, res) => {
  const { to, subject, html_body, text_body, from, from_name, tag } = req.body;
  if (!to || !subject) {
    return res.status(400).json({ error: 'to and subject are required' });
  }

  // Try Resend API if key is available
  const resendApiKey = process.env.RESEND_API_KEY;
  if (resendApiKey) {
    try {
      const resp = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${resendApiKey}`
        },
        body: JSON.stringify({
          from: 'DésirParent <contact@desirparent.com>',
          to: [to],
          reply_to: 'noreply@desirparent.com',
          subject: subject,
          html: html_body || '',
          text: text_body || '',
          tags: [{ name: 'category', value: tag || 'internal' }]
        })
      });
      if (resp.ok) {
        console.log(`[email] Internal route: sent via Resend to ${to}`);
        return res.json({ success: true });
      }
      const errText = await resp.text();
      console.error(`[email] Internal Resend error: HTTP ${resp.status} — ${errText.slice(0, 200)}`);
    } catch (e) {
      console.error(`[email] Internal Resend fetch error: ${e.message}`);
    }
  }

  // Queue in DB as fallback
  try {
    await pool.query(
      `INSERT INTO email_queue (to_email, subject, html_body, text_body, tag, metadata)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
      [to, subject, html_body || '', text_body || '', tag || 'internal', JSON.stringify({ from: from || 'DésirParent', queued_reason: 'resend_fallback' })]
    );
    console.log(`[email] Internal route: queued for ${to}`);
    return res.json({ success: true, queued: true });
  } catch (err) {
    console.error('[email] Internal route queue error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── Internal: Email Queue (for Polsia agent processing) ──
app.get('/internal/email/queue', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, to_email, subject, html_body, text_body, tag, status, attempts, last_error, created_at, metadata
       FROM email_queue WHERE status = 'pending' ORDER BY created_at ASC LIMIT 50`
    );
    res.json({ emails: result.rows, count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/internal/email/queue/:id/sent', async (req, res) => {
  try {
    await pool.query(
      `UPDATE email_queue SET status = 'sent', sent_at = NOW() WHERE id = $1`,
      [req.params.id]
    );
    // Also record in notification_emails for rate-limiting
    const email = await pool.query('SELECT metadata FROM email_queue WHERE id = $1', [req.params.id]);
    if (email.rows.length && email.rows[0].metadata?.receiver_id) {
      await pool.query(
        `INSERT INTO notification_emails (user_id, type) VALUES ($1, 'message')`,
        [email.rows[0].metadata.receiver_id]
      ).catch(() => {});
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── API: Login ────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis.' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER($1)',
      [email.trim()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
    }

    const user = result.rows[0];

    if (!user.password_hash || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
    }

    // Create session
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query(
      'INSERT INTO sessions (user_id, token) VALUES ($1, $2)',
      [user.id, token]
    );

    res.cookie('dp_session', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000,
      path: '/'
    });

    console.log(`[auth] User logged in: ${user.email}`);

    res.json({ user: formatUser(user) });
  } catch (err) {
    console.error('[auth] Login error:', err.message);
    res.status(500).json({ error: 'Erreur lors de la connexion.' });
  }
});

// ── API: Logout ───────────────────────────────────────────
app.post('/api/auth/logout', async (req, res) => {
  const cookies = parseCookies(req);
  const token = cookies['dp_session'];

  if (token) {
    try {
      await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
    } catch (err) {
      console.error('[auth] Logout error:', err.message);
    }
  }

  res.clearCookie('dp_session', { path: '/' });
  res.json({ success: true });
});

// ── API: Current User ─────────────────────────────────────
app.get('/api/auth/me', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Non authentifié' });
  }
  res.json({ user: formatUser(req.user) });
});

// ── API: Merged me + unread counts (single round-trip for nav init) ──
// Called once per page load instead of sequential /api/auth/me + /api/notifications/unread-count
app.get('/api/me', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Non authentifié' });
  }
  const userId = req.user.id;
  try {
    const [notifResult, msgResult] = await Promise.all([
      pool.query(`SELECT COUNT(*) as count FROM notifications WHERE user_id = $1 AND is_read = FALSE`, [userId]),
      pool.query(`SELECT COUNT(*) as count FROM messages WHERE receiver_id = $1 AND read_at IS NULL`, [userId])
    ]);
    res.json({
      user: formatUser(req.user),
      unread: {
        notifications: parseInt(notifResult.rows[0].count),
        messages: parseInt(msgResult.rows[0].count)
      }
    });
  } catch (err) {
    console.error('[me] Unread count error:', err.message);
    // Still return user even if counts fail
    res.json({ user: formatUser(req.user), unread: { notifications: 0, messages: 0 } });
  }
});

// ── API: Update Profile ───────────────────────────────────
app.put('/api/profile', requireAuth, async (req, res) => {
  const { name, age, city, categories, bio, photo_url, gender, country, region } = req.body;

  const updates = [];
  const values = [];
  let i = 1;

  if (name !== undefined) { updates.push(`name = $${i++}`); values.push(name.trim()); }
  if (age !== undefined) { updates.push(`age = $${i++}`); values.push(parseInt(age) || null); }
  if (city !== undefined) { updates.push(`city = $${i++}`); values.push(city.trim()); }
  if (categories !== undefined) { updates.push(`categories = $${i++}::jsonb`); values.push(JSON.stringify(normalizeCategories(categories))); }
  if (bio !== undefined) { updates.push(`bio = $${i++}`); values.push(bio.trim()); }
  if (photo_url !== undefined) { updates.push(`photo_url = $${i++}`); values.push(photo_url); }
  if (gender !== undefined) { updates.push(`gender = $${i++}`); values.push(gender || null); }
  if (country !== undefined) { updates.push(`country = $${i++}`); values.push(country || null); }
  if (region !== undefined) { updates.push(`region = $${i++}`); values.push(region || null); }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'Aucune modification.' });
  }

  updates.push('updated_at = NOW()');
  values.push(req.user.id);

  try {
    const result = await pool.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${i}
       RETURNING id, email, name, age, city, categories, bio, photo_url, registration_order, created_at`,
      values
    );

    res.json({ user: formatUser(result.rows[0]) });
  } catch (err) {
    console.error('[profile] Update error:', err.message);
    res.status(500).json({ error: 'Erreur lors de la mise à jour.' });
  }
});

// ── API: Get Profile ──────────────────────────────────────
app.get('/api/profile/:id', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, age, city, categories, bio, photo_url, registration_order, created_at,
              gender, country, region,
              COALESCE(subscription_type, plan, 'free') AS subscription_type,
              subscription_expires_at
       FROM users WHERE id = $1`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Profil non trouvé.' });
    }

    res.json({ user: formatUser(result.rows[0]) });
  } catch (err) {
    console.error('[profile] Fetch error:', err.message);
    res.status(500).json({ error: 'Erreur.' });
  }
});

// ── API: Photo Upload ─────────────────────────────────────
app.post('/api/upload/photo', requireAuth, async (req, res) => {
  const { photo } = req.body;

  if (!photo) {
    return res.status(400).json({ error: 'Photo requise.' });
  }

  try {
    const r2BaseUrl = process.env.POLSIA_R2_BASE_URL;
    const apiKey = process.env.POLSIA_API_KEY;

    if (r2BaseUrl && apiKey) {
      const matches = photo.match(/^data:(.+);base64,(.+)$/);
      if (matches) {
        const contentType = matches[1];
        const base64Data = matches[2];
        const ext = contentType.split('/')[1] === 'png' ? 'png' : 'jpg';
        const filename = `desirparent/photos/${req.user.id}_${Date.now()}.${ext}`;

        const body = JSON.stringify({
          key: filename,
          content_type: contentType,
          data: base64Data
        });

        const r2Result = await fetchJson(`${r2BaseUrl}/r2/v1/upload`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`
          },
          body
        });

        if (r2Result && r2Result.url) {
          return res.json({ url: r2Result.url });
        }
      }
    }

    // Fallback: return data URI directly (works for MVP)
    res.json({ url: photo });
  } catch (err) {
    console.error('[upload] Photo error:', err.message);
    res.json({ url: req.body.photo });
  }
});

// ── API: Discover Feed ────────────────────────────────────
app.get('/api/feed', requireAuth, async (req, res) => {
  const { category, offset = 0, limit = 20 } = req.query;
  const userId = req.user.id;

  try {
    const params = [userId, parseInt(limit), parseInt(offset)];
    let categoryFilter = '';
    if (category && category !== 'all') {
      params.push(JSON.stringify([category]));
      categoryFilter = `AND u.categories @> $${params.length}::jsonb`;
    }

    const result = await pool.query(
      `SELECT u.id, u.name, u.age, u.city, u.photo_url, u.categories,
              u.bio, u.registration_order, u.gender, u.country, u.region,
              CASE WHEN l.id IS NOT NULL THEN TRUE ELSE FALSE END AS liked_by_me
       FROM users u
       LEFT JOIN likes l ON l.from_user_id = $1 AND l.to_user_id = u.id
       WHERE u.id != $1
         AND u.name IS NOT NULL AND u.name != ''
         AND COALESCE(u.email_verified, TRUE) = TRUE
         ${categoryFilter}
       ORDER BY u.registration_order ASC
       LIMIT $2 OFFSET $3`,
      params
    );

    const users = result.rows.map(u => ({
      ...formatUser(u),
      liked_by_me: u.liked_by_me
    }));

    res.json({ users, offset: parseInt(offset), limit: parseInt(limit) });
  } catch (err) {
    console.error('[feed] Error:', err.message);
    res.status(500).json({ error: 'Erreur lors du chargement du fil.' });
  }
});

// ── API: Like a User ──────────────────────────────────────
app.post('/api/likes/:userId', requireAuth, async (req, res) => {
  const toUserId = parseInt(req.params.userId);
  const fromUserId = req.user.id;

  if (toUserId === fromUserId) {
    return res.status(400).json({ error: 'Vous ne pouvez pas vous liker vous-même.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `INSERT INTO likes (from_user_id, to_user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING id`,
      [fromUserId, toUserId]
    );
    // Create notification only if like was actually inserted (not a duplicate)
    if (result.rows.length > 0) {
      await client.query(
        `INSERT INTO notifications (user_id, type, from_user_id)
         VALUES ($1, 'like', $2)
         ON CONFLICT DO NOTHING`,
        [toUserId, fromUserId]
      ).catch(() => {}); // non-blocking
    }
    await client.query('COMMIT');
    res.json({ success: true, liked: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[likes] Like error:', err.message);
    res.status(500).json({ error: 'Erreur.' });
  } finally {
    client.release();
  }
});

// ── API: Unlike a User ────────────────────────────────────
app.delete('/api/likes/:userId', requireAuth, async (req, res) => {
  const toUserId = parseInt(req.params.userId);
  const fromUserId = req.user.id;

  try {
    await pool.query(
      `DELETE FROM likes WHERE from_user_id = $1 AND to_user_id = $2`,
      [fromUserId, toUserId]
    );
    res.json({ success: true, liked: false });
  } catch (err) {
    console.error('[likes] Unlike error:', err.message);
    res.status(500).json({ error: 'Erreur.' });
  }
});

// ── API: Received Likes ───────────────────────────────────
app.get('/api/likes/received', requireAuth, async (req, res) => {
  const userId = req.user.id;

  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.age, u.city, u.photo_url, u.categories,
              u.bio, u.registration_order, u.gender, u.country, u.region,
              l.created_at as liked_at
       FROM likes l
       JOIN users u ON l.from_user_id = u.id
       WHERE l.to_user_id = $1
         AND u.name IS NOT NULL AND u.name != ''
       ORDER BY l.created_at DESC`,
      [userId]
    );

    const users = result.rows.map(u => ({
      ...formatUser(u),
      liked_at: u.liked_at
    }));

    res.json({ users });
  } catch (err) {
    console.error('[likes] Received error:', err.message);
    res.status(500).json({ error: 'Erreur.' });
  }
});

// ── API: Search ───────────────────────────────────────────
app.get('/api/search', requireAuth, async (req, res) => {
  const { q, age_min, age_max, gender, categories, country, region, offset = 0, limit = 20 } = req.query;
  const userId = req.user.id;

  try {
    const params = [userId];
    const conditions = [
      `u.id != $1`,
      `u.name IS NOT NULL AND u.name != ''`,
      `COALESCE(u.email_verified, TRUE) = TRUE`
    ];

    if (q && q.trim()) {
      params.push(`%${q.trim()}%`);
      conditions.push(`u.name ILIKE $${params.length}`);
    }

    if (age_min) {
      params.push(parseInt(age_min));
      conditions.push(`u.age >= $${params.length}`);
    }

    if (age_max) {
      params.push(parseInt(age_max));
      conditions.push(`u.age <= $${params.length}`);
    }

    if (gender && gender !== 'all') {
      params.push(gender);
      conditions.push(`u.gender = $${params.length}`);
    }

    if (categories) {
      const catArray = Array.isArray(categories) ? categories : [categories];
      if (catArray.length > 0) {
        params.push(JSON.stringify(catArray));
        conditions.push(`u.categories @> $${params.length}::jsonb`);
      }
    }

    if (country && country.trim()) {
      params.push(country.trim());
      conditions.push(`u.country = $${params.length}`);
    }

    if (region && region.trim()) {
      params.push(`%${region.trim()}%`);
      conditions.push(`u.region ILIKE $${params.length}`);
    }

    params.push(parseInt(limit));
    params.push(parseInt(offset));

    const result = await pool.query(
      `SELECT u.id, u.name, u.age, u.city, u.photo_url, u.categories,
              u.bio, u.registration_order, u.gender, u.country, u.region,
              CASE WHEN l.id IS NOT NULL THEN TRUE ELSE FALSE END AS liked_by_me
       FROM users u
       LEFT JOIN likes l ON l.from_user_id = $1 AND l.to_user_id = u.id
       WHERE ${conditions.join(' AND ')}
       ORDER BY u.name ASC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    const users = result.rows.map(u => ({
      ...formatUser(u),
      liked_by_me: u.liked_by_me
    }));

    res.json({ users, offset: parseInt(offset), limit: parseInt(limit) });
  } catch (err) {
    console.error('[search] Error:', err.message);
    res.status(500).json({ error: 'Erreur lors de la recherche.' });
  }
});

// ── API: Conversations ────────────────────────────────────
app.get('/api/conversations', requireAuth, async (req, res) => {
  const userId = req.user.id;
  try {
    const result = await pool.query(
      `WITH conv AS (
         SELECT
           CASE WHEN sender_id = $1 THEN receiver_id ELSE sender_id END AS other_id,
           id, sender_id, content, created_at, read_at,
           ROW_NUMBER() OVER (
             PARTITION BY LEAST(sender_id, receiver_id), GREATEST(sender_id, receiver_id)
             ORDER BY created_at DESC
           ) AS rn
         FROM messages
         WHERE sender_id = $1 OR receiver_id = $1
       )
       SELECT
         c.other_id, c.id AS last_message_id, c.sender_id AS last_sender_id,
         c.content AS last_content, c.created_at AS last_at, c.read_at AS last_read_at,
         u.name, u.photo_url, u.age, u.city,
         (SELECT COUNT(*) FROM messages
          WHERE sender_id = c.other_id AND receiver_id = $1 AND read_at IS NULL) AS unread_count
       FROM conv c
       JOIN users u ON u.id = c.other_id
       WHERE c.rn = 1
       ORDER BY c.created_at DESC`,
      [userId]
    );
    res.json({ conversations: result.rows });
  } catch (err) {
    console.error('[conv] Error:', err.message);
    res.status(500).json({ error: 'Erreur.' });
  }
});

// ── API: Get Message Count Remaining (Freemium) ───────────
// MUST be registered before /api/messages/:userId to avoid route collision
app.get('/api/messages/quota', requireAuth, async (req, res) => {
  const FREE_DAILY_LIMIT = 5;
  const userId = req.user.id;
  try {
    const userData = await pool.query(
      'SELECT messages_today, messages_today_date, plan, subscription_type, subscription_expires_at FROM users WHERE id = $1',
      [userId]
    );
    const u = userData.rows[0];
    const today = new Date().toISOString().split('T')[0];
    const msgDate = u.messages_today_date ? u.messages_today_date.toISOString().split('T')[0] : null;
    const todayCount = msgDate === today ? (u.messages_today || 0) : 0;

    // Use subscription_type if available, fall back to plan
    const rawTier = u.subscription_type || u.plan || 'free';
    const expired = u.subscription_expires_at && new Date(u.subscription_expires_at) < new Date();
    const tier = expired ? 'free' : rawTier;

    if (tier !== 'free') {
      return res.json({ plan: tier, unlimited: true, remaining: null });
    }

    res.json({
      plan: 'free',
      unlimited: false,
      used: todayCount,
      limit: FREE_DAILY_LIMIT,
      remaining: Math.max(0, FREE_DAILY_LIMIT - todayCount)
    });
  } catch (err) {
    res.json({ plan: 'free', unlimited: false, used: 0, limit: 5, remaining: 5 });
  }
});

// ── API: Get Messages with a User ─────────────────────────
app.get('/api/messages/:userId', requireAuth, async (req, res) => {
  const otherUserId = parseInt(req.params.userId);
  const userId = req.user.id;
  const { before, limit = 50 } = req.query;

  try {
    const params = [userId, otherUserId];
    let beforeClause = '';
    if (before) {
      params.push(before);
      beforeClause = `AND m.created_at < $${params.length}`;
    }
    params.push(parseInt(limit));

    const result = await pool.query(
      `SELECT m.id, m.sender_id, m.receiver_id, m.content, m.created_at, m.read_at
       FROM messages m
       WHERE ((m.sender_id = $1 AND m.receiver_id = $2) OR (m.sender_id = $2 AND m.receiver_id = $1))
         ${beforeClause}
       ORDER BY m.created_at DESC
       LIMIT $${params.length}`,
      params
    );

    // Mark as read: messages sent by the other user to us
    await pool.query(
      `UPDATE messages SET read_at = NOW()
       WHERE sender_id = $1 AND receiver_id = $2 AND read_at IS NULL`,
      [otherUserId, userId]
    ).catch(() => {});

    // Mark related notifications as read
    await pool.query(
      `UPDATE notifications SET is_read = TRUE
       WHERE user_id = $1 AND type = 'message' AND from_user_id = $2`,
      [userId, otherUserId]
    ).catch(() => {});

    // Reset per-conversation email notification flag so a new email can be sent
    // the next time this user receives a message and is offline.
    const convFlagA = Math.min(userId, otherUserId);
    const convFlagB = Math.max(userId, otherUserId);
    // Only reset email_notified — do NOT touch updated_at.
    // updated_at must reflect the last EMAIL send time, not conversation open time.
    // Setting updated_at here caused the "active reader" check to block all emails
    // for 10 minutes after the recipient merely opened the conversation.
    await pool.query(
      `INSERT INTO conversation_notification_flags (user_a_id, user_b_id, recipient_id, email_notified, updated_at)
       VALUES ($1, $2, $3, FALSE, NOW())
       ON CONFLICT (user_a_id, user_b_id, recipient_id)
       DO UPDATE SET email_notified = FALSE`,
      [convFlagA, convFlagB, userId]
    ).catch(err => {
      console.error(`[messages] Flag reset FAILED for user ${userId}, conv ${convFlagA}-${convFlagB}: ${err.message}`);
    });

    res.json({ messages: result.rows.reverse(), other_user_id: otherUserId });
  } catch (err) {
    console.error('[messages] Fetch error:', err.message);
    res.status(500).json({ error: 'Erreur.' });
  }
});

// ── API: Send Message ─────────────────────────────────────
app.post('/api/messages/:userId', requireAuth, async (req, res) => {
  const receiverId = parseInt(req.params.userId);
  const senderId = req.user.id;
  const { content } = req.body;

  if (!content || !content.trim()) {
    return res.status(400).json({ error: 'Message vide.' });
  }

  if (receiverId === senderId) {
    return res.status(400).json({ error: 'Vous ne pouvez pas vous écrire à vous-même.' });
  }

  // Tier-based messaging access control
  const FREE_DAILY_LIMIT = 5;
  const senderTier = getEffectiveTier(req.user);

  if (senderTier === 'free') {
    // Free users: 5 messages/day cap
    const today = new Date().toISOString().split('T')[0];
    const userData = await pool.query(
      'SELECT messages_today, messages_today_date FROM users WHERE id = $1',
      [senderId]
    );
    const u = userData.rows[0];
    const msgDate = u.messages_today_date ? u.messages_today_date.toISOString().split('T')[0] : null;
    const todayCount = msgDate === today ? (u.messages_today || 0) : 0;

    if (todayCount >= FREE_DAILY_LIMIT) {
      return res.status(429).json({
        error: 'Limite de messages atteinte. Abonnez-vous pour envoyer des messages illimités.',
        limit_reached: true,
        limit: FREE_DAILY_LIMIT
      });
    }

    // Update counter
    await pool.query(
      `UPDATE users SET messages_today = $1, messages_today_date = $2 WHERE id = $3`,
      [todayCount + 1, today, senderId]
    );
  } else if (senderTier === 'standard') {
    // Standard: unlimited messaging, but only with subscribed users (Standard or Premium)
    const receiverData = await pool.query(
      `SELECT COALESCE(subscription_type, plan, 'free') AS sub_type, subscription_expires_at
       FROM users WHERE id = $1`,
      [receiverId]
    );
    if (receiverData.rows.length > 0) {
      const r = receiverData.rows[0];
      const rExpired = r.subscription_expires_at && new Date(r.subscription_expires_at) < new Date();
      const receiverTier = rExpired ? 'free' : (r.sub_type || 'free');
      if (receiverTier === 'free') {
        return res.status(403).json({
          error: 'Avec le plan Standard, vous pouvez écrire uniquement aux membres abonnés. Passez Premium pour contacter tous les profils.',
          tier_restricted: true
        });
      }
    }
  }
  // Premium: unlimited, no restrictions

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const msgResult = await client.query(
      `INSERT INTO messages (sender_id, receiver_id, content) VALUES ($1, $2, $3)
       RETURNING id, sender_id, receiver_id, content, created_at`,
      [senderId, receiverId, content.trim()]
    );
    const msg = msgResult.rows[0];

    // Create notification for receiver
    await client.query(
      `INSERT INTO notifications (user_id, type, from_user_id, metadata)
       VALUES ($1, 'message', $2, $3::jsonb)`,
      [receiverId, senderId, JSON.stringify({ message_id: msg.id, preview: content.trim().substring(0, 100) })]
    ).catch(() => {});

    await client.query('COMMIT');

    // ── Send notification email if receiver is not actively reading this conversation ──
    // Runs after COMMIT so it doesn't affect the message response.
    // Guards: (1) per-conversation flag prevents spam, (2) 2-min "active reader" window
    // skips users who have the conversation open right now.
    (async () => {
      try {
        // Get receiver details (email, name)
        const recResult = await pool.query(
          'SELECT id, email, name FROM users WHERE id = $1',
          [receiverId]
        );
        if (!recResult.rows.length) {
          console.log(`[notif-email] Receiver ${receiverId} not found — skipping`);
          return;
        }
        const receiver = recResult.rows[0];

        // 1. Per-conversation email flag: only 1 email per unread conversation.
        // Flag resets when the recipient reads the conversation (GET /api/messages/:userId).
        const convA = Math.min(senderId, receiverId);
        const convB = Math.max(senderId, receiverId);
        const flagCheck = await pool.query(
          `SELECT email_notified, updated_at FROM conversation_notification_flags
           WHERE user_a_id = $1 AND user_b_id = $2 AND recipient_id = $3`,
          [convA, convB, receiverId]
        );
        if (flagCheck.rows.length > 0 && flagCheck.rows[0].email_notified) {
          console.log(`[notif-email] Already notified for conv ${convA}-${convB}, recipient ${receiverId} — skipping`);
          return;
        }

        // Active reader check REMOVED: the email_notified flag alone prevents spam.
        // The old time-based check compared updated_at against a 10-min window, but
        // updated_at was also set when the recipient opened the conversation (flag reset),
        // causing ALL subsequent emails to be blocked for 10 minutes after any conversation open.
        // The email_notified=TRUE/FALSE lifecycle is sufficient:
        //   - Set TRUE when email sent → blocks further emails for this conversation
        //   - Set FALSE when recipient opens conversation → allows next email

        // 2. Build email content
        const senderName = req.user.name
          ? req.user.name.split(' ')[0].split(',')[0].trim()
          : 'Quelqu\'un';
        const messagePreview = content.trim().substring(0, 100);
        const appUrl = process.env.APP_URL || 'https://www.desirparent.com';
        const readUrl = `${appUrl}/messages?sender=${senderId}`;
        const recipientName = receiver.name ? receiver.name.split(' ')[0].split(',')[0].trim() : 'Membre';

        const subject = `${senderName} vous a envoye un message - DesirParent`;
        const htmlBody = `<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#F7F8FC;font-family:Arial,sans-serif;">
  <div style="display:none;max-height:0;overflow:hidden;mso-hide:all">${senderName} vous a envoye un message sur DesirParent</div>
  <div style="max-width:520px;margin:0 auto;padding:32px 16px;">
    <div style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
      <div style="background:#E8185A;padding:24px 32px;">
        <div style="color:#fff;font-size:20px;font-weight:bold;">Nouveau message</div>
      </div>
      <div style="padding:28px 32px;">
        <p style="margin:0 0 16px;font-size:16px;color:#333;">Bonjour ${recipientName},</p>
        <p style="margin:0 0 20px;font-size:15px;color:#555;">
          <strong style="color:#E8185A;">${senderName}</strong> vous a envoye un message sur <strong>DesirParent</strong> :
        </p>
        <div style="background:#F7F8FC;border-left:4px solid #E8185A;padding:14px 18px;border-radius:0 8px 8px 0;margin:0 0 24px;">
          <p style="margin:0;font-size:15px;color:#333;font-style:italic;">"${messagePreview}${content.trim().length > 100 ? '...' : ''}"</p>
        </div>
        <div style="text-align:center;margin:0 0 24px;">
          <a href="${readUrl}" style="display:inline-block;background:#E8185A;color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:16px;font-weight:bold;">Lire le message</a>
        </div>
      </div>
      <div style="padding:16px 32px;background:#f0f0f0;border-top:1px solid #eee;">
        <p style="margin:0;font-size:12px;color:#999;text-align:center;">
          Vous recevez cet email car vous etes inscrit sur DesirParent.<br>
          <a href="${appUrl}/compte" style="color:#E8185A;text-decoration:none;">Modifier mes preferences</a>
        </p>
      </div>
    </div>
  </div>
</body>
</html>`;

        const textBody = `Bonjour ${recipientName},\n\n${senderName} vous a envoye un message sur DesirParent :\n\n"${messagePreview}${content.trim().length > 100 ? '...' : ''}"\n\nLire le message : ${readUrl}\n\n---\nVous recevez cet email car vous etes inscrit sur DesirParent.`;

        // ── Send via shared sendTransactionalEmail (Resend -> DB queue) ──
        // Uses the same path as verification/welcome/payment emails.
        console.log(`[notif-email] Sending notification to ${receiver.email} from ${senderName} (sender ${senderId})`);
        await sendTransactionalEmail({
          toEmail: receiver.email,
          subject,
          html: htmlBody,
          textBody,
          tag: 'message_notification'
        });

        // ── Mark conversation as notified (prevents further emails until read) ──
        await pool.query(
          `INSERT INTO conversation_notification_flags (user_a_id, user_b_id, recipient_id, email_notified, updated_at)
           VALUES ($1, $2, $3, TRUE, NOW())
           ON CONFLICT (user_a_id, user_b_id, recipient_id)
           DO UPDATE SET email_notified = TRUE, updated_at = NOW()`,
          [convA, convB, receiverId]
        ).catch(err => {
          console.error(`[notif-email] Flag set FAILED for recipient ${receiverId}, conv ${convA}-${convB}: ${err.message}`);
        });
        console.log(`[notif-email] Conversation flag set for recipient ${receiverId} (conv ${convA}-${convB})`);
      } catch (notifyErr) {
        console.error('[notif-email] Error:', notifyErr.message);
      }
    })();

    res.status(201).json({ message: msg });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[messages] Send error:', err.message);
    res.status(500).json({ error: 'Erreur lors de l\'envoi.' });
  } finally {
    client.release();
  }
});

// ── API: Get Notifications ────────────────────────────────
app.get('/api/notifications', requireAuth, async (req, res) => {
  const userId = req.user.id;
  try {
    const result = await pool.query(
      `SELECT n.id, n.type, n.is_read, n.created_at, n.metadata,
              u.id AS from_id, u.name AS from_name, u.photo_url AS from_photo,
              u.age AS from_age, u.city AS from_city
       FROM notifications n
       LEFT JOIN users u ON u.id = n.from_user_id
       WHERE n.user_id = $1
       ORDER BY n.created_at DESC
       LIMIT 100`,
      [userId]
    );
    res.json({ notifications: result.rows });
  } catch (err) {
    console.error('[notifs] Error:', err.message);
    res.status(500).json({ error: 'Erreur.' });
  }
});

// ── API: Unread Notification Count ────────────────────────
app.get('/api/notifications/unread-count', requireAuth, async (req, res) => {
  const userId = req.user.id;
  try {
    const [notifResult, msgResult] = await Promise.all([
      pool.query(
        `SELECT COUNT(*) as count FROM notifications WHERE user_id = $1 AND is_read = FALSE`,
        [userId]
      ),
      pool.query(
        `SELECT COUNT(*) as count FROM messages WHERE receiver_id = $1 AND read_at IS NULL`,
        [userId]
      )
    ]);
    res.json({
      notifications: parseInt(notifResult.rows[0].count),
      messages: parseInt(msgResult.rows[0].count),
      total: parseInt(notifResult.rows[0].count) + parseInt(msgResult.rows[0].count)
    });
  } catch (err) {
    console.error('[notifs] Unread count error:', err.message);
    res.json({ notifications: 0, messages: 0, total: 0 });
  }
});

// ── API: Mark Notifications Read ──────────────────────────
app.put('/api/notifications/read', requireAuth, async (req, res) => {
  const userId = req.user.id;
  try {
    await pool.query(
      `UPDATE notifications SET is_read = TRUE WHERE user_id = $1`,
      [userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('[notifs] Mark read error:', err.message);
    res.status(500).json({ error: 'Erreur.' });
  }
});

// ── API: Subscription Status ──────────────────────────────
app.get('/api/subscription/status', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT COALESCE(subscription_type, 'free') AS subscription_type,
              subscription_expires_at,
              COALESCE(plan, 'free') AS plan
       FROM users WHERE id = $1`,
      [req.user.id]
    );
    const u = result.rows[0];
    const expired = u.subscription_expires_at && new Date(u.subscription_expires_at) < new Date();
    const tier = expired ? 'free' : (u.subscription_type || 'free');

    res.json({
      tier,
      expires_at: u.subscription_expires_at,
      active: tier !== 'free',
      expired: !!expired
    });
  } catch (err) {
    console.error('[subscription] Status error:', err.message);
    res.json({ tier: 'free', active: false });
  }
});

// ── Payment Confirmation Email (to customer) ──────────────
async function sendPaymentConfirmationEmail(userEmail, userName, planConfig, planKey, expiresAt) {
  const appUrl = process.env.APP_URL || 'https://www.desirparent.com';
  const tierLabel = planConfig.type === 'premium' ? 'Premium' : 'Standard';
  const durationMap = { 1: '1 mois', 3: '3 mois', 6: '6 mois', 12: '12 mois' };
  const durationLabel = durationMap[planConfig.months] || `${planConfig.months} mois`;
  const priceFormatted = planConfig.price.toFixed(2).replace('.', ',');
  const expiryFormatted = new Date(expiresAt).toLocaleDateString('fr-FR', {
    day: 'numeric', month: 'long', year: 'numeric'
  });
  const firstName = (userName || 'là').split(' ')[0];

  const tierEmoji = planConfig.type === 'premium' ? '💎' : '⭐';
  const tierBenefits = planConfig.type === 'premium'
    ? 'Accès illimité à <strong>tous les profils</strong>, messagerie sans restriction, profil mis en avant'
    : 'Accès illimité au <strong>réseau d\'abonnés</strong>, messagerie sans restriction';

  const htmlBody = `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Confirmation de paiement — DésirParent</title>
</head>
<body style="margin:0;padding:0;background-color:#F7F8FC;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#F7F8FC;min-height:100vh;">
    <tr>
      <td align="center" style="padding:40px 16px;">
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;">

          <!-- Logo bar -->
          <tr>
            <td align="center" style="padding-bottom:24px;">
              <table cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td align="center">
                    <div style="display:inline-block;background:linear-gradient(135deg,#E8185A 0%,#F5922A 100%);border-radius:16px;padding:12px 20px;">
                      <span style="font-size:22px;font-weight:900;color:#ffffff;letter-spacing:-0.5px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">DésirParent</span>
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Hero card -->
          <tr>
            <td>
              <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;border-radius:20px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

                <!-- Hero header -->
                <tr>
                  <td style="background:linear-gradient(135deg,#E8185A 0%,#F5922A 100%);padding:40px 40px 32px;text-align:center;">
                    <div style="font-size:48px;margin-bottom:12px;">🎉</div>
                    <h1 style="margin:0 0 8px;font-size:26px;font-weight:800;color:#ffffff;line-height:1.2;">Bienvenue dans la communauté DésirParent !</h1>
                    <p style="margin:0;font-size:15px;color:rgba(255,255,255,0.88);line-height:1.5;">Merci pour votre confiance. Votre abonnement est actif.</p>
                  </td>
                </tr>

                <!-- Greeting -->
                <tr>
                  <td style="padding:36px 40px 0;">
                    <p style="margin:0 0 8px;font-size:18px;font-weight:700;color:#1a1a2e;">Bonjour ${firstName} 👋</p>
                    <p style="margin:0;font-size:15px;color:#6b7280;line-height:1.6;">
                      Votre abonnement <strong style="color:#E8185A;">${tierLabel} ${tierEmoji}</strong> est maintenant actif et prêt à vous aider à trouver votre partenaire de parentalité idéal.
                    </p>
                  </td>
                </tr>

                <!-- Receipt box -->
                <tr>
                  <td style="padding:24px 40px;">
                    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F7F8FC;border-radius:12px;overflow:hidden;">
                      <tr>
                        <td style="padding:16px 20px 4px;">
                          <p style="margin:0;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#9ca3af;">Récapitulatif de commande</p>
                        </td>
                      </tr>
                      <!-- row -->
                      <tr>
                        <td style="padding:12px 20px;border-bottom:1px solid #e5e7eb;">
                          <table width="100%" cellpadding="0" cellspacing="0" border="0">
                            <tr>
                              <td style="font-size:14px;color:#6b7280;">Abonnement</td>
                              <td align="right" style="font-size:14px;font-weight:700;color:#1a1a2e;">${tierLabel} ${tierEmoji}</td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:12px 20px;border-bottom:1px solid #e5e7eb;">
                          <table width="100%" cellpadding="0" cellspacing="0" border="0">
                            <tr>
                              <td style="font-size:14px;color:#6b7280;">Durée</td>
                              <td align="right" style="font-size:14px;color:#1a1a2e;">${durationLabel}</td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:12px 20px;border-bottom:1px solid #e5e7eb;">
                          <table width="100%" cellpadding="0" cellspacing="0" border="0">
                            <tr>
                              <td style="font-size:14px;color:#6b7280;">Valide jusqu'au</td>
                              <td align="right" style="font-size:14px;color:#1a1a2e;">${expiryFormatted}</td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                      <!-- Total row -->
                      <tr>
                        <td style="padding:16px 20px;background:linear-gradient(135deg,rgba(232,24,90,0.06) 0%,rgba(245,146,42,0.06) 100%);">
                          <table width="100%" cellpadding="0" cellspacing="0" border="0">
                            <tr>
                              <td style="font-size:15px;font-weight:700;color:#1a1a2e;">Montant payé</td>
                              <td align="right" style="font-size:20px;font-weight:800;color:#E8185A;">${priceFormatted}&nbsp;€</td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>

                <!-- Benefits -->
                <tr>
                  <td style="padding:0 40px 28px;">
                    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:linear-gradient(135deg,rgba(232,24,90,0.05) 0%,rgba(245,146,42,0.05) 100%);border-radius:12px;border-left:3px solid #E8185A;">
                      <tr>
                        <td style="padding:16px 20px;">
                          <p style="margin:0 0 4px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;color:#E8185A;">Ce que vous débloquez</p>
                          <p style="margin:0;font-size:14px;color:#374151;line-height:1.6;">${tierBenefits}</p>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>

                <!-- CTA -->
                <tr>
                  <td style="padding:0 40px 36px;text-align:center;">
                    <a href="${appUrl}/decouvrir" style="display:inline-block;background:linear-gradient(135deg,#E8185A 0%,#F5922A 100%);color:#ffffff;text-decoration:none;padding:16px 40px;border-radius:50px;font-size:16px;font-weight:700;letter-spacing:0.01em;box-shadow:0 4px 16px rgba(232,24,90,0.35);">
                      Découvrir des profils &rarr;
                    </a>
                    <p style="margin:16px 0 0;font-size:13px;color:#9ca3af;">Des centaines de profils vous attendent</p>
                  </td>
                </tr>

                <!-- Divider -->
                <tr>
                  <td style="padding:0 40px;">
                    <div style="height:1px;background:#f3f4f6;"></div>
                  </td>
                </tr>

                <!-- Quick links -->
                <tr>
                  <td style="padding:24px 40px;">
                    <p style="margin:0 0 12px;font-size:13px;font-weight:700;color:#374151;">Liens utiles</p>
                    <table cellpadding="0" cellspacing="0" border="0">
                      <tr>
                        <td style="padding-right:16px;">
                          <a href="${appUrl}/compte" style="font-size:13px;color:#E8185A;text-decoration:none;font-weight:600;">Mon compte</a>
                        </td>
                        <td style="padding-right:16px;color:#e5e7eb;">|</td>
                        <td style="padding-right:16px;">
                          <a href="${appUrl}/messages" style="font-size:13px;color:#E8185A;text-decoration:none;font-weight:600;">Mes messages</a>
                        </td>
                        <td style="padding-right:16px;color:#e5e7eb;">|</td>
                        <td>
                          <a href="${appUrl}/decouvrir" style="font-size:13px;color:#E8185A;text-decoration:none;font-weight:600;">Explorer</a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>

                <!-- Footer -->
                <tr>
                  <td style="padding:20px 40px 28px;background:#fafafa;border-top:1px solid #f3f4f6;">
                    <p style="margin:0 0 8px;font-size:12px;color:#9ca3af;text-align:center;line-height:1.6;">
                      Vous recevez cet email car vous avez souscrit un abonnement sur DésirParent.<br>
                      Des questions ? Contactez-nous : <a href="mailto:contact@desirparent.com" style="color:#E8185A;text-decoration:none;">contact@desirparent.com</a>
                    </p>
                    <p style="margin:8px 0 0;font-size:11px;color:#d1d5db;text-align:center;">
                      <a href="${appUrl}/cgu" style="color:#d1d5db;text-decoration:none;">CGU</a>
                      &nbsp;&middot;&nbsp;
                      <a href="${appUrl}/confidentialite" style="color:#d1d5db;text-decoration:none;">Confidentialité</a>
                      &nbsp;&middot;&nbsp;
                      <a href="${appUrl}/compte" style="color:#d1d5db;text-decoration:none;">Gérer mon abonnement</a>
                    </p>
                    <p style="margin:10px 0 0;font-size:11px;color:#d1d5db;text-align:center;">
                      &copy; ${new Date().getFullYear()} DésirParent — Tous droits réservés
                    </p>
                  </td>
                </tr>

              </table>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

  const textBody = `Bonjour ${firstName},\n\nMerci pour votre achat ! Votre abonnement ${tierLabel} est maintenant actif.\n\nRécapitulatif :\n- Abonnement : ${tierLabel}\n- Durée : ${durationLabel}\n- Valide jusqu'au : ${expiryFormatted}\n- Montant payé : ${priceFormatted} €\n\nProfitez de DésirParent : ${appUrl}/decouvrir\n\n---\nDésirParent — Trouvez votre partenaire parentalité`;

  // Use centralized sender (Resend → DB queue fallback)
  const subject = `Confirmation de paiement - Abonnement ${tierLabel} DesirParent`;
  return sendTransactionalEmail({ toEmail: userEmail, subject, html: htmlBody, textBody, tag: 'payment_confirmation' });
}

// ── Admin Sale Notification (branded, French, €) ───────────
async function sendAdminSaleNotification(userName, userEmail, planConfig, planKey, expiresAt) {
  const adminEmail = process.env.ADMIN_EMAIL;
  if (!adminEmail) {
    console.log('[admin-sale] No ADMIN_EMAIL env var — skipping admin notification');
    return false;
  }
  const appUrl = process.env.APP_URL || 'https://www.desirparent.com';
  const tierLabel = planConfig.type === 'premium' ? 'Premium' : 'Standard';
  const durationMap = { 1: '1 mois', 3: '3 mois', 6: '6 mois', 12: '12 mois' };
  const durationLabel = durationMap[planConfig.months] || `${planConfig.months} mois`;
  const priceFormatted = planConfig.price.toFixed(2).replace('.', ',');
  const expiryFormatted = new Date(expiresAt).toLocaleDateString('fr-FR', {
    day: 'numeric', month: 'long', year: 'numeric'
  });
  const dateNow = new Date().toLocaleDateString('fr-FR', {
    day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit'
  });

  const htmlBody = `<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#F7F8FC;font-family:Arial,sans-serif;">
  <div style="max-width:520px;margin:0 auto;padding:32px 16px;">
    <div style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
      <!-- Header -->
      <div style="background:linear-gradient(135deg,#E8185A 0%,#F5922A 100%);padding:24px 32px;text-align:center;">
        <div style="color:#fff;font-size:22px;font-weight:bold;">🎉 Nouvelle vente !</div>
        <div style="color:rgba(255,255,255,0.9);font-size:13px;margin-top:4px;">DésirParent</div>
      </div>
      <!-- Body -->
      <div style="padding:28px 32px;">
        <p style="margin:0 0 16px;font-size:16px;color:#333;">
          Un utilisateur vient de souscrire un abonnement !
        </p>
        <div style="background:#F7F8FC;border-radius:8px;padding:20px;margin:0 0 20px;">
          <table style="width:100%;border-collapse:collapse;">
            <tr>
              <td style="padding:8px 0;font-size:14px;color:#888;border-bottom:1px solid #eee;">Client</td>
              <td style="padding:8px 0;font-size:14px;color:#333;text-align:right;border-bottom:1px solid #eee;font-weight:600;">${userName || 'N/A'}</td>
            </tr>
            <tr>
              <td style="padding:8px 0;font-size:14px;color:#888;border-bottom:1px solid #eee;">Email</td>
              <td style="padding:8px 0;font-size:14px;color:#333;text-align:right;border-bottom:1px solid #eee;">${userEmail}</td>
            </tr>
            <tr>
              <td style="padding:8px 0;font-size:14px;color:#888;border-bottom:1px solid #eee;">Abonnement</td>
              <td style="padding:8px 0;font-size:14px;color:#E8185A;text-align:right;border-bottom:1px solid #eee;font-weight:600;">${tierLabel} — ${durationLabel}</td>
            </tr>
            <tr>
              <td style="padding:10px 0;font-size:16px;color:#333;font-weight:bold;">Montant</td>
              <td style="padding:10px 0;font-size:16px;color:#E8185A;text-align:right;font-weight:bold;">${priceFormatted} €</td>
            </tr>
          </table>
        </div>
        <p style="margin:0 0 8px;font-size:13px;color:#888;">
          Date : ${dateNow} · Expire le ${expiryFormatted}
        </p>
        <div style="text-align:center;margin:20px 0 0;">
          <a href="${appUrl}/admin"
             style="display:inline-block;background:#E8185A;color:#fff;text-decoration:none;padding:12px 28px;border-radius:8px;font-size:14px;font-weight:bold;">
            Voir le dashboard admin →
          </a>
        </div>
      </div>
      <!-- Footer -->
      <div style="padding:12px 32px;background:#f0f0f0;border-top:1px solid #eee;">
        <p style="margin:0;font-size:11px;color:#999;text-align:center;">
          Notification automatique — DésirParent
        </p>
      </div>
    </div>
  </div>
</body>
</html>`;

  const textBody = `🎉 Nouvelle vente DésirParent !\n\nClient : ${userName || 'N/A'} (${userEmail})\nAbonnement : ${tierLabel} — ${durationLabel}\nMontant : ${priceFormatted} €\nDate : ${dateNow}\nExpire le : ${expiryFormatted}\n\nDashboard admin : ${appUrl}/admin`;

  try {
    const apiKey = process.env.POLSIA_API_KEY;
    if (!apiKey) {
      console.error('[admin-sale] No POLSIA_API_KEY — cannot send admin notification');
      return false;
    }
    const baseUrl = (process.env.POLSIA_R2_BASE_URL || 'https://polsia.com').replace(/\/$/, '');
    const resp = await fetch(`${baseUrl}/api/proxy/email/send`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        from: 'DésirParent <contact@desirparent.com>',
        from_name: 'DésirParent',
        reply_to: 'noreply@desirparent.com',
        to: adminEmail,
        subject: `Nouvelle vente - ${tierLabel} ${durationLabel} (${priceFormatted} EUR)`,
        html_body: htmlBody,
        text_body: textBody,
        tag: 'admin_sale_notification'
      })
    });

    const bodyText = await resp.text();
    let data;
    try { data = JSON.parse(bodyText); } catch { data = {}; }
    if (resp.ok && data.success !== false) {
      console.log(`[admin-sale] Notification sent to ${adminEmail} for ${planKey}`);
      return true;
    }
    console.error(`[admin-sale] Proxy error: HTTP ${resp.status} — ${bodyText.slice(0, 200)}`);
    return false;
  } catch (err) {
    console.error(`[admin-sale] Send error: ${err.message}`);
    return false;
  }
}

// ── API: Activate Subscription (post-Stripe redirect) ─────
// Called by the frontend after returning from a successful Stripe payment.
// Stripe payment links redirect to /compte?plan=X&status=success — the
// frontend detects this and POSTs here to activate the subscription.
app.post('/api/subscription/activate', requireAuth, async (req, res) => {
  const { plan } = req.body;

  if (!plan || !PLAN_CONFIG[plan]) {
    return res.status(400).json({ error: 'Plan invalide.' });
  }

  const config = PLAN_CONFIG[plan];

  // Calculate expiry: add months to now (or extend from current expiry if upgrading)
  const now = new Date();
  let baseDate = now;

  // If user already has an active subscription of the same or lower tier, extend from its expiry
  const existing = await pool.query(
    `SELECT subscription_type, subscription_expires_at FROM users WHERE id = $1`,
    [req.user.id]
  );
  const ex = existing.rows[0];
  if (ex && ex.subscription_expires_at && new Date(ex.subscription_expires_at) > now) {
    // Only extend (not replace) if same tier
    if (ex.subscription_type === config.type) {
      baseDate = new Date(ex.subscription_expires_at);
    }
  }

  const expiresAt = new Date(baseDate);
  expiresAt.setMonth(expiresAt.getMonth() + config.months);

  try {
    await pool.query(
      `UPDATE users
       SET subscription_type = $1, plan = $1, subscription_expires_at = $2
       WHERE id = $3`,
      [config.type, expiresAt.toISOString(), req.user.id]
    );

    console.log(`[subscription] Activated ${plan} for user ${req.user.id}, expires ${expiresAt.toISOString()}`);

    // Fetch user details for email
    const userResult = await pool.query(
      `SELECT name, email FROM users WHERE id = $1`,
      [req.user.id]
    );
    const user = userResult.rows[0];

    // Send payment confirmation email to customer (non-blocking)
    if (user && user.email) {
      sendPaymentConfirmationEmail(user.email, user.name, config, plan, expiresAt).catch(err => {
        console.error(`[subscription] Payment confirmation email error: ${err.message}`);
      });
    }

    // Send admin sale notification (non-blocking)
    sendAdminSaleNotification(user?.name, user?.email, config, plan, expiresAt).catch(err => {
      console.error(`[subscription] Admin sale notification error: ${err.message}`);
    });

    res.json({
      success: true,
      tier: config.type,
      expires_at: expiresAt.toISOString(),
      plan
    });
  } catch (err) {
    console.error('[subscription] Activate error:', err.message);
    res.status(500).json({ error: 'Erreur lors de l\'activation.' });
  }
});

// ── API: Get Stripe Payment Links ─────────────────────────
app.get('/api/subscription/links', (req, res) => {
  res.json({ links: STRIPE_LINKS });
});
// ── Stripe Webhook ────────────────────────────────────────
app.post('/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('[webhook] Signature error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed' || event.type === 'invoice.paid') {
    const session = event.data.object;
    const customerEmail = session.customer_email || session.customer_details?.email;
    if (customerEmail) {
      try {
        const planType = session.amount_total <= 1000 ? 'standard' : 'premium';
        const expiresAt = new Date();
        expiresAt.setMonth(expiresAt.getMonth() + 12);
        await pool.query(
          `UPDATE users SET subscription_type = $1, plan = $1, subscription_expires_at = $2 WHERE LOWER(email) = LOWER($3)`,
          [planType, expiresAt.toISOString(), customerEmail]
        );
        console.log(`[webhook] Activated ${planType} for ${customerEmail}`);
      } catch (err) {
        console.error('[webhook] DB error:', err.message);
      }
    }
  }

  res.json({ received: true });
});
// ── Admin Auth ────────────────────────────────────────────
const adminSessions = new Set();

function requireAdmin(req, res, next) {
  const cookies = parseCookies(req);
  const token = cookies['dp_admin'];
  if (!token || !adminSessions.has(token)) {
    return res.status(401).json({ error: 'Non autorisé' });
  }
  next();
}

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (!adminPassword) {
    return res.status(500).json({ error: 'Admin non configuré' });
  }

  if (!password || password !== adminPassword) {
    return res.status(401).json({ error: 'Mot de passe incorrect' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.add(token);

  res.cookie('dp_admin', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
    path: '/'
  });

  console.log('[admin] Admin login successful');
  res.json({ success: true });
});

app.post('/api/admin/logout', (req, res) => {
  const cookies = parseCookies(req);
  const token = cookies['dp_admin'];
  if (token) adminSessions.delete(token);
  res.clearCookie('dp_admin', { path: '/' });
  res.json({ success: true });
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const [
      totalResult,
      todayResult,
      weekResult,
      monthResult,
      categoriesResult,
      growthResult,
      recentResult,
      genderResult,
      subscriptionResult
    ] = await Promise.all([
      // Total users
      pool.query(`SELECT COUNT(*) AS count FROM users WHERE name IS NOT NULL AND name != ''`),
      // Today
      pool.query(`SELECT COUNT(*) AS count FROM users WHERE name IS NOT NULL AND name != '' AND created_at >= CURRENT_DATE`),
      // This week
      pool.query(`SELECT COUNT(*) AS count FROM users WHERE name IS NOT NULL AND name != '' AND created_at >= date_trunc('week', NOW())`),
      // This month
      pool.query(`SELECT COUNT(*) AS count FROM users WHERE name IS NOT NULL AND name != '' AND created_at >= date_trunc('month', NOW())`),
      // Categories breakdown
      pool.query(`
        SELECT cat, COUNT(*) AS count
        FROM users, jsonb_array_elements_text(categories) AS cat
        WHERE name IS NOT NULL AND name != '' AND categories IS NOT NULL AND jsonb_array_length(categories) > 0
        GROUP BY cat
        ORDER BY count DESC
      `),
      // Daily growth last 60 days
      pool.query(`
        SELECT TO_CHAR(DATE(created_at), 'YYYY-MM-DD') AS date, COUNT(*) AS count
        FROM users
        WHERE name IS NOT NULL AND name != '' AND created_at >= NOW() - INTERVAL '60 days'
        GROUP BY DATE(created_at)
        ORDER BY date ASC
      `),
      // 10 most recent signups
      pool.query(`
        SELECT name, age, city, gender, country, categories, created_at
        FROM users
        WHERE name IS NOT NULL AND name != ''
        ORDER BY created_at DESC
        LIMIT 10
      `),
      // Gender breakdown (excluding seeds)
      pool.query(`
        SELECT COALESCE(NULLIF(TRIM(gender), ''), 'Non renseigné') AS gender, COUNT(*) AS count
        FROM users
        WHERE name IS NOT NULL AND name != ''
          AND (is_seed IS NULL OR is_seed = false)
        GROUP BY COALESCE(NULLIF(TRIM(gender), ''), 'Non renseigné')
        ORDER BY count DESC
      `),
      // Subscription breakdown — effective tier (expired paid = free), excluding seeds
      pool.query(`
        SELECT
          CASE
            WHEN COALESCE(subscription_type, plan, 'free') IN ('standard', 'premium')
              AND subscription_expires_at IS NOT NULL
              AND subscription_expires_at < NOW()
            THEN 'free'
            ELSE COALESCE(subscription_type, plan, 'free')
          END AS tier,
          COUNT(*) AS count
        FROM users
        WHERE name IS NOT NULL AND name != ''
          AND (is_seed IS NULL OR is_seed = false)
        GROUP BY tier
        ORDER BY count DESC
      `)
    ]);

    res.json({
      total: parseInt(totalResult.rows[0].count),
      today: parseInt(todayResult.rows[0].count),
      week: parseInt(weekResult.rows[0].count),
      month: parseInt(monthResult.rows[0].count),
      categories: categoriesResult.rows,
      growth: growthResult.rows,
      recent: recentResult.rows,
      genders: genderResult.rows,
      subscriptions: subscriptionResult.rows
    });
  } catch (err) {
    console.error('[admin] Stats error:', err.message);
    res.status(500).json({ error: 'Erreur lors du chargement des stats' });
  }
});

// Admin check endpoint
app.get('/api/admin/check', (req, res) => {
  const cookies = parseCookies(req);
  const token = cookies['dp_admin'];
  res.json({ authenticated: !!(token && adminSessions.has(token)) });
});

// Admin test email — sends a preview confirmation email to the admin with fake data
app.post('/api/admin/test-email', requireAdmin, async (req, res) => {
  const adminEmail = process.env.ADMIN_EMAIL;
  if (!adminEmail) {
    return res.status(400).json({ error: 'ADMIN_EMAIL non configuré — impossible d\'envoyer le test.' });
  }

  // Fake plan data
  const fakePlanConfig = { type: 'premium', months: 6, price: 89.99 };
  const fakeExpiresAt = new Date(Date.now() + 6 * 30 * 24 * 60 * 60 * 1000);

  try {
    const sent = await sendPaymentConfirmationEmail(
      adminEmail,
      'Jean Dupont',
      fakePlanConfig,
      'premium_6',
      fakeExpiresAt
    );
    if (sent) {
      console.log(`[admin-test-email] Test email sent to ${adminEmail}`);
      // Warn: proxy may accept but not deliver (known platform issue — reported)
      return res.json({ success: true, message: `Email de test envoyé à ${adminEmail}`, warning: 'Le proxy email peut accepter sans livrer. Vérifiez votre inbox et spams dans les 5 minutes.' });
    } else {
      return res.status(500).json({ error: 'Échec de l\'envoi — vérifiez les logs serveur. Email mis en file d\'attente pour réessai.' });
    }
  } catch (err) {
    console.error('[admin-test-email] Error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── Admin: Manual Email Verification ─────────────────────
// Workaround while email proxy is broken — admin can verify users manually
app.post('/api/admin/verify-user/:userId', requireAdmin, async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await pool.query(
      `UPDATE users SET email_verified = TRUE, email_verify_token = NULL, email_verify_expires_at = NULL
       WHERE id = $1 AND email_verified = FALSE
       RETURNING id, email, name`,
      [userId]
    );
    if (!result.rows.length) {
      return res.json({ success: false, message: 'Utilisateur non trouvé ou déjà vérifié.' });
    }
    const user = result.rows[0];
    console.log(`[admin] Manual email verification for user ${user.id} (${user.email})`);

    // Trigger welcome email (non-blocking)
    sendWelcomeEmail(user.email, user.name)
      .then(sent => {
        if (sent) pool.query(`UPDATE users SET welcome_email_sent_at = NOW() WHERE id = $1`, [user.id]).catch(() => {});
      })
      .catch(() => {});

    res.json({ success: true, message: `Email vérifié manuellement pour ${user.name} (${user.email})` });
  } catch (err) {
    console.error('[admin] Manual verify error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Admin: List unverified users ─────────────────────────
app.get('/api/admin/unverified-users', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, name, created_at FROM users
       WHERE email_verified = FALSE AND email_verify_token IS NOT NULL
       ORDER BY created_at DESC LIMIT 20`
    );
    res.json({ users: result.rows, count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin page route
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ── Helpers ───────────────────────────────────────────────
function formatUser(user) {
  const sub = user.subscription_type || user.plan || 'free';
  const expired = user.subscription_expires_at && new Date(user.subscription_expires_at) < new Date();
  const tier = expired ? 'free' : sub;

  return {
    id: user.id,
    email: user.email,
    name: user.name,
    age: user.age,
    city: user.city,
    gender: user.gender || null,
    country: user.country || null,
    region: user.region || null,
    categories: typeof user.categories === 'string' ? JSON.parse(user.categories) : (user.categories || []),
    bio: user.bio,
    photo_url: user.photo_url,
    registration_order: user.registration_order,
    is_pioneer: user.registration_order && user.registration_order <= 500,
    created_at: user.created_at,
    email_verified: user.email_verified !== undefined ? !!user.email_verified : true,
    plan: tier,
    subscription_type: tier,
    subscription_expires_at: user.subscription_expires_at || null,
    is_premium: tier === 'premium',
    is_subscribed: tier === 'standard' || tier === 'premium',
  };
}

// ── Disposable Email Domain Blocklist ─────────────────────
const DISPOSABLE_DOMAINS = new Set([
  'yopmail.com','yopmail.fr','cool.fr.nf','jetable.fr.nf','nospam.ze.tc',
  'nomail.xl.cx','mega.zik.dj','speed.1s.fr','courriel.fr.nf','moncourrier.fr.nf',
  'tempmail.com','temp-mail.org','temp-mail.io','tempinbox.com','mailnull.com',
  'guerrillamail.com','guerrillamail.net','guerrillamail.org','guerrillamail.biz',
  'guerrillamail.de','guerrillamail.info','grr.la','sharklasers.com','guerrillamailblock.com',
  'spam4.me','trashmail.com','trashmail.me','trashmail.net','trashmail.at',
  'trashmail.io','trashmail.xyz','dispostable.com','mailinator.com','mailinator.net',
  'mailinator.org','mailnesia.com','mintemail.com','fakeinbox.com','spamgourmet.com',
  'spamgourmet.net','spamgourmet.org','spamevader.net','maildrop.cc','throwam.com',
  'throwam.net','throwam.org','throwam.io','mailnull.com','spambox.us',
  'mailnull.com','yevme.com','binkmail.com','safetymail.info','filzmail.com',
  'owlpic.com','nwldx.com','spamfree24.org','spamfree24.de','spamfree24.eu',
  'einrot.com','kasmail.com','spammotel.com','smapfree24.com','spamfree.eu',
  'spaml.com','spamfree24.info','spam.la','mail.mezimages.net','fuckingdamnit.com',
  'mailzilla.com','throwam.com','meltmail.com','wegwerfmail.de','wegwerfmail.net',
  'wegwerfmail.org','10minutemail.com','10minutemail.net','10minutemail.org',
  '20minutemail.com','mailexpire.com','spamhereplease.com','temporaryemail.net',
  'temporaryinbox.com','throwaway.email','throwam.com','spamgob.com',
  'incognitomail.com','incognitomail.net','incognitomail.org',
  'discard.email','filzmail.com','sneakemail.com','mailnull.com',
  'spamcorner.com','spamevader.net','spam.la','spamfree.eu',
]);

function isDisposableEmail(email) {
  const domain = email.split('@')[1]?.toLowerCase();
  return domain ? DISPOSABLE_DOMAINS.has(domain) : false;
}

// ── Registration Rate Limiting (DB-backed) ────────────────
const RATE_LIMIT_HOUR = 3;   // max 3 per IP per hour
const RATE_LIMIT_DAY  = 10;  // max 10 per IP per day

async function checkRegistrationRateLimit(ip) {
  try {
    // Cleanup old entries > 2 days periodically (1-in-50 chance per request)
    if (Math.random() < 0.02) {
      pool.query(`DELETE FROM registration_attempts WHERE created_at < NOW() - INTERVAL '2 days'`).catch(() => {});
    }

    const result = await pool.query(
      `SELECT
         COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 hour') AS hour_count,
         COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 day')  AS day_count
       FROM registration_attempts
       WHERE ip_address = $1 AND created_at > NOW() - INTERVAL '2 days'`,
      [ip]
    );
    const { hour_count, day_count } = result.rows[0];
    if (parseInt(hour_count) >= RATE_LIMIT_HOUR) {
      return { limited: true, reason: 'Trop d\'inscriptions depuis votre adresse IP. Réessayez dans 1 heure.' };
    }
    if (parseInt(day_count) >= RATE_LIMIT_DAY) {
      return { limited: true, reason: 'Limite journalière atteinte pour votre adresse IP. Réessayez demain.' };
    }
    return { limited: false };
  } catch (err) {
    console.error('[rate-limit] Check error:', err.message);
    return { limited: false }; // fail open — don't block legit users on DB error
  }
}

async function recordRegistrationAttempt(ip) {
  try {
    await pool.query(
      `INSERT INTO registration_attempts (ip_address) VALUES ($1)`,
      [ip]
    );
  } catch (err) {
    console.error('[rate-limit] Record error:', err.message);
  }
}

// ── Email Verification Sender ─────────────────────────────
// Spam-fix: ASCII-only from_name, no emoji in subject/CTA, List-Unsubscribe, clean HTML
async function sendVerificationEmail(toEmail, verifyUrl, userName) {
  const resendApiKey = process.env.RESEND_API_KEY;
  const appUrl = process.env.APP_URL || 'https://www.desirparent.com';
  const unsubUrl = `${appUrl}/compte`;

  const subject = 'Confirmez votre email - DesirParent';

  const html = `<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:Arial,Helvetica,sans-serif;background:#f5f5f5;margin:0;padding:24px">
  <div style="display:none;max-height:0;overflow:hidden;mso-hide:all">Confirmez votre email pour activer votre profil DesirParent.</div>
  <div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:12px;padding:32px">
    <h2 style="color:#E8185A;font-size:20px;margin:0 0 8px">DesirParent</h2>
    <p style="color:#555;margin:0 0 20px">Bonjour ${userName || ''},</p>
    <p style="color:#333;margin:0 0 20px;line-height:1.5">Merci de vous etre inscrit(e) sur DesirParent. Confirmez votre adresse email pour activer votre profil.</p>
    <div style="text-align:center;margin:28px 0">
      <a href="${verifyUrl}" style="background:#E8185A;color:#ffffff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:16px;font-weight:600;display:inline-block">Confirmer mon email</a>
    </div>
    <p style="color:#888;font-size:13px;margin:0 0 8px">Ce lien expire dans 24 heures.</p>
    <p style="color:#888;font-size:13px;margin:0 0 24px">Si vous n'avez pas cree de compte, ignorez cet email.</p>
    <hr style="border:none;border-top:1px solid #eeeeee;margin:24px 0">
    <p style="color:#999999;font-size:11px;text-align:center;margin:0">DesirParent - Trouvez votre partenaire parentalite</p>
    <p style="color:#999999;font-size:11px;text-align:center;margin:8px 0 0"><a href="${unsubUrl}" style="color:#999999">Gerer mes preferences</a></p>
  </div>
</body>
</html>`;

  const textBody = `Bonjour ${userName || ''},\n\nConfirmez votre email DesirParent :\n${verifyUrl}\n\nCe lien expire dans 24 heures.\n\nSi vous n'avez pas cree de compte, ignorez cet email.\n\n--\nDesirParent - Trouvez votre partenaire parentalite\nGerer mes preferences : ${unsubUrl}`;

  // ── Strategy 1: Resend API ────────────────────────────────
  if (resendApiKey) {
    try {
      const resendResp = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${resendApiKey}`
        },
        body: JSON.stringify({
          from: 'DésirParent <contact@desirparent.com>',
          to: [toEmail],
          reply_to: 'noreply@desirparent.com',
          subject: subject,
          html: html,
          text: textBody,
          tags: [{ name: 'category', value: 'email_verification' }]
        })
      });

      if (resendResp.ok) {
        console.log(`[email] Verification email sent via Resend to ${toEmail}`);
        return true;
      }

      const bodyText = await resendResp.text();
      console.error(`[email] Resend API error for ${toEmail}: HTTP ${resendResp.status} — ${bodyText.slice(0, 300)}`);
    } catch (resendErr) {
      console.error(`[email] Resend fetch error for ${toEmail}: ${resendErr.message}`);
    }
  } else {
    console.log(`[email] No RESEND_API_KEY — skipping Resend API for ${toEmail}`);
  }

  // ── Strategy 2: Queue in DB as last resort ──
  try {
    await pool.query(
      `INSERT INTO email_queue (to_email, subject, html_body, text_body, tag, metadata)
       VALUES ($1, $2, $3, $4, 'email_verification', $5::jsonb)`,
      [toEmail, subject, html, textBody, JSON.stringify({ verify_url: verifyUrl, queued_reason: 'resend_fallback' })]
    );
    console.log(`[email] Verification queued in DB for ${toEmail} — Resend failed`);
  } catch (queueErr) {
    console.error(`[email] Failed to queue verification for ${toEmail}: ${queueErr.message}`);
  }

  return false;
}

// ── Shared Email Sender (Resend) ──────────────────────────
async function sendTransactionalEmail({ toEmail, subject, html, textBody, tag }) {
  const resendApiKey = process.env.RESEND_API_KEY;
  const appUrl = process.env.APP_URL || 'https://www.desirparent.com';
  const unsubUrl = `${appUrl}/compte`;

  // Strategy 1: Resend API
  if (resendApiKey) {
    try {
      const resp = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${resendApiKey}`
        },
        body: JSON.stringify({
          from: 'DésirParent <contact@desirparent.com>',
          to: [toEmail],
          reply_to: 'noreply@desirparent.com',
          subject: subject,
          html: html,
          text: textBody,
          tags: [{ name: 'category', value: tag }]
        })
      });
      if (resp.ok) {
        console.log(`[email] ${tag} sent via Resend to ${toEmail}`);
        return true;
      }
      const errText = await resp.text();
      console.error(`[email] Resend error for ${tag}/${toEmail}: HTTP ${resp.status} — ${errText.slice(0, 200)}`);
    } catch (e) {
      console.error(`[email] Resend fetch error for ${tag}/${toEmail}: ${e.message}`);
    }
  }

  // Strategy 2: Queue in DB as last resort
  try {
    await pool.query(
      `INSERT INTO email_queue (to_email, subject, html_body, text_body, tag, metadata)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
      [toEmail, subject, html, textBody || '', tag, JSON.stringify({ queued_reason: 'resend_fallback' })]
    );
    console.log(`[email] ${tag} queued in DB for ${toEmail} — Resend failed`);
  } catch (queueErr) {
    console.error(`[email] Failed to queue ${tag} for ${toEmail}: ${queueErr.message}`);
  }

  console.error(`[email] ALL STRATEGIES FAILED for ${tag}/${toEmail}`);
  return false;
}

// ── Onboarding Email 1 — Welcome (triggered on email verification) ─
async function sendWelcomeEmail(toEmail, userName) {
  const profileUrl = 'https://www.desirparent.com/profil';
  const html = `<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:sans-serif;background:#f9f0f5;margin:0;padding:24px">
  <div style="display:none;max-height:0;overflow:hidden;mso-hide:all">Bienvenue ${userName || ''} ! Completez votre profil en 3 etapes pour trouver votre partenaire parentalite.</div>
  <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:14px;padding:36px 32px;box-shadow:0 2px 10px rgba(232,24,90,0.08)">
    <h2 style="color:#E8185A;font-size:22px;margin:0 0 4px">DesirParent</h2>
    <p style="color:#888;font-size:13px;margin:0 0 28px">Votre communaute parentalite</p>

    <p style="color:#333;font-size:16px;margin:0 0 8px">Bonjour <strong>${userName || ''}</strong>,</p>
    <p style="color:#555;margin:0 0 24px;line-height:1.6">
      Bienvenue sur <strong>DesirParent</strong> ! Votre compte est maintenant actif.
      Voici comment trouver votre partenaire parentalite en 3 etapes :
    </p>

    <table style="width:100%;border-collapse:collapse;margin:0 0 28px">
      <tr>
        <td style="padding:12px 16px;background:#fdf0f5;border-radius:8px;margin-bottom:8px;display:block">
          <span style="color:#E8185A;font-weight:700;font-size:18px">1.</span>
          <strong style="color:#333;margin-left:8px">Completez votre profil</strong>
          <p style="color:#777;font-size:13px;margin:4px 0 0 26px">Ajoutez votre photo, bio et categories - les profils complets recoivent <strong>3x plus de messages</strong>.</p>
        </td>
      </tr>
      <tr><td style="height:8px"></td></tr>
      <tr>
        <td style="padding:12px 16px;background:#fff8f0;border-radius:8px;display:block">
          <span style="color:#F5922A;font-weight:700;font-size:18px">2.</span>
          <strong style="color:#333;margin-left:8px">Decouvrez les profils</strong>
          <p style="color:#777;font-size:13px;margin:4px 0 0 26px">Parcourez les membres pres de chez vous et filtrez par projet parental.</p>
        </td>
      </tr>
      <tr><td style="height:8px"></td></tr>
      <tr>
        <td style="padding:12px 16px;background:#f0f8ff;border-radius:8px;display:block">
          <span style="color:#1890E8;font-weight:700;font-size:18px">3.</span>
          <strong style="color:#333;margin-left:8px">Envoyez un message</strong>
          <p style="color:#777;font-size:13px;margin:4px 0 0 26px">Presentez-vous simplement - un message sincere ouvre toutes les portes.</p>
        </td>
      </tr>
    </table>

    <div style="text-align:center;margin:32px 0">
      <a href="${profileUrl}" style="background:#E8185A;color:#ffffff;text-decoration:none;padding:16px 40px;border-radius:8px;font-size:16px;font-weight:700;display:inline-block">
        Completer mon profil
      </a>
    </div>

    <hr style="border:none;border-top:1px solid #eeeeee;margin:24px 0">
    <p style="color:#999999;font-size:11px;text-align:center;margin:0">DesirParent - Trouvez votre partenaire parentalite</p>
    <p style="color:#999999;font-size:11px;text-align:center;margin:8px 0 0"><a href="https://www.desirparent.com/compte" style="color:#999999">Gerer mes preferences</a></p>
  </div>
</body>
</html>`;

  const textBody = `Bonjour ${userName || ''},

Bienvenue sur DesirParent ! Votre compte est actif.

Voici les 3 etapes pour trouver votre partenaire parentalite :
1. Completez votre profil (photo, bio, categories)
2. Decouvrez les profils pres de chez vous
3. Envoyez un message sincere

Completer mon profil : ${profileUrl}

--
DesirParent - Trouvez votre partenaire parentalite
Gerer mes preferences : https://www.desirparent.com/compte`;

  return sendTransactionalEmail({ toEmail, subject: 'Bienvenue sur DesirParent - Votre profil vous attend', html, textBody, tag: 'welcome_email' });
}

// ── Onboarding Email 2 — Reminder (24h after signup, incomplete profile) ─
async function sendReminderEmail(toEmail, userName) {
  const profileUrl = 'https://www.desirparent.com/profil';
  const html = `<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:sans-serif;background:#f9f0f5;margin:0;padding:24px">
  <div style="display:none;max-height:0;overflow:hidden;mso-hide:all">Votre profil est presque pret ! Les profils complets recoivent 3x plus de messages.</div>
  <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:14px;padding:36px 32px;box-shadow:0 2px 10px rgba(232,24,90,0.08)">
    <h2 style="color:#E8185A;font-size:22px;margin:0 0 4px">DesirParent</h2>
    <p style="color:#888;font-size:13px;margin:0 0 28px">Votre communaute parentalite</p>

    <p style="color:#333;font-size:16px;margin:0 0 8px">Bonjour <strong>${userName || ''}</strong>,</p>
    <p style="color:#555;margin:0 0 24px;line-height:1.6">
      Votre profil DesirParent est presque pret - il ne manque plus grand chose !
    </p>

    <div style="background:#fff0f5;border-radius:12px;padding:24px;margin:0 0 28px;text-align:center;border:1px solid #f5d0e0">
      <p style="color:#E8185A;font-size:20px;font-weight:700;margin:0 0 8px">Les profils complets recoivent</p>
      <p style="color:#E8185A;font-size:28px;font-weight:800;margin:0 0 8px">3x plus de messages</p>
      <p style="color:#777;font-size:13px;margin:0">Ajoutez votre photo, bio et categories pour maximiser vos chances.</p>
    </div>

    <p style="color:#555;margin:0 0 20px;line-height:1.6">
      Il vous suffit de quelques minutes pour finaliser votre profil et commencer a recevoir des messages de personnes partageant votre projet parental.
    </p>

    <div style="text-align:center;margin:32px 0">
      <a href="${profileUrl}" style="background:#E8185A;color:#ffffff;text-decoration:none;padding:16px 40px;border-radius:8px;font-size:16px;font-weight:700;display:inline-block">
        Finaliser mon profil
      </a>
    </div>

    <hr style="border:none;border-top:1px solid #eeeeee;margin:24px 0">
    <p style="color:#999999;font-size:11px;text-align:center;margin:0">DesirParent - Trouvez votre partenaire parentalite</p>
    <p style="color:#999999;font-size:11px;text-align:center;margin:8px 0 0"><a href="https://www.desirparent.com/compte" style="color:#999999">Gerer mes preferences</a></p>
  </div>
</body>
</html>`;

  const textBody = `Bonjour ${userName || ''},

Votre profil DesirParent est presque pret !

Les profils complets recoivent 3x plus de messages. Ajoutez votre photo, bio et categories pour maximiser vos chances.

Finaliser mon profil : ${profileUrl}

--
DesirParent - Trouvez votre partenaire parentalite
Gerer mes preferences : https://www.desirparent.com/compte`;

  return sendTransactionalEmail({ toEmail, subject: 'Votre profil DesirParent est presque pret', html, textBody, tag: 'reminder_email' });
}

// ── Hourly onboarding reminder cron ──────────────────────
async function sendOnboardingReminders() {
  try {
    // Find users who:
    // - signed up > 24h ago and have verified email
    // - haven't received the reminder yet
    // - have an incomplete profile (no bio OR no photo OR empty categories)
    // - haven't sent any message yet (not yet active)
    const result = await pool.query(`
      SELECT u.id, u.email, u.name
      FROM users u
      WHERE u.email_verified = TRUE
        AND u.created_at < NOW() - INTERVAL '24 hours'
        AND u.reminder_email_sent_at IS NULL
        AND (
          u.bio IS NULL OR TRIM(u.bio) = ''
          OR u.photo_url IS NULL OR TRIM(u.photo_url) = ''
          OR u.categories IS NULL OR u.categories::text = '[]' OR u.categories::text = 'null'
        )
        AND NOT EXISTS (
          SELECT 1 FROM messages m WHERE m.sender_id = u.id
        )
        AND u.email NOT LIKE '%@desirparent.internal'
      LIMIT 50
    `);

    if (result.rows.length === 0) return;

    console.log(`[onboarding-cron] ${result.rows.length} user(s) eligible for reminder`);

    for (const user of result.rows) {
      try {
        const sent = await sendReminderEmail(user.email, user.name);
        // Mark sent regardless of outcome to avoid retry spam; worst case: user didn't get it
        await pool.query(
          `UPDATE users SET reminder_email_sent_at = NOW() WHERE id = $1`,
          [user.id]
        );
        if (sent) {
          console.log(`[onboarding-cron] Reminder sent to user ${user.id} (${user.email})`);
        } else {
          console.error(`[onboarding-cron] Reminder FAILED for user ${user.id} — marked to avoid retry`);
        }
      } catch (userErr) {
        console.error(`[onboarding-cron] Error processing user ${user.id}: ${userErr.message}`);
      }
    }
  } catch (err) {
    console.error(`[onboarding-cron] Query error: ${err.message}`);
  }
}

function fetchJson(url, options) {
  return new Promise((resolve) => {
    const lib = url.startsWith('https') ? https : http;
    const urlObj = new URL(url);

    const req = lib.request({
      hostname: urlObj.hostname,
      port: urlObj.port,
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: options.headers || {}
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve(null); }
      });
    });

    req.on('error', () => resolve(null));
    req.setTimeout(10000, () => { req.destroy(); resolve(null); });

    if (options.body) req.write(options.body);
    req.end();
  });
}

// ── Seed Fake Profiles ────────────────────────────────────
async function seedFakeProfiles() {
  try {
    // Check if gender column exists (migration may not have run yet in dev)
    const colCheck = await pool.query(`
      SELECT column_name FROM information_schema.columns
      WHERE table_name='users' AND column_name='gender'
    `);
    if (colCheck.rows.length === 0) return;

    const result = await pool.query(
      "SELECT COUNT(*) as count FROM users WHERE name IS NOT NULL AND name != ''"
    );
    const count = parseInt(result.rows[0].count);
    if (count >= 3) return;

    const seeds = [
      { name: 'Marie', age: 32, city: 'Paris', gender: 'Femme', country: 'France', region: 'Île-de-France',
        categories: ['Coparentalité', 'Fonder une Famille'],
        bio: 'Enseignante passionnée, je rêve de fonder une famille avec le partenaire idéal. Ouverte à la coparentalité bienveillante.',
        photo: 'https://i.pravatar.cc/200?img=47' },
      { name: 'Thomas', age: 28, city: 'Lyon', gender: 'Homme', country: 'France', region: 'Auvergne-Rhône-Alpes',
        categories: ['Géniteur'],
        bio: 'Médecin de 28 ans, cherche à donner la vie à des personnes qui en ont besoin. Sérieux et impliqué.',
        photo: 'https://i.pravatar.cc/200?img=15' },
      { name: 'Sofiane', age: 35, city: 'Marseille', gender: 'Homme', country: 'France', region: 'Provence-Alpes-Côte d\'Azur',
        categories: ['Coparentalité'],
        bio: 'Papa solo depuis 3 ans, je cherche une partenaire pour agrandir la famille en toute bienveillance.',
        photo: 'https://i.pravatar.cc/200?img=51' },
      { name: 'Lucie', age: 29, city: 'Bordeaux', gender: 'Femme', country: 'France', region: 'Nouvelle-Aquitaine',
        categories: ['Homoparentalité', 'Fonder une Famille'],
        bio: 'En couple avec ma compagne, nous cherchons un donneur ou co-parent pour réaliser notre rêve de maternité.',
        photo: 'https://i.pravatar.cc/200?img=56' },
      { name: 'Antoine', age: 40, city: 'Toulouse', gender: 'Homme', country: 'France', region: 'Occitanie',
        categories: ['Coparentalité'],
        bio: 'Architecte de 40 ans, divorcé sans enfant. Je veux m\'investir pleinement dans un projet de co-parentalité.',
        photo: 'https://i.pravatar.cc/200?img=33' },
      { name: 'Nadia', age: 26, city: 'Montpellier', gender: 'Femme', country: 'France', region: 'Occitanie',
        categories: ['Homoparentalité'],
        bio: 'Je cherche une co-mère pour vivre la maternité ensemble. Valeurs : respect, partage, amour.',
        photo: 'https://i.pravatar.cc/200?img=49' },
      { name: 'Camille', age: 34, city: 'Nantes', gender: 'Femme', country: 'France', region: 'Pays de la Loire',
        categories: ['Fonder une Famille'],
        bio: 'Consultante RH, célibataire épanouie. J\'espère trouver ici l\'homme avec qui bâtir une belle famille.',
        photo: 'https://i.pravatar.cc/200?img=44' },
      { name: 'Romain', age: 31, city: 'Strasbourg', gender: 'Homme', country: 'France', region: 'Grand Est',
        categories: ['Géniteur', 'Fonder une Famille'],
        bio: 'Je suis ouvert à être géniteur ou à fonder une famille dans un cadre stable et chaleureux.',
        photo: 'https://i.pravatar.cc/200?img=12' },
      { name: 'Yasmine', age: 27, city: 'Nice', gender: 'Femme', country: 'France', region: 'Provence-Alpes-Côte d\'Azur',
        categories: ['Coparentalité', 'Homoparentalité'],
        bio: 'Ouverte à tous les modèles familiaux. L\'important pour moi : un projet sincère et des valeurs communes.',
        photo: 'https://i.pravatar.cc/200?img=21' },
      { name: 'Pierre', age: 38, city: 'Lille', gender: 'Homme', country: 'France', region: 'Hauts-de-France',
        categories: ['Famille Recomposée'],
        bio: 'Papa de deux enfants, je cherche une partenaire prête à construire une belle famille recomposée.',
        photo: 'https://i.pravatar.cc/200?img=59' }
    ];

    for (const s of seeds) {
      const email = `seed_${s.name.toLowerCase().replace(/[^a-z]/g, '')}@desirparent.internal`;
      const exists = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1', [email]);
      if (exists.rows.length > 0) continue;

      const orderResult = await pool.query("SELECT nextval('user_registration_seq') as n");
      const order = parseInt(orderResult.rows[0].n);
      const passwordHash = hashPassword('SeedPassw0rd!');

      await pool.query(
        `INSERT INTO users (email, password_hash, name, age, city, gender, country, region, categories, bio, photo_url, registration_order, email_verified)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, TRUE)`,
        [email, passwordHash, s.name, s.age, s.city, s.gender, s.country, s.region,
         JSON.stringify(s.categories), s.bio, s.photo, order]
      );
    }

    console.log('[seed] Fake profiles seeded successfully');
  } catch (err) {
    console.error('[seed] Seeding error:', err.message);
  }
}

// ── Email Queue Processor ─────────────────────────────────
// Processes emails stuck in email_queue (from failed Strategy 1/2 attempts).
// Sends via Polsia proxy. Runs every 2 minutes, processes up to 10 per batch.
async function processEmailQueue() {
  const apiKey = process.env.POLSIA_API_KEY;
  const baseUrl = (process.env.POLSIA_R2_BASE_URL || 'https://polsia.com').replace(/\/$/, '');
  if (!apiKey) return; // No API key = can't send

  try {
    const pending = await pool.query(
      `SELECT id, to_email, subject, html_body, text_body, tag, metadata
       FROM email_queue
       WHERE sent_at IS NULL AND attempts < 3
       ORDER BY created_at ASC
       LIMIT 10`
    );
    if (!pending.rows.length) return;

    console.log(`[email-queue] Processing ${pending.rows.length} queued email(s)`);

    for (const email of pending.rows) {
      try {
        const resp = await fetch(`${baseUrl}/api/proxy/email/send`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`
          },
          body: JSON.stringify({
            to: email.to_email,
            subject: email.subject,
            body: email.text_body || '',
            html: email.html_body || ''
          })
        });
        const body = await resp.text();
        let data;
        try { data = JSON.parse(body); } catch { data = {}; }

        if (resp.ok && data.success !== false) {
          await pool.query(
            `UPDATE email_queue SET sent_at = NOW(), metadata = metadata || $2::jsonb WHERE id = $1`,
            [email.id, JSON.stringify({ sent_via: 'proxy_queue', message_id: data.message_id || null })]
          );
          console.log(`[email-queue] Sent queued ${email.tag} to ${email.to_email} (id: ${email.id})`);
        } else {
          await pool.query(
            `UPDATE email_queue SET attempts = attempts + 1 WHERE id = $1`,
            [email.id]
          );
          console.error(`[email-queue] Failed ${email.tag}/${email.to_email}: HTTP ${resp.status}`);
        }
      } catch (sendErr) {
        await pool.query(
          `UPDATE email_queue SET attempts = attempts + 1 WHERE id = $1`,
          [email.id]
        ).catch(() => {});
        console.error(`[email-queue] Error sending ${email.id}: ${sendErr.message}`);
      }
    }
  } catch (err) {
    console.error(`[email-queue] Processor error: ${err.message}`);
  }
}

// ── Start ─────────────────────────────────────────────────
app.listen(port, async () => {
  console.log(`[desirparent] Server running on port ${port}`);
  await seedFakeProfiles();

  // ── Onboarding reminder cron (every hour) ───────────────
  // First run 5 minutes after startup to let DB settle, then every hour
  const REMINDER_INTERVAL_MS = 60 * 60 * 1000; // 1 hour
  setTimeout(async () => {
    console.log('[onboarding-cron] Initial reminder check running...');
    await sendOnboardingReminders();
    setInterval(sendOnboardingReminders, REMINDER_INTERVAL_MS);
  }, 5 * 60 * 1000); // 5 min delay on startup
  console.log('[onboarding-cron] Reminder cron scheduled (runs hourly, first check in 5 min)');

  // ── Email queue processor (every 2 minutes) ────────────
  // Flushes emails that fell through to DB queue. First run 30s after startup.
  setTimeout(async () => {
    console.log('[email-queue] Initial queue flush running...');
    await processEmailQueue();
    setInterval(processEmailQueue, 2 * 60 * 1000);
  }, 30 * 1000);
  console.log('[email-queue] Queue processor scheduled (runs every 2 min, first flush in 30s)');
});
