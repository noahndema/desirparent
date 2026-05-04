/* ══════════════════════════════════════════════════════════
   DésirParent — Client-side JavaScript
   ══════════════════════════════════════════════════════════ */

const API = {
  async fetch(url, options = {}) {
    const res = await fetch(url, {
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      ...options
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Erreur');
    return data;
  },

  register(body) {
    return this.fetch('/api/auth/register', { method: 'POST', body: JSON.stringify(body) });
  },

  login(body) {
    return this.fetch('/api/auth/login', { method: 'POST', body: JSON.stringify(body) });
  },

  logout() {
    return this.fetch('/api/auth/logout', { method: 'POST' });
  },

  // Merged endpoint: returns { user, unread: { notifications, messages } }
  me() {
    return this.fetch('/api/me');
  },

  updateProfile(body) {
    return this.fetch('/api/profile', { method: 'PUT', body: JSON.stringify(body) });
  },

  getProfile(id) {
    return this.fetch(`/api/profile/${id}`);
  },

  uploadPhoto(base64) {
    return this.fetch('/api/upload/photo', { method: 'POST', body: JSON.stringify({ photo: base64 }) });
  },

  stats() {
    return this.fetch('/api/stats');
  },

  getFeed(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.fetch(`/api/feed${qs ? '?' + qs : ''}`);
  },

  likeUser(userId) {
    return this.fetch(`/api/likes/${userId}`, { method: 'POST' });
  },

  unlikeUser(userId) {
    return this.fetch(`/api/likes/${userId}`, { method: 'DELETE' });
  },

  getLikesReceived() {
    return this.fetch('/api/likes/received');
  },

  search(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.fetch(`/api/search${qs ? '?' + qs : ''}`);
  },

  getConversations() {
    return this.fetch('/api/conversations');
  },

  getMessages(userId, params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.fetch(`/api/messages/${userId}${qs ? '?' + qs : ''}`);
  },

  sendMessage(userId, content) {
    return this.fetch(`/api/messages/${userId}`, {
      method: 'POST',
      body: JSON.stringify({ content })
    });
  },

  getNotifications() {
    return this.fetch('/api/notifications');
  },

  markNotificationsRead() {
    return this.fetch('/api/notifications/read', { method: 'PUT' });
  },

  getUnreadCount() {
    return this.fetch('/api/notifications/unread-count');
  },

  getMessageQuota() {
    return this.fetch('/api/messages/quota');
  }
};

// ── Category helpers ────────────────────────────────────
const CATEGORIES = {
  'Géniteur':            { key: 'geniteur',         color: '#7C3AED', cssClass: 'badge-geniteur' },
  'Coparentalité':       { key: 'coparentalite',    color: '#FB923C', cssClass: 'badge-coparentalite' },
  'Homoparentalité':     { key: 'homoparentalite',  color: '#F472B6', cssClass: 'badge-homoparentalite' },
  'Fonder une Famille':  { key: 'fonder',           color: '#0D9488', cssClass: 'badge-fonder' },
  'Famille Recomposée':  { key: 'recomposee',       color: '#F59E0B', cssClass: 'badge-recomposee' }
};

function categoryBadge(name) {
  const cat = CATEGORIES[name];
  if (!cat) return `<span class="badge">${name}</span>`;
  return `<span class="badge ${cat.cssClass}">${name}</span>`;
}

// ── Auth state ──────────────────────────────────────────
let currentUser = null;

// sessionStorage key for cached user (invalidated on logout)
const USER_CACHE_KEY = 'dp_user_v1';
// How long cached user data is valid (5 minutes — short enough to catch plan changes)
const USER_CACHE_TTL = 5 * 60 * 1000;

// checkAuth: uses /api/me (returns user + unread counts in one call).
// Caches user in sessionStorage to skip DB hit on tab switches / back-nav.
// Returns { loggedIn, unread } so callers can paint badges without an extra fetch.
let _mePromise = null; // deduplicate concurrent checkAuth() calls on the same page
async function checkAuth() {
  // Return in-flight promise if already called this page load
  if (_mePromise) return _mePromise;

  _mePromise = (async () => {
    // Try sessionStorage cache first
    try {
      const cached = sessionStorage.getItem(USER_CACHE_KEY);
      if (cached) {
        const { user, unread, ts } = JSON.parse(cached);
        if (Date.now() - ts < USER_CACHE_TTL) {
          currentUser = user;
          return { loggedIn: true, unread };
        }
      }
    } catch { /* corrupt cache — fall through */ }

    // Cache miss or stale — fetch from server
    try {
      const data = await API.me();
      currentUser = data.user;
      // Write to sessionStorage for subsequent navigations
      try {
        sessionStorage.setItem(USER_CACHE_KEY, JSON.stringify({
          user: data.user,
          unread: data.unread,
          ts: Date.now()
        }));
      } catch { /* storage full or private — harmless */ }
      return { loggedIn: true, unread: data.unread };
    } catch {
      currentUser = null;
      try { sessionStorage.removeItem(USER_CACHE_KEY); } catch {}
      return { loggedIn: false, unread: { notifications: 0, messages: 0 } };
    }
  })();

  return _mePromise;
}

async function updateNav() {
  const loggedIn = currentUser !== null;
  document.querySelectorAll('.nav-logged-in').forEach(el => el.style.display = loggedIn ? '' : 'none');
  document.querySelectorAll('.nav-logged-out').forEach(el => el.style.display = loggedIn ? 'none' : '');
}

async function handleLogout(e) {
  if (e) e.preventDefault();
  try {
    await API.logout();
  } catch {}
  currentUser = null;
  // Invalidate user cache so next page load re-fetches fresh state
  try { sessionStorage.removeItem(USER_CACHE_KEY); } catch {}
  window.location.href = '/';
}

// ── Photo reader ────────────────────────────────────────
function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

// ── Alert helper ────────────────────────────────────────
function showAlert(id, message, type = 'error') {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = `alert show alert-${type}`;
  el.textContent = message;
  if (type === 'success') {
    setTimeout(() => el.classList.remove('show'), 4000);
  }
}

function hideAlert(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('show');
}

// ── Default photo placeholder ────────────────────────────
const DEFAULT_PHOTO = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200' viewBox='0 0 200 200'%3E%3Crect fill='%23E5E7EB' width='200' height='200'/%3E%3Ccircle cx='100' cy='80' r='35' fill='%239CA3AF'/%3E%3Cellipse cx='100' cy='170' rx='55' ry='45' fill='%239CA3AF'/%3E%3C/svg%3E";

// ── Bottom nav ───────────────────────────────────────────
function initBottomNav() {
  const path = window.location.pathname;
  document.querySelectorAll('.bottom-nav-item').forEach(el => {
    el.classList.remove('active');
    const href = el.getAttribute('href') || el.dataset.href;
    if (href && (path === href || (href !== '/' && path.startsWith(href)))) {
      el.classList.add('active');
    }
  });
  document.body.classList.add('has-bottom-nav');
}

// ── Unified badge painter ────────────────────────────────
// Paints ALL unread badges (header bell, bottom nav messages + notifications)
// using data already fetched by checkAuth — zero extra network calls.
function paintUnreadBadges(unread) {
  if (!unread) return;
  const path = window.location.pathname;

  // Header bell badge
  if (unread.notifications > 0) {
    const bell = document.getElementById('headerBell');
    if (bell && !bell.querySelector('.nav-badge')) {
      const badge = document.createElement('span');
      badge.className = 'nav-badge';
      badge.style.cssText = 'position:absolute;top:4px;right:4px;background:#E8185A;color:#fff;border-radius:50%;min-width:16px;height:16px;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;padding:0 2px';
      badge.textContent = unread.notifications > 9 ? '9+' : unread.notifications;
      bell.appendChild(badge);
    }
  }

  // Bottom nav: messages badge (skip on /messages — page handles its own)
  if (path !== '/messages' && unread.messages > 0) {
    const msgNav = document.querySelector('.bottom-nav a[href="/messages"]');
    if (msgNav) {
      const icon = msgNav.querySelector('.bottom-nav-icon');
      if (icon) {
        icon.style.position = 'relative';
        const badge = document.createElement('span');
        badge.style.cssText = 'position:absolute;top:-4px;right:-6px;background:#E8185A;color:#fff;border-radius:50%;width:16px;height:16px;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center';
        badge.textContent = unread.messages > 9 ? '9+' : unread.messages;
        icon.appendChild(badge);
      }
    }
    // Also paint header nav messages badge if present
    const msgNavHeader = document.getElementById('navMessages');
    if (msgNavHeader && !msgNavHeader.querySelector('.nav-badge')) {
      const icon = msgNavHeader.querySelector('.bottom-nav-icon');
      if (icon) {
        icon.style.position = 'relative';
        const badge = document.createElement('span');
        badge.className = 'nav-badge';
        badge.style.cssText = 'position:absolute;top:-4px;right:-6px;background:#E8185A;color:#fff;border-radius:50%;width:16px;height:16px;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center';
        badge.textContent = unread.messages > 9 ? '9+' : unread.messages;
        icon.appendChild(badge);
      }
    }
  }

  // Bottom nav: notifications badge (skip on /notifications page)
  if (path !== '/notifications' && unread.notifications > 0) {
    const notifNav = document.querySelector('.bottom-nav a[href="/notifications"]');
    if (notifNav) {
      const icon = notifNav.querySelector('.bottom-nav-icon');
      if (icon) {
        icon.style.position = 'relative';
        const badge = document.createElement('span');
        badge.style.cssText = 'position:absolute;top:-4px;right:-6px;background:#E8185A;color:#fff;border-radius:50%;width:16px;height:16px;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center';
        badge.textContent = unread.notifications > 9 ? '9+' : unread.notifications;
        icon.appendChild(badge);
      }
    }
  }
}

// Legacy aliases — kept for page-specific scripts that call these directly.
// Both now use the data already cached by checkAuth() rather than refetching.
async function loadUnreadBadges() {
  // If we already have cached unread data from checkAuth, use it
  try {
    const cached = sessionStorage.getItem(USER_CACHE_KEY);
    if (cached) {
      const { unread } = JSON.parse(cached);
      if (unread) { paintUnreadBadges(unread); return; }
    }
  } catch {}
  // Fallback: fetch directly (e.g. after auth cache cleared)
  try {
    const data = await API.getUnreadCount();
    paintUnreadBadges(data);
  } catch {}
}

// loadGlobalUnreadBadges kept for any external callers
const loadGlobalUnreadBadges = loadUnreadBadges;

// ── Feed card renderer ───────────────────────────────────
function renderFeedCard(user, { onLike } = {}) {
  const cats = Array.isArray(user.categories) ? user.categories : [];
  const badgesHtml = cats.slice(0, 3).map(c => categoryBadge(c)).join('');
  const meta = [];
  if (user.age) meta.push(`${user.age} ans`);
  if (user.city) meta.push(`📍 ${user.city}`);
  if (user.gender) meta.push(user.gender);

  const likedClass = user.liked_by_me ? 'liked' : '';
  const likedIcon = user.liked_by_me ? '❤️' : '🤍';

  const card = document.createElement('div');
  card.className = 'feed-card';
  card.dataset.userId = user.id;
  card.innerHTML = `
    <img class="feed-card-photo" src="${user.photo_url || DEFAULT_PHOTO}" alt="${user.name}" onerror="this.src='${DEFAULT_PHOTO}'">
    <div class="feed-card-body">
      <div class="feed-card-name">${user.name || 'Anonyme'}</div>
      ${meta.length ? `<div class="feed-card-meta">${meta.join(' · ')}</div>` : ''}
      ${badgesHtml ? `<div class="feed-card-badges">${badgesHtml}</div>` : ''}
      <div class="feed-card-actions">
        <button class="btn-icon like-btn ${likedClass}" data-user-id="${user.id}" title="${user.liked_by_me ? 'Retirer le like' : 'Liker'}">${likedIcon}</button>
        <a href="/messages?with=${user.id}" class="btn-icon" title="Message">💬</a>
        <a href="/profil/${user.id}" class="btn-icon" title="Voir le profil">👤</a>
      </div>
    </div>
  `;

  const likeBtn = card.querySelector('.like-btn');
  likeBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    const liked = likeBtn.classList.contains('liked');
    try {
      if (liked) {
        await API.unlikeUser(user.id);
        likeBtn.classList.remove('liked');
        likeBtn.textContent = '🤍';
        user.liked_by_me = false;
      } else {
        await API.likeUser(user.id);
        likeBtn.classList.add('liked');
        likeBtn.textContent = '❤️';
        user.liked_by_me = true;
      }
      if (onLike) onLike(user);
    } catch (err) {
      console.error('Like error:', err.message);
    }
  });

  return card;
}

// ── Email verification banner ───────────────────────────
function showEmailVerificationBanner() {
  if (!currentUser || currentUser.email_verified !== false) return;
  // Don't show on inscription or verifier-email pages
  const path = window.location.pathname;
  if (path === '/inscription' || path === '/verifier-email' || path === '/connexion') return;
  if (document.getElementById('email-verify-banner')) return;

  const banner = document.createElement('div');
  banner.id = 'email-verify-banner';
  banner.style.cssText = 'position:fixed;bottom:72px;left:0;right:0;z-index:9000;background:#F59E0B;color:#fff;padding:10px 16px;display:flex;align-items:center;justify-content:space-between;gap:8px;font-size:13px;font-weight:600;box-shadow:0 -2px 8px rgba(0,0,0,0.15)';
  banner.innerHTML = `
    <span>📧 Confirmez votre email pour être visible dans le fil.</span>
    <button onclick="resendVerificationEmail()" style="background:#fff;color:#F59E0B;border:none;border-radius:6px;padding:4px 10px;font-size:12px;font-weight:700;cursor:pointer;white-space:nowrap">Renvoyer</button>
  `;
  document.body.appendChild(banner);
}

async function resendVerificationEmail() {
  try {
    const btn = document.querySelector('#email-verify-banner button');
    if (btn) { btn.textContent = '…'; btn.disabled = true; }
    const resp = await fetch('/api/auth/resend-verification', { method: 'POST', credentials: 'same-origin' });
    const data = await resp.json();
    const banner = document.getElementById('email-verify-banner');
    if (banner) {
      if (data.delivered) {
        banner.innerHTML = '<span>Email envoye ! Verifiez votre boite mail (et les spams).</span>';
      } else {
        banner.innerHTML = '<span>Demande envoyee. L\'email arrive sous peu -- verifiez aussi les spams.</span>';
      }
      setTimeout(() => banner.remove(), 5000);
    }
  } catch {
    const btn = document.querySelector('#email-verify-banner button');
    if (btn) { btn.textContent = 'Renvoyer'; btn.disabled = false; }
  }
}

// ── Init nav on all pages ───────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  const { loggedIn, unread } = await checkAuth();
  updateNav();

  // Bind logout buttons
  document.querySelectorAll('.logout-btn').forEach(el => {
    el.addEventListener('click', handleLogout);
  });

  // Init bottom nav if present
  if (document.querySelector('.bottom-nav')) {
    initBottomNav();
  }

  // Paint all badges from data already returned by checkAuth — no extra fetch
  if (loggedIn) {
    paintUnreadBadges(unread);
    showEmailVerificationBanner();
  }
});
