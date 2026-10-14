// TeleGate — общий фронтенд-код для всех страниц.
// Проверяет авторизацию, оборачивает API-запросы (с CSRF), рендерит сайдбар.

const TG = {
  // ---- Cookies / CSRF ----
  getCookie(name) {
    const m = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
    return m ? decodeURIComponent(m[2]) : '';
  },

  get csrf() {
    return this.getCookie('telegate_csrf') || '';
  },

  // ---- Auth ----
  async checkAuth() {
    try {
      const res = await fetch('/api/auth/me');
      return res.ok;
    } catch (e) {
      return false;
    }
  },

  // Инициализация защищённой страницы: редирект на логин, если нет сессии.
  async requireAuth() {
    const ok = await this.checkAuth();
    if (!ok) {
      window.location.href = '/login.html';
      return false;
    }
    return true;
  },

  async login(username, password) {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    return res;
  },

  async logout() {
    try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (e) {}
    window.location.href = '/login.html';
  },

  // ---- API wrapper с CSRF + авто-редиректом на логин ----
  async api(path, options = {}) {
    const opts = { ...options };
    opts.headers = { ...(opts.headers || {}) };
    const method = (opts.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
      opts.headers['X-CSRF-Token'] = this.csrf;
      if (opts.body && !opts.headers['Content-Type']) {
        opts.headers['Content-Type'] = 'application/json';
      }
    }
    const res = await fetch(path, opts);
    if (res.status === 401) {
      window.location.href = '/login.html';
      throw new Error('unauthorized');
    }
    return res;
  },

  async getState() {
    const res = await this.api('/api/state');
    if (!res.ok) throw new Error('state unavailable');
    return res.json();
  },

  // ---- Helpers ----
  genHex(len) {
    const arr = new Uint8Array(len);
    crypto.getRandomValues(arr);
    return Array.from(arr).map((b) => b.toString(16).padStart(2, '0')).join('');
  },

  strToHex(str) {
    let hex = '';
    for (let i = 0; i < str.length; i++) hex += str.charCodeAt(i).toString(16).padStart(2, '0');
    return hex;
  },

  esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  },

  async copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      return false;
    }
  },

  toast(msg, kind = 'ok') {
    let box = document.getElementById('tg-toast');
    if (!box) {
      box = document.createElement('div');
      box.id = 'tg-toast';
      box.className = 'fixed bottom-6 right-6 z-[100] space-y-2';
      document.body.appendChild(box);
    }
    const colors = {
      ok: 'bg-emerald-600', err: 'bg-rose-600', info: 'bg-indigo-600',
    };
    const el = document.createElement('div');
    el.className = `px-4 py-2.5 rounded-lg text-xs font-medium text-white shadow-lg ${colors[kind] || colors.info}`;
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(() => el.remove(), 2600);
  },

  // ---- Layout (сайдбар + шапка) ----
  renderChrome(active, title, headerExtra = '') {
    const nav = [
      { id: 'dashboard', href: '/index.html', label: 'Дашборд & Ноды', icon: 'grid' },
      { id: 'proxies', href: '/proxies.html', label: 'Конфигуратор прокси', icon: 'code' },
      { id: 'connections', href: '/connections.html', label: 'Подключения & IP', icon: 'users' },
      { id: 'security', href: '/security.html', label: 'Черный список & GeoIP', icon: 'lock' },
    ];
    const icons = {
      grid: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/>',
      code: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>',
      users: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/>',
      lock: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>',
    };

    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
      sidebar.className = 'w-64 border-r border-zinc-800 bg-zinc-900/60 flex flex-col justify-between shrink-0 min-h-screen';
      sidebar.innerHTML = `
        <div>
          <div class="h-16 flex items-center gap-2.5 px-6 border-b border-zinc-800">
            <div class="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center text-white shadow-md shadow-indigo-500/20">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
            </div>
            <div>
              <span class="font-bold tracking-tight text-base block leading-none">TeleGate</span>
              <span class="text-[11px] text-zinc-400 font-medium tracking-wide">PROXY CONTROL</span>
            </div>
          </div>
          <nav class="p-3 space-y-1">
            ${nav.map((n) => {
              const isActive = n.id === active;
              const cls = isActive
                ? 'w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium text-indigo-400 bg-indigo-950/40 transition'
                : 'w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 transition';
              return `<a href="${n.href}" class="${cls}">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">${icons[n.icon]}</svg>
                <span>${n.label}</span>
              </a>`;
            }).join('')}
          </nav>
        </div>
        <div class="p-4 border-t border-zinc-800">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-full bg-zinc-800 flex items-center justify-center font-bold text-xs">AD</div>
              <div class="text-xs">
                <div class="font-semibold text-zinc-100">admin</div>
                <div class="text-zinc-400">Master: Live</div>
              </div>
            </div>
            <button onclick="TG.logout()" title="Выйти" class="p-1.5 rounded-md text-zinc-400 hover:text-rose-500 transition">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>
            </button>
          </div>
        </div>`;
    }

    const header = document.getElementById('page-header');
    if (header) {
      header.className = 'h-16 border-b border-zinc-800 bg-zinc-900/40 backdrop-blur px-8 flex items-center justify-between sticky top-0 z-20';
      header.innerHTML = `
        <h1 class="text-lg font-semibold tracking-tight">${title}</h1>
        <div class="flex items-center gap-2">${headerExtra}</div>`;
    }
  },
};
