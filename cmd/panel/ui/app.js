// Проверка авторизации на защищенных страницах
async function checkAuth() {
  if (window.location.pathname.endsWith('login.html')) return;
  try {
    const res = await fetch('/api/auth/me');
    if (res.status === 401) {
      window.location.href = '/login.html';
    }
  } catch (err) {
    console.error("Auth check failed:", err);
  }
}

// Показ всплывающего уведомления
function showToast(message, type = 'info') {
  let toast = document.getElementById('toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toast';
    toast.className = 'toast';
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.className = `toast ${type} show`;
  setTimeout(() => {
    toast.classList.remove('show');
  }, 3000);
}

// Генераторы секретов
function generateHex(bytes = 16) {
  const arr = new Uint8Array(bytes);
  window.crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

function stringToHex(str) {
  let hex = '';
  for (let i = 0; i < str.length; i++) {
    hex += str.charCodeAt(i).toString(16).padStart(2, '0');
  }
  return hex;
}

function generateFakeTLSSecret(domain) {
  const cleanDomain = domain.trim().toLowerCase();
  const hex16 = generateHex(16);
  if (!cleanDomain) return 'ee' + hex16;
  return 'ee' + hex16 + stringToHex(cleanDomain);
}

function copyToClipboard(text, msg = 'Скопировано в буфер') {
  navigator.clipboard.writeText(text).then(() => {
    showToast(msg, 'success');
  }).catch(() => {
    showToast('Не удалось скопировать', 'error');
  });
}

async function logout() {
  await fetch('/api/auth/logout', { method: 'POST' });
  window.location.href = '/login.html';
}

document.addEventListener('DOMContentLoaded', checkAuth);
