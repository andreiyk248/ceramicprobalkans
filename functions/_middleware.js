// Закрывает весь сайт логином и паролем (HTTP Basic Auth).
// В коде хранится только SHA-256 от строки "логин:пароль", не сам пароль.
// Чтобы сменить пароль без правки кода, задайте в Cloudflare Pages → Settings →
// Variables переменную AUTH_SHA256 с хэшем новой пары "логин:пароль".
const DEFAULT_HASH = '3c4612a240df632a674ccf6486551756c1cbbcc5d6ceefea2e3556fb1589e90d';

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function deny() {
  return new Response('Требуется вход / Authentication required', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="Ceramic Pro Balkans", charset="UTF-8"',
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

export async function onRequest({ request, env, next }) {
  const header = request.headers.get('Authorization') || '';
  if (!header.startsWith('Basic ')) return deny();
  let pair;
  try {
    pair = new TextDecoder().decode(Uint8Array.from(atob(header.slice(6)), c => c.charCodeAt(0)));
  } catch {
    return deny();
  }
  if ((await sha256(pair)) !== (env.AUTH_SHA256 || DEFAULT_HASH)) return deny();
  const res = await next();
  const out = new Response(res.body, res);
  out.headers.set('Cache-Control', 'private, no-store');
  return out;
}
