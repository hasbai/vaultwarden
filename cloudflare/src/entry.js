import app from '../build/index.js';
const MAX_BODY = 2 * 1024 * 1024;
function finish(result, request) {
  const response = new Response(result.body, result);
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'no-referrer');
  response.headers.set('X-Frame-Options', 'SAMEORIGIN');
  response.headers.set('Strict-Transport-Security', 'max-age=31536000');
  const path = new URL(request.url).pathname;
  if (path.startsWith('/api/') || path.startsWith('/identity/') || path.startsWith('/setup')) {
    response.headers.set('Cache-Control', 'no-store');
    response.headers.set('Access-Control-Allow-Origin', '*');
    response.headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, Device-Type, Client-Version, Bitwarden-Client-Name, Bitwarden-Client-Version');
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  }
  return response;
}
export default class extends app {
  async fetch(request) {
    try {
      if (request.body) {
        const reader = request.body.getReader();
        const chunks = []; let size = 0;
        while (true) {
          const {done, value} = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > MAX_BODY) {
            await reader.cancel();
            return finish(Response.json({message: 'Request exceeds 2 MiB'}, {status: 413}), request);
          }
          chunks.push(value);
        }
        const body = new Uint8Array(size); let offset = 0;
        for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
        request = new Request(request, {body});
      }
      return finish(await super.fetch(request), request);
    } catch {
      console.error(JSON.stringify({event: 'request_failed', path: new URL(request.url).pathname}));
      return finish(Response.json({message: 'Internal server error'}, {status: 500}), request);
    }
  }
}
