import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const address = process.argv[2];
if (!address) {
  console.error('Usage: npm run configure:render -- https://YOUR-SERVICE.onrender.com');
  process.exit(1);
}
let url;
try {
  url = new URL(address);
} catch {
  console.error('Provide the complete HTTPS Render service URL.');
  process.exit(1);
}
if (url.protocol !== 'https:' || !url.hostname.endsWith('.onrender.com') ||
    url.hostname === 'replace-with-your-render-service.onrender.com' ||
    url.username || url.password || url.port || url.search || url.hash || url.pathname !== '/') {
  console.error('Expected https://YOUR-SERVICE.onrender.com with no path, credentials, port or query.');
  process.exit(1);
}
const filename = fileURLToPath(new URL('../vercel.json', import.meta.url));
const config = JSON.parse(fs.readFileSync(filename, 'utf8'));
config.rewrites = [{ source: '/api/:path*', destination: `${url.origin}/api/:path*` }];
fs.writeFileSync(filename, JSON.stringify(config, null, 2) + '\n');
console.log(`Vercel /api now proxies to ${url.origin}. Commit frontend/vercel.json and redeploy Vercel.`);
