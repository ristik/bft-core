// A recording pass-through for the aggregator, used by pos-gap (bridge_pos.py) to evidence the trust-base page traffic of one tester process: the
// tester container resolves `aggregator` to this container (docker run --add-host), every request is forwarded unchanged to UPSTREAM, and each
// GET /api/v1/trustbases is appended to /rec/pages.jsonl with its query, HTTP status and the undecoded response bytes (hex). The harness decodes and
// checks them; this records only. Node's own http module, no dependencies (it runs in the bridge tools image).
import { appendFileSync } from 'node:fs';
import http from 'node:http';

const UPSTREAM = new URL(process.env.UPSTREAM ?? 'http://aggregator:8080');
const OUT = process.env.OUT ?? '/rec/pages.jsonl';
const PORT = Number(process.env.PORT ?? '8080');

http
  .createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const up = http.request(
        { host: UPSTREAM.hostname, port: UPSTREAM.port || 80, method: req.method, path: req.url, headers: { ...req.headers, host: UPSTREAM.host } },
        (r) => {
          const body = [];
          r.on('data', (c) => body.push(c));
          r.on('end', () => {
            const bytes = Buffer.concat(body);
            if (req.method === 'GET' && new URL(req.url, 'http://x').pathname === '/api/v1/trustbases') {
              appendFileSync(OUT, JSON.stringify({ path: req.url, http: r.statusCode, body: bytes.toString('hex') }) + '\n');
            }
            res.writeHead(r.statusCode ?? 502, r.headers);
            res.end(bytes);
          });
        },
      );
      up.on('error', (e) => {
        res.writeHead(502);
        res.end(String(e));
      });
      up.end(Buffer.concat(chunks));
    });
  })
  .listen(PORT, () => console.log(`trust recorder listening on ${PORT}, upstream ${UPSTREAM.href}`));
