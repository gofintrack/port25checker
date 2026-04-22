const http = require('http');
const https = require('https');
const net = require('net');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 8787);
const ENGINE_TOKEN = process.env.ENGINE_TOKEN || 'change-this-long-random-token';
const TARGET_HOST = process.env.TARGET_HOST || 'gmail-smtp-in.l.google.com';
const TARGET_PORT = Number(process.env.TARGET_PORT || 25);
const jobs = new Map();

function json(res, status, payload) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Engine-Token'
  });
  res.end(JSON.stringify(payload));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function postJson(urlString, payload, token) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const data = JSON.stringify(payload);
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: `${url.pathname}${url.search}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        'X-Engine-Token': token
      }
    }, res => {
      let raw = '';
      res.on('data', chunk => { raw += chunk; });
      res.on('end', () => resolve({ statusCode: res.statusCode, body: raw }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function connectSocket(host, port, timeout) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, host);
    let settled = false;

    const fail = (err) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(err);
    };

    socket.setTimeout(timeout, () => fail(new Error('timeout')));
    socket.on('error', fail);
    socket.on('connect', () => {
      if (settled) return;
      settled = true;
      resolve(socket);
    });
  });
}

function waitForData(socket, expectedLength, timeout) {
  return new Promise((resolve, reject) => {
    let chunks = Buffer.alloc(0);
    const timer = setTimeout(() => done(new Error('timeout')), timeout);

    function done(err, data) {
      clearTimeout(timer);
      socket.off('data', onData);
      socket.off('error', onErr);
      if (err) reject(err);
      else resolve(data);
    }

    function onErr(err) {
      done(err);
    }

    function onData(chunk) {
      chunks = Buffer.concat([chunks, chunk]);
      if (chunks.length >= expectedLength) {
        done(null, chunks);
      }
    }

    socket.on('data', onData);
    socket.on('error', onErr);
  });
}

function isIPv4(host) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
}

function buildSocks5Address(host, port) {
  if (isIPv4(host)) {
    const parts = host.split('.').map(Number);
    return Buffer.from([0x01, ...parts, (port >> 8) & 0xff, port & 0xff]);
  }

  const hostBuffer = Buffer.from(host, 'utf8');
  return Buffer.concat([
    Buffer.from([0x03, hostBuffer.length]),
    hostBuffer,
    Buffer.from([(port >> 8) & 0xff, port & 0xff])
  ]);
}

function parseSocks5ReplyLength(reply) {
  const atyp = reply[3];
  if (atyp === 0x01) return 10;
  if (atyp === 0x04) return 22;
  if (atyp === 0x03 && reply.length >= 5) return 7 + reply[4];
  return 10;
}

function readUntil(socket, matcher, timeout) {
  return new Promise((resolve, reject) => {
    let chunks = Buffer.alloc(0);
    const timer = setTimeout(() => done(new Error('timeout')), timeout);

    function done(err, data) {
      clearTimeout(timer);
      socket.off('data', onData);
      socket.off('error', onErr);
      if (err) reject(err);
      else resolve(data);
    }

    function onErr(err) {
      done(err);
    }

    function onData(chunk) {
      chunks = Buffer.concat([chunks, chunk]);
      if (matcher(chunks)) {
        done(null, chunks);
      }
    }

    socket.on('data', onData);
    socket.on('error', onErr);
  });
}

async function connectSocks5(proxy, timeout, targetHost, targetPort) {
  const socket = await connectSocket(proxy.host, proxy.port, timeout);
  try {
    const methods = proxy.username ? [0x00, 0x02] : [0x00];
    socket.write(Buffer.from([0x05, methods.length, ...methods]));
    let reply = await waitForData(socket, 2, timeout);
    if (reply[0] !== 0x05 || reply[1] === 0xff) {
      throw new Error('socks5 auth method rejected');
    }

    if (reply[1] === 0x02) {
      const user = Buffer.from(proxy.username || '');
      const pass = Buffer.from(proxy.password || '');
      socket.write(Buffer.concat([
        Buffer.from([0x01, user.length]),
        user,
        Buffer.from([pass.length]),
        pass
      ]));
      reply = await waitForData(socket, 2, timeout);
      if (reply[1] !== 0x00) {
        throw new Error('username/password rejected');
      }
    }

    socket.write(Buffer.concat([
      Buffer.from([0x05, 0x01, 0x00]),
      buildSocks5Address(targetHost, targetPort)
    ]));
    reply = await waitForData(socket, 5, timeout);
    const expectedLength = parseSocks5ReplyLength(reply);
    if (reply.length < expectedLength) {
      reply = Buffer.concat([reply, await waitForData(socket, expectedLength - reply.length, timeout)]);
    }
    if (reply[1] !== 0x00) {
      throw new Error(`connect failed (${reply[1]})`);
    }
    return socket;
  } finally {
    if (socket.destroyed) {
      socket.destroy();
    }
  }
}

async function connectSocks4(proxy, timeout, targetHost, targetPort) {
  const socket = await connectSocket(proxy.host, proxy.port, timeout);
  try {
    const user = Buffer.from(proxy.username || '');
    let req;
    if (isIPv4(targetHost)) {
      const hostParts = targetHost.split('.').map(Number);
      req = Buffer.concat([
        Buffer.from([0x04, 0x01, (targetPort >> 8) & 0xff, targetPort & 0xff, ...hostParts]),
        user,
        Buffer.from([0x00])
      ]);
    } else {
      req = Buffer.concat([
        Buffer.from([0x04, 0x01, (targetPort >> 8) & 0xff, targetPort & 0xff, 0x00, 0x00, 0x00, 0x01]),
        user,
        Buffer.from([0x00]),
        Buffer.from(targetHost, 'utf8'),
        Buffer.from([0x00])
      ]);
    }

    socket.write(req);
    const reply = await waitForData(socket, 8, timeout);
    if (reply[1] !== 0x5a) {
      throw new Error(`connect failed (${reply[1]})`);
    }
    return socket;
  } finally {
    if (socket.destroyed) {
      socket.destroy();
    }
  }
}

async function verifySmtpBanner(socket, timeout) {
  const banner = await readUntil(socket, data => data.includes(0x0a), timeout);
  const text = banner.toString('utf8').trim().replace(/\s+/g, ' ');
  if (!text.startsWith('220')) {
    throw new Error(`smtp banner invalid: ${text || 'empty response'}`);
  }
  return text;
}

async function checkProxy(proxy, timeout, targetHost, targetPort) {
  const started = Date.now();
  let socket;
  try {
    if (proxy.type === 'socks4') {
      socket = await connectSocks4(proxy, timeout, targetHost, targetPort);
    } else {
      socket = await connectSocks5(proxy, timeout, targetHost, targetPort);
    }

    const banner = await verifySmtpBanner(socket, timeout);
    return {
      proxy: proxy.raw,
      type: proxy.type,
      status: 'live',
      latency_ms: Date.now() - started,
      note: `SMTP 220 from ${targetHost}:${targetPort} | ${banner}`
    };
  } catch (err) {
    return {
      proxy: proxy.raw,
      type: proxy.type,
      status: err.message === 'timeout' ? 'unstable' : 'dead',
      latency_ms: null,
      note: err.message
    };
  } finally {
    if (socket && !socket.destroyed) {
      socket.destroy();
    }
  }
}

async function runJob(job) {
  const total = job.proxies.length;
  let done = 0;
  let live = 0;
  let dead = 0;
  let unstable = 0;
  let index = 0;

  function sendUpdate(payload) {
    const current = jobs.get(job.job_id) || job;
    if (payload.status) current.status = payload.status;
    if (payload.summary) current.summary = { ...current.summary, ...payload.summary };
    if (payload.result) current.results.push(payload.result);
    if (payload.log) current.logs.push(payload.log);
    if (current.logs.length > 150) current.logs = current.logs.slice(-150);
    current.updated_at = new Date().toISOString();
    jobs.set(job.job_id, current);
  }

  sendUpdate({
    status: 'running',
    log: { time: new Date().toISOString().slice(11, 19), level: 'info', message: 'Engine started processing proxies.' }
  });

  async function worker() {
    while (true) {
      const current = index++;
      if (current >= total) return;
      const proxy = job.proxies[current];
      const result = await checkProxy(proxy, job.timeout, job.target_host, job.target_port);
      done += 1;
      if (result.status === 'live') live += 1;
      else if (result.status === 'dead') dead += 1;
      else unstable += 1;

      sendUpdate({
        result,
        summary: {
          total,
          done,
          live,
          dead,
          unstable,
          progress_pct: Math.round((done / total) * 100)
        },
        log: {
          time: new Date().toISOString().slice(11, 19),
          level: result.status === 'live' ? 'info' : 'warn',
          message: `${proxy.raw} => ${result.status.toUpperCase()} (${result.note})`
        }
      });
    }
  }

  await Promise.all(Array.from({ length: Math.max(1, job.threads) }, worker));
  sendUpdate({
    status: 'completed',
    summary: {
      total,
      done,
      live,
      dead,
      unstable,
      progress_pct: 100
    },
    log: { time: new Date().toISOString().slice(11, 19), level: 'info', message: 'Engine completed the job.' }
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'POST' && req.url === '/start') {
    if (req.headers['x-engine-token'] !== ENGINE_TOKEN) {
      return json(res, 401, { ok: false, error: 'Unauthorized' });
    }

    try {
      const body = await readBody(req);
      json(res, 200, { ok: true, accepted: true });
      setImmediate(() => {
        runJob(body).catch(async err => {
          try {
            await postJson(body.callback_url, {
              job_id: body.job_id,
              status: 'failed',
              log: { time: new Date().toISOString().slice(11, 19), level: 'error', message: `Engine failed: ${err.message}` }
            }, body.callback_token);
          } catch (_) {
          }
        });
      });
    } catch (err) {
      json(res, 400, { ok: false, error: err.message });
    }
    return;
  }

  if (req.method === 'OPTIONS') {
    return json(res, 200, { ok: true });
  }

  if (req.method === 'POST' && req.url === '/jobs/start') {
    try {
      const body = await readBody(req);
      const proxyType = body.proxy_type === 'socks4' ? 'socks4' : 'socks5';
      const rawInput = String(body.proxy_input || '').trim();
      const threads = Math.max(1, Math.min(200, Number(body.threads || 20)));
      const timeout = Math.max(1000, Math.min(30000, Number(body.timeout || 8000)));
      const targetHost = String(body.target_host || TARGET_HOST).trim() || TARGET_HOST;
      const targetPort = Math.max(1, Math.min(65535, Number(body.target_port || TARGET_PORT)));

      if (!rawInput) {
        return json(res, 400, { ok: false, error: 'Proxy input is required.' });
      }

      const proxies = rawInput
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean)
        .map((line, idx) => {
          const parts = line.split(':');
          return {
            id: idx + 1,
            raw: line,
            host: parts[0],
            port: Number(parts[1]),
            username: parts[2] || null,
            password: parts[3] || null,
            type: proxyType
          };
        })
        .filter(item => item.host && item.port);

      if (!proxies.length) {
        return json(res, 400, { ok: false, error: 'No valid proxies found.' });
      }

      const jobId = `job_${Math.random().toString(16).slice(2, 12)}`;
      const job = {
        job_id: jobId,
        status: 'queued',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        proxy_type: proxyType,
        timeout,
        threads,
        target_host: targetHost,
        target_port: targetPort,
        proxies,
        results: [],
        logs: [{
          time: new Date().toISOString().slice(11, 19),
          level: 'info',
          message: `Job accepted by engine. Target SMTP ${targetHost}:${targetPort}`
        }],
        summary: {
          total: proxies.length,
          done: 0,
          live: 0,
          dead: 0,
          unstable: 0,
          progress_pct: 0
        }
      };

      jobs.set(jobId, job);
      json(res, 200, { ok: true, job_id: jobId });
      setImmediate(() => {
        runJob(job).catch(err => {
          const current = jobs.get(jobId);
          if (!current) return;
          current.status = 'failed';
          current.logs.push({ time: new Date().toISOString().slice(11, 19), level: 'error', message: `Engine failed: ${err.message}` });
          current.updated_at = new Date().toISOString();
          jobs.set(jobId, current);
        });
      });
    } catch (err) {
      return json(res, 400, { ok: false, error: err.message });
    }
    return;
  }

  if (req.method === 'GET' && req.url.startsWith('/jobs/status')) {
    const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
    const jobId = url.searchParams.get('id');
    if (!jobId || !jobs.has(jobId)) {
      return json(res, 404, { ok: false, error: 'Job not found.' });
    }
    return json(res, 200, { ok: true, job: jobs.get(jobId) });
  }

  if (req.method === 'GET' && req.url === '/health') {
    return json(res, 200, {
      ok: true,
      service: 'proxy-engine-node',
      smtp_target: `${TARGET_HOST}:${TARGET_PORT}`
    });
  }

  json(res, 404, { ok: false, error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`Proxy engine listening on http://0.0.0.0:${PORT}`);
});
