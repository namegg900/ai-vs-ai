const axios = require('axios');
const crypto = require('crypto');
const openpgp = require('openpgp');
const express = require('express');
const path = require('path');

const BASE_URL = 'https://lumo.proton.me/api';
const APP_VERSION = 'web-lumo@1.3.3.4';
const USER_AGENT =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36';
const LUMO_PUBLIC_KEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEaA9k7RYJKwYBBAHaRw8BAQdABaPA24xROahXs66iuekwPmdOpJbPE1a8A69r
siWP8rfNL1Byb3RvbiBMdW1vIChQcm9kIEtleSAwMDAyKSA8c3VwcG9ydEBwcm90
b24ubWU+wpkEExYKAEEWIQTwMqEWnd/47aco5ZqadMPvYVFKKgUCaA9k7QIbAwUJ
B4TOAAULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRCadMPvYVFKKqiVAQD7
JNeudEXTaNMoQMkYjcutNwNAalwbLr5qe6N5rPogDQD/bA5KBWmDlvxVz7If6SBS
7Xzcvk8VMHYkBLKfh+bfUQzOOARoD2TtEgorBgEEAZdVAQUBAQdAnBIJoFt6Pxnp
RAJMHwhdCXaE+lwQFbKgwb6LCUFWvHYDAQgHwn4EGBYKACYWIQTwMqEWnd/47aco
5ZqadMPvYVFKKgUCaA9k7QIbDAUJB4TOAAAKCRCadMPvYVFKKkuRAQChUthLyAcc
UD6UrJkroc6exHIMSR5Vlk4d4L8OeFUWWAEA3ugyE/b/pSQ4WO+fiTkHN2ZeKlyj
dZMbxO6yWPA5uQk=
=h/mc
-----END PGP PUBLIC KEY BLOCK-----`;

class LumoCrypto {
  encryptMessage(message, aesKey, iv, requestId, context = 'turn') {
    const aeadData = Buffer.from(`lumo.request.${requestId}.${context}`, 'utf-8');
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    cipher.setAAD(aeadData);
    const encrypted = Buffer.concat([cipher.update(message, 'utf-8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, encrypted, tag]);
  }

  decryptResponse(encryptedBase64, aesKey, requestId) {
    const data = Buffer.from(encryptedBase64, 'base64');
    const iv = data.subarray(0, 12);
    const tag = data.subarray(-16);
    const ciphertext = data.subarray(12, -16);
    const aeadData = Buffer.from(`lumo.response.${requestId}.chunk`, 'utf-8');
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAAD(aeadData);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf-8');
  }

  async encryptAESKeyWithPGP(aesKey) {
    const publicKey = await openpgp.readKey({ armoredKey: LUMO_PUBLIC_KEY });
    const message = await openpgp.createMessage({ binary: aesKey });
    const encrypted = await openpgp.encrypt({
      message,
      encryptionKeys: publicKey,
      format: 'binary',
      config: { preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed }
    });
    return Buffer.from(encrypted).toString('base64');
  }
}

class LumoClient {
  constructor() {
    this.uid = null;
    this.accessToken = null;
    this.refreshToken = null;
    this.cookieJar = '';
    this.sessionExpiry = null;

    this.axios = axios.create({
      baseURL: BASE_URL,
      timeout: 60000,
      headers: {
        'User-Agent': USER_AGENT,
        'x-pm-appversion': APP_VERSION,
        Accept: 'application/vnd.protonmail.v1+json',
        Origin: 'https://lumo.proton.me',
        Referer: 'https://lumo.proton.me/guest'
      },
      httpAgent: new (require('http').Agent)({ keepAlive: true }),
      httpsAgent: new (require('https').Agent)({ keepAlive: true }),
      withCredentials: true
    });

    this._setupInterceptors();
  }

  _setupInterceptors() {
    this.axios.interceptors.request.use(config => {
      if (this.uid) config.headers['x-pm-uid'] = this.uid;
      if (this.accessToken) config.headers.Authorization = `Bearer ${this.accessToken}`;
      if (this.cookieJar) config.headers.Cookie = this.cookieJar;
      return config;
    });

    this.axios.interceptors.response.use(
      res => {
        const setCookie = res.headers['set-cookie'];
        if (setCookie) this.cookieJar = setCookie.map(c => c.split(';')[0]).join('; ');
        return res;
      },
      async err => {
        const originalRequest = err.config;

        if (err.response?.status === 401 && !originalRequest._retried) {
          originalRequest._retried = true;
          await this.refreshSession().catch(async () => {
            await this.initGuestSession();
          });
          originalRequest.headers['x-pm-uid'] = this.uid;
          originalRequest.headers.Authorization = `Bearer ${this.accessToken}`;
          originalRequest.headers.Cookie = this.cookieJar;
          return this.axios(originalRequest);
        }

        return Promise.reject(err);
      }
    );
  }

  async initGuestSession() {
    const { data, headers } = await this.axios.post('/auth/v4/sessions', null, {
      headers: { 'x-enforce-unauthsession': 'true' }
    });

    this.uid = data.UID;
    this.accessToken = data.AccessToken;
    this.refreshToken = data.RefreshToken;
    this.sessionExpiry = Date.now() + (data.ExpiresIn * 1000 || 3600000);

    const setCookie = headers['set-cookie'];
    if (setCookie) this.cookieJar = setCookie.map(c => c.split(';')[0]).join('; ');

    await this.refreshCookies();
  }

  async refreshSession() {
    if (this.refreshToken) {
      try {
        const { data } = await this.axios.post('/auth/v4/refresh', {
          RefreshToken: this.refreshToken,
          ResponseType: 'token',
          GrantType: 'refresh_token',
          RedirectURI: 'https://protonmail.com'
        });

        this.accessToken = data.AccessToken;
        this.refreshToken = data.RefreshToken;
        this.sessionExpiry = Date.now() + data.ExpiresIn * 1000;
        return;
      } catch (_e) {
        // noop
      }
    }

    await this.initGuestSession();
  }

  async refreshCookies() {
    const state = crypto.randomBytes(24).toString('base64url');
    const { data, headers } = await this.axios.post('/core/v4/auth/cookies', {
      UID: this.uid,
      ResponseType: 'token',
      GrantType: 'refresh_token',
      RefreshToken: this.refreshToken,
      RedirectURI: 'https://protonmail.com',
      Persistent: 0,
      State: state
    });

    if (data.Code !== 1000) throw new Error(`Cookie refresh failed: ${data.Code}`);

    const setCookie = headers['set-cookie'];
    if (setCookie) this.cookieJar = setCookie.map(c => c.split(';')[0]).join('; ');
  }

  async ensureValidSession() {
    if (this.sessionExpiry && Date.now() > this.sessionExpiry - 300000) {
      await this.refreshSession();
    }
  }

  async sendMessage(prompt, onToken = null) {
    await this.ensureValidSession();

    const cryptoUtil = new LumoCrypto();
    const requestId = crypto.randomUUID();
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const encryptedMessage = cryptoUtil.encryptMessage(prompt, aesKey, iv, requestId, 'turn');
    const encryptedKey = await cryptoUtil.encryptAESKeyWithPGP(aesKey);

    const payload = {
      Prompt: {
        type: 'generation_request',
        turns: [
          {
            role: 'user',
            content: encryptedMessage.toString('base64'),
            images: [],
            encrypted: true
          }
        ],
        options: { tools: ['proton_info', 'web_search'] },
        targets: ['message', 'title'],
        request_key: encryptedKey,
        request_id: requestId
      }
    };

    const response = await this.axios.post('/ai/v1/chat', payload, {
      headers: { 'Content-Type': 'application/json' },
      responseType: 'stream',
      timeout: 120000
    });

    return this._parseStream(response.data, aesKey, requestId, cryptoUtil, onToken);
  }

  _parseStream(stream, aesKey, requestId, cryptoUtil, onToken) {
    return new Promise((resolve, reject) => {
      let buffer = '';
      let gotData = false;
      const result = { message: '' };
      const timeout = setTimeout(() => !gotData && reject(new Error('Response timeout')), 30000);

      stream.on('data', chunk => {
        gotData = true;
        clearTimeout(timeout);
        buffer += chunk.toString();
        const lines = buffer.split('\n');
        buffer = lines.pop();

        for (const line of lines) {
          if (!line.startsWith('data:')) continue;
          try {
            const data = JSON.parse(line.slice(5).trim());
            if (data.type === 'token_data' && data.encrypted) {
              const decrypted = cryptoUtil.decryptResponse(data.content, aesKey, requestId);
              if (data.target === 'message') {
                result.message += decrypted;
                onToken?.(decrypted);
              }
            }
            if (data.type === 'error') reject(new Error(data.error || 'Stream error'));
          } catch (_e) {
            // ignore malformed chunk
          }
        }
      });

      stream.on('end', () => {
        clearTimeout(timeout);
        resolve(result);
      });

      stream.on('error', err => {
        clearTimeout(timeout);
        reject(err);
      });
    });
  }
}

const app = express();
const PORT = process.env.PORT || 3000;
const lumoClient = new LumoClient();
const debates = new Map();

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/favicon.ico', (_req, res) => res.status(204).end());

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.post('/api/debate/stop', (req, res) => {
  const { debateId } = req.body || {};
  if (!debateId || !debates.has(debateId)) {
    res.json({ ok: true });
    return;
  }
  const debate = debates.get(debateId);
  debate.active = false;
  debates.delete(debateId);
  res.json({ ok: true });
});

app.get('/api/debate/stream', async (req, res) => {
  const topic = `${req.query.topic || ''}`.trim();
  const proName = `${req.query.proName || 'Mie Goreng'}`.trim().slice(0, 30);
  const conName = `${req.query.conName || 'Mie Kuah'}`.trim().slice(0, 30);

  if (!topic) {
    res.status(400).json({ error: 'Topik wajib diisi.' });
    return;
  }

  const debateId = crypto.randomUUID();
  debates.set(debateId, { active: true });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const send = payload => res.write(`data: ${JSON.stringify(payload)}\n\n`);

  req.on('close', () => {
    const debate = debates.get(debateId);
    if (debate) debate.active = false;
    debates.delete(debateId);
  });

  send({ debateId, status: 'started' });

  const personas = [
    {
      key: 'pro',
      name: proName,
      style:
        'Kamu agresif, lucu, pede tinggi. Jawaban maksimal 2 kalimat, langsung ke poin, bahasa gaul Indonesia.'
    },
    {
      key: 'con',
      name: conName,
      style:
        'Kamu tenang, logis, tajam. Jawaban maksimal 2 kalimat, langsung bantah inti argumen lawan, bahasa Indonesia santai.'
    }
  ];

  let lastTurn = `Debat dimulai. Topik: ${topic}`;
  let round = 1;

  while (debates.get(debateId)?.active) {
    const speaker = personas[(round - 1) % 2];
    const prompt = [
      `Topik debat: ${topic}`,
      `Persona kamu: ${speaker.name}. ${speaker.style}`,
      `Argumen lawan terakhir: ${lastTurn}`,
      'Tugas: sampaikan 1 argumen kuat atau sanggahan singkat yang human, bukan bahasa AI kaku.',
      'Batasan keras: max 28 kata, tanpa pembuka panjang, tanpa bullet, langsung isi.'
    ].join('\n');

    try {
      const { message } = await lumoClient.sendMessage(prompt);
      const cleaned = `${message || ''}`.replace(/\s+/g, ' ').trim().slice(0, 220);
      lastTurn = cleaned || 'Poin lawan tidak jelas.';
      send({
        type: 'turn',
        round,
        speaker: speaker.key,
        speakerName: speaker.name,
        text: lastTurn
      });
    } catch (error) {
      send({ type: 'error', message: error.message || 'Gagal lanjut debat.' });
      break;
    }

    round += 1;
    await new Promise(r => setTimeout(r, 700));
  }

  send({ type: 'done' });
  res.end();
});

async function boot() {
  try {
    await lumoClient.initGuestSession();
    app.listen(PORT, () => {
      console.log(`AI vs AI hidup di http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('Gagal init sesi Lumo:', error.message);
    process.exit(1);
  }
}

boot();
