// End-to-end webauthn verification against a running example app:
// registers a passkey, then completes two concurrent login ceremonies
// (which a single-slot ceremony cookie would fail).
//
// Zero deps - node >= 22 (built-in WebSocket) + headless Chrome with a CDP
// virtual authenticator. Usage:
//
//   node dev/e2e/webauthn.mjs                  # against http://localhost:3000
//   BASE=http://localhost:4000 node dev/e2e/webauthn.mjs
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE = process.env.BASE ?? "http://localhost:3000";
const CHROME = process.env.CHROME ?? "/usr/bin/google-chrome";
const port = 9223;

const chrome = spawn(CHROME, [
  "--headless=new",
  `--remote-debugging-port=${port}`,
  "--no-first-run",
  "--no-default-browser-check",
  `--user-data-dir=${mkdtempSync(join(tmpdir(), "authery-e2e-"))}`,
  "about:blank",
]);
chrome.stderr.on("data", () => {});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getWsUrl() {
  for (let i = 0; i < 50; i++) {
    try {
      const res = await fetch(`http://localhost:${port}/json`);
      const pages = await res.json();
      const page = pages.find((p) => p.type === "page");
      if (page) return page.webSocketDebuggerUrl;
    } catch {}
    await sleep(200);
  }
  throw new Error("chrome did not come up");
}

const ws = new WebSocket(await getWsUrl());
await new Promise((r) => (ws.onopen = r));

let msgId = 0;
const pending = new Map();
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
  }
};
const cdp = (method, params = {}) =>
  new Promise((resolve, reject) => {
    const id = ++msgId;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });

async function evalAsync(expression) {
  const { result, exceptionDetails } = await cdp("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (exceptionDetails) throw new Error(JSON.stringify(exceptionDetails, null, 2));
  return result.value;
}

// Virtual authenticator: resident-key capable, auto-completes ceremonies.
await cdp("WebAuthn.enable");
await cdp("WebAuthn.addVirtualAuthenticator", {
  options: {
    protocol: "ctap2",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
});

await cdp("Page.enable");
await cdp("Page.navigate", { url: `${BASE}/login` });
await sleep(1500);

const script = `(async () => {
  const log = [];
  const fromB64url = (s) => {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)).buffer;
  };
  const toB64url = (b) =>
    btoa(String.fromCharCode.apply(null, new Uint8Array(b)))
      .replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");

  // 1. Sign up (password) so there is a user to attach a passkey to.
  const email = "wa-" + Math.random().toString(36).slice(2) + "@x.com";
  await fetch("/signup/password", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "password_id=" + encodeURIComponent(email) + "&password=hunter2",
  });

  // 2. Register a passkey.
  let res = await fetch("/user/webauthn/register/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ display_name: email }),
  });
  const ccr = await res.json();
  log.push(["reg start", res.status]);
  const pk = ccr.publicKey;
  pk.challenge = fromB64url(pk.challenge);
  pk.user.id = fromB64url(pk.user.id);
  if (pk.excludeCredentials) pk.excludeCredentials = pk.excludeCredentials.map((c) => ({ ...c, id: fromB64url(c.id) }));
  const cred = await navigator.credentials.create({ publicKey: pk });
  res = await fetch("/user/webauthn/register/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id: cred.id,
      rawId: toB64url(cred.rawId),
      type: cred.type,
      extensions: cred.getClientExtensionResults(),
      response: {
        attestationObject: toB64url(cred.response.attestationObject),
        clientDataJSON: toB64url(cred.response.clientDataJSON),
      },
    }),
  });
  log.push(["reg finish", res.status]);

  // 3. Log out, then start TWO login ceremonies (two tabs).
  await fetch("/logout", { method: "POST" });
  const start = async () => (await fetch("/login/webauthn/start", { method: "POST" })).json();
  const rcr1 = await start();
  const rcr2 = await start();
  log.push(["distinct challenges", rcr1.publicKey.challenge !== rcr2.publicKey.challenge]);

  // 4. Complete the FIRST ceremony - with a single cookie slot this fails.
  const finish = async (rcr) => {
    const pk = rcr.publicKey;
    pk.challenge = fromB64url(pk.challenge);
    if (pk.allowCredentials) pk.allowCredentials = pk.allowCredentials.map((c) => ({ ...c, id: fromB64url(c.id) }));
    const cred = await navigator.credentials.get({ publicKey: pk });
    const res = await fetch("/login/webauthn/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: cred.id,
        rawId: toB64url(cred.rawId),
        type: cred.type,
        extensions: cred.getClientExtensionResults(),
        response: {
          authenticatorData: toB64url(cred.response.authenticatorData),
          clientDataJSON: toB64url(cred.response.clientDataJSON),
          signature: toB64url(cred.response.signature),
          userHandle: cred.response.userHandle ? toB64url(cred.response.userHandle) : null,
        },
      }),
    });
    return res.status;
  };
  log.push(["finish ceremony 1 (older)", await finish(rcr1)]);
  await fetch("/logout", { method: "POST" });
  log.push(["finish ceremony 2 (newer)", await finish(rcr2)]);
  return log;
})()`;

let out = "";
try {
  const result = await evalAsync(script);
  out = result.map((row) => row.join(": ")).join("\n");
} catch (e) {
  out = "ERROR: " + e.message;
}
chrome.kill();
process.stdout.write(out + "\n", () => process.exit(0));
