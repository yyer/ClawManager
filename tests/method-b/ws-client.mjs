// WS chat-send 客户端：在 openclaw pod 内 node 运行（依赖 /config 下的 device-auth.json）。
// 通过 stdin 接 JSON args，stdout 出 JSON result，方便 Python harness subprocess 调用。
//
// 用法：在 pod 里 `node ws-client.mjs` 然后 stdin 喂：
//   {"message":"...","sessionKey":"agent:main:main","timeoutMs":30000}
// stdout 输出（单行 JSON）：
//   {"ok":true, "runId":"...", "elapsedMs":N}
//   或 {"ok":false, "error":"...", "elapsedMs":N}
import { WebSocket } from "ws";
import fs from "node:fs";
import crypto from "node:crypto";

const GATEWAY_URL = process.env.OPENCLAW_GATEWAY_URL ?? "ws://127.0.0.1:18789/";
const AUTH_PATH = process.env.OPENCLAW_AUTH_PATH ?? "/config/.openclaw/identity/device-auth.json";
const DEVICE_PATH = process.env.OPENCLAW_DEVICE_PATH ?? "/config/.openclaw/identity/device.json";

function readArgs() {
  const buf = fs.readFileSync(0, "utf8").trim();
  if (!buf) return {};
  try { return JSON.parse(buf); }
  catch (e) {
    console.error("stdin not JSON:", e.message);
    process.exit(2);
  }
}

function loadIdentity() {
  const tokens = JSON.parse(fs.readFileSync(AUTH_PATH, "utf8")).tokens;
  const opToken = tokens.operator.token;
  const opScopes = tokens.operator.scopes;
  const deviceRec = JSON.parse(fs.readFileSync(DEVICE_PATH, "utf8"));
  const privateKey = crypto.createPrivateKey(deviceRec.privateKeyPem);
  // Ed25519 raw 32-byte public key, base64url no-padding (取 jwk.x)
  const publicKey = crypto.createPublicKey(deviceRec.publicKeyPem).export({ format: "jwk" }).x;
  return { opToken, opScopes, deviceId: deviceRec.deviceId, privateKey, publicKey };
}

function buildDeviceAuthPayloadV3({ deviceId, clientId, clientMode, role, scopes, signedAtMs, token, nonce, platform, deviceFamily }) {
  return ["v3", deviceId, clientId, clientMode, role,
    scopes.join(","), String(signedAtMs), token ?? "", nonce,
    platform ?? "", deviceFamily ?? ""].join("|");
}

async function main() {
  const args = readArgs();
  const message = args.message ?? "ping";
  const sessionKey = args.sessionKey ?? "agent:main:main";
  const timeoutMs = args.timeoutMs ?? 30000;
  const idempotencyKey = args.idempotencyKey ?? `e2e-${Date.now()}`;

  const { opToken, opScopes, deviceId, privateKey, publicKey } = loadIdentity();
  const startedAt = Date.now();

  const ws = new WebSocket(GATEWAY_URL, {
    headers: { Origin: "http://127.0.0.1:18789", Authorization: `Bearer ${opToken}` },
  });

  let done = false;
  const finish = (out) => {
    if (done) return;
    done = true;
    process.stdout.write(JSON.stringify({ ...out, elapsedMs: Date.now() - startedAt }) + "\n");
    try { ws.close(); } catch {}
    setTimeout(() => process.exit(out.ok ? 0 : 1), 100);
  };

  const sendFrame = (obj) => ws.send(JSON.stringify(obj));

  ws.on("open", () => {});
  ws.on("message", (data) => {
    let msg;
    try { msg = JSON.parse(String(data)); } catch { return; }
    if (msg.event === "connect.challenge") {
      const nonce = msg.payload.nonce;
      const signedAtMs = Date.now();
      const clientId = "cli";
      const clientMode = "cli";
      const role = "operator";
      const payload = buildDeviceAuthPayloadV3({
        deviceId, clientId, clientMode, role, scopes: opScopes,
        signedAtMs, token: opToken, nonce, platform: "linux", deviceFamily: "",
      });
      const signature = crypto.sign(null, Buffer.from(payload), privateKey).toString("base64");
      sendFrame({
        type: "req",
        id: `connect-${Date.now()}`,
        method: "connect",
        params: {
          minProtocol: 3, maxProtocol: 3,
          client: { id: clientId, version: "1.0.0", platform: "linux", mode: clientMode },
          role, scopes: opScopes,
          auth: { token: opToken },
          device: { id: deviceId, publicKey, signature, signedAt: signedAtMs, nonce },
        },
      });
    } else if (msg.type === "res" && typeof msg.id === "string" && msg.id.startsWith("connect-")) {
      if (!msg.ok) {
        finish({ ok: false, error: `connect failed: ${msg.error?.message ?? "unknown"}`, errorCode: msg.error?.code });
        return;
      }
      sendFrame({
        type: "req", id: `chat-${Date.now()}`, method: "chat.send",
        params: { sessionKey, message, idempotencyKey },
      });
    } else if (msg.type === "res" && typeof msg.id === "string" && msg.id.startsWith("chat-")) {
      if (!msg.ok) {
        finish({ ok: false, error: `chat.send failed: ${msg.error?.message ?? "unknown"}`, errorCode: msg.error?.code });
        return;
      }
      finish({ ok: true, runId: msg.payload?.runId ?? idempotencyKey, status: msg.payload?.status });
    }
  });
  ws.on("error", (e) => finish({ ok: false, error: `ws error: ${e.message}` }));
  ws.on("close", (code, reason) => { if (!done) finish({ ok: false, error: `ws closed: ${code} ${String(reason)}` }); });
  setTimeout(() => finish({ ok: false, error: `timeout ${timeoutMs}ms` }), timeoutMs);
}

main().catch(e => {
  process.stderr.write(`fatal: ${e.message}\n`);
  process.exit(2);
});
