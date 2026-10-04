// webrtc_drive — all app code in one ES module. See docs/design.md.
// Pure functions are exported for tests; the DOM is touched only in the browser.

import {
  gcm,
  hkdf,
  ristretto255,
  ristretto255_hasher,
  sha256,
  sha512 as nobleSha512,
} from "./vendor/noble-crypto-2.4.0.js";
import qrcode from "./vendor/qrcode-generator-2.0.4.mjs";

// ---------------------------------------------------------------------------
// Constants (docs/design.md §3, §4, §7, §10)
// ---------------------------------------------------------------------------

export const PROTOCOL_VERSION = "1";

export const CODE_DIGITS = 9;
export const CHANNEL_DIGITS = 4;
export const SECRET_DIGITS = 5;

export const CODE_TTL_MS = 5 * 60_000;
export const JOIN_GET_TIMEOUT_MS = 10_000;
export const STEP_TIMEOUT_MS = 20_000;
export const ICE_GATHER_TIMEOUT_MS = 3_000;
export const CONNECT_TIMEOUT_MS = 15_000;
export const DISCONNECTED_GRACE_MS = 10_000;

export const MAX_BODY_BYTES = 8 * 1024;
export const RETRY_DELAYS_MS = [1_000, 2_000, 4_000, 5_000]; // the last value repeats
export const MAX_CONSECUTIVE_ERRORS = 3;
export const PIPE_PATH_PREFIX = `webrtc-drive-${PROTOCOL_VERSION}-`;

export const CHUNK_BYTES = 16 * 1024;
export const CHUNK_MAX_BYTES = 64 * 1024;
export const BUFFER_HIGH_BYTES = 4 * 1024 * 1024;
export const BUFFER_LOW_BYTES = 1024 * 1024;

export const STUN_URLS = ["stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"];

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

const textEncoder = new TextEncoder();

export const utf8 = (text) => textEncoder.encode(text);

export function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function base64urlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Returns null for anything that is not canonical unpadded base64url.
export function base64urlDecode(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    return null;
  }
  const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return base64urlEncode(bytes) === text ? bytes : null;
}

// ---------------------------------------------------------------------------
// Pairing codes (docs/design.md §3)
// ---------------------------------------------------------------------------

const CODE_SPACE = 10 ** CODE_DIGITS;
// Largest multiple of CODE_SPACE below 2^32, for rejection sampling.
const CODE_SAMPLE_LIMIT = Math.floor(2 ** 32 / CODE_SPACE) * CODE_SPACE;

// A uniformly random 9-digit code, as a string (leading zeros kept).
export function generateCode() {
  const word = new Uint32Array(1);
  do {
    crypto.getRandomValues(word);
  } while (word[0] >= CODE_SAMPLE_LIMIT);
  return String(word[0] % CODE_SPACE).padStart(CODE_DIGITS, "0");
}

// Accepts digits with optional spaces and dashes. Returns
// { code, channel, secret } or null.
export function parseCode(input) {
  if (typeof input !== "string") return null;
  const code = input.replace(/[\s-]/g, "");
  if (!new RegExp(`^\\d{${CODE_DIGITS}}$`).test(code)) return null;
  return { code, channel: code.slice(0, CHANNEL_DIGITS), secret: code.slice(CHANNEL_DIGITS) };
}

// "123456789" -> "123 456 789"
export const formatCode = (code) => code.replace(/(\d{3})(?=\d)/g, "$1 ");

export const joinUrl = (base, code) => `${base}#code=${code}`;

// Reads a "#code=..." URL fragment. Returns { status: "none" } when there is
// no code, { status: "invalid" } when it is malformed, else { status: "ok", code }.
export function codeFromHash(hash) {
  const match = /^#code=(.*)$/.exec(hash ?? "");
  if (!match) return { status: "none" };
  const parsed = parseCode(decodeURIComponentSafe(match[1]));
  return parsed ? { status: "ok", code: parsed.code } : { status: "invalid" };
}

function decodeURIComponentSafe(text) {
  try {
    return decodeURIComponent(text);
  } catch {
    return "";
  }
}

// ---------------------------------------------------------------------------
// CPace, CPACE-RISTR255-SHA512, initiator-responder (docs/design.md §5)
// Spec: draft-irtf-cfrg-cpace-21. Hashing and group operations use the
// vendored noble libraries, so this also works where crypto.subtle does not
// exist (plain http pages).
// ---------------------------------------------------------------------------

const CPACE_DSI = utf8("CPaceRistretto255");
const CPACE_DSI_ISK = utf8("CPaceRistretto255_ISK");
const SHA512_BLOCK_BYTES = 128; // H.s_in_bytes
const CPACE_GROUP_SIZE_BITS = 252;
export const CPACE_SHARE_BYTES = 32;
export const CPACE_SID_BYTES = 16;

export async function sha512(bytes) {
  return nobleSha512(bytes);
}

// prepend_len: LEB128 length, then the bytes.
export function prependLen(bytes) {
  const length = [];
  let n = bytes.length;
  do {
    length.push(n < 128 ? n : (n & 0x7f) | 0x80);
    n >>>= 7;
  } while (n > 0);
  return concatBytes(Uint8Array.from(length), bytes);
}

export const lvCat = (...parts) => concatBytes(...parts.map(prependLen));

export function generatorString(dsi, prs, ci, sid, sInBytes) {
  const zpad = Math.max(0, sInBytes - 1 - prependLen(prs).length - prependLen(dsi).length);
  return lvCat(dsi, prs, new Uint8Array(zpad), ci, sid);
}

export const transcriptIr = (ya, ada, yb, adb) => concatBytes(lvCat(ya, ada), lvCat(yb, adb));

export async function cpaceGenerator(prs, ci, sid) {
  const hash = await sha512(generatorString(CPACE_DSI, prs, ci, sid, SHA512_BLOCK_BYTES));
  return ristretto255_hasher.deriveToCurve(hash);
}

export function scalarFromLittleEndian(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

// Random 32 bytes with the bits above 252 cleared, read little-endian.
export function cpaceSampleScalar() {
  const bytes = new Uint8Array(32);
  let y = 0n;
  while (y === 0n) {
    crypto.getRandomValues(bytes);
    bytes[31] &= 0xff >> (256 - CPACE_GROUP_SIZE_BITS);
    y = scalarFromLittleEndian(bytes);
  }
  return y;
}

export const cpaceScalarMult = (y, g) => g.multiply(y).toBytes();

// Returns the encoding of y * decode(X), or null where the spec returns G.I
// (X does not decode, or the result is the neutral element). null means abort.
export function cpaceScalarMultVfy(y, encoded) {
  let point;
  try {
    point = ristretto255.Point.fromBytes(encoded);
  } catch {
    return null;
  }
  const result = point.multiply(y);
  return result.is0() ? null : result.toBytes();
}

export async function cpaceIsk(sid, k, ya, ada, yb, adb) {
  return sha512(concatBytes(lvCat(CPACE_DSI_ISK, sid, k), transcriptIr(ya, ada, yb, adb)));
}

const cpaceChannelId = (channel) => utf8(`webrtc-drive/${PROTOCOL_VERSION}/${channel}`);
const NO_AD = new Uint8Array(0);

// Step 1, both sides: make this side's scalar and public share.
export async function cpaceStart({ secret, channel, sid }) {
  const g = await cpaceGenerator(utf8(secret), cpaceChannelId(channel), sid);
  const y = cpaceSampleScalar();
  return { y, share: cpaceScalarMult(y, g) };
}

// Step 2, both sides: derive ISK from the peer's share. The creator (A) is the
// initiator, the joiner (B) the responder. Returns null if the protocol must abort.
export async function cpaceFinish({ y, sid, ownShare, peerShare, role }) {
  if (!(peerShare instanceof Uint8Array) || peerShare.length !== CPACE_SHARE_BYTES) return null;
  const k = cpaceScalarMultVfy(y, peerShare);
  if (!k) return null;
  const [ya, yb] = role === "initiator" ? [ownShare, peerShare] : [peerShare, ownShare];
  return cpaceIsk(sid, k, ya, NO_AD, yb, NO_AD);
}

// ---------------------------------------------------------------------------
// Session key and sealing (docs/design.md §5)
// ---------------------------------------------------------------------------

const NONCE_BYTES = 12;
const TAG_BYTES = 16;
export const SEAL_LABELS = Object.freeze({ offer: "offer", answer: "answer" });

// The AES-256-GCM key: HKDF-SHA256(ikm = ISK, salt = empty, info).
export async function deriveAeadKey(isk) {
  return hkdf(sha256, isk, new Uint8Array(0), utf8(`webrtc-drive/${PROTOCOL_VERSION}/aead`), 32);
}

const sealAad = (label, channel, sid) => utf8(`${label}|${channel}|${base64urlEncode(sid)}`);

// Returns base64url(nonce || ciphertext || tag).
export async function seal(key, label, channel, sid, plaintext) {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const ciphertext = gcm(key, nonce, sealAad(label, channel, sid)).encrypt(utf8(plaintext));
  return base64urlEncode(concatBytes(nonce, ciphertext));
}

// Returns the plaintext string, or null if anything does not match.
export async function open(key, label, channel, sid, sealed) {
  const bytes = base64urlDecode(sealed);
  if (!bytes || bytes.length < NONCE_BYTES + TAG_BYTES) return null;
  try {
    const nonce = bytes.subarray(0, NONCE_BYTES);
    const plaintext = gcm(key, nonce, sealAad(label, channel, sid)).decrypt(
      bytes.subarray(NONCE_BYTES),
    );
    return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  } catch {
    return null;
  }
}

// A random id for messages and transfers (crypto.randomUUID needs https).
export const randomId = () => base64urlEncode(crypto.getRandomValues(new Uint8Array(16)));

// ---------------------------------------------------------------------------
// Pipe message formats (docs/design.md §5)
// ---------------------------------------------------------------------------

export const byteLength = (text) => utf8(text).length;

// Pipe step "a" (creator -> joiner): "1.<sid>.<Ya>"
export const encodeStepA = (sid, share) =>
  `${PROTOCOL_VERSION}.${base64urlEncode(sid)}.${base64urlEncode(share)}`;

// Pipe step "b" (joiner -> creator): "1.<Yb>"
export const encodeStepB = (share) => `${PROTOCOL_VERSION}.${base64urlEncode(share)}`;

// Returns { version } errors distinctly so the UI can say "reload both pages".
function parseVersioned(text, fieldCount) {
  if (typeof text !== "string" || byteLength(text) > MAX_BODY_BYTES) return { error: "malformed" };
  const fields = text.split(".");
  if (fields[0] !== PROTOCOL_VERSION) {
    return /^\d+$/.test(fields[0]) ? { error: "version" } : { error: "malformed" };
  }
  if (fields.length !== fieldCount + 1) return { error: "malformed" };
  const decoded = fields.slice(1).map(base64urlDecode);
  return decoded.includes(null) ? { error: "malformed" } : { fields: decoded };
}

export function parseStepA(text) {
  const result = parseVersioned(text, 2);
  if (result.error) return result;
  const [sid, share] = result.fields;
  if (sid.length !== CPACE_SID_BYTES || share.length !== CPACE_SHARE_BYTES) {
    return { error: "malformed" };
  }
  return { sid, share };
}

export function parseStepB(text) {
  const result = parseVersioned(text, 1);
  if (result.error) return result;
  const [share] = result.fields;
  return share.length === CPACE_SHARE_BYTES ? { share } : { error: "malformed" };
}

// ---------------------------------------------------------------------------
// DataChannel control messages (docs/design.md §10)
// ---------------------------------------------------------------------------

const MAX_ID_LENGTH = 64;
const MAX_NAME_LENGTH = 1024;
const MAX_MIME_LENGTH = 256;
const MAX_REASON_LENGTH = 256;

const isId = (x) => typeof x === "string" && x.length > 0 && x.length <= MAX_ID_LENGTH;
const isShortString = (max) => (x) => typeof x === "string" && x.length <= max;
const isSize = (x) => Number.isSafeInteger(x) && x >= 0;

const CONTROL_FIELDS = {
  hello: { v: isShortString(16) },
  text: { id: isId, body: (x) => typeof x === "string" },
  "file-offer": {
    id: isId,
    name: isShortString(MAX_NAME_LENGTH),
    size: isSize,
    mime: isShortString(MAX_MIME_LENGTH),
  },
  "file-accept": { id: isId },
  "file-decline": { id: isId },
  "file-end": { id: isId },
  "file-cancel": { id: isId, reason: isShortString(MAX_REASON_LENGTH) },
};

export const encodeControl = (message) => JSON.stringify(message);

// Returns a message with only the known fields, or null if it is not valid.
export function parseControl(text) {
  let raw;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const fields = Object.hasOwn(CONTROL_FIELDS, raw.t) ? CONTROL_FIELDS[raw.t] : null;
  if (!fields) return null;
  const message = { t: raw.t };
  for (const [name, isValid] of Object.entries(fields)) {
    if (!isValid(raw[name])) return null;
    message[name] = raw[name];
  }
  return message;
}

// ---------------------------------------------------------------------------
// File transfer state machines (docs/design.md §10)
// Pure reducers, one per direction. Each step returns the next state, the
// control messages to send, and notices for the caller (start sending
// chunks, a transfer finished, the peer broke the protocol).
// ---------------------------------------------------------------------------

export const createOutgoing = () => ({ queue: [], current: null });

function offerNext(state, send) {
  if (state.current || state.queue.length === 0) return state;
  const [next, ...queue] = state.queue;
  send.push({ t: "file-offer", id: next.id, name: next.name, size: next.size, mime: next.mime });
  return { queue, current: { ...next, status: "offered" } };
}

export function outgoingStep(state, event) {
  const send = [];
  const notices = [];
  const finish = (outcome, reason) => {
    notices.push({ type: "done", id: state.current.id, outcome, reason });
    state = { ...state, current: null };
  };
  const current = state.current;

  switch (event.type) {
    case "enqueue":
      state = { ...state, queue: [...state.queue, event.file] };
      break;
    case "peer": {
      const { message } = event;
      if (!current || message.id !== current.id) {
        notices.push({ type: "protocol-error", message });
      } else if (message.t === "file-accept" && current.status === "offered") {
        state = { ...state, current: { ...current, status: "sending" } };
        notices.push({ type: "start-sending", id: current.id });
      } else if (message.t === "file-decline" && current.status === "offered") {
        finish("declined");
      } else if (message.t === "file-cancel") {
        finish("cancelled", message.reason);
      } else {
        notices.push({ type: "protocol-error", message });
      }
      break;
    }
    case "sent-all":
      if (current?.id === event.id && current.status === "sending") {
        send.push({ t: "file-end", id: current.id });
        finish("sent");
      }
      break;
    case "cancel":
      if (current?.id === event.id) {
        send.push({ t: "file-cancel", id: current.id, reason: "cancelled" });
        finish("cancelled", "cancelled");
      } else if (state.queue.some((f) => f.id === event.id)) {
        state = { ...state, queue: state.queue.filter((f) => f.id !== event.id) };
        notices.push({ type: "done", id: event.id, outcome: "cancelled", reason: "cancelled" });
      }
      break;
    case "reset":
      for (const file of [current, ...state.queue].filter(Boolean)) {
        notices.push({ type: "done", id: file.id, outcome: "cancelled", reason: "disconnected" });
      }
      return { state: createOutgoing(), send, notices };
  }
  return { state: offerNext(state, send), send, notices };
}

export const createIncoming = () => ({ current: null });

export function incomingStep(state, event) {
  const send = [];
  const notices = [];
  const current = state.current;
  const finish = (outcome, reason) => {
    notices.push({ type: "done", id: current.id, outcome, reason });
    state = { current: null };
  };

  switch (event.type) {
    case "peer": {
      const { message } = event;
      if (message.t === "file-offer") {
        if (current) {
          send.push({ t: "file-cancel", id: message.id, reason: "busy" });
        } else {
          const { id, name, size, mime } = message;
          state = { current: { id, name, size, mime, status: "offered", received: 0 } };
          notices.push({ type: "offered", file: { id, name, size, mime } });
        }
      } else if (!current || message.id !== current.id) {
        notices.push({ type: "protocol-error", message });
      } else if (message.t === "file-end" && current.status === "receiving") {
        if (current.received === current.size) finish("received");
        else finish("failed", "size-mismatch");
      } else if (message.t === "file-cancel") {
        finish("cancelled", message.reason);
      } else {
        notices.push({ type: "protocol-error", message });
      }
      break;
    }
    case "chunk":
      if (current?.status !== "receiving") {
        notices.push({ type: "protocol-error", chunk: event.bytes });
      } else if (current.received + event.bytes > current.size) {
        send.push({ t: "file-cancel", id: current.id, reason: "too-much-data" });
        finish("failed", "too-much-data");
      } else {
        state = { current: { ...current, received: current.received + event.bytes } };
      }
      break;
    case "accept":
      if (current?.id === event.id && current.status === "offered") {
        state = { current: { ...current, status: "receiving" } };
        send.push({ t: "file-accept", id: current.id });
      }
      break;
    case "decline":
      if (current?.id === event.id && current.status === "offered") {
        send.push({ t: "file-decline", id: current.id });
        finish("declined");
      }
      break;
    case "cancel":
      if (current?.id === event.id) {
        send.push({ t: "file-cancel", id: current.id, reason: "cancelled" });
        finish("cancelled", "cancelled");
      }
      break;
    case "reset":
      if (current) finish("cancelled", "disconnected");
      break;
  }
  return { state, send, notices };
}

// ---------------------------------------------------------------------------
// Pipe client (docs/design.md §7)
// Results: { status: "ok", body? } | { status: "timeout" } | { status: "aborted" }
//        | { status: "too-large" } | { status: "error", httpStatus?, quick }
// ---------------------------------------------------------------------------

// A failure this soon after starting a request means the pipe is not
// answering; a later one is a long-waiting connection that was dropped.
export const QUICK_FAILURE_MS = 3_000;

export const pipePathUrl = (pipeUrl, channel, step) =>
  `${pipeUrl.replace(/\/$/, "")}/${PIPE_PATH_PREFIX}${channel}-${step}`;

// Combines a caller's signal with a timeout. Avoids AbortSignal.any for
// older Safari versions.
function linkedSignal(signal, timeoutMs) {
  const controller = new AbortController();
  let timedOut = false;
  const onAbort = () => controller.abort();
  signal?.addEventListener("abort", onAbort, { once: true });
  if (signal?.aborted) controller.abort();
  const timer =
    timeoutMs === undefined
      ? null
      : setTimeout(() => {
          timedOut = true;
          controller.abort();
        }, timeoutMs);
  return {
    signal: controller.signal,
    timedOut: () => timedOut,
    done() {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    },
  };
}

// Reads a response body, giving up (and cancelling it) beyond maxBytes.
async function readCapped(response, maxBytes) {
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > maxBytes) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  return concatBytes(...chunks);
}

async function pipeRequest(run, { signal, timeoutMs, now = Date.now }) {
  const link = linkedSignal(signal, timeoutMs);
  const started = now();
  try {
    return await run(link.signal);
  } catch {
    if (link.timedOut()) return { status: "timeout" };
    if (signal?.aborted) return { status: "aborted" };
    return { status: "error", quick: now() - started < QUICK_FAILURE_MS };
  } finally {
    link.done();
  }
}

// Waits for one body on the path and returns it as text.
export function pipeReceive(url, { signal, timeoutMs, fetchImpl = fetch } = {}) {
  return pipeRequest(
    async (linked) => {
      const res = await fetchImpl(url, { signal: linked, cache: "no-store" });
      if (!res.ok) {
        await res.body?.cancel();
        return { status: "error", httpStatus: res.status, quick: true };
      }
      const bytes = await readCapped(res, MAX_BODY_BYTES);
      if (!bytes) return { status: "too-large" };
      try {
        return { status: "ok", body: new TextDecoder("utf-8", { fatal: true }).decode(bytes) };
      } catch {
        return { status: "error", quick: true };
      }
    },
    { signal, timeoutMs },
  );
}

// Sends one body and resolves once the receiver has it (the POST response
// body, a progress log, ends on delivery; see design.md §7).
export function pipeSend(url, body, { signal, timeoutMs, fetchImpl = fetch } = {}) {
  if (byteLength(body) > MAX_BODY_BYTES) return Promise.resolve({ status: "too-large" });
  return pipeRequest(
    async (linked) => {
      const res = await fetchImpl(url, {
        method: "POST",
        body,
        headers: { "Content-Type": "text/plain" },
        signal: linked,
        cache: "no-store",
      });
      const log = await res.text();
      if (!res.ok || log.includes("[ERROR]")) {
        return { status: "error", httpStatus: res.status, quick: true };
      }
      return { status: "ok" };
    },
    { signal, timeoutMs },
  );
}

// Repeats a pipe request until it succeeds or the deadline passes, waiting
// between attempts. attempt({ signal, timeoutMs }) returns a pipe result.
// Ends with the "ok" result, or { status: "expired" | "aborted" | "unreachable" },
// or a non-retryable error (a 4xx, e.g. someone else on the path).
export async function retryUntil(
  attempt,
  {
    deadline,
    signal,
    delaysMs = RETRY_DELAYS_MS,
    maxConsecutiveErrors = MAX_CONSECUTIVE_ERRORS,
    now = Date.now,
  },
) {
  let errors = 0;
  let retries = 0;
  for (;;) {
    if (signal?.aborted) return { status: "aborted" };
    const remaining = deadline - now();
    if (remaining <= 0) return { status: "expired" };
    const result = await attempt({ signal, timeoutMs: remaining });
    if (result.status === "ok" || result.status === "aborted") return result;
    if (result.status === "timeout") return { status: "expired" };
    if (result.httpStatus >= 400 && result.httpStatus < 500) return result;
    if (result.status === "error" && result.quick) {
      errors += 1;
      if (errors >= maxConsecutiveErrors) return { status: "unreachable" };
    } else {
      errors = 0;
    }
    const delay = delaysMs[Math.min(retries, delaysMs.length - 1)];
    retries += 1;
    await abortableSleep(Math.min(delay, Math.max(0, deadline - now())), signal);
  }
}

export function abortableSleep(ms, signal) {
  return new Promise((resolve) => {
    const timer = setTimeout(done, ms);
    signal?.addEventListener("abort", done, { once: true });
    function done() {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    }
  });
}

// ---------------------------------------------------------------------------
// Pairing (docs/design.md §4)
// runCreator / runJoiner resolve to one of:
//   { status: "connected", pc, dc }
//   { status: "expired" }            creator: nobody used the code in time
//   { status: "collision" }          someone else is on this channel's paths
//   { status: "unreachable" }        the pipe does not answer
//   { status: "aborted" }
//   { status: "failed", reason }     reason: "no-device" | "mismatch" | "version"
//                                    | "malformed" | "timeout" | "no-direct-path"
//                                    | "ip-mismatch"
// The peer connection is closed on every outcome except "connected".
// ---------------------------------------------------------------------------

export const DEFAULT_TIMEOUTS = Object.freeze({
  codeTtl: CODE_TTL_MS,
  joinGet: JOIN_GET_TIMEOUT_MS,
  step: STEP_TIMEOUT_MS,
  iceGather: ICE_GATHER_TIMEOUT_MS,
  connect: CONNECT_TIMEOUT_MS,
});

// Sent by a joiner on step "r" when the offer does not open, so the creator
// fails at once instead of waiting for a timeout. Unauthenticated on purpose:
// it can only end a pairing, which anyone on the channel could do anyway.
export const MISMATCH_SIGNAL = `${PROTOCOL_VERSION}.mismatch`;

export const defaultPeerConnection = () =>
  new RTCPeerConnection({ iceServers: [{ urls: STUN_URLS }] });

const defaultPipe = { send: pipeSend, receive: pipeReceive };

// Counts ICE candidates in an SDP by type and address family, for
// diagnosing failed connections without logging any address.
export function candidateSummary(sdp) {
  const summary = { host: 0, srflx: 0, prflx: 0, relay: 0, ipv4: 0, ipv6: 0, mdns: 0 };
  for (const line of sdp.split(/\r?\n/)) {
    const match = /^a=candidate:\S+ \d+ \S+ \d+ (\S+) \d+ typ (\S+)/.exec(line);
    if (!match) continue;
    const [, address, type] = match;
    if (type in summary) summary[type] += 1;
    if (address.endsWith(".local")) summary.mdns += 1;
    else if (address.includes(":")) summary.ipv6 += 1;
    else summary.ipv4 += 1;
  }
  return summary;
}

// The IP families ("ipv4", "ipv6") among an SDP's candidates. mDNS host
// candidates are left out: they only work within one local network.
export function ipFamilies(sdp) {
  const { ipv4, ipv6 } = candidateSummary(sdp);
  return new Set([...(ipv4 ? ["ipv4"] : []), ...(ipv6 ? ["ipv6"] : [])]);
}

export function ipFamiliesIncompatible(localSdp, remoteSdp) {
  const local = ipFamilies(localSdp);
  const remote = ipFamilies(remoteSdp);
  return local.size > 0 && remote.size > 0 && ![...local].some((f) => remote.has(f));
}

function logCandidates(side, sdp) {
  if (typeof document === "undefined") return; // quiet in Node tests
  console.info(`webrtc_drive: ${side} ICE candidates`, candidateSummary(sdp));
}

export function waitForIceGathering(pc, timeoutMs) {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === "complete") return resolve();
    const timer = setTimeout(finish, timeoutMs);
    pc.addEventListener("icegatheringstatechange", check);
    function check() {
      if (pc.iceGatheringState === "complete") finish();
    }
    function finish() {
      clearTimeout(timer);
      pc.removeEventListener("icegatheringstatechange", check);
      resolve();
    }
  });
}

// Resolves "open", "failed", "timeout", or "aborted". getChannel() returns the
// data channel once known (the joiner learns it from ondatachannel).
function waitForOpen(pc, getChannel, timeoutMs, signal) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => finish("timeout"), timeoutMs);
    const poll = setInterval(check, 50);
    pc.addEventListener("connectionstatechange", check);
    signal?.addEventListener("abort", onAbort, { once: true });
    check();
    function onAbort() {
      finish("aborted");
    }
    function check() {
      if (getChannel()?.readyState === "open") finish("open");
      else if (pc.connectionState === "failed") finish("failed");
    }
    function finish(result) {
      clearTimeout(timer);
      clearInterval(poll);
      pc.removeEventListener("connectionstatechange", check);
      signal?.removeEventListener("abort", onAbort);
      resolve(result);
    }
  });
}

// Maps a pipe result that is not "ok" to a pairing outcome.
function pipeFailure(result, timeoutReason) {
  if (result.status === "aborted") return { status: "aborted" };
  if (result.status === "unreachable") return { status: "unreachable" };
  if (result.status === "expired") return { status: "expired" };
  if (result.status === "timeout") return { status: "failed", reason: timeoutReason };
  if (result.status === "too-large") return { status: "failed", reason: "malformed" };
  if (result.httpStatus >= 400 && result.httpStatus < 500) return { status: "collision" };
  return { status: "unreachable" };
}

// On failure, tells apart the common case where one side is reachable only
// over IPv4 and the other only over IPv6 (e.g. an IPv6-only cellular network).
async function connectedOrFailed(pc, getChannel, timeouts, signal, sdps) {
  const opened = await waitForOpen(pc, getChannel, timeouts.connect, signal);
  if (opened === "open") return { status: "connected", pc, dc: getChannel() };
  if (opened === "aborted") return { status: "aborted" };
  const reason = ipFamiliesIncompatible(sdps.local, sdps.remote) ? "ip-mismatch" : "no-direct-path";
  return { status: "failed", reason };
}

function withCleanup(pc, outcome) {
  if (outcome.status !== "connected") pc?.close();
  return outcome;
}

export async function runCreator({
  code,
  pipeUrl,
  signal,
  pipe = defaultPipe,
  createPeerConnection = defaultPeerConnection,
  timeouts = DEFAULT_TIMEOUTS,
  onProgress = () => {},
}) {
  const { channel, secret } = parseCode(code);
  const url = (step) => pipePathUrl(pipeUrl, channel, step);
  const sid = crypto.getRandomValues(new Uint8Array(CPACE_SID_BYTES));
  const cpace = await cpaceStart({ secret, channel, sid });

  let pc = null;
  let dc = null;
  try {
    // Idle: offer our share on "a" and wait for a joiner's share on "b".
    onProgress("waiting");
    const deadline = Date.now() + timeouts.codeTtl;
    const idle = new AbortController();
    const stopIdle = () => idle.abort();
    signal?.addEventListener("abort", stopIdle, { once: true });
    const stepA = encodeStepA(sid, cpace.share);
    const sending = retryUntil((o) => pipe.send(url("a"), stepA, o), {
      deadline,
      signal: idle.signal,
    });
    const receiving = retryUntil((o) => pipe.receive(url("b"), o), {
      deadline,
      signal: idle.signal,
    });
    // "b" normally arrives after "a" was delivered; if "a" fails first
    // (collision, unreachable, expiry, abort), stop.
    const first = await Promise.race([
      sending.then((result) => ({ step: "a", result })),
      receiving.then((result) => ({ step: "b", result })),
    ]);
    const failure = first.step === "a" && first.result.status !== "ok" ? first.result : null;
    const received = failure ? null : first.step === "b" ? first.result : await receiving;
    stopIdle();
    signal?.removeEventListener("abort", stopIdle);
    await Promise.allSettled([sending, receiving]);
    if (failure) return pipeFailure(failure);
    if (received.status !== "ok") return pipeFailure(received);

    // The code is now used, whatever happens next.
    onProgress("exchanging");
    const stepB = parseStepB(received.body);
    if (stepB.error) return { status: "failed", reason: stepB.error };
    const isk = await cpaceFinish({
      y: cpace.y,
      sid,
      ownShare: cpace.share,
      peerShare: stepB.share,
      role: "initiator",
    });
    if (!isk) return { status: "failed", reason: "malformed" };
    const key = await deriveAeadKey(isk);

    // Gather candidates now, not when the code was first shown: the network
    // may have changed since (say Wi-Fi to cellular), making an early offer stale.
    pc = createPeerConnection();
    dc = pc.createDataChannel("main");
    await pc.setLocalDescription(await pc.createOffer());
    await waitForIceGathering(pc, timeouts.iceGather);
    const offerSdp = pc.localDescription.sdp;
    logCandidates("local", offerSdp);

    const options = { signal, timeoutMs: timeouts.step };
    const sentOffer = await pipe.send(
      url("o"),
      await seal(key, "offer", channel, sid, offerSdp),
      options,
    );
    if (sentOffer.status !== "ok") return withCleanup(pc, pipeFailure(sentOffer, "timeout"));
    const answer = await pipe.receive(url("r"), options);
    if (answer.status !== "ok") return withCleanup(pc, pipeFailure(answer, "timeout"));
    const answerSdp = await open(key, "answer", channel, sid, answer.body);
    if (answerSdp === null) return withCleanup(pc, { status: "failed", reason: "mismatch" });

    onProgress("connecting");
    logCandidates("remote", answerSdp);
    await pc.setRemoteDescription({ type: "answer", sdp: answerSdp });
    const sdps = { local: offerSdp, remote: answerSdp };
    return withCleanup(pc, await connectedOrFailed(pc, () => dc, timeouts, signal, sdps));
  } catch (error) {
    pc?.close();
    if (signal?.aborted) return { status: "aborted" };
    throw error;
  }
}

export async function runJoiner({
  code,
  pipeUrl,
  signal,
  pipe = defaultPipe,
  createPeerConnection = defaultPeerConnection,
  timeouts = DEFAULT_TIMEOUTS,
  onProgress = () => {},
}) {
  const { channel, secret } = parseCode(code);
  const url = (step) => pipePathUrl(pipeUrl, channel, step);
  let pc = null;
  try {
    onProgress("exchanging");
    const gotA = await retryUntil((o) => pipe.receive(url("a"), o), {
      deadline: Date.now() + timeouts.joinGet,
      signal,
    });
    if (gotA.status === "expired") return { status: "failed", reason: "no-device" };
    if (gotA.status !== "ok") return pipeFailure(gotA, "no-device");
    const stepA = parseStepA(gotA.body);
    if (stepA.error) return { status: "failed", reason: stepA.error };

    const { sid } = stepA;
    const cpace = await cpaceStart({ secret, channel, sid });
    const isk = await cpaceFinish({
      y: cpace.y,
      sid,
      ownShare: cpace.share,
      peerShare: stepA.share,
      role: "responder",
    });
    if (!isk) return { status: "failed", reason: "malformed" };
    const key = await deriveAeadKey(isk);

    const options = { signal, timeoutMs: timeouts.step };
    const sentB = await pipe.send(url("b"), encodeStepB(cpace.share), options);
    if (sentB.status !== "ok") return pipeFailure(sentB, "timeout");
    const offer = await pipe.receive(url("o"), options);
    if (offer.status !== "ok") return pipeFailure(offer, "timeout");
    const offerSdp = await open(key, "offer", channel, sid, offer.body);
    if (offerSdp === null) {
      await pipe.send(url("r"), MISMATCH_SIGNAL, { signal, timeoutMs: 3_000 });
      return { status: "failed", reason: "mismatch" };
    }

    onProgress("connecting");
    pc = createPeerConnection();
    let dc = null;
    pc.addEventListener("datachannel", (event) => {
      if (event.channel.label === "main") dc = event.channel;
    });
    logCandidates("remote", offerSdp);
    await pc.setRemoteDescription({ type: "offer", sdp: offerSdp });
    await pc.setLocalDescription(await pc.createAnswer());
    await waitForIceGathering(pc, timeouts.iceGather);
    logCandidates("local", pc.localDescription.sdp);
    const sealedAnswer = await seal(key, "answer", channel, sid, pc.localDescription.sdp);
    const sentAnswer = await pipe.send(url("r"), sealedAnswer, options);
    if (sentAnswer.status !== "ok") return withCleanup(pc, pipeFailure(sentAnswer, "timeout"));
    const sdps = { local: pc.localDescription.sdp, remote: offerSdp };
    return withCleanup(pc, await connectedOrFailed(pc, () => dc, timeouts, signal, sdps));
  } catch (error) {
    pc?.close();
    if (signal?.aborted) return { status: "aborted" };
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Session: text and files over the "main" channel (docs/design.md §10)
// Emits "update" events with detail { kind: "message" | "transfer", item }
// and a "version" event when the peer speaks another protocol version.
// ---------------------------------------------------------------------------

const PROGRESS_INTERVAL_MS = 100;
const ACTIVE_STATUSES = new Set(["queued", "offered", "sending", "receiving"]);

export const isActiveTransfer = (item) => ACTIVE_STATUSES.has(item.status);

export class Session extends EventTarget {
  constructor(pc, dc) {
    super();
    this.pc = pc;
    this.dc = dc;
    this.outgoing = createOutgoing();
    this.incoming = createIncoming();
    this.transfers = new Map(); // id -> item shown in the UI
    this.files = new Map(); // id -> File being sent
    this.parts = [];
    this.pumping = null; // { id, cancelled }
    this.closed = false;
    this.chunkBytes = pc.sctp?.maxMessageSize >= CHUNK_MAX_BYTES ? CHUNK_MAX_BYTES : CHUNK_BYTES;
    dc.binaryType = "arraybuffer";
    dc.bufferedAmountLowThreshold = BUFFER_LOW_BYTES;
    dc.addEventListener("message", (event) => this.onMessage(event.data));
    this.sendControl({ t: "hello", v: PROTOCOL_VERSION });
  }

  emit(kind, item) {
    this.dispatchEvent(Object.assign(new Event("update"), { detail: { kind, item } }));
  }

  sendControl(message) {
    if (this.dc.readyState === "open") this.dc.send(encodeControl(message));
  }

  sendText(body) {
    const item = { id: randomId(), body, mine: true };
    this.sendControl({ t: "text", id: item.id, body });
    this.emit("message", item);
  }

  sendFiles(files) {
    for (const file of files) {
      const id = randomId();
      this.files.set(id, file);
      const meta = { id, name: file.name, size: file.size, mime: file.type };
      this.updateTransfer(id, { ...meta, direction: "out", status: "queued", bytes: 0 });
      this.applyOutgoing({ type: "enqueue", file: meta });
    }
  }

  accept(id) {
    this.applyIncoming({ type: "accept", id });
  }

  decline(id) {
    this.applyIncoming({ type: "decline", id });
  }

  cancel(id) {
    const item = this.transfers.get(id);
    if (item?.direction === "out") this.applyOutgoing({ type: "cancel", id });
    else if (item) this.applyIncoming({ type: "cancel", id });
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.applyOutgoing({ type: "reset" });
    this.applyIncoming({ type: "reset" });
    this.dc.close();
    this.pc.close();
  }

  updateTransfer(id, changes) {
    const item = { ...this.transfers.get(id), ...changes };
    this.transfers.set(id, item);
    this.emit("transfer", item);
    return item;
  }

  onMessage(data) {
    if (typeof data !== "string") {
      if (this.incoming.current?.status === "receiving") this.parts.push(data);
      this.applyIncoming({ type: "chunk", bytes: data.byteLength });
      return;
    }
    const message = parseControl(data);
    if (!message) return;
    switch (message.t) {
      case "hello":
        if (message.v !== PROTOCOL_VERSION) this.dispatchEvent(new Event("version"));
        break;
      case "text":
        this.emit("message", { id: message.id, body: message.body, mine: false });
        break;
      case "file-accept":
      case "file-decline":
        this.applyOutgoing({ type: "peer", message });
        break;
      case "file-offer":
      case "file-end":
        this.applyIncoming({ type: "peer", message });
        break;
      case "file-cancel":
        if (this.outgoing.current?.id === message.id) {
          this.applyOutgoing({ type: "peer", message });
        } else {
          this.applyIncoming({ type: "peer", message });
        }
        break;
    }
  }

  applyOutgoing(event) {
    const { state, send, notices } = outgoingStep(this.outgoing, event);
    this.outgoing = state;
    for (const message of send) this.sendControl(message);
    for (const notice of notices) {
      if (notice.type === "start-sending") {
        this.updateTransfer(notice.id, { status: "sending" });
        this.pump(notice.id);
      } else if (notice.type === "done") {
        if (this.pumping?.id === notice.id) this.pumping.cancelled = true;
        this.files.delete(notice.id);
        this.updateTransfer(notice.id, { status: notice.outcome, reason: notice.reason });
      }
    }
    const current = this.outgoing.current;
    if (current?.status === "offered" && this.transfers.get(current.id)?.status === "queued") {
      this.updateTransfer(current.id, { status: "offered" });
    }
  }

  applyIncoming(event) {
    const { state, send, notices } = incomingStep(this.incoming, event);
    this.incoming = state;
    for (const message of send) this.sendControl(message);
    for (const notice of notices) {
      if (notice.type === "offered") {
        this.parts = [];
        this.updateTransfer(notice.file.id, {
          ...notice.file,
          direction: "in",
          status: "offered",
          bytes: 0,
        });
      } else if (notice.type === "done") {
        const item = this.transfers.get(notice.id);
        const blob =
          notice.outcome === "received"
            ? new Blob(this.parts, { type: item.mime || "application/octet-stream" })
            : undefined;
        this.parts = [];
        this.updateTransfer(notice.id, {
          status: notice.outcome,
          reason: notice.reason,
          bytes: blob ? blob.size : item.bytes,
          blob,
        });
      }
    }
    const current = this.incoming.current;
    if (current) {
      const item = this.transfers.get(current.id);
      const status = current.status === "receiving" ? "receiving" : "offered";
      const progressDue = Date.now() - (item.shownAt ?? 0) >= PROGRESS_INTERVAL_MS;
      if (item.status !== status || (item.bytes !== current.received && progressDue)) {
        this.updateTransfer(current.id, { status, bytes: current.received, shownAt: Date.now() });
      }
    }
  }

  async pump(id) {
    const file = this.files.get(id);
    const token = { id, cancelled: false };
    this.pumping = token;
    let shownAt = 0;
    for (let offset = 0; offset < file.size; offset += this.chunkBytes) {
      if (this.dc.bufferedAmount > BUFFER_HIGH_BYTES) await this.drained();
      if (token.cancelled || this.dc.readyState !== "open") return;
      const chunk = await file.slice(offset, offset + this.chunkBytes).arrayBuffer();
      if (token.cancelled || this.dc.readyState !== "open") return;
      this.dc.send(chunk);
      if (Date.now() - shownAt >= PROGRESS_INTERVAL_MS) {
        shownAt = Date.now();
        this.updateTransfer(id, { bytes: offset + chunk.byteLength });
      }
    }
    if (token.cancelled) return;
    this.updateTransfer(id, { bytes: file.size });
    this.applyOutgoing({ type: "sent-all", id });
  }

  drained() {
    return new Promise((resolve) => {
      const done = () => {
        this.dc.removeEventListener("bufferedamountlow", done);
        this.dc.removeEventListener("close", done);
        resolve();
      };
      this.dc.addEventListener("bufferedamountlow", done);
      this.dc.addEventListener("close", done);
    });
  }
}

// ---------------------------------------------------------------------------
// QR scanning helpers (docs/design.md §8)
// ---------------------------------------------------------------------------

// Returns the code from a scanned QR text if it is a link to this page
// (same origin and path) with a valid #code=, else null.
export function codeFromScannedText(text, pageBase) {
  let url;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  if (url.origin + url.pathname !== pageBase) return null;
  const found = codeFromHash(url.hash);
  return found.status === "ok" ? found.code : null;
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

const MESSAGES = {
  "no-device": "No device is showing this code. Check the code and try again.",
  mismatch: "Code did not match. Try again.",
  "creator-mismatch": "Pairing failed. Try again with a new code.",
  version: "The other device runs a different version. Reload both pages.",
  malformed: "Pairing failed. Try again with a new code.",
  timeout: "Pairing failed. Try again with a new code.",
  "no-direct-path":
    "Could not connect directly. These two networks do not allow a direct connection.",
  "ip-mismatch":
    "Could not connect directly: one device is online only over IPv4 and the other only over IPv6, and the two cannot reach each other.",
  unreachable: "Pairing service is unreachable.",
  "invalid-link": "This link is invalid. Scan the QR code on the other device again.",
  "own-code": "That is this device's code. Enter the code shown on the other device.",
  "bad-code": "Enter the 9-digit code shown on the other device.",
  "not-ours": "This is not a webrtc_drive code.",
  camera: "Could not open the camera. Type the code instead.",
  disconnected: "Disconnected.",
  unexpected: "Something went wrong. Try again.",
  unsupported: "This browser cannot run webrtc_drive. Try a current Chrome, Safari, or Firefox.",
  "no-scanner":
    "In-page QR scanning needs https. Type the code, or scan with the phone's camera app.",
};

// Tiny DOM builder: h("p", { className: "x", dataset: { a: "1" } }, "text", child)
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "dataset") Object.assign(el.dataset, value);
    else if (key.startsWith("aria-")) el.setAttribute(key, value);
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else el[key] = value;
  }
  el.append(...children.filter((c) => c !== null && c !== undefined && c !== false));
  return el;
}

export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

function qrDataUrl(text) {
  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();
  return qr.createDataURL(6, 4);
}

// The camera is available only in secure contexts (https or localhost).
const canScan = () => globalThis.isSecureContext && !!navigator.mediaDevices?.getUserMedia;

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const script = h("script", { src, onload: resolve, onerror: reject });
    document.head.append(script);
  });
}

async function startScanner(video, { onText }) {
  const stream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: { ideal: "environment" } },
    audio: false,
  });
  video.srcObject = stream;
  await video.play();
  let detect;
  const formats = await globalThis.BarcodeDetector?.getSupportedFormats?.().catch(() => []);
  if (formats?.includes("qr_code")) {
    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    detect = async () => (await detector.detect(video))[0]?.rawValue;
  } else {
    if (!globalThis.jsQR) await loadScript("vendor/jsQR-1.4.0.js");
    const canvas = h("canvas");
    const context = canvas.getContext("2d", { willReadFrequently: true });
    detect = async () => {
      if (!video.videoWidth) return undefined;
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      context.drawImage(video, 0, 0);
      const image = context.getImageData(0, 0, canvas.width, canvas.height);
      return globalThis.jsQR(image.data, image.width, image.height)?.data;
    };
  }
  let stopped = false;
  (async function loop() {
    while (!stopped) {
      const text = await detect().catch(() => undefined);
      if (stopped) break;
      if (text) onText(text);
      await new Promise((r) => setTimeout(r, 200));
    }
  })();
  return () => {
    stopped = true;
    for (const track of stream.getTracks()) track.stop();
    video.srcObject = null;
  };
}

class App {
  constructor(root, { pipeUrl, pageBase }) {
    this.root = root;
    this.pipeUrl = pipeUrl;
    this.pageBase = pageBase;
    this.myCode = null;
    this.idleAbort = null;
    this.pairAbort = null;
    this.timer = null;
    this.stopScanner = null;
    this.session = null;
  }

  setState(state) {
    document.body.dataset.state = state;
  }

  show(view) {
    clearInterval(this.timer);
    this.stopScanner?.();
    this.stopScanner = null;
    this.root.replaceChildren(view);
  }

  // Idle: show my code and listen for a joiner as the creator.
  startIdle(message) {
    this.idleAbort?.abort();
    const controller = new AbortController();
    this.idleAbort = controller;
    const code = generateCode();
    this.myCode = code;
    const expiresAt = Date.now() + CODE_TTL_MS;
    this.renderIdle(code, expiresAt, message);
    runCreator({
      code,
      pipeUrl: this.pipeUrl,
      signal: controller.signal,
      onProgress: (step) => {
        if (step === "exchanging" && this.idleAbort === controller) {
          this.renderPairing("Connecting…", controller);
        }
      },
    }).then(
      (result) => this.idleAbort === controller && this.onCreatorResult(result),
      (error) => this.idleAbort === controller && this.fail(error),
    );
  }

  onCreatorResult(result) {
    switch (result.status) {
      case "connected":
        return this.enterConnected(result);
      case "expired":
      case "collision":
        return this.startIdle();
      case "unreachable":
        return this.renderUnreachable();
      case "aborted":
        return undefined;
      default:
        return this.startIdle(
          MESSAGES[result.reason === "mismatch" ? "creator-mismatch" : result.reason] ??
            MESSAGES.timeout,
        );
    }
  }

  join(code) {
    if (code === this.myCode && this.idleAbort) {
      this.notice(MESSAGES["own-code"]);
      return;
    }
    this.idleAbort?.abort();
    this.idleAbort = null;
    this.myCode = null;
    this.pairAbort?.abort();
    const controller = new AbortController();
    this.pairAbort = controller;
    this.renderPairing("Connecting…", controller);
    runJoiner({ code, pipeUrl: this.pipeUrl, signal: controller.signal }).then(
      (result) => {
        if (this.pairAbort !== controller) return;
        this.pairAbort = null;
        if (result.status === "connected") this.enterConnected(result);
        else if (result.status === "unreachable") this.renderUnreachable();
        else if (result.status === "aborted") this.startIdle();
        else if (result.status === "collision") this.startIdle(MESSAGES["no-device"]);
        else this.startIdle(MESSAGES[result.reason] ?? MESSAGES.timeout);
      },
      (error) => this.fail(error),
    );
  }

  // An unexpected error: stop everything and wait for the user, so a bug
  // can never turn into a tight retry loop.
  fail(error) {
    console.error(error);
    this.idleAbort?.abort();
    this.idleAbort = null;
    this.pairAbort?.abort();
    this.pairAbort = null;
    this.setState("error");
    this.show(
      h(
        "section",
        { className: "card", dataset: { view: "error" } },
        h("p", { className: "notice", role: "alert" }, MESSAGES.unexpected),
        h("button", { onclick: () => this.startIdle() }, "Retry"),
      ),
    );
  }

  notice(text) {
    const el = this.root.querySelector(".notice");
    if (el) el.textContent = text;
  }

  renderIdle(code, expiresAt, message) {
    this.setState("idle");
    const url = joinUrl(this.pageBase, code);
    const expires = h("p", { className: "expires" });
    const input = h("input", {
      id: "code-input",
      inputMode: "numeric",
      autocomplete: "off",
      placeholder: "123 456 789",
      "aria-label": "Code shown on the other device",
    });
    const form = h(
      "form",
      {
        className: "join",
        onsubmit: (event) => {
          event.preventDefault();
          const parsed = parseCode(input.value);
          if (parsed) this.join(parsed.code);
          else this.notice(MESSAGES["bad-code"]);
        },
      },
      input,
      h("button", { type: "submit" }, "Connect"),
    );
    this.show(
      h(
        "section",
        { className: "card", dataset: { view: "idle" } },
        h("h2", {}, "This device's code"),
        h("p", { className: "code", dataset: { code } }, formatCode(code)),
        h("img", {
          className: "qr",
          src: qrDataUrl(url),
          alt: `QR code for ${formatCode(code)}`,
          dataset: { joinUrl: url },
        }),
        expires,
        h("h2", {}, "Connect to another device"),
        form,
        canScan()
          ? h(
              "button",
              { className: "secondary", onclick: () => this.renderScanner() },
              "Scan a QR code",
            )
          : h("p", { className: "hint" }, MESSAGES["no-scanner"]),
        h("p", { className: "notice", role: "status" }, message ?? ""),
      ),
    );
    const tick = () => {
      const left = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
      expires.textContent = `Expires in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
    };
    tick();
    this.timer = setInterval(tick, 1000);
  }

  renderScanner() {
    const video = h("video", { className: "scanner", muted: true, playsInline: true });
    video.setAttribute("playsinline", "");
    const status = h(
      "p",
      { className: "notice", role: "status" },
      "Point the camera at the QR code on the other device.",
    );
    this.show(
      h(
        "section",
        { className: "card", dataset: { view: "scan" } },
        h("h2", {}, "Scan a QR code"),
        video,
        status,
        h("button", { className: "secondary", onclick: () => this.startIdle() }, "Back"),
      ),
    );
    this.setState("scanning");
    // The idle code keeps listening while the camera is open.
    startScanner(video, {
      onText: (text) => {
        const code = codeFromScannedText(text, this.pageBase);
        if (code) this.join(code);
        else status.textContent = MESSAGES["not-ours"];
      },
    }).then(
      (stop) => {
        if (this.root.contains(video)) this.stopScanner = stop;
        else stop();
      },
      () => {
        status.textContent = MESSAGES.camera;
      },
    );
  }

  renderPairing(text, controller) {
    this.setState("pairing");
    this.show(
      h(
        "section",
        { className: "card", dataset: { view: "pairing" } },
        h("p", { className: "progress", role: "status" }, text),
        h(
          "button",
          {
            className: "secondary",
            onclick: () => {
              controller.abort();
              if (this.pairAbort === controller) this.pairAbort = null;
              this.startIdle();
            },
          },
          "Cancel",
        ),
      ),
    );
  }

  renderUnreachable() {
    this.idleAbort?.abort();
    this.idleAbort = null;
    this.setState("unreachable");
    this.show(
      h(
        "section",
        { className: "card", dataset: { view: "unreachable" } },
        h("p", { className: "notice", role: "status" }, MESSAGES.unreachable),
        h("button", { onclick: () => this.startIdle() }, "Retry"),
      ),
    );
  }

  enterConnected({ pc, dc }) {
    this.idleAbort = null;
    this.myCode = null;
    const session = new Session(pc, dc);
    this.session = session;
    const blobUrls = [];
    const end = (message = MESSAGES.disconnected) => {
      if (this.session !== session) return;
      this.session = null;
      session.close();
      for (const url of blobUrls) URL.revokeObjectURL(url);
      this.startIdle(message);
    };
    dc.addEventListener("close", () => end());
    pc.addEventListener("connectionstatechange", () => {
      if (["failed", "closed"].includes(pc.connectionState)) end();
    });
    session.addEventListener("version", () => end(MESSAGES.version));

    const messages = h("ul", { className: "messages", "aria-live": "polite" });
    const transfers = h("ul", { className: "transfers" });
    const textInput = h("textarea", {
      id: "message-input",
      rows: 2,
      placeholder: "Message",
      "aria-label": "Message",
    });
    const sendText = () => {
      if (textInput.value.trim() === "") return;
      session.sendText(textInput.value);
      textInput.value = "";
    };
    textInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
        event.preventDefault();
        sendText();
      }
    });
    const fileInput = h("input", {
      id: "file-input",
      type: "file",
      multiple: true,
      onchange: () => {
        session.sendFiles([...fileInput.files]);
        fileInput.value = "";
      },
    });
    const view = h(
      "section",
      { className: "card", dataset: { view: "connected" } },
      h("p", { className: "progress", role: "status" }, "Connected"),
      messages,
      h(
        "form",
        {
          className: "compose",
          onsubmit: (event) => {
            event.preventDefault();
            sendText();
          },
        },
        textInput,
        h("button", { type: "submit" }, "Send"),
      ),
      h(
        "label",
        { className: "file-pick" },
        fileInput,
        h("span", {}, "Send files"),
        h("span", { className: "hint" }, " or drop them here"),
      ),
      transfers,
      h("button", { className: "secondary", onclick: () => end() }, "Disconnect"),
    );
    view.addEventListener("dragover", (event) => {
      event.preventDefault();
      view.classList.add("dropping");
    });
    view.addEventListener("dragleave", () => view.classList.remove("dropping"));
    view.addEventListener("drop", (event) => {
      event.preventDefault();
      view.classList.remove("dropping");
      session.sendFiles([...event.dataTransfer.files]);
    });

    const items = new Map();
    session.addEventListener("update", ({ detail: { kind, item } }) => {
      if (kind === "message") {
        messages.append(this.renderMessage(item));
        messages.lastElementChild.scrollIntoView({ block: "nearest" });
        return;
      }
      const li = this.renderTransfer(item, session, blobUrls);
      const old = items.get(item.id);
      if (old) old.replaceWith(li);
      else transfers.append(li);
      items.set(item.id, li);
    });

    this.setState("connected");
    this.show(view);
  }

  renderMessage(item) {
    return h(
      "li",
      { className: `message ${item.mine ? "mine" : "theirs"}`, dataset: { id: item.id } },
      h("p", { className: "body" }, item.body),
      h(
        "button",
        {
          className: "copy",
          type: "button",
          onclick: (event) => {
            navigator.clipboard?.writeText(item.body).then(
              () => (event.target.textContent = "Copied"),
              () => (event.target.textContent = "Copy failed"),
            );
          },
        },
        "Copy",
      ),
    );
  }

  renderTransfer(item, session, blobUrls) {
    const statusText = {
      queued: "Waiting to send",
      offered: item.direction === "out" ? "Waiting for the other device" : "Wants to send you this",
      sending: "Sending",
      receiving: "Receiving",
      sent: "Sent",
      received: "Received",
      declined: "Declined",
      cancelled: "Cancelled",
      failed: "Failed",
    }[item.status];
    const button = (label, className, onclick) =>
      h("button", { type: "button", className, onclick }, label);
    const li = h(
      "li",
      {
        className: "transfer",
        dataset: { id: item.id, direction: item.direction, status: item.status },
      },
      h("p", { className: "name" }, item.name || "(no name)"),
      h("p", { className: "meta" }, `${formatBytes(item.size)} · ${statusText}`),
    );
    if (item.status === "sending" || item.status === "receiving") {
      li.append(h("progress", { max: item.size || 1, value: item.bytes }));
    }
    const actions = h("div", { className: "actions" });
    if (item.direction === "in" && item.status === "offered") {
      actions.append(
        button("Accept", "accept", () => session.accept(item.id)),
        button("Decline", "decline secondary-inline", () => session.decline(item.id)),
      );
    } else if (isActiveTransfer(item)) {
      actions.append(button("Cancel", "cancel secondary-inline", () => session.cancel(item.id)));
    }
    if (item.status === "received" && item.blob) {
      item.url ??= URL.createObjectURL(item.blob);
      if (!blobUrls.includes(item.url)) blobUrls.push(item.url);
      if (item.mime.startsWith("image/")) {
        li.append(h("img", { className: "thumb", src: item.url, alt: item.name }));
      }
      actions.append(
        h(
          "a",
          { className: "download", href: item.url, download: item.name || "file" },
          "Download",
        ),
      );
    }
    if (actions.childElementCount) li.append(actions);
    return li;
  }

  // Handles a #code= fragment: remove it at once, then join or report.
  takeHashCode() {
    const found = codeFromHash(location.hash);
    if (found.status === "none") return false;
    history.replaceState(null, "", location.pathname + location.search);
    if (found.status === "ok") this.join(found.code);
    else this.startIdle(MESSAGES["invalid-link"]);
    return true;
  }
}

function main() {
  const root = document.getElementById("app");
  if (!globalThis.crypto?.getRandomValues || !globalThis.RTCPeerConnection) {
    document.body.dataset.state = "unsupported";
    root.replaceChildren(
      h(
        "section",
        { className: "card" },
        h("p", { className: "notice", role: "alert" }, MESSAGES.unsupported),
      ),
    );
    return;
  }
  // The pipe URL may be relative (the dev server relays the pipe at /pipe).
  const pipeMeta = document.querySelector('meta[name="pipe-url"]').content;
  const pipeUrl = new URL(pipeMeta, location.href).href.replace(/\/$/, "");
  const app = new App(root, { pipeUrl, pageBase: location.origin + location.pathname });
  if (!app.takeHashCode()) app.startIdle();
  window.addEventListener("hashchange", () => app.takeHashCode());
}

if (typeof document !== "undefined") {
  main();
}
