// app.js — KACLS POC (Cloud Run × Cloud KMS)
// 스펙 포인트: /wrap 응답 {wrapped_key}, /unwrap 응답 {key}
// 운영 전: JWT 검증(사용자/Authorization), 정책/감사 추가 필수

const express = require("express");
const bodyParser = require("body-parser");
const { KeyManagementServiceClient } = require("@google-cloud/kms");

const app = express();
const kms = new KeyManagementServiceClient();

// 환경 변수 체크
const KMS_KEY_RESOURCE = process.env.KMS_KEY_RESOURCE;
if (!KMS_KEY_RESOURCE) {
  console.error("FATAL: KMS_KEY_RESOURCE 미설정. 예) projects/<PRJ>/locations/<LOC>/keyRings/<KR>/cryptoKeys/<CK>");
  process.exit(1);
}

// CORS 및 헤더 설정 (Google CSE 요구사항 준수)
app.use((req, res, next) => {
  const origin = req.headers.origin || "https://client-side-encryption.google.com";
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,HEAD");
  
  const reqACRH = req.headers["access-control-request-headers"];
  res.setHeader(
    "Access-Control-Allow-Headers",
    reqACRH || "Content-Type, Authorization, X-Requested-With, X-Goog-AuthAssertion, X-Goog-Api-Client, X-Client-Data"
  );
  
  res.setHeader("Access-Control-Max-Age", "86400");
  
  // Pre-flight 요청 처리
  if (req.method === "OPTIONS" || req.method === "HEAD") return res.status(204).end();
  next();
});

// Payload 크기 제한 설정
app.use(bodyParser.json({ limit: "2mb" }));

// --- 유틸리티 함수 시작 ---
function b64urlToBuf(b64) {
  if (typeof b64 !== "string") return null;
  b64 = b64.trim().replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  try { return Buffer.from(b64, "base64"); } catch { return null; }
}

function looksLikeB64(s) {
  return typeof s === "string" && s.length >= 8 && /^[A-Za-z0-9+/_-]+=*$/.test(s);
}

// 요청 본문에서 재귀적으로 Base64 문자열(키 데이터) 탐색
function pickBase64(body, preferredKeys = [], enableRecursive = true) {
  if (!body || typeof body !== "object") return null;
  
  // 1. 선호하는 키 이름 먼저 검색
  for (const k of preferredKeys) {
    const v = body[k];
    if (looksLikeB64(v)) return { key: k, b64: v, path: k };
    if (k in body && typeof body[k] === "object") {
      const inner = pickBase64(body[k], preferredKeys, enableRecursive);
      if (inner) { inner.path = `${k}.${inner.path}`; return inner; }
    }
  }
  
  if (!enableRecursive) return null;

  // 2. 전체 탐색
  if (Array.isArray(body)) {
    for (let i = 0; i < body.length; i++) {
      const found = pickBase64(body[i], preferredKeys, enableRecursive);
      if (found) { found.path = `[${i}].${found.path}`; return found; }
    }
  } else {
    for (const [k, v] of Object.entries(body)) {
      if (looksLikeB64(v)) return { key: k, b64: v, path: k };
      if (v && typeof v === "object") {
        const found = pickBase64(v, preferredKeys, enableRecursive);
        if (found) { found.path = `${k}.${found.path}`; return found; }
      }
    }
  }
  return null;
}
// --- 유틸리티 함수 끝 ---

// 기본 상태 확인 엔드포인트
app.get("/", (_, res) => res.json({ ok: true, tip: "use /status, /wrap, /unwrap" }));
app.get("/status", (_, res) => res.json({
  server_type: "KACLS",
  vendor_id: "POC",
  version: "2.3.0",
  operations_supported: ["wrap", "unwrap"],
  key_resource: KMS_KEY_RESOURCE
}));
app.get("/.well-known/kacls", (_, res) => res.json({ ok: true, path: "/.well-known/kacls" }));

// WRAP (암호화)
app.post("/wrap", async (req, res) => {
  try {
    const hasReason = typeof req.body?.reason === "string";
    const got = pickBase64(req.body, [
      "key", // 스펙 정식 키
      "key_to_wrap_b64", "keyToWrapB64", "keyToWrap",
      "dek", "plaintext_b64", "plaintext", "data"
    ], true);

    if (!got) {
      // 에러 리포팅 요청인 경우 성공 처리 (POC 편의성)
      if (hasReason) return res.json({ ok: true, note: "noop (error envelope)", reason: req.body.reason });
      const keys = Object.keys(req.body || {});
      return res.status(400).json({ error: "missing DEK (base64)", received_keys: keys });
    }

    const plaintext = b64urlToBuf(got.b64);
    if (!plaintext) return res.status(400).json({ error: "invalid base64/plaintext" });

    // Cloud KMS 호출
    const [resp] = await kms.encrypt({ name: KMS_KEY_RESOURCE, plaintext });
    const ct_b64 = Buffer.from(resp.ciphertext).toString("base64");
    
    // ★ 스펙 준수: wrapped_key
    return res.json({ wrapped_key: ct_b64 }); 
  } catch (e) {
    console.error("Wrap Error:", e);
    return res.status(500).json({ error: "wrap_failed", detail: String(e?.message || e) });
  }
});

// UNWRAP (복호화)
app.post("/unwrap", async (req, res) => {
  try {
    const got = pickBase64(req.body, [
      "wrapped_key", // 스펙 정식 키
      "wrapped_key_b64", "wrappedKeyB64", "wrappedDek",
      "ciphertext_b64", "ciphertext", "data"
    ], true);

    if (!got) {
      const keys = Object.keys(req.body || {});
      return res.status(400).json({ error: "missing wrapped_key/ciphertext (base64)", received_keys: keys });
    }

    const ciphertext = b64urlToBuf(got.b64);
    if (!ciphertext) return res.status(400).json({ error: "invalid base64/ciphertext" });

    // Cloud KMS 호출
    const [resp] = await kms.decrypt({ name: KMS_KEY_RESOURCE, ciphertext });
    const pt_b64 = Buffer.from(resp.plaintext).toString("base64");
    
    // ★ 스펙 준수: key
    return res.json({ key: pt_b64 }); 
  } catch (e) {
    console.error("Unwrap Error:", e);
    return res.status(500).json({ error: "unwrap_failed", detail: String(e?.message || e) });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`KACLS POC listening on ${PORT}`));
