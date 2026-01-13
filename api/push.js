import { GoogleAuth } from "google-auth-library";
import admin from "firebase-admin";

// --- Firebase Admin init (Firestore access to fetch tokens by userId/role)
function initAdmin() {
  if (admin.apps.length) return;
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n");

  if (!projectId || !clientEmail || !privateKey) {
    throw new Error("Missing Firebase service account env vars");
  }

  admin.initializeApp({
    credential: admin.credential.cert({
      projectId,
      clientEmail,
      privateKey,
    }),
  });
}

async function getAccessToken() {
  const auth = new GoogleAuth({
    credentials: {
      client_email: process.env.FIREBASE_CLIENT_EMAIL,
      private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
    },
    scopes: ["https://www.googleapis.com/auth/firebase.messaging"],
  });

  const client = await auth.getClient();
  const { token } = await client.getAccessToken();
  if (!token) throw new Error("Failed to obtain access token");
  return token;
}

async function sendToTokens({ tokens, title, body, data }) {
  if (!tokens?.length) return { sent: 0, skipped: true };

  const accessToken = await getAccessToken();
  const projectId = process.env.FIREBASE_PROJECT_ID;

  // HTTP v1 supports one token per call, so we batch.
  // Keep batches modest to avoid timeouts.
  const unique = [...new Set(tokens)].filter(Boolean);
  const chunkSize = 200; // practical
  const chunks = [];
  for (let i = 0; i < unique.length; i += chunkSize) chunks.push(unique.slice(i, i + chunkSize));

  let ok = 0;
  let fail = 0;

  for (const chunk of chunks) {
    await Promise.all(
      chunk.map(async (t) => {
        const payload = {
          message: {
            token: t,
            notification: { title, body },
            data: Object.fromEntries(Object.entries(data || {}).map(([k, v]) => [String(k), String(v)])),
            android: { priority: "high", notification: { sound: "default" } },
            apns: { payload: { aps: { sound: "default" } } },
          },
        };

        const r = await fetch(
          `https://fcm.googleapis.com/v1/projects/${projectId}/messages:send`,
          {
            method: "POST",
            headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          }
        );

        if (r.ok) ok++;
        else fail++;
      })
    );
  }

  return { sent: ok, failed: fail, totalTokens: unique.length };
}

async function tokensForUserIds(userIds) {
  initAdmin();
  const db = admin.firestore();

  const uniqueIds = [...new Set(userIds)].filter(Boolean);
  const chunks = [];
  const chunkSize = 10; // Firestore 'in' query limit
  for (let i = 0; i < uniqueIds.length; i += chunkSize) chunks.push(uniqueIds.slice(i, i + chunkSize));

  const tokens = [];
  for (const c of chunks) {
    const snap = await db.collection("users").where(admin.firestore.FieldPath.documentId(), "in", c).get();
    snap.forEach((doc) => {
      const t = doc.data()?.fcmTokens || [];
      if (Array.isArray(t)) tokens.push(...t);
    });
  }
  return tokens;
}

async function tokensByRole(role) {
  initAdmin();
  const db = admin.firestore();
  const snap = await db.collection("users").where("role", "==", role).get();

  const tokens = [];
  snap.forEach((doc) => {
    const t = doc.data()?.fcmTokens || [];
    if (Array.isArray(t)) tokens.push(...t);
  });
  return tokens;
}

async function tokensAllUsers() {
  initAdmin();
  const db = admin.firestore();

  const tokens = [];
  let last = null;
  while (true) {
    let q = db.collection("users").orderBy(admin.firestore.FieldPath.documentId()).limit(500);
    if (last) q = q.startAfter(last);

    const snap = await q.get();
    if (snap.empty) break;

    snap.forEach((doc) => {
      const t = doc.data()?.fcmTokens || [];
      if (Array.isArray(t)) tokens.push(...t);
      last = doc.id;
    });
  }
  return tokens;
}

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") return res.status(405).json({ ok: false, error: "Use POST" });

    // Simple auth guard
    const secret = process.env.API_SECRET;
    if (secret && req.headers["x-api-secret"] !== secret) {
      return res.status(401).json({ ok: false, error: "Unauthorized" });
    }

    const { title, body, data, userIds, role, all, tokens } = req.body || {};
    if (!title || !body) return res.status(400).json({ ok: false, error: "Missing title/body" });

    let targetTokens = [];

    if (Array.isArray(tokens) && tokens.length) {
      targetTokens = tokens; // direct
    } else if (Array.isArray(userIds) && userIds.length) {
      targetTokens = await tokensForUserIds(userIds);
    } else if (role) {
      targetTokens = await tokensByRole(role); // "admin" / "collector"
    } else if (all === true) {
      targetTokens = await tokensAllUsers();
    } else {
      return res.status(400).json({ ok: false, error: "No target provided" });
    }

    const result = await sendToTokens({ tokens: targetTokens, title, body, data });
    return res.status(200).json({ ok: true, ...result });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message || "Server error" });
  }
}
