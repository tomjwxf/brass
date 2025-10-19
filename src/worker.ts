import { Oprf, EvaluationRequest, Evaluation, DLEQProof } from "@cloudflare/voprf-ts";

const SUITE = Oprf.Suite.P256_SHA256;
const MODE  = Oprf.Mode.VOPRF;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function json(obj: unknown, status = 200, extra: Record<string,string> = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", ...CORS, ...extra }
  });
}

export default {
  async fetch(req: Request, env: Record<string,string>): Promise<Response> {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response("", { headers: CORS });

    // Issuer directory
    if (req.method === "GET" && url.pathname === "/.well-known/private-token-issuer-directory") {
      const { pubKeyBytes, kidB64 } = await getPublicKey(env);
      const directory = {
        issuerName: env.ISSUER_NAME || "brass-issuer-pro",
        "issuer-request-uri": `${url.origin}/token-request`,
        "token-keys": [{ "token-type": 2, "token-key": b64url(pubKeyBytes), "token-key-id": kidB64 }],
      };
      return json(directory);
    }

    // VOPRF evaluate (binary)
    if (req.method === "POST" && url.pathname === "/token-request") {
      const ct = (req.headers.get("content-type") || "").toLowerCase();
      if (!ct.includes("application/private-token-request")) {
        return json({ ok: false, reason: "wrong_content_type" }, 400);
      }
      try {
        const body = new Uint8Array(await req.arrayBuffer());
        const evalReq = EvaluationRequest.deserialize(SUITE, body);
        const g = Oprf.getGroup(SUITE);

        const { sk, Y } = await getKeypair(env);
        const evaluated = evalReq.blinded.map(be => be.scalarMult(sk));

        const proof = await DLEQProof.prove(
          g.id, sk, Y, evalReq.blinded, evaluated,
          Oprf.getDST(MODE, SUITE, "Finalize")
        );

        const evaluation = new Evaluation(MODE, evaluated, proof);
        const bytes = evaluation.serialize();
        return new Response(bytes, { status: 200, headers: { "content-type": "application/private-token-response", ...CORS } });
      } catch (e: any) {
        return json({ ok: false, reason: "exception", message: String(e?.message || e) }, 500);
      }
    }

    return new Response("BRASS Issuer Pro ready", { headers: CORS });
  }
};

// ---- keys ----
async function getKeypair(env: Record<string,string>) {
  const g = Oprf.getGroup(SUITE);
  let skBytes: Uint8Array;
  if (env.ISSUER_SK) skBytes = b64urlDecode(env.ISSUER_SK);
  else skBytes = crypto.getRandomValues(new Uint8Array(32)); // ephemeral for testing
  const sk = g.scalarDes.deserialize(skBytes);
  const Y  = g.baseScalarMult ? g.baseScalarMult(sk) : g.scalarBaseMult(sk);
  return { sk, Y };
}

async function getPublicKey(env: Record<string,string>) {
  const { Y } = await getKeypair(env);
  const g = Oprf.getGroup(SUITE);
  const pubKeyBytes = g.eltSer.serialize(Y);
  const kid = await crypto.subtle.digest("SHA-256", pubKeyBytes);
  const kidB64 = b64url(new Uint8Array(kid).slice(0,6));
  return { pubKeyBytes, kidB64 };
}

// ---- utils ----
function b64url(u8: Uint8Array): string {
  let s = btoa(String.fromCharCode(...u8));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/,"");
}
function b64urlDecode(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  s += "=".repeat(pad);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out;
}
