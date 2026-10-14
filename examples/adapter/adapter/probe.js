// The boundary probe. Not an adapter: a step that tries, from inside the same run and
// under the same grant, the three things hostile adapter code would try, and reports
// what happened. Usage: node probe.js <the vendor's URL as the host sees it>
"use strict";
const http = require("node:http");

async function tryDecommissionThroughClient() {
  try { await fleet.decommissionRobot("r1"); return "allowed"; } catch (e) { return "refused: " + e.message; }
}

// The injected client is JavaScript inside the sandbox, so its own allowlist check
// is the guest's to skip. This skips it: a raw request on the broker socket.
function tryDecommissionBypassingClient() {
  return new Promise((resolve) => {
    const req = http.request({ socketPath: process.env.HOST_API_SOCKET, method: "DELETE", path: "/robots/r1" }, (res) => {
      let text = ""; res.setEncoding("utf8");
      res.on("data", (c) => (text += c));
      res.on("end", () => resolve("broker answered " + res.statusCode + " " + text.trim()));
    });
    req.on("error", (e) => resolve("no broker: " + e.message));
    req.end();
  });
}

async function tryDirect(url) {
  try {
    const r = await fetch(url + "/robots", { signal: AbortSignal.timeout(3000) });
    return "reached the vendor directly: " + r.status;
  } catch (e) {
    return "failed: " + ((e && e.cause && e.cause.code) || (e && e.name) || String(e));
  }
}

function huntForCredential() {
  const suspicious = Object.entries(process.env).filter(([k, v]) =>
    /token|secret|bearer|auth|key/i.test(k) || /^[A-Za-z0-9_-]{32,}$/.test(v));
  const clientKeys = Object.keys(fleet).sort();
  let clientSourceHasBearer = false;
  for (const k of clientKeys) {
    if (typeof fleet[k] === "function" && /bearer|authorization/i.test(String(fleet[k]))) clientSourceHasBearer = true;
  }
  return { env_entries_that_look_like_credentials: suspicious.map(([k]) => k), client_keys: clientKeys, client_source_mentions_a_bearer: clientSourceHasBearer };
}

(async () => {
  const results = {
    decommission_through_client: await tryDecommissionThroughClient(),
    decommission_bypassing_client: await tryDecommissionBypassingClient(),
    direct_request_to_vendor: await tryDirect(process.argv[2]),
    credential_hunt: huntForCredential(),
  };
  console.log("PROBE " + JSON.stringify(results));
})();
