// FR-004, automated: from inside the agent container, the upstream tools
// network must be unreachable — by service name and by IP — while the gateway
// answers. Runs against a live `docker compose up`; see the `security` job in
// .github/workflows/ci.yml.
//
//   node tests/security/bypass.mjs            (or: npm run test:security)

import { execFileSync } from "node:child_process";

const failures = [];

function sh(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: "utf8", ...opts }).trim();
}

function inAgent(script) {
  // The probe runs in the agent container: that is the attacker's position.
  return sh("docker", ["compose", "exec", "-T", "agent", "sh", "-c", script], {
    stdio: ["ignore", "pipe", "pipe"]
  });
}

function tryInAgent(script) {
  try {
    inAgent(script);
    return { ok: true };
  } catch (err) {
    return { ok: false, err };
  }
}

function check(name, fn) {
  try {
    fn();
    console.log(`ok   ${name}`);
  } catch (err) {
    failures.push(name);
    console.log(`FAIL ${name}\n     ${err.message.split("\n")[0]}`);
  }
}

// The upstream's address on its own network, so the test can try the IP as
// well as the name: a DNS answer must not be the only thing missing.
const upstreamIp = sh("docker", [
  "compose", "ps", "-q", "mock-tools"
]).split("\n")[0];
const upstreamAddress = sh("docker", [
  "inspect", "-f",
  "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
  upstreamIp
]);

console.log(`upstream mock-tools is at ${upstreamAddress}, agent is on agent_edge only\n`);

check("the agent cannot resolve or reach the upstream by service name", () => {
  const res = tryInAgent("curl -sS --max-time 5 http://mock-tools:8092/hits");
  if (res.ok) throw new Error("the agent reached mock-tools by name");
});

check("the agent cannot reach the upstream by IP", () => {
  const res = tryInAgent(`curl -sS --max-time 5 http://${upstreamAddress}:8092/hits`);
  if (res.ok) throw new Error(`the agent reached mock-tools at ${upstreamAddress}`);
});

check("the agent cannot reach the control API", () => {
  const res = tryInAgent("curl -sS --max-time 5 http://api:8080/readyz");
  if (res.ok) throw new Error("the agent reached the api");
});

check("the agent cannot reach postgres", () => {
  const res = tryInAgent("timeout 5 sh -c '</dev/tcp/postgres/5432'");
  if (res.ok) throw new Error("the agent opened a TCP connection to postgres");
});

check("the agent reaches the gateway, and the gateway answers as itself", () => {
  const health = inAgent("curl -sS --max-time 5 http://gateway:8091/healthz");
  if (!health.includes("ok")) throw new Error(`unexpected /healthz body: ${health}`);

  // Reachable is not enough: it must be the gateway answering, and an
  // unauthenticated MCP call must be refused there.
  const status = inAgent(
    "curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -X POST http://gateway:8091/mcp"
  );
  if (status !== "401") throw new Error(`POST /mcp from the agent returned ${status}, expected 401`);
});

if (failures.length) {
  console.error(`\n${failures.length} network-segmentation check(s) failed`);
  process.exit(1);
}
console.log("\nnetwork segmentation holds: gateway only");
