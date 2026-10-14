// Tiny webhook receiver for local demos: logs every POST body to stdout.
// Run: node examples/webhook-receiver/server.mjs 8099
import { createServer } from "node:http";

const PORT = Number(process.argv[2] ?? 8099);
createServer((req, res) => {
  let data = "";
  req.on("data", (c) => (data += c));
  req.on("end", () => {
    console.log(JSON.stringify({
      event: req.headers["x-traceguard-event"],
      signature: String(req.headers["x-traceguard-signature"] ?? "").slice(0, 16) + "...",
      body: JSON.parse(data || "{}")
    }));
    res.writeHead(200).end("ok");
  });
}).listen(PORT, () => console.log(`webhook receiver on :${PORT}`));
