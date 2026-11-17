import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { copyFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";

test(
  "AES-KW vectors, generated keys and rejected operations in celld",
  { timeout: 60000 },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), "celld-aes-kw-"));
    let child;
    let startError;
    t.after(async () => {
      try {
        if (!child || child.exitCode !== null || child.signalCode !== null || startError) return;
        const ended = once(child, "exit");
        child.kill("SIGTERM");
        const kill = setTimeout(() => child.kill("SIGKILL"), 5000);
        try {
          await ended;
        } finally {
          clearTimeout(kill);
        }
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    });
    await copyFile(new URL("./fixtures/aes-kw.js", import.meta.url), join(directory, "worker.js"));
    await writeFile(
      join(directory, "wrangler.json"),
      JSON.stringify({
        name: "aes-kw-test",
        main: "worker.js",
        no_bundle: true,
        compatibility_date: "2026-10-01",
      }),
    );
    const reservation = createServer();
    reservation.listen(0, "127.0.0.1");
    await once(reservation, "listening");
    const { port } = reservation.address();
    await new Promise((resolve, reject) =>
      reservation.close((error) => (error ? reject(error) : resolve())),
    );
    child = spawn(
      process.env.CELLD_BINARY ?? resolve("target/debug/celld"),
      ["dev", directory, "--host", "127.0.0.1", "--port", String(port), "--no-watch"],
      { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, CELLD_OTEL: "0" } },
    );
    let output = "";
    child.stdout.on("data", (chunk) => {
      output += chunk;
    });
    child.stderr.on("data", (chunk) => {
      output += chunk;
    });
    child.on("error", (error) => {
      startError = error;
    });
    const origin = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + 30000;
    let ready = false;
    while (Date.now() < deadline) {
      if (startError) throw startError;
      assert.equal(child.exitCode, null, output);
      try {
        const response = await fetch(`${origin}/.well-known/celld/health`, {
          signal: AbortSignal.timeout(1000),
        });
        if (response.ok) {
          ready = true;
          break;
        }
      } catch {
        /* Wait for the local listener. */
      }
      await delay(100);
    }
    assert.ok(ready, output);
    const response = await fetch(origin, { signal: AbortSignal.timeout(10000) });
    const body = await response.text();
    assert.equal(response.status, 200, `${body}\n${output}`);
    assert.deepEqual(JSON.parse(body), { ok: true });
  },
);
