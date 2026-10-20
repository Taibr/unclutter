import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { JSDOM } from "jsdom";
import { collectCandidates } from "../lib/dom";
import { evaluate, evaluationCall, evaluationRequest, rulesFromAnswers } from "../lib/jev";
import type { Snapshot } from "../lib/model";
import { redactSensitiveText } from "../lib/privacy";

// All values are constructed synthetic fixtures, never live credentials.
const opaque = ["mQ7pL9xR2vT5nB8c", "D4fH6jK3sW1zY0aE"].join("");
const credentials = [
  ["ghp", opaque].join("_"),
  ["github_pat", opaque, opaque].join("_"),
  ["sk", "proj", opaque].join("-"),
  ["xoxb", "1357924680", "2468013579", opaque].join("-"),
  ["AKIA", "QWERTYUIOPASDFGH"].join(""),
  ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJzeW50aGV0aWMifQ", opaque].join("."),
];
const snapshot = (text: string, signals = "ad-banner"): Snapshot => ({
  url: "https://example.test/private?token=excluded",
  context: {
    key: "private-template",
    kind: "article",
    label: "Private page title",
    origin: "https://example.test",
  },
  candidates: [
    { id: "e0", selector: "div.ad-banner", tag: "div", signals, text, position: "fixed", count: 1 },
  ],
});

test("privacy filter removes common credential formats and retains useful clutter words", () => {
  for (const credential of credentials) {
    const clean = redactSensitiveText(`Advertisement ${credential} Subscribe to our newsletter`);
    assert.ok(!clean.includes(credential), "credential must be removed");
    assert.ok(clean.includes("Advertisement"));
    assert.ok(clean.includes("newsletter"));
  }
  const ordinary = "Advertisement. Subscribe to our newsletter. Accept or reject cookies.";
  assert.equal(redactSensitiveText(ordinary), ordinary);
});

test("privacy filter removes labelled, quoted, bearer, connection and private-key secrets", () => {
  const values = [
    ["password = 'meadow fox'", "meadow fox"],
    ['"api_key": "short-fixture"', "short-fixture"],
    ["client_secret: fixture-value", "fixture-value"],
    ["Authorization: Bearer fixture-bearer-value", "fixture-bearer-value"],
    ["Cookie: sid=fixture-session; theme=dark", "fixture-session"],
    ["postgres://fixture-user:fixture-pass@db.example.test/mydb", "fixture-pass"],
    [
      ["-----BEGIN", "PRIVATE KEY-----"].join(" ") +
        "\n" +
        opaque +
        "\n" +
        ["-----END", "PRIVATE KEY-----"].join(" "),
      opaque,
    ],
    ["password\u200b=fixture-hidden", "fixture-hidden"],
  ];
  for (const [input, secret] of values) {
    const clean = redactSensitiveText(input!);
    assert.ok(!clean.includes(secret!), "labelled or encoded credential must be removed");
  }
});

test("privacy filter covers contact/network identifiers, long numbers and opaque tokens", () => {
  for (const value of [
    "person@example.test",
    "https://example.test/reset?token=fixture",
    "+44 (0)20 7946 0958",
    "4111 1111 1111 1111",
    "192.168.20.42",
    "2001:db8:85a3::8a2e:370:7334",
    "a0b1c2d3-e4f5-4a6b-8c9d-0e1f2a3b4c5d",
    opaque,
  ]) {
    assert.ok(
      !redactSensitiveText(`Ad contact ${value}`).includes(value),
      "identifier must be removed",
    );
  }
});

test("filter is deterministic, idempotent and removes exact configured secrets literally", () => {
  const key = "fixture.[literal]+key?";
  const clean = redactSensitiveText(`Ad ${key} then ${key}`, [key, "", key]);
  assert.ok(!clean.includes(key));
  assert.equal(redactSensitiveText(clean, [key]), clean);
  assert.equal(redactSensitiveText(""), "");
});

test("collection redacts before truncation without mutating the original page", () => {
  const secret = credentials[0]!;
  const prefix = "Advertisement ".padEnd(440, ".");
  const dom = new JSDOM(
    `<div class="ad-banner" aria-label="promotion password='fixture-aria'">${prefix}${secret}</div>`,
  );
  const candidates = collectCandidates(dom.window.document);
  assert.equal(candidates.length, 1);
  assert.ok(!candidates[0]!.text.includes(secret.slice(0, 10)));
  assert.ok(!candidates[0]!.signals.includes("fixture-aria"));
  assert.ok(candidates[0]!.text.length <= 450);
  assert.ok(candidates[0]!.signals.length <= 300);
  assert.ok(dom.window.document.body.textContent!.includes(secret));
});

test("every provider request sanitizes raw snapshots and excludes local-only context", () => {
  const privateValue = credentials[0]!;
  const raw = snapshot(`Advertisement ${privateValue}`, `ad-banner api_key="fixture-attribute"`);
  const original = JSON.stringify(raw);
  for (const provider of ["typesafe", "vercel"] as const) {
    const key = "fixture.[literal]+key?";
    const call = evaluationCall(
      snapshot(`${raw.candidates[0]!.text} ${key}`, raw.candidates[0]!.signals),
      key,
      provider,
    );
    const body = String(call.init.body);
    for (const excluded of [
      privateValue,
      "fixture-attribute",
      key,
      raw.url,
      raw.context.label,
      raw.candidates[0]!.selector,
    ])
      assert.ok(!body.includes(excluded), "outbound JSON must exclude sensitive/local-only data");
    assert.equal(new Headers(call.init.headers).get("Authorization"), `Bearer ${key}`);
    const parsed = JSON.parse(body);
    assert.equal(parsed.state.elements[0].id, "e0");
    assert.equal(parsed.state.elements[0].tag, "div");
    assert.equal(parsed.state.elements[0].count, 1);
    assert.equal(parsed.state.pageType, "article");
  }
  assert.equal(JSON.stringify(raw), original);
  assert.ok(!JSON.stringify(evaluationRequest(raw)).includes(privateValue));
});

test("request boundary strips a credential before field-length limits cut it in half", () => {
  const secret = credentials[0]!;
  const body = JSON.stringify(
    evaluationRequest(snapshot("a".repeat(440) + secret, "b".repeat(290) + secret)),
  );
  assert.ok(!body.includes(secret.slice(0, 10)));
  const element = evaluationRequest(snapshot("a".repeat(600), "b".repeat(400))).state.elements[0]!;
  assert.ok(element.text.length <= 450);
  assert.ok(element.signals.length <= 300);
});

test("collection never leaves a partial configured key for the outbound filter", () => {
  const key = "fixture.[literal]+key?";
  const prefix = "Advertisement ".padEnd(440, ".") + " ";
  const dom = new JSDOM(
    `<div class="ad-banner" aria-label="${"promotion ".padEnd(290, ".")} ${key}">${prefix}${key}</div>`,
  );
  const candidates = collectCandidates(dom.window.document);
  const raw = snapshot("");
  raw.candidates = candidates;
  const body = String(evaluationCall(raw, key, "typesafe").init.body);
  assert.ok(!body.includes("fixture."), "a cut-off key prefix must not escape literal filtering");
  assert.ok(body.includes("Advertisement"));
  assert.ok(dom.window.document.body.textContent!.includes(key));
});

test("fetch uses the filtered payload and response rules still map to original local selectors", async (t) => {
  const raw = snapshot(`Advertisement password=fixture-fetch-secret`);
  const replies = { answers: { e0: { type: "choice", choice: "ad", confidence: 0.99 } } };
  const fetch = t.mock.method(globalThis, "fetch", async (_url: unknown, init: RequestInit) => {
    assert.ok(!String(init.body).includes("fixture-fetch-secret"));
    return Response.json(replies);
  });
  assert.deepEqual(await evaluate(raw, "synthetic-test-key", "typesafe"), [
    { selector: "div.ad-banner", category: "ad", enabled: true },
  ]);
  assert.equal(fetch.mock.calls.length, 1);
  assert.deepEqual(rulesFromAnswers(replies, raw.candidates), [
    { selector: "div.ad-banner", category: "ad", enabled: true },
  ]);
});

const script = resolve("scripts/check-secrets.mjs");
function fixtureRepo(t: { after: (fn: () => void) => void }) {
  const cwd = mkdtempSync(join(tmpdir(), "unclutter-secret-check-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  const init = spawnSync("git", ["init", "--quiet"], { cwd, windowsHide: true });
  assert.equal(init.status, 0);
  return cwd;
}

test("repository check refuses missing scanner and exposes no file contents", (t) => {
  const cwd = fixtureRepo(t);
  const result = spawnSync(process.execPath, [script], {
    cwd,
    env: { ...process.env, GITLEAKS_PATH: join(cwd, "missing-scanner") },
    encoding: "utf8",
    windowsHide: true,
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stdout + result.stderr, /gitleaks|scanner/i);
});

test("repository check rejects tracked credential files even if gitignored", (t) => {
  for (const file of [
    ".env",
    "config/.env.production",
    "cert/private.pem",
    "browser-profile/Default/Local Extension Settings/key",
    "browser-profile-smoke/Default/Preferences",
    "chrome-profile-personal/Default/Preferences",
    "firefox_profile_backup/prefs.js",
  ]) {
    const cwd = fixtureRepo(t);
    mkdirSync(resolve(cwd, file, ".."), { recursive: true });
    writeFileSync(join(cwd, file), "fixture-value-must-not-appear-in-output");
    const add = spawnSync("git", ["add", "--force", "--", file], { cwd, windowsHide: true });
    assert.equal(add.status, 0);
    const result = spawnSync(process.execPath, [script], {
      cwd,
      encoding: "utf8",
      windowsHide: true,
    });
    const output = result.stdout + result.stderr;
    assert.notEqual(result.status, 0);
    assert.match(output, /credential|forbidden|sensitive|blocked/i);
    assert.ok(!output.includes("fixture-value-must-not-appear-in-output"));
  }
});
