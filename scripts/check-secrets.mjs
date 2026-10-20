import { spawnSync } from "node:child_process";

function fail(message) {
  console.error(`Secrets check failed: ${message}`);
  process.exit(1);
}

function run(executable, args, cwd) {
  // Keep captured diagnostics private: even scanner errors can quote file text.
  return spawnSync(executable, args, {
    cwd,
    encoding: "utf8",
    windowsHide: true,
    shell: false,
    maxBuffer: 16 * 1024 * 1024,
  });
}

const location = run("git", ["rev-parse", "--show-toplevel"], process.cwd());
if (location.error || location.status !== 0)
  fail("current directory is not an accessible Git repository.");
const root = location.stdout.trim();
const tracked = run("git", ["ls-files", "--cached", "-z"], root);
if (tracked.error || tracked.status !== 0) fail("could not inspect tracked paths.");

const forbidden = (path) =>
  /(?:^|\/)\.env(?:[./_-]|$)/i.test(path) ||
  /\.(?:pem|key|p12|pfx|jks|keystore)$/i.test(path) ||
  /(?:^|\/)(?:\.npmrc|\.pypirc|\.netrc|_netrc|\.git-credentials|credentials(?:\.json)?|secrets?\.(?:json|ya?ml|toml))$/i.test(
    path,
  ) ||
  /(?:^|\/)(?:\.aws|\.ssh|browser[-_]?profiles?|chrome[-_]?profiles?|chromium[-_]?profiles?|firefox[-_]?profiles?|user[-_]?data)(?:\/|$)/i.test(
    path,
  ) ||
  /(?:^|\/)(?:Local Extension Settings|Session Storage|Local Storage|IndexedDB)(?:\/|$)/i.test(
    path,
  ) ||
  /(?:^|\/)(?:Login Data|Web Data|Cookies|History|Local State)$/i.test(path) ||
  /(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)(?:$|\.)/i.test(path);

const blocked = tracked.stdout.split("\0").filter((path) => path && forbidden(path));
if (blocked.length) {
  // JSON quoting prevents tracked path names from injecting terminal controls.
  fail(
    `forbidden credential or browser-profile artifacts are tracked: ${blocked.map((path) => JSON.stringify(path)).join(", ")}`,
  );
}

const scanner = process.env.GITLEAKS_PATH || "gitleaks";
const version = run(scanner, ["version"], root);
if (version.error || version.status !== 0)
  fail(
    "Gitleaks scanner is missing or could not run; install it or set GITLEAKS_PATH to its executable.",
  );

const head = run("git", ["rev-parse", "--verify", "HEAD^{commit}"], root);
if (head.error || head.status !== 0)
  fail("repository has no committed HEAD; history scanning cannot pass on an unborn repository.");
const refs = run("git", ["show-ref"], root);
if (refs.error || refs.status !== 0 || !refs.stdout.trim())
  fail("repository refs are unavailable; history scanning cannot be verified.");

for (const [label, args] of [
  [
    "all-ref history",
    ["git", ".", "--log-opts=--all", "--redact=100", "--ignore-gitleaks-allow", "--no-banner"],
  ],
  [
    "staged diff",
    [
      "git",
      ".",
      "--pre-commit",
      "--staged",
      "--redact=100",
      "--ignore-gitleaks-allow",
      "--no-banner",
    ],
  ],
]) {
  const result = run(scanner, args, root);
  if (result.error || result.status !== 0) {
    fail(
      `Gitleaks ${label} scan did not pass. Inspect locally with full redaction; stop publication and investigate. Scanner output is withheld to avoid exposing file contents.`,
    );
  }
}
console.log("Secrets check passed: tracked artifact policy, all-ref history and staged diff.");
