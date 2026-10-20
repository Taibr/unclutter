const replacement = "[redacted]";

/** Best-effort local filtering, not anonymization of arbitrary page content. */
export function redactSensitiveText(text: string, secrets: readonly string[] = []): string {
  // Format characters can invisibly split labels and tokens. Remove them before
  // matching, including in explicitly configured credentials.
  let clean = text.replace(/\p{Cf}/gu, "");
  for (const secret of new Set(secrets.map((value) => value.replace(/\p{Cf}/gu, "")))) {
    if (secret) clean = clean.split(secret).join(replacement);
  }
  return (
    clean
      // Consume incomplete blocks too: a field limit must never expose a key prefix.
      .replace(
        /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)/g,
        replacement,
      )
      .replace(
        /\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:[^\r\n]*/gi,
        replacement,
      )
      .replace(
        /\b(?:password|passwd|pwd|api[-_ ]?key|(?:access|refresh|auth)[-_ ]?token|token|client[-_ ]?secret|secret[-_ ]?(?:key|access[-_ ]?key))\b["']?\s*[:=]\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}\]<>]+)/gi,
        replacement,
      )
      .replace(/\bBearer\s+[^\s,;"'<>]+/gi, replacement)
      .replace(/(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})/g, replacement)
      .replace(/sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{16,}/g, replacement)
      .replace(/xox[baprs]-[A-Za-z0-9-]{10,}/g, replacement)
      .replace(/(?:AKIA|ASIA)[A-Z0-9]{16}/g, replacement)
      .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, replacement)
      // Covers connection-string userinfo as well as ordinary web URLs.
      .replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s<>"']+/gi, replacement)
      .replace(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi, replacement)
      .replace(/\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b/gi, replacement)
      .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement)
      .replace(/(?<![\w:])(?:[a-f0-9]{0,4}:){2,}[a-f0-9:]{0,39}(?![\w:])/gi, replacement)
      .replace(/\+?\d[\d(). -]{5,}\d/g, (value) =>
        value.replace(/\D/g, "").length >= 8 ? replacement : value,
      )
      .replace(/[A-Za-z0-9_+/=-]{24,}/g, (value) =>
        /[a-z]/i.test(value) && /\d/.test(value) ? replacement : value,
      )
  );
}
