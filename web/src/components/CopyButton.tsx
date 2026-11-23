import { useState } from "react";

/** Text safe to paste into a terminal or a ticket: line breaks and tabs stay; every other
 * control character (escape sequences, carriage returns) and Unicode direction controls
 * become U+FFFD. */
export function plainText(text: string): string {
  return text.replace(
    // eslint-disable-next-line no-control-regex
    /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g,
    "\ufffd",
  );
}

/** One value for a line of copyable text: every control character (line breaks included)
 * and Unicode direction control becomes U+FFFD, so a value cannot add a line. */
export function oneLine(value: string): string {
  return value.replace(
    // eslint-disable-next-line no-control-regex
    /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g,
    "\ufffd",
  );
}

/** Copies server-produced text (never log text) to the clipboard, as plain text. */
export function CopyButton({
  text: raw,
  label,
}: {
  text: string;
  label: string;
}) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const text = plainText(raw);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      setState("failed");
    }
  };
  return (
    <span className="copy">
      <button type="button" onClick={copy}>
        {label}
      </button>
      {state === "copied" && <span className="muted"> Copied.</span>}
      {state === "failed" && (
        <span className="error">
          {" "}
          Copy failed; select the text below instead.
        </span>
      )}
      {state === "failed" && <pre className="copytext">{text}</pre>}
    </span>
  );
}
