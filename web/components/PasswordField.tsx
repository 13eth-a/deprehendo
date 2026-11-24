"use client";

import { useId, useState } from "react";

/**
 * A password input with a Show / Hide button. The button is a real button
 * (type="button", so it never submits the form) that says what it will do,
 * with aria-pressed for screen readers. Showing a password does not change
 * its name or autocomplete, so password managers still recognise the field.
 */
export function PasswordField({
  name,
  label,
  autoComplete,
  minLength,
  maxLength,
}: {
  name: string;
  label: string;
  autoComplete: "current-password" | "new-password";
  minLength?: number;
  maxLength?: number;
}) {
  const id = useId();
  const [shown, setShown] = useState(false);
  return (
    <div className="uv-field uv-field--password">
      <input
        id={id}
        className="uv-input"
        name={name}
        type={shown ? "text" : "password"}
        autoComplete={autoComplete}
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        minLength={minLength}
        maxLength={maxLength}
        required
      />
      <label htmlFor={id} className="uv-field__label">{label}</label>
      <button
        type="button"
        className="uv-field__toggle"
        aria-controls={id}
        aria-pressed={shown}
        aria-label={shown ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`}
        onClick={() => setShown((v) => !v)}
      >
        {shown ? "Hide" : "Show"}
      </button>
    </div>
  );
}
