// Personal data (class `personal_data`), spec section 9.5.3. v1 recognises only these four kinds.

import { type DetectorMatch, dropOverlaps } from "./common.js";

const EMAIL = /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g;
const PHONE = /(?<![\w+])\+[1-9]\d{7,14}\b/g;
const CARD = /\b(?:\d[ -]?){13,19}\b/g;
const IBAN = /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g;

export function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return digits.length > 0 && sum % 10 === 0;
}

export function ibanValid(iban: string): boolean {
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let rem = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const part = code >= 65 && code <= 90 ? String(code - 55) : ch;
    for (const digit of part) rem = (rem * 10 + (digit.charCodeAt(0) - 48)) % 97;
  }
  return rem === 1;
}

export function detectPersonalData(text: string): DetectorMatch[] {
  const found: DetectorMatch[] = [];
  const push = (kind: string, label: string, start: number, value: string) =>
    found.push({ class: "personal_data", kind, label, start, end: start + value.length, value, valueStart: 0 });

  EMAIL.lastIndex = 0;
  for (let m = EMAIL.exec(text); m; m = EMAIL.exec(text)) push("email", "Email address", m.index, m[0]);
  IBAN.lastIndex = 0;
  for (let m = IBAN.exec(text); m; m = IBAN.exec(text)) if (ibanValid(m[0])) push("iban", "IBAN", m.index, m[0]);
  CARD.lastIndex = 0;
  for (let m = CARD.exec(text); m; m = CARD.exec(text)) {
    const raw = m[0].replace(/[ -]+$/, "");
    const digits = raw.replace(/[ -]/g, "");
    if (digits.length >= 13 && digits.length <= 19 && luhnValid(digits)) push("card", "Payment card number", m.index, raw);
  }
  PHONE.lastIndex = 0;
  for (let m = PHONE.exec(text); m; m = PHONE.exec(text)) push("phone", "Phone number", m.index, m[0]);
  return dropOverlaps(found);
}
