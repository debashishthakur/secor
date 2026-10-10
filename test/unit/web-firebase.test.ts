import { describe, expect, it } from "vitest";
import { classifyAllow, classifyRtdb, hasWildcardDocumentSegment, normaliseCondition, parseRtdbRules, parseRulesFile } from "../../src/engine/backends/firebase.js";
import { jsonProp, lineAt, parseJsonPos } from "../../src/engine/backends/json-pos.js";

const FS = `rules_version = '2';
// allow read: if true;   (a comment, not a rule)
service cloud.firestore {
  function signedIn() { return request.auth != null; }
  function isOwner(uid) { return request.auth.uid == uid; }
  match /databases/{database}/documents {
    match /open/{id} { allow read: if true; }
    match /bare/{id} { allow write; }
    match /test/{doc=**} {
      allow read,
            write: if request.time <
              timestamp.date(2031, 1, 1);
    }
    match /users/{userId} {
      allow get: if request.auth != null;
      allow list: if signedIn();
      allow update: if isOwner(userId);
      match /private/settings { allow read: if (request.auth != null); }
    }
    match /settings/global {
      allow read: if request.auth != null;
      allow write: if resource.data.note == "a;b" && false;
    }
  }
}
`;

describe("parseRulesFile", () => {
  const parsed = parseRulesFile(FS);
  const at = (needle: string) => parsed.allows.find((a) => a.text.includes(needle))!;

  it("finds allow statements with their nested match paths and lines", () => {
    expect(parsed.allows).toHaveLength(9);
    const open = at("if true");
    expect(open).toMatchObject({ service: "cloud.firestore", paths: ["/databases/{database}/documents", "/open/{id}"], methods: ["read"], condition: "true", line: 7 });
    expect(at("allow write;").condition).toBeNull();
    expect(at("request.time").methods).toEqual(["read", "write"]);
    expect(at("request.time").line).toBe(10);
    expect(at('"a;b"').condition).toBe('resource.data.note == "a;b" && false');
  });

  it("records functions with a single return", () => {
    expect(parsed.functions.get("signedIn")).toEqual({ name: "signedIn", params: [], returns: "request.auth != null" });
    expect(parsed.functions.get("isOwner")!.params).toEqual(["uid"]);
  });

  it("classifies open, test-mode and auth-only rules", () => {
    const f = parsed.functions;
    expect(classifyAllow(at("if true"), f)).toEqual({ kind: "open", reason: "condition is always true" });
    expect(classifyAllow(at("allow write;"), f)?.kind).toBe("open");
    expect(classifyAllow(at("request.time"), f)).toEqual({ kind: "open", reason: "test-mode rule with an expiry date" });
    expect(classifyAllow(at("allow get"), f)).toEqual({ kind: "auth-only" });
    expect(classifyAllow(at("signedIn()"), f)).toEqual({ kind: "auth-only" });
    expect(classifyAllow(at("isOwner(userId)"), f)).toBeNull();
    // wildcard in an enclosing match counts; a fixed document path does not
    expect(classifyAllow(at("(request.auth != null)"), f)).toEqual({ kind: "auth-only" });
    const settings = parsed.allows.filter((a) => a.paths.includes("/settings/global"));
    expect(settings.map((a) => classifyAllow(a, f))).toEqual([null, null]);
  });

  it("ignores the service-root wildcards when looking for document wildcards", () => {
    const base = { service: "firebase.storage", methods: ["read"], condition: "request.auth != null", start: 0, line: 1, text: "" };
    expect(hasWildcardDocumentSegment({ ...base, paths: ["/b/{bucket}/o", "/public/logo.png"] })).toBe(false);
    expect(hasWildcardDocumentSegment({ ...base, paths: ["/b/{bucket}/o", "/images/{imageId}"] })).toBe(true);
    expect(hasWildcardDocumentSegment({ ...base, paths: ["/databases/{database}/documents"] })).toBe(false);
  });

  it("normaliseCondition strips whitespace and wrapping parentheses only", () => {
    expect(normaliseCondition(" ( (request.auth != null) ) ")).toBe("request.auth!=null");
    expect(normaliseCondition("(a) && (b)")).toBe("(a)&&(b)");
  });

  it("does not throw on malformed input", () => {
    expect(() => parseRulesFile("service cloud.firestore { match /x/{y} { allow read: if (")).not.toThrow();
    expect(parseRulesFile("").allows).toEqual([]);
  });
});

describe("Realtime Database rules", () => {
  const text = `{
  // comments are fine
  "rules": {
    ".read": true,
    ".write": "auth != null",
    "users": { "$uid": { ".read": "$uid === auth.uid", ".write": "true", }, },
    "posts": { ".read": " auth !== null " }
  }
}`;
  it("lists .read/.write rules with key paths and lines", () => {
    const rules = parseRtdbRules(text)!;
    expect(rules.map((r) => `${r.path}@${r.line}:${classifyRtdb(r)}`)).toEqual([
      "rules/.read@4:open",
      "rules/.write@5:auth-only",
      "rules/users/$uid/.read@6:null",
      "rules/users/$uid/.write@6:open",
      "rules/posts/.read@7:auth-only",
    ]);
  });

  it("returns null for invalid JSON", () => {
    expect(parseRtdbRules("{ rules: }")).toBeNull();
  });
});

describe("parseJsonPos", () => {
  it("keeps offsets of keys and values", () => {
    const text = '{\n  "a": [1, {"b": "x\\"y"}],\n  "c": null\n}';
    const root = parseJsonPos(text)!;
    const a = jsonProp(root, "a")!;
    expect(lineAt(text, a.keyStart)).toBe(2);
    expect(a.value.kind).toBe("array");
    const b = jsonProp(a.value.kind === "array" ? a.value.items[1] : null, "b")!;
    expect(b.value).toMatchObject({ kind: "string", value: 'x"y' });
    expect(text.slice(b.value.start, b.value.end)).toBe('"x\\"y"');
    expect(jsonProp(root, "c")!.value.kind).toBe("null");
  });

  it("accepts comments and trailing commas, rejects garbage", () => {
    expect(parseJsonPos('/* x */ { "a": 1, } // y')).not.toBeNull();
    expect(parseJsonPos("{ a: 1 }")).toBeNull();
    expect(parseJsonPos('{"a": 1} trailing')).toBeNull();
    expect(parseJsonPos("")).toBeNull();
  });
});
