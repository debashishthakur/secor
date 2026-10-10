import type { DataClass } from "../../types.js";
import type { DetectOptions, DetectorMatch } from "./common.js";
import { detectConfidential } from "./confidential.js";
import { detectCredentials } from "./credentials.js";
import { detectPersonalData } from "./personal-data.js";
import { detectSecrets } from "./secrets.js";

export type { DetectOptions, DetectorMatch } from "./common.js";
export { detectSecrets, isPublicByDesign, jwtRole } from "./secrets.js";
export { detectCredentials } from "./credentials.js";
export { detectPersonalData, luhnValid, ibanValid } from "./personal-data.js";
export { detectConfidential, compileConfidentialPatterns } from "./confidential.js";
export { detectInstructions, type InstructionCategory, type InstructionMatch } from "./instructions.js";

/** Run the detector for one data class. */
export function detectClass(text: string, cls: DataClass, opts: DetectOptions & { confidential?: readonly RegExp[] } = {}): DetectorMatch[] {
  switch (cls) {
    case "secret":
      return detectSecrets(text, opts);
    case "credential":
      return detectCredentials(text, opts);
    case "personal_data":
      return detectPersonalData(text);
    case "confidential":
      return detectConfidential(text, opts.confidential ?? []);
  }
}

/** File names whose unquoted `KEY=value` / `key: value` lines count as assignments. */
export function isConfigLikeFile(file: string): boolean {
  const base = file.split("/").pop() ?? file;
  return /^\.env(\..*)?$/.test(base) || /\.(ya?ml|ini|properties|cfg|conf|toml)$/i.test(base) || /^\.?(npmrc|pypirc|netrc)$/.test(base);
}
