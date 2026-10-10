// SECOR Probe (spec section 9A). Loaded only by `secor probe` (a separate tsup entry -> dist/probe.js).
// No other module may import this one (enforced by test/probe/isolation.test.ts).

export { runProbe, verifyTargetOnly, checkForFinding, ProbeError, type RunProbeOptions, type RunProbeResult } from "./run.js";
export { verifyTarget } from "./verify.js";
export { classifyTarget, type Resolver, nodeResolver } from "./scope-guard.js";
export { obtainConsent, type ConsentIO } from "./consent.js";
export { PROBE_CHECK_IDS, type ProbeCheckId, ProbeRefusal, type VerifiedTarget } from "./types.js";
export { CONFIRMS } from "./merge.js";
