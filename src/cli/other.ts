// Remaining command groups: ledger, dashboard, mcp, probe (spec section 11.1). Each lives in its own file.

import type { Command } from "commander";
import { registerDashboardCommand } from "./dashboard.js";
import { registerLedgerCommand } from "./ledger.js";
import { registerMcpCommand } from "./mcp.js";
import { registerProbeCommand } from "./probe.js";

export function registerOtherCommands(program: Command): void {
  registerLedgerCommand(program);
  registerDashboardCommand(program);
  registerMcpCommand(program);
  registerProbeCommand(program);
}
