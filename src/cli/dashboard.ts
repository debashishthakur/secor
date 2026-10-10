// `secor dashboard [--no-open]` (spec sections 11.1 and 12.1): starts or reuses the local read-only dashboard for
// the current project and prints its URL. A new dashboard runs in this process until it has been idle for 30
// minutes or the user presses Ctrl-C; a reused one belongs to another process, so this command exits at once.

import type { Command } from "commander";

export function registerDashboardCommand(program: Command): void {
  program
    .command("dashboard")
    .description("start or reuse the local read-only dashboard and print its URL")
    .option("--no-open", "do not open the browser")
    .action(async (o: { open: boolean }) => {
      const { openDashboard } = await import("../dashboard/launch.js");
      const r = await openDashboard({ root: process.cwd(), open: o.open });
      if (!r.server) {
        process.stdout.write(`SECOR dashboard (already running): ${r.url}\n`);
        return;
      }
      const server = r.server;
      process.stdout.write(`SECOR dashboard: ${r.url}\n`);
      process.stdout.write("Read-only, on 127.0.0.1 only. It stops after 30 minutes without requests; press Ctrl-C to stop it now.\n");
      const stop = (): void => void server.close();
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
      await server.closed;
      process.off("SIGINT", stop);
      process.off("SIGTERM", stop);
    });
}
