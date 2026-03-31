#!/usr/bin/env node

import { Command } from "commander";
import { initCommand } from "./commands/init.js";
import { addCommand } from "./commands/add.js";
import { removeCommand } from "./commands/remove.js";
import { listCommand } from "./commands/list.js";
import { serveCommand } from "./commands/serve.js";
import { auditCommand } from "./commands/audit.js";
import { evalCommand } from "./commands/eval.js";

const program = new Command();

program
  .name("mavryn")
  .description("The MCP control plane — one server to route them all")
  .version("0.1.0");

program.addCommand(initCommand);
program.addCommand(addCommand);
program.addCommand(removeCommand);
program.addCommand(listCommand);
program.addCommand(serveCommand);
program.addCommand(auditCommand);
program.addCommand(evalCommand);

program.parseAsync().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
