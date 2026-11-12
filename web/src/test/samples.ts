import { readFileSync } from "node:fs";
import { join } from "node:path";

// Vitest runs with the web/ folder as the working directory.
export const sample = (name: string): string =>
  readFileSync(join(process.cwd(), "public", "samples", `${name}.json`), "utf8");
