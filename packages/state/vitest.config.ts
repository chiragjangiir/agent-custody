// Tests spawn gateways and sidecars and load PGlite's engine; on a loaded machine that takes longer than the
// five-second default, which produced timeouts that were not failures. Thirty seconds is the budget for one test.
import { defineConfig } from "vitest/config";

// Coverage is off unless `--coverage.enabled` is passed (`bun run coverage`). It counts code that runs in the test
// process; a test that runs the CLI with spawnSync exercises code that coverage cannot see.
export default defineConfig({
  test: {
    testTimeout: 30_000,
    hookTimeout: 60_000,
    coverage: { provider: "v8", include: ["src/**"], reporter: ["text-summary", "json-summary", "json", "html"], reportsDirectory: "coverage" },
  },
});
