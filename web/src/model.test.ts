import { describe, expect, it } from "vitest";
import { parseReport } from "./model";
import { sample } from "./test/samples";

describe("parseReport", () => {
  it("reads the rejected sample", () => {
    const result = parseReport(sample("rejected"));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.report.finalVerdict).toBe("REJECTED");
    expect(result.report.oracles.map((row) => row.oracle)).toEqual([
      "integrity",
      "exploit",
      "variant",
      "behavior",
      "regression",
    ]);
    const variant = result.report.oracles.find((row) => row.oracle === "variant");
    expect(variant?.verdict).toBe("FAIL");
    expect(variant?.reasons[0]?.code).toBe("variant_found");
  });

  it("reads the verified and inconclusive samples", () => {
    for (const name of ["verified", "inconclusive"]) {
      expect(parseReport(sample(name)).ok).toBe(true);
    }
  });

  it("rejects text that is not JSON", () => {
    expect(parseReport("{nope")).toEqual({ ok: false, errors: ["The file is not valid JSON."] });
  });

  it("rejects an unsupported schema version and a bad verdict", () => {
    const result = parseReport(JSON.stringify({ schema_version: 2, final_verdict: "SAFE", oracles: [] }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors).toHaveLength(2);
  });

  it("explains that result.json of `ci verify` is not a report", () => {
    const result = parseReport(JSON.stringify({ format: "assay-ci-verify/1" }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0]).toContain("assay ci verify");
  });

  it("rejects an oracle row with a bad status", () => {
    const document = JSON.parse(sample("rejected"));
    document.oracles[0].status = "weird";
    expect(parseReport(JSON.stringify(document)).ok).toBe(false);
  });
});
