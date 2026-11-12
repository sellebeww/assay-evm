// Types and a hand-written validator for the JSON of `assay verify --json`
// (docs/schemas/verify.schema.json, schema_version 3). The viewer reads untrusted files, so
// nothing is trusted before it passes `parseReport`, and every string is rendered as text.

export type Verdict = "PASS" | "FAIL" | "INCONCLUSIVE";
export type FinalVerdict = "VERIFIED_WITHIN_BOUNDS" | "REJECTED" | "INCONCLUSIVE";
export type OracleStatus = "ran" | "skipped" | "missing";

export interface Reason {
  code: string;
  detail: string;
  path: string | null;
  line: number | null;
}

export interface OracleRow {
  oracle: string;
  status: OracleStatus;
  verdict: Verdict | null;
  summary: string;
  reasons: Reason[];
  warnings: Reason[];
}

export interface Report {
  schemaVersion: 3;
  finalVerdict: FinalVerdict;
  evidenceLevel: string | null;
  integrityViolation: boolean;
  reasons: string[];
  boundsStatement: string;
  annotations: string[];
  oracles: OracleRow[];
  inputs: Record<string, string | null>;
  bounds: Record<string, unknown>;
  totalSeconds: number | null;
}

export type ParseResult = { ok: true; report: Report } | { ok: false; errors: string[] };

const FINAL: readonly string[] = ["VERIFIED_WITHIN_BOUNDS", "REJECTED", "INCONCLUSIVE"];
const VERDICTS: readonly string[] = ["PASS", "FAIL", "INCONCLUSIVE"];
const STATUSES: readonly string[] = ["ran", "skipped", "missing"];

type Json = Record<string, unknown>;

function isObject(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function reasonList(value: unknown, where: string, errors: string[]): Reason[] {
  if (!Array.isArray(value)) {
    errors.push(`${where} must be a list`);
    return [];
  }
  const out: Reason[] = [];
  value.forEach((item: unknown, index) => {
    if (!isObject(item) || typeof item.code !== "string" || typeof item.detail !== "string") {
      errors.push(`${where}[${index}] needs a string code and detail`);
      return;
    }
    out.push({
      code: item.code,
      detail: item.detail,
      path: typeof item.path === "string" ? item.path : null,
      line: typeof item.line === "number" ? item.line : null,
    });
  });
  return out;
}

export function parseReport(text: string): ParseResult {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return { ok: false, errors: ["The file is not valid JSON."] };
  }
  if (!isObject(data)) return { ok: false, errors: ["The JSON document must be an object."] };
  if (data.format === "assay-ci-verify/1") {
    return {
      ok: false,
      errors: [
        "This is the summary of `assay ci verify` (result.json). Open the report of one PoC " +
          "instead: run `assay verify --json` or `assay replay --json` on a bundle under bundles/.",
      ],
    };
  }
  const errors: string[] = [];
  if (data.schema_version !== 3) {
    errors.push(
      `Unsupported schema_version ${JSON.stringify(data.schema_version)}; this viewer reads 3.`,
    );
  }
  if (typeof data.final_verdict !== "string" || !FINAL.includes(data.final_verdict)) {
    errors.push("final_verdict must be VERIFIED_WITHIN_BOUNDS, REJECTED or INCONCLUSIVE.");
  }
  if (!Array.isArray(data.oracles)) errors.push("oracles must be a list.");
  if (errors.length > 0) return { ok: false, errors };

  const oracles: OracleRow[] = [];
  for (const [index, raw] of (data.oracles as unknown[]).entries()) {
    if (
      !isObject(raw) ||
      typeof raw.oracle !== "string" ||
      typeof raw.status !== "string" ||
      !STATUSES.includes(raw.status)
    ) {
      errors.push(`oracles[${index}] needs an oracle name and a status (ran, skipped, missing).`);
      continue;
    }
    if (raw.verdict !== null && (typeof raw.verdict !== "string" || !VERDICTS.includes(raw.verdict))) {
      errors.push(`oracles[${index}].verdict must be PASS, FAIL, INCONCLUSIVE or null.`);
      continue;
    }
    oracles.push({
      oracle: raw.oracle,
      status: raw.status as OracleStatus,
      verdict: raw.verdict as Verdict | null,
      summary: typeof raw.summary === "string" ? raw.summary : "",
      reasons: reasonList(raw.reasons ?? [], `oracles[${index}].reasons`, errors),
      warnings: reasonList(raw.warnings ?? [], `oracles[${index}].warnings`, errors),
    });
  }
  if (errors.length > 0) return { ok: false, errors };

  const inputs: Record<string, string | null> = {};
  if (isObject(data.inputs)) {
    for (const [key, value] of Object.entries(data.inputs)) {
      inputs[key] = typeof value === "string" ? value : null;
    }
  }
  const timing = isObject(data.timing) ? data.timing : {};
  return {
    ok: true,
    report: {
      schemaVersion: 3,
      finalVerdict: data.final_verdict as FinalVerdict,
      evidenceLevel: typeof data.evidence_level === "string" ? data.evidence_level : null,
      integrityViolation: data.integrity_violation === true,
      reasons: Array.isArray(data.reasons)
        ? data.reasons.filter((item): item is string => typeof item === "string")
        : [],
      boundsStatement: typeof data.bounds_statement === "string" ? data.bounds_statement : "",
      annotations: Array.isArray(data.annotations)
        ? data.annotations.filter((item): item is string => typeof item === "string")
        : [],
      oracles,
      inputs,
      bounds: isObject(data.bounds) ? data.bounds : {},
      totalSeconds: typeof timing.total_s === "number" ? timing.total_s : null,
    },
  };
}

// What the verdict says in words. It never claims more than the verdict does.
export const VERDICT_TEXT: Record<FinalVerdict, string> = {
  VERIFIED_WITHIN_BOUNDS:
    "Every required oracle passed and nothing was found within the recorded bounds. This is not a proof that the patch is correct.",
  REJECTED: "At least one oracle failed. The reasons below say which check and why.",
  INCONCLUSIVE:
    "No oracle failed, but at least one was inconclusive or did not run (a timeout, an unknown result, a flaky replay).",
};

export const EVIDENCE_TEXT: Record<string, string> = {
  E0: "Unverified signal",
  E1: "Exploit reproduced on the vulnerable revision",
  E2: "The patch blocks the PoC without a detected regression; the variant search did not decide",
  E3: "All required oracles passed within the recorded bounds",
};
