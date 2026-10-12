# ADR 0006: The language model is an untrusted proposer

- Status: Accepted
- Date: 2026-10-02

## Context

A language model can help draft hypotheses, PoCs and patches. Its output is not reliable, and the
input it reads (target code, comments, NatSpec, identifiers, revert messages, analyzer text) can
contain hostile instructions. Sending code to a model endpoint can also leak secrets.

## Decision

- The model layer is optional. Without it, everything except `assay prove`, `assay fix` and
  `assay run` works.
- One client talks to any OpenAI-compatible Chat Completions endpoint through httpx. There are no
  vendor SDKs and no vendor-specific code paths. Configuration comes only from the `ASSAY_LLM_*`
  environment variables; the base URL must be `https` or localhost.
- Model output is untrusted data. It must be JSON validated by strict models with size limits. A
  generated PoC passes a default-deny static checker before anything runs. A generated patch is
  applied only through the sandboxed patch path, inside the allowed scope and size limits. Model
  output never executes on the host and never reaches a shell.
- A `model_run` record can never change a status. Only oracle evidence can (ADR 0005).
- Before anything is sent: an allowlist of files, pattern-based secret redaction, removal of
  absolute paths and user names. Sending requires the explicit flag `--allow-llm`;
  `--llm-dry-run` shows the size and hash of the payload instead of sending it.
- Cassettes record and replay model exchanges. Replay is the default in tests and CI, needs no
  environment variables, and never falls back to the network.
- Hard budgets cap calls and tokens per command.
- Prompts never contain seeds, fuzz campaign settings or oracle code. The final decision of a fix
  loop always uses a held-out seed family.

## Consequences

- The full pipeline can be tested without a real model, using synthetic cassettes.
- A misled or hostile model can waste attempts but cannot gain authority, write outside the PoC
  directory, or change a status.
- Redaction is pattern based and can miss unusual secrets; the documentation states this limit.
- Results that involve a live model are not deterministic; benchmark reports state this as a
  threat to validity.
