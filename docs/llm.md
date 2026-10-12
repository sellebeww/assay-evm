# The LLM layer

The model layer is optional. Without it, `assay verify`, `assay replay` and `assay scan` work
exactly the same. When it is used, the model only proposes; deterministic oracles decide, and no
model output ever changes a status on its own
([ADR 0006](adr/0006-llm-as-untrusted-proposer.md)).

This page covers the client, what is sent and what is not, cassettes, budgets, how model output
is handled, the ledger record, `assay prove` (hypothesis and PoC drafting), the static PoC
checker and the threat model with its limits. Patch proposals are built on the same parts; the
loop that verifies them is described in [the fix loop](fix-loop.md).

## What is sent, and what is not

Sent, only after explicit consent (`--allow-llm`):

- the prompt text of the command, after redaction;
- `.sol` files that lie inside the project scope (by default under `src/`), or line ranges of
  them (finding snippets), after redaction.

Never sent:

- `.env` files, `foundry.toml`, `remappings.txt`, hidden files and directories, and any file
  that is not a `.sol` file;
- files outside the project scope, files reached through a symbolic link, files that are not
  regular UTF-8 text, and files larger than 256 KiB;
- the API key anywhere except the authorization header of the request to the endpoint;
- seeds, fuzz campaign settings and oracle code;
- anything in `replay` mode: replay answers from a file and does not open a network connection.

Redaction runs on every request, in every mode, before the cassette key and the payload hash are
computed. It removes:

| Kind | Examples |
|---|---|
| `private_key` | PEM private key blocks; 64-digit hex values assigned to names such as `privateKey` or `pk`, or passed to `vm.addr`, `vm.sign` and `vm.startBroadcast` |
| `mnemonic` | 12 to 24 lowercase words after `mnemonic` or `seed phrase`, or as one quoted string |
| `api_key` | common token formats (`sk-...`, `ghp_...`, `AKIA...`, JWTs, `Bearer ...`), long quoted values assigned to names such as `apiKey`, `secret` or `token`, and `NAME_KEY=value` lines |
| `rpc_url` | URLs with credentials, a token in the query string or a long token-like path segment |
| `path` | absolute Unix and Windows paths, `~/` paths and `file://` URLs |
| `username` | the login name, the `USER`, `LOGNAME` and `USERNAME` variables and the home directory name of the host (names of at least three characters) |
| `email` | e-mail addresses |

Each replacement shows as `[REDACTED:<kind>]`, `<user>`. Reports and `--llm-dry-run` give counts
per kind, never the values.

Redaction is pattern based. It lowers the chance of a leak; it does not exclude one. A secret in
an unusual format, a bare 64-digit hex constant, or a name that is not on the host's list can
pass through. Review `--llm-dry-run` output before sending code that matters, and keep secrets
out of the project tree.

## Configuration

Only these environment variables are read for the model; nothing else is.

| Variable | Meaning |
|---|---|
| `ASSAY_LLM_BASE_URL` | Base URL of an OpenAI-compatible Chat Completions endpoint, for example `https://llm.example.org/v1`. Assay appends `/chat/completions`. |
| `ASSAY_LLM_API_KEY` | API key, sent as a bearer token. May be left unset only for a localhost endpoint. |
| `ASSAY_LLM_MODEL` | Model name sent in the request. |
| `ASSAY_LLM_TIMEOUT_S` | Optional. Request timeout in seconds, 1 to 600, default 60. |
| `ASSAY_LLM_MAX_TOKENS` | Optional. Reply token limit per call, 1 to 32768, default 1024. |

Rules enforced on the base URL: the scheme is `https`, or `http` for `localhost` and loopback
addresses only; it carries no user name or password, no query and no fragment. Redirects are
not followed, so the key is never forwarded to another host. Requests use temperature 0.

The key is held in an object that prints as `ApiKey(<redacted>)`. It is removed from every error
message, it is never written to a log, the ledger, a cassette or a bundle, and error messages
never repeat text returned by the endpoint. Commands print `SET` or `NOT SET` for a variable,
never its value.

### A local endpoint

Start any local inference server that offers an OpenAI-compatible Chat Completions API, then:

```sh
export ASSAY_LLM_BASE_URL=http://localhost:8000/v1
export ASSAY_LLM_MODEL=my-local-model
```

No key is needed unless the server asks for one. Nothing leaves the machine.

### A cloud endpoint

```sh
export ASSAY_LLM_BASE_URL=https://llm.example.org/v1
export ASSAY_LLM_API_KEY=...        # from the provider; keep it out of the repository
export ASSAY_LLM_MODEL=provider-model-name
```

The code of the project is sent to that provider when you pass `--allow-llm`. Check the
provider's terms before sending code that is not public.

### Turning it off

The layer is off unless asked for: the default mode is `replay`, sending needs `--allow-llm`,
and nothing is sent when the variables are unset. To be sure, unset the variables:

```sh
unset ASSAY_LLM_BASE_URL ASSAY_LLM_API_KEY ASSAY_LLM_MODEL
```

Continuous integration needs none of them; its jobs never call a model.

## Cassettes

Every request goes through one of three modes:

| Mode | Behavior |
|---|---|
| `replay` | The default. Answers from a cassette. A missing cassette is an error; replay never falls back to the network and needs no environment variable. |
| `record` | Needs `--allow-llm`. Calls the endpoint and writes the cassette. |
| `live` | Needs `--allow-llm`. Calls the endpoint and writes nothing. |

A cassette is a JSON file named by its key under `tests/data/cassettes/` (`--cassette-dir`
changes it). The key is the SHA-256 of the canonical request: the redacted messages and the
parameters, and nothing from the environment (not the model name, the endpoint or the per-call
token limit), so a cassette recorded on one machine replays on another. A cassette holds the
request, the reply, the host of the endpoint without credentials, and the model name that the
endpoint returned, exactly as it came, as a provenance note. It holds no header, no API key and
no absolute host path: a cassette that still looks like it does is not written. Cassettes that
were written by hand carry `"synthetic": true` and a note that starts with `SYNTHETIC`.

Replay checks that the stored request still hashes to the file name, so an edited cassette is
refused.

## Budgets

Every command has hard limits on the number of requests and on tokens (input plus output), counted
from the usage the endpoint reports, or from the cassette that replays it. Defaults are
4 requests and 20,000 tokens; `--budget-calls` and `--budget-tokens` change them. Each HTTP
attempt, including a retry, counts as a request. Reaching a limit stops the command with an
error that names it. An endpoint that reports no usage is an error, because the count would be
unknown.

Failed requests are retried at most twice, after 0.5 s and 1 s, for timeouts, connection
problems and HTTP 429 and 5xx. Other errors are not retried.

## Model output

The reply is untrusted input. A command that needs structured output accepts only one JSON
object that its strict model validates (no extra fields, bounded strings, at most 64 KiB and 32
levels of nesting, no duplicate keys). If the reply does not qualify, the model gets one chance
to repair the format, and then the command fails with a structured error. The reply is never
executed on the host and never reaches a shell. Replies pass through the same redaction as
requests before they are stored or returned.

## The ledger record

Each call is recorded as a `model_run` row: the endpoint host without credentials, the model
name as returned, the hash of the request, the hash of the reply, tokens in and out, latency and
the mode. Prompts and replies are not stored in the ledger. A `model_run` has no verdict and no
effect on a claim or a finding: statuses change only through oracle runs
([ADR 0005](adr/0005-only-deterministic-oracles-promote-claims.md)), and tests check that no
code path of the LLM layer creates a claim or changes a status.

## `assay prove`

```sh
assay prove <project dir> (--finding ID | --class CLASS)
            [--mode replay|record|live] [--allow-llm] [--llm-dry-run] [--max-attempts N]
            [--poc-dir DIR] [--cassette-dir DIR] [--budget-calls N] [--budget-tokens N]
            [--ledger FILE]
```

`prove` takes a candidate finding that `assay scan` recorded for this very version of the
project (`--class` picks the first candidate of that class) and tries to reproduce it with a
model-written PoC:

1. The target is refused when its `src/` reads the test environment (imports of a test library,
   Foundry's cheatcode, console or default-sender addresses, chain id 31337). Nothing runs then.
2. The model gets the finding, the analyzer text and the redacted source of the function it points
   at, not the whole repository, and returns a structured hypothesis: class, target function,
   attack idea, preconditions and the kind of predicate an exploit would show. The finding moves
   from `CANDIDATE` to `HYPOTHESIZED` at evidence level E0. A hypothesis never has a higher
   level.
3. For each attempt (3 by default, `--max-attempts` 1 to 5) the model returns one PoC file. The
   [static checker](#the-static-poc-checker) must accept it; only then is it written to the PoC
   directory, the finding moves to `POC_DRAFTED` (the first time), and the ExploitOracle runs it
   on the unpatched project in the sandbox, with three replays.
4. A PoC that the checker rejects, does not compile, does not reproduce or records no predicate
   gives the model short feedback (reason codes and clipped, redacted details, quoted as data)
   and the next attempt.
5. The finding ends `REPRODUCED` (evidence level E1) when an exploit run has the verdict `PASS`.
   When the attempts run out, the verdict of the last exploit run decides: `NOT_REPRODUCED` for
   `FAIL`, `INCONCLUSIVE` otherwise. A finding for which no PoC ever passed the checker stays
   `HYPOTHESIZED`.

Statuses and levels change only through the ledger and only on oracle evidence: every execution
is an `oracle_run` with a claim, every model call a `model_run`, and `REPRODUCED` names the run
that backs it. A model reply is never read as a verdict. `assay dev ledger-audit <db>` checks
the invariants afterwards: no claim `trusted` without an oracle run, no `REPRODUCED` or
`VERIFIED_WITHIN_BOUNDS` finding without oracle runs, no status that rests on a model run, and
an intact audit chain.

The PoC directory defaults to `.assay/poc/finding-<id>`. It must lie outside the project (the
project hash must not change) and must be empty or hold only the file `prove` writes.

| Exit code | Meaning |
|---|---|
| 0 | `REPRODUCED` |
| 1 | `NOT_REPRODUCED` |
| 2 | Usage error: consent missing, configuration, selector, finding not a candidate or recorded for another version of the project, bad options |
| 3 | `INCONCLUSIVE`, still `HYPOTHESIZED`, a budget limit, or a model reply that never qualified |
| 4 | Infrastructure: Docker or the runner image, the ledger, no cassette, endpoint failure |
| 5 | The project or the target was rejected, or a cassette is damaged |

`--llm-dry-run` prints the size and hash of the first payload (the hypothesis request) and sends
nothing.

## The static PoC checker

Before anything of a model-written PoC is written or run, a default-deny checker reads the
source as data (comments and string contents masked). A PoC passes only when all of this holds:

- it is ASCII, at most 32 KiB;
- it imports only `assay/AssayExploit.sol` and files under `../src/`;
- exactly one contract inherits `AssayPoC`, and it inherits nothing else; no other contract,
  library or interface inherits anything; no function is named like a test (`test*`,
  `invariant*`, `check*`, `prove*`, `setUp`) or starts with `assay`;
- `vm` is used only as `vm.<name>(` with a name from the allowlist: `prank`, `startPrank`,
  `stopPrank`, `deal`, `warp`, `roll`, `expectRevert`, `assume`, `label`, `sign`, `addr`,
  `toString`. File access, environment access, `vm.store`, `vm.etch`, `vm.mockCall`, forks and
  every other cheatcode are refused, and so are the `Vm` types, the cheatcode address (as a
  literal or derived from its seed text), inline assembly, console output, `selfdestruct`,
  `deployCode` and storage helpers;
- predicates come from the `AssayExploit` helpers: the PoC calls at least one of
  `attacker_profit`, `victim_loss`, `unauthorized_role_change`, `invariant_broken`, and never
  declares or emits events, names the predicate events or counter, or the harness entry points.

A PoC that breaks a rule is rejected with structured reasons (a code, a detail, a line) and never
runs. The checker is calibrated on the PoCs of the eight fixtures, which all pass.

## Threat model

Hostile instructions can sit in comments, NatSpec, identifiers, string literals, revert
messages and analyzer text. The defence is structural, not a filter:

- the model has no authority: its output is validated by strict models, checked statically, and
  executed only in the sandbox after the checks; statuses change only through oracle runs;
- the prompt is one JSON document in which everything from the project is quoted in a field
  named `untrusted_data`, so planted text cannot close a delimiter or start a section, and the
  system message says that the field holds data, never instructions;
- the PoC checker above refuses a PoC that a compromised model would write on request (`vm.ffi`,
  file or environment access, storage writes, forged predicate events);
- the ExploitOracle counts a predicate only from an event that the test contract itself emitted,
  with a kind the harness defines. Console lines in the harness format, an event with the same
  signature emitted by the target, and one emitted by a contract the PoC deploys do not count.
  A target that imports a test library or names Foundry's addresses is refused before `prove`
  runs anything, and the IntegrityOracle refuses it in a patch;
- prompts never hold seeds, fuzz settings or oracle code.

Tests in `tests/data/injection/` plant instructions in a target and replay a model that obeys
them: the checker refuses its PoCs, no command is started on the host, nothing is written outside
the PoC directory, and no claim or status rises without an oracle run. Tests in
`tests/data/forgery/` run forged evidence against the real sandbox.

Limits: a model can still be misled into a useless proposal and waste attempts; it cannot gain
authority. The checker is a pattern-based reader of source text and can refuse a harmless PoC. A
PoC that the checker accepts is only as strong as the sandbox it runs in, whose own limits are
described in the sandbox documentation. A PoC that could emit the predicate event from the test
contract is stopped by the checker, not by the oracle. Redaction can miss secrets, as described
above, so check `--llm-dry-run` before sending code that matters.

## `assay dev llm-ask`

A hidden command that sends one neutral question through the whole path.

```sh
assay dev llm-ask <text> [--mode replay|record|live] [--allow-llm] [--llm-dry-run]
                  [--cassette-dir DIR] [--budget-calls N] [--budget-tokens N] [--ledger FILE]
```

- `--llm-dry-run` prints the number of messages, the size and the SHA-256 of the payload that
  would be sent, and what redaction removed (counts only). It sends nothing, needs no consent and
  no configuration. The hash equals the cassette key of the request.
- Do not paste project code into `<text>`; it is meant for a connectivity check.

| Exit code | Meaning |
|---|---|
| 0 | Answered, or dry run |
| 2 | Usage error: consent missing, configuration missing or not allowed, bad option |
| 3 | A budget limit was reached, or the reply was not valid JSON for the expected format |
| 4 | No cassette, endpoint failure, or ledger problem |
| 5 | A cassette is damaged or does not match its key |

The repository ships one synthetic cassette for the question `Name one planet of the solar
system.` so the replay path can be tried and tested without a model:

```sh
assay dev llm-ask "Name one planet of the solar system."
```

## Limits

- Redaction is pattern based, as described above.
- A model that sees hostile text in the code (comments, strings, revert messages) can be misled
  into a useless proposal. It cannot gain authority: its output is validated, checked and
  executed only in the sandbox, and only oracle evidence changes a status.
- Results that involve a live model are not deterministic.
