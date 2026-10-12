# Security policy

## Supported versions

Assay is in early development and has no release yet. Only the latest state of the `main` branch
receives fixes.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting: open the
**Security** tab of the repository and choose **Report a vulnerability**. Do not open a public
issue for a suspected vulnerability.

If you cannot use GitHub's private reporting, write to the maintainer, Vassel Goleyu, by email at
vassel.jgo@gmail.com, or by WhatsApp at +62 878-6891-8900. Do not put the details of a
vulnerability in a public place.

A useful report contains the affected version or commit, the steps to reproduce, the expected and
the observed behavior, and the impact. Reports are acknowledged as soon as possible; there is no
formal response deadline. Fixes and their disclosure are coordinated with the reporter.

In scope, in particular:

- escaping the runner sandbox, or reaching the network or host files from inside it
  (see [docs/sandbox.md](docs/sandbox.md));
- making a wrong patch receive `VERIFIED_WITHIN_BOUNDS`, or forging oracle evidence;
- changing a claim's status without a matching oracle run;
- tampering with an evidence bundle without replay detecting it;
- leaking secrets, such as an API key, into logs, cassettes, bundles or model requests.

Out of scope:

- the intentional vulnerabilities in the fixtures under `fixtures/` and `bench/heldout/`;
- kernel vulnerabilities, flaws in the Docker Desktop virtual machine and hardware side channels,
  which the sandbox documentation lists as not covered;
- bounds that are stated and known, such as a variant that the search does not reach because it
  does not randomize the block environment (see [the self-audit](docs/audit.md), finding B1, and
  [the limitations](docs/limitations.md)); a new way to pass a wrong patch that the bounds do not
  already describe is in scope.

The self-audit and the evidence for every claim are documented in [docs/audit.md](docs/audit.md)
and [docs/claims.md](docs/claims.md).

## Usage policy

- Assay simulates locally only. It runs Foundry's in-process EVM inside an offline container. It
  does not fork mainnet or any other live network, and it does not connect to RPC endpoints.
- Assay contains no code that signs or broadcasts transactions or interacts with a mempool.
  Contributions that add such capabilities are not accepted.
- The fixtures are synthetic contracts that are vulnerable on purpose. Every fixture source file
  carries the header `INTENTIONALLY VULNERABLE: test fixture, do not deploy`. Never deploy them.
- Use Assay only on code that you are authorized to analyze.
