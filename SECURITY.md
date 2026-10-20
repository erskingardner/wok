# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
[report a vulnerability](https://github.com/erskingardner/wok/security/advisories/new).
Do not open a public issue or pull request for a security problem.

Please include:

- the Wok version or commit, and how you run it (transport, reverse proxy,
  relevant configuration);
- what an attacker can do, and what access they need, for example an
  unauthenticated client, an authenticated client, or local access;
- steps or a script to reproduce it, ideally against a fresh local relay.

We will confirm receipt, work with you on a fix, and credit you in the advisory
unless you would rather not be named. Please give us a reasonable chance to
release a fix before you disclose the problem publicly.

## Supported versions

Fixes go to `master` and ship in the next release. Only the latest release
receives security fixes; upgrade to it before reporting.

## Scope

In scope:
- the `wok` relay and its transports (WebSocket, HTTP, NIP-11, the Unix
  socket);
- AUTH and read restrictions;
- the NIP-86 management API and the admin dashboard;
- storage, migration and the other `wok` subcommands.

Examples of what counts:
- reading events a client should not see, such as restricted kinds or gift
  wraps addressed to someone else;
- bypassing AUTH or write restrictions;
- crashing the relay or exhausting its resources beyond the documented limits;
- corrupting or losing stored data;
- memory-safety bugs.

Out of scope:
- problems that need a configuration the deployment guide warns against, such
  as an exposed admin interface or a trusted forwarded-IP header on a listener
  clients can reach directly;
- vulnerabilities in strfry itself.

## More detail

- [docs/security.md](docs/security.md): the threat model, input limits, the
  unsafe-code boundary, dependency policy, fuzzing and adversarial testing.
- [docs/production-deployment.md](docs/production-deployment.md): how to run a
  hardened relay.
