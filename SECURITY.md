# Security policy

## Supported versions

The project is pre-1.0. Only the tip of `main` (the most recent commit or
the most recent tagged pre-release, when tags exist) is supported with
security fixes. Older commits, forks, and locally modified deployments
are not supported; if you run a modified build, reproduce the issue on an
unmodified checkout before reporting it.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's private
vulnerability reporting:

**https://github.com/suhas-svg/TraceGuard/security/advisories/new**

That channel is visible only to repository maintainers. Do not open a
public issue, pull request, or discussion for an unpatched vulnerability.
If GitHub's private reporting is unavailable to you, open a minimal public
issue asking for a private channel and include no vulnerability details.

Please include:

1. What you found, and which commit or version it affects.
2. Steps to reproduce, ideally as a script or a failing test.
3. What you think the impact is, including the boundary you believe is
   crossed (gateway policy, approval, audit integrity, authentication,
   secret handling, or network isolation).
4. Any suggested fix or mitigation, if you have one.

## What to expect

- **Acknowledgment:** within 5 business days.
- **Triage:** an initial severity assessment and reproduction status.
- **Fix plan:** once confirmed, we agree on a remediation timeline and a
  coordinated disclosure date. Public disclosure waits until a patched
  release or commit exists.
- **Credit:** we will credit you in the advisory unless you ask us not to.

## Scope

In scope: the gateway and control listener, policy signing and bundle
loading, approval sealing and state machines, the audit hash chain and
checkpoint verification, authentication and workspace scoping, secret
handling, the OTLP ingestion boundary, container and network isolation in
the provided compose and Kubernetes manifests, and the reference clients
and demo stack where a flaw demonstrates a control-plane weakness.

Out of scope: the development API and approver keys shipped in
`docker-compose.yml` and `.env.example` (they are explicitly dev-only and
must never be used outside local development), missing hardening of a
modified deployment, self-XSS that requires pasting code into the console,
and denial-of-service reports that do not cross an isolation boundary.
Dependency vulnerabilities already public in the upstream package should
be reported upstream; if TraceGuard's pinned version is affected, a
private report here is still welcome.

## Safe harbor

We will not pursue legal action for research conducted in good faith on
your own deployment, that avoids privacy violations, data destruction, and
service disruption, and that gives us reasonable time to fix the issue
before disclosure.
