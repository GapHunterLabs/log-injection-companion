# Log Injection Companion

Flags an unsanitized logging call reachable from an HTTP endpoint
parameter, anywhere in the project's real call graph.

## Why it exists

CWE-117 (Log Injection): an attacker injects a CRLF sequence to forge
fake log entries. SEI CERT IDS03-J ("Do not log unsanitized user
input"). AWS CodeGuru Reviewer has a dedicated detector -- CI/batch,
not an inline IDE inspection. Qodana's own taint analysis covers OWASP
A01/A03/A07/A08/A10 -- A09 (Security Logging and Monitoring Failures,
which Log Injection falls under) is confirmed NOT among them, and
Qodana taint analysis requires a paid Ultimate Plus license regardless
(not Community Edition). No dedicated Marketplace plugin found.

## Why built this way

- **A real whole-project interprocedural taint analysis** -- the
  hardest algorithmic technique in this catalog. Builds the actual
  project call graph, condenses it into strongly connected components
  via a real, from-scratch **Tarjan's algorithm** implementation
  (`TarjanSccComputer`, iterative rather than recursive to never
  overflow the stack on a deep real call graph), then computes each
  method's taint summary (which of ITS OWN parameters reach a logging
  call, directly or transitively) to a genuine FIXED POINT -- SCCs are
  processed callees-before-callers, and a cyclic SCC (mutual
  recursion) is iterated internally until nothing changes.
- **Cached by a TEXT key, never a raw `PsiMethod`** across the
  `CachedValuesManager` cache boundary (`MethodKey`) -- avoids relying
  on PSI object identity being stable between the project-wide scan
  that built the cache and a later, separately-obtained `PsiMethod`
  looking itself up in it.
- **Taint flows only through a bare reference or one-hop
  concatenation** (`TaintReferenceMatcher`) -- any wrapping method
  call, sanitizing or not, breaks the chain (a deliberate v0.1
  simplification that can only under-report, never over-report).
- **Logging call recognition is text-only** (`LoggingCallSignals`) --
  by the qualifier's own reference name (`log`/`logger`) or declared
  type text mentioning `Logger`, never resolved against the real
  SLF4J/Log4j2 classpath.

## v0.1 scope — stated honestly, not exhaustively

- Only project methods -- a call into a compiled library/dependency
  terminates that branch of the graph (assumed unknown, never
  inferred).
- A project with more than 3,000 total analyzable methods skips
  analysis entirely rather than risk pathological cost.
- Only `Logger.info/warn/error/debug/trace` (SLF4J/Log4j2/
  `java.util.logging`-shaped calls) -- a bespoke logging wrapper isn't
  recognized unless its own field/variable is literally named
  `log`/`logger`.

## Usage

Open a Java file with an HTTP endpoint method whose parameter reaches
an unsanitized `log.info(...)`/etc. call, whether directly or through
one or more helper method calls -- the log call (or the forwarding call
site closest to the endpoint) shows a warning.

## Support

- **Bugs and feature requests:** [GitHub Issues](https://github.com/GapHunterLabs/log-injection-companion/issues)
- **Questions, or custom rules for a team's codebase:** **gaphunterlabs@gmail.com**
- **Security vulnerabilities:** report privately as described in [SECURITY.md](SECURITY.md), not in a public issue.
- **Privacy and network behavior:** [PRIVACY.md](PRIVACY.md)

## Development

```
./gradlew test           # unit tests
./gradlew buildPlugin    # generates build/distributions/*.zip
./gradlew verifyPlugin   # checks compatibility against real IDEs
```

## License

Apache-2.0. See `LICENSE`.
