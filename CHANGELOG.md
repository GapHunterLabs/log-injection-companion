<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# Log Injection Companion Changelog

## [Unreleased]

## [0.1.0]

### Added

- Real whole-project interprocedural taint analysis: the project call
  graph, condensed via a from-scratch Tarjan's SCC algorithm, with
  per-method taint summaries computed to a real fixed point --
  flagging an HTTP endpoint parameter that reaches an unsanitized
  logging call anywhere in the real call graph (CWE-117).

[Unreleased]: https://github.com/GapHunterLabs/log-injection-companion/compare/0.1.0...HEAD
[0.1.0]: https://github.com/GapHunterLabs/log-injection-companion/commits/0.1.0
