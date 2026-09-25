<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# Log Injection Companion Changelog

## [Unreleased]

## [0.1.2]

### Fixed

- Review/star CTA now links to this plugin's own Marketplace
  reviews page instead of the vendor's generic plugin list.

## [0.1.1]

### Fixed

- The interprocedural taint fixed-point computation (whole-project
  Tarjan-SCC + per-file scan) now checks for cancellation
  (`ProgressManager.checkCanceled()`) once per file and once per
  fixed-point iteration -- a large real project could previously block
  the read action uncancellably while the user kept typing. Catalog-wide
  gap found via manual review, retrofitted here.

## [0.1.0]

### Added

- Real whole-project interprocedural taint analysis: the project call
  graph, condensed via a from-scratch Tarjan's SCC algorithm, with
  per-method taint summaries computed to a real fixed point --
  flagging an HTTP endpoint parameter that reaches an unsanitized
  logging call anywhere in the real call graph (CWE-117).

[Unreleased]: https://github.com/GapHunterLabs/log-injection-companion/compare/0.1.2...HEAD
[0.1.2]: https://github.com/GapHunterLabs/log-injection-companion/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/GapHunterLabs/log-injection-companion/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/GapHunterLabs/log-injection-companion/commits/0.1.0
