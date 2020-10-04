<!-- markdownlint-disable MD024 -->
# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] (OpenSSH middleware API version 5) - xxxx-xx-xx

## [1.1.0] (OpenSSH middleware API version 5) - 2020-10-04

### Added

- You can now create and use keys created with `no-touch-required` option.

### Fixed

- Variable cleanup in an error handling case.
- Bug fixes.

## [1.0.2] (OpenSSH middleware API version 0x00050000) - 2020-09-01

### Changed

- Fine tuned some of output debug messages.

### Fixed

- `user_id` wasn't set properly([#4](https://github.com/tavrez/openssh-sk-winhello/issues/4)).

## [1.0.1] (OpenSSH middleware API version 0x00050000) - 2020-07-06

### Changed

- Skip check for WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable due to some problems(this may not fix it, it's actually for testing).

## [1.0.0] (OpenSSH middleware API version 0x00050000) - 2020-06-13

### Changed

- Since changes I made in `ssh-sk-helper` are approved and applied to OpenSSH source, this project now uses version 0x00050000 which is the API version of OpenSSH 8.3p1.

## [0.1.0] (OpenSSH middleware API version 0x001c0000) - 2020-04-01

### Added

- First version, support key generation and signing with key.

[Unreleased]: https://github.com/tavrez/openssh-sk-winhello/compare/v1.1.0...v1
[1.1.0]: https://github.com/tavrez/openssh-sk-winhello/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/tavrez/openssh-sk-winhello/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/tavrez/openssh-sk-winhello/compare/v1.0...v1.0.1
[1.0.0]: https://github.com/tavrez/openssh-sk-winhello/compare/v0.1...v1.0
[0.1.0]: https://github.com/tavrez/openssh-sk-winhello/releases/tag/v0.1
