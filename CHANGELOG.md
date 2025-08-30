# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2-rc.6] - 2025-08-30

### Changed

- Update MSTest to v3.10.3 - (deps) [cdb06ed](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=cdb06edd842d736e9c3848e57b66fcca24e2283c)
- Centralize MSBuild config via Directory.Build.props; drop MS_ARGS - [b997dc6](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=b997dc68dd5e1af1cb99d527e069b7cb01eb1790)
- Update `vnlib.core` to v0.1.2-rc.9 - (deps) [062259c](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=062259c1a71fea2eac10d11b84f9283e00eb6350)
- Update vnlib.plugins.extensions` to v0.1.2-rc.7 - (deps) [58d4fd1](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=58d4fd1a1a2ef54746c5a8232d101c2bfddc581c)
- Update `vnlib.data.caching` to v0.1.2-rc.7 - (deps) [663fd2c](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=663fd2c94909d61af0d93e526df4504262f68646)
- Update vnlib.browser dependencies and api-test packages - (deps) [c20a511](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=c20a511e046e47ccf314ed8888dec00b8265e1d7)

### Fixed

- Update usage of obsolete `Users.UpdatePasswordAsync` extension function - (accounts) [b977eee](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=b977eee50c55024314a3e5952f96c8413424d499)

## [0.1.2-rc.5] - 2025-08-15

### Added

- Add ProcessRoutine enum and refactor Route class - (routing) [3f7bd73](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=3f7bd73129dbe8953af6bf8eb151423c946f361e)
- Added optional route change detection support for routing stores - (router) [0c8f770](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=0c8f7706ed8c72109111c8b7c0f73c83ab89154b)
- Added xml route file change detection support. - (router) [7d39566](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=7d395665ecbfe70d65addd37703ad89ce08d70c8)
- Add better error handling and logging for xml route file errors - (router) [fc76dc7](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=fc76dc700fd218bee72a12f9c28c7e83243f9204)
- Added ability to ignore xml route format errors when loading routes - (router) [d41e401](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=d41e40151162f08d79d054cdafff02901d211cf5)
- Add a qol support for reading file routine enums as case-insensitive text or numbers - (router) [a6b033d](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=a6b033db66a8983976f6c06699384dcf5e1622a0)

### Changed

- Update MSTest packages to version 3.10.2 - (tests) [b27209b](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=b27209b32a8b99a889365057ac22bef5813a397a)
- Update vnlib.browser library dependencies - (deps) [93574b3](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=93574b3e71fdd18f5fb2ea33f458fd219a806115)
- Update api-test npm dependencies - (deps) [d5cc92a](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=d5cc92a5518d49e63be3941960cab2c4bf0e5912)
- Update vnlib.core to v0.1.2-rc.8 - (deps) [c0ea4ac](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=c0ea4ac884113d9de6d929dc04a032978260a8a2)
- Update vnlib.plugins.extensions to v0.1.2-rc.6 - (deps) [406c15f](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=406c15fa50b07bc1575802f2fee22845901a1192)
- Update vnlib.data.caching to v0.1.2-rc.6 - (deps) [d37237f](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=d37237f8bbfbac5f64fd88dc486567e527a47b5c)
- Updated the default configuration types to include "xml" store type - (routing) [90e4aaf](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=90e4aafd91b52f7a2073e3ea4dbd6c6add8a402f)
- Improved xml router confige with well-defined json types - (router) [75f602f](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=75f602f7e255c2db42d8a8e7e59e4ce08710eda2)
- Change `sample.routes.xml` to `sample-routes.xml` and publish to package output. - (router) [66cc750](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=66cc75073f463351ed774078c087048f89e3e861)
- Publish a sample page router plugin config json file to distribution - (router) [d9b7432](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=d9b74321eb58ce08eae1023d215aeb0ad9078a6f)

### Fixed

- Fall back to no route store when store unconfigured, warn users on invalid store type but silently fail to no router. - (router) [208ff19](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=208ff19ff964cd643ddb946af32e35a2d397daeb)
- Update router tests to use new syntax and configuration flags/options - (router) [86f847c](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=86f847c2a6c85de9de133fd2f40d1311e444a386)
- Fix api type merging issue in latest typescript updates - (browser) [9eba04a](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=9eba04aa0f4a3b942b19245da8c0cef854e0042e)

### Removed

- Removed sql routing store - (router) [81b4197](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=81b419716035d4b2c5ea0d84da0397112a08bb97)

## [0.1.2-rc.4] - 2025-07-31

### Changed

- Update vnlib.core to v0.1.2-rc.7 - (deps) [78168db](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=78168db2126e1389ea4348b5f38d00e5b0156e2e)
- Update vnlib.plugins.extensions to v0.1.2-rc.5 - (deps) [ad2dd0c](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=ad2dd0c437b192577f84e526a5950a5ceb556e58)
- Update and audit vnlib.browser npm dependencies - (deps) [43b53c6](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=43b53c6461ac0693fc526d66d3bfa299d2588c1b)
- Update vnlib.data.caching to v0.1.2-rc.5 - (deps) [65ccaa7](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=65ccaa7cada215a17301699c4e0dce8d51a75cc1)
- Update library readme to include latest vnlib information - (readme) [0a5bdc5](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=0a5bdc5a927a115e584a8aec80ca9fa73edf5b87)

### Fixed

- Fix vnlib.browser distribution package using npm pack - [43253eb](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=43253ebc3ecd021c58d4dfc683c3f60d69fb5dbd)

## [0.1.2-rc.3] - 2025-07-10

### Changed

- Update Yubico.YubiKey to 1.13.2 - (vauth) [9217000](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=9217000d95df240a3109eab2e5581235d2e55d53)
- Update MSTest packages to 3.9.3 - (tests) [7a5310a](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=7a5310ae7e7f057531dbe96fe940d136adda836f)
- Update ErrorProne.NET.CoreAnalyzers to 0.8.0-beta.1 - (libs) [8c815ac](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=8c815ac752c0bcfb6f7180eb5c74db06e3e7cf20)
- Update ErrorProne.NET.CoreAnalyzers to 0.8.0-beta.1 - (plugins) [91da54a](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=91da54afbd2829ff6fd211209822224a2758435b)
- Update vnlib.browser typescript dendencies - (vnlib.browser) [99d0737](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=99d0737511cec4a4e16d8270f6fd181fa2a25b4d)

## [0.1.2-rc.2] - 2025-06-14

### Changed

- Update npm dependencies for vnlib.browser library - (deps) [34db720](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=34db72020fe3e0f137a047679c00ad8989edb1e0)

### Fixed

- Integrate pending vnlib.data.caching upgrades - (plugins) [778b861](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=778b861b00ebb54a519592f5686644aaeda46848)

## [0.1.1] - 2025-05-16

### Added

- Add optional svg base64 icons for social OAuth2 connections - [f8aea64](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=f8aea6453ddb2d56c1ce2ecb6a9e67d1af523c2e)
- Add AppData client plugin and browser library updated - (app) [1082bd1](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=1082bd146549a1aff47877bcd28e6be1ce0ef5e9)
- Allow config to toggle strict user-agent checking - [34ca3d0](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=34ca3d09a96fb615d00e14abb4a70fe787fe1965)
- Adding fido as an mfa type - [e854846](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=e8548467d945ccb286da595a02c816abb596439d)
- Update caching with new helpers - [041941d](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=041941d85e5088837dc419d9ff1f1c9b70d41cbf)
- 4 WIP expand oidc using the new Account rpc api - [96ef78f](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=96ef78f3e104aff698dde17e8622d7905501c17f)
- Add session status to account rpc document - [ef52dac](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=ef52dac52b94a86a5fac34f2664c53a887a7c109)

### Changed

- Pull apart session authorization for future dev - [2a11454](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=2a114541a3bfddae887adaa98c1ed326b125d511)
- Preparing for WebAuthn and core updates - [1e8b429](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=1e8b4296d3a2093dbddcfd8479f162d077606f71)
- Massive jrpc migration and overhaul - [efe4c97](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=efe4c97b19e3bf682a8067814ce2af5626fa6bb4)

### Fixed

- #1 logout redirection updated to support social methods - [f2ac807](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=f2ac807486a00db4ba8486133d567e392f0fe98a)
- Dangling/expired session security check and cookie cleanup - [44803e0](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=44803e06d1aa45496c04127930aa8897272d42f6)
- Missing cookie set on cred regen - [377c8a5](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=377c8a5f8bb272eff5089094f5b764eb043b728f)
- Clearify log, fix package.json and origin validation - [073a57d](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=073a57dcfc613e329548602365103bb17e93605a)

### Refactor

- **Breaking Change:** Disable users auto "migrate" & add json config type - [a5fa032](https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/commit/?id=a5fa032810c4f5e4afde43cea157e28fa1547561)

[0.1.2-rc.6]: https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/diff?id=vv0.1.2-rc.6&id2=v0.1.2-rc.5
[0.1.2-rc.5]: https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/diff?id=v0.1.2-rc.5&id2=v0.1.2-rc.4
[0.1.2-rc.4]: https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/diff?id=v0.1.2-rc.4&id2=v0.1.2-rc.3
[0.1.2-rc.3]: https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/diff?id=v0.1.2-rc.3&id2=v0.1.2-rc.2
[0.1.2-rc.2]: https://git.vaughnnugent.com/cgit/vnuge/plugins-essentials.git/diff?id=v0.1.2-rc.2&id2=v0.1.1

<!-- generated by git-cliff -->
