# Plugins.Essentials  
This repository contains a collection of essential "Web Plugins" that are built to be loaded directly by a `ServiceStack` in your application, and conform to all required constrains for runtime loading. Some library packages my be consumed directly by your library/application to perform included functionality or provide a base class or set of classes to reduce complexity. Please see each package's readme.md file for further information.  

This repo will be used a small "mono-repo" for essential runtime loadable plugins that provide essential web-site/api functionality.  

This repo also now contains the [vnlib.browser](lib/vnlib.browser) TypeScript library, which is a collection of TypeScript classes and functions that are used to provide a consistent and easy to use interface for common web-site functionality.

## Project Information & Resources

#### Quick Links
The easiest way to access the .NET libraries is by adding the [VNLib NuGet feed](https://www.vaughnnugent.com/resources/software/modules#support-info-title) to your project.

- [Project Homepage](https://www.vaughnnugent.com/resources/software/modules/plugins.essentials)
- [Issue Tracker](https://www.vaughnnugent.com/resources/software/modules/plugins.essentials-issues) (GitHub issues are disabled)
- [Package Downloads](https://www.vaughnnugent.com/resources/software/modules/plugins.essentials?tab=downloads)
- [Documentation and Guides](https://www.vaughnnugent.com/resources/software/articles?tags=docs,_plugins.essentials)

#### Release Cycle & Distribution
VNLib follows a Continuous Delivery model, which allows for rapid and incremental development, aiming for small weekly releases. Projects are distributed as individual packages, and official distributions include:
- Pre-built binaries for most platforms that support Ahead-of-Time (AOT) compilation.
- Component-level source code and build scripts.
- SHA256 checksums and PGP cryptographic signatures for all packages.

#### API Stability & Versioning
As a fast-moving project, VNLib is effectively in a pre-release state.
- **Public APIs are subject to change**, potentially with little warning in any given release.
- Notable and breaking changes will be recorded in the [changelog](CHANGELOG.md) and commit messages.
- Obsoleted APIs will be marked with the `[Obsolete]` attribute where possible and are expected to be removed in a future release. While advance warning will be given, a strict API stability guarantee cannot be provided at this time.

#### Runtime Stability & Cross-Platform Support
A core pillar of VNLib is runtime stability. Great care is taken to ensure that components are reliable and that functionality, once working, continues to work as expected.

VNLib is designed to be cross-platform. Components should work on any platform that supports a C compiler or a modern .NET runtime. While integration testing is not performed on all operating systems, the architecture is platform-agnostic by design.

#### Contributing
Note that GitHub and Codeberg integrations are disabled. VNLib takes its independence seriously and does not use third-party platforms for development, issue tracking, or pull requests. Information about contributing to the project can be found on the official website. While the reach of free platforms is respected, project independence is a core value.

The project is, however, very interested in seeing what is built with VNLib! If you have created a plugin or a project you would like to share, please get in touch via the contact information on the official website.

## Donations
If you find VNLib valuable and wish to support its development, please consider making a donation. Your support helps fund the ongoing work and maintenance of the ecosystem.

**Fiat:** [PayPal](https://www.paypal.com/donate/?business=VKEDFD74QAQ72&no_recurring=0&item_name=By+donating+you+are+funding+my+love+for+producing+free+software+for+my+community.+&currency_code=USD)  
**On-Chain Bitcoin:** `bc1qgj4fk6gdu8lnhd4zqzgxgcts0vlwcv3rqznxn9`  
**LNURL:** `ChipTuner@coinos.io`
