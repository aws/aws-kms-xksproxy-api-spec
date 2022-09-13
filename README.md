## AWS KMS External Keystore (XKS) Proxy API Specification

This repository contains the AWS KMS External Keystore (XKS) Proxy API Specification in markdown format, which can be used to generate a PDF file via [pandoc](https://pandoc.org/).

### Install pandoc

```bash
# On OSX
brew install pandoc

# Or alternatively,
make install_pandoc_osx
```

### Generate PDF from markdown

```bash
# This would generate xks_proxy_api_spec_<version>.pdf under the build folder
make

# Create a source bundle of this repository
make bundle
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License Summary

The documentation is made available under the Creative Commons Attribution-ShareAlike 4.0 International License. See the LICENSE file.

The sample code within this documentation is made available under the MIT-0 license. See the LICENSE-SAMPLECODE file.
