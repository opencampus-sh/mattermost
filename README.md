Simple workflow to build a mattermost release tarball with patches
applied.

## Usage

The upstream mettermost version is specified in
`.github/workflows/build.yml` with the `VERSION` variable.
All patch files (files ending with .patch) in the root directory of the
repository are applied onto the specified mattermost version. When
adding new patches or changing them please make sure a description
exists and is up to date.

## License

The code is published under the AGPL version 3.0 only. See the
`LICENSE` file for details.
