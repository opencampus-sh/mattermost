Simple workflow to build a mattermost release tarball with patches
applied.

## Usage

The upstream mettermost version is specified in the `VERSION` file.
All patch files (files ending with .patch) in the root directory of the
repository are applied onto the specified mattermost version. Files
inside of the `overlay/` directory are copied directly. When adding new
patches or changing them please make sure a description exists and is
up to date.

## License

The code is published under the AGPL version 3.0 only unless otherwise
specified in the file. See the `LICENSE` file for details.
