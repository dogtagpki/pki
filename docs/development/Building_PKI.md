Building PKI
============

## Getting the Source Code

To clone the source repository:

````bash
$ git clone git@github.com:dogtagpki/pki.git
$ cd pki
````

By default it will checkout the `master` branch.

To list available branches:

````bash
$ git branch -r
````

To switch to a different branch:

````bash
$ git checkout <branch>
````

The branch names follow the following formats:

- `master`
- `v<major>`
- `v<major>.<minor>`
- `DOGTAG_<major>_<minor>_BRANCH`

## Installing the Dependencies

During development PKI may require dependencies that are only available in [COPR repositories](https://github.com/dogtagpki/pki/wiki/COPR-Repositories).

The COPR repository names follow the following formats:

- `@pki/11.7`
- `@pki/<major>`
- `@pki/<major>.<minor>`

Enable the COPR repository that corresponds to the current branch:

````bash
$ sudo dnf copr -y enable <repository>
````

To install PKI dependencies:

````bash
$ sudo dnf builddep -y --spec pki.spec
````

## Building PKI

To build PKI:

````bash
$ ./build.sh [OPTIONS] <target>
````

Available targets:

- `dist`: build PKI binaries (default)
- `install`: install PKI binaries
- `src`: build RPM sources (tarball and patch)
- `spec`: build RPM sources and RPM spec
- `srpm`: build RPM sources, RPM spec, and SRPM package
- `rpm`: build RPM sources, RPM spec, SRPM package, and RPM packages


To build the binaries:

````bash
$ ./build.sh dist
````

It will build the binaries with the current files in the source directory.

The package version number and release number will be determined by the macros defined in the [pki.spec](../../pki.spec).

To install the binaries:

````bash
$ ./build.sh install
````

### Changing Working Directory

The default working directory is `~/build/pki`.
To change the working directory:

````bash
$ ./build.sh --work-dir=<path>
````

## Building RPM Packages

To build RPM packages:

````bash
$ ./build.sh rpm
````

The following subfolders will be created in the working directory:

- `BUILD`: contains unpacked source code
- `BUILDROOT`: contains installed binaries
- `RPMS`: contains the binary packages
- `SOURCES`: contains the tarball and patch files
- `SPECS`: contains the spec file
- `SRPMS`: contains the source package

### Adding Timestamp and Commit ID

To add the current timestamp and the latest commit ID of the current branch into the release number:

````bash
$ ./build.sh --with-timestamp --with-commit-id rpm
````

### Changing Distribution Name

The default distribution name can be obtained with the following command:

````bash
$ rpm --eval '%{dist}' | cut -c 2-
````

To change the distribution name:

````bash
$ ./build.sh --dist=<name> rpm
````

**Note:** The distribution name should not be prefixed with a dot (e.g. `fc36`).

### Building with Checked-in Source Code

To build with the source code already committed into the current branch:

````bash
$ ./build.sh --source-tag=HEAD rpm
````

This will produce the following file:

- `pki-<version>.tar.gz`: tarball containing the source code up to the `HEAD` of the branch

### Building with Patched Tarball

To build with a tarball and a patch file:

````bash
$ ./build.sh --source-tag=<tag> rpm
````

This will produce the following files:

- `pki-<version>.tar.gz`: a tarball containing the source code tagged with `<tag>`
- `pki-<version>-<release>.patch`: a combined patch containing all changes after  `<tag>` up to `HEAD`

### Building Select Packages


To build the specified packages only:

````bash
$ ./build.sh --with-pkgs=base,server,ca,kra,ocsp,tks,tps,acme rpm
````

To build everything except the specified packages:

````bash
$ ./build.sh --without-pkgs=javadoc,theme,meta,tests,debug rpm
````

Available packages:

- `base`
- `server`
- `ca`
- `kra`
- `ocsp`
- `tks`
- `tps`
- `acme`
- `javadoc`
- `theme`
- `meta`
- `tests`
- `debug`

### Installing RPM Packages

To install the RPM packages:

````bash
$ sudo dnf install ~/build/pki/RPMS/*
````
