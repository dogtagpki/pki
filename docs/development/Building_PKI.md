Building PKI
============

## Getting the Source Code

To clone the source repository:

<pre>
$ git clone git@github.com:dogtagpki/pki.git
$ cd pki
</pre>

By default it will checkout the master branch.

To list available branches:

<pre>
$ git branch -r
</pre>

To switch to a different branch:

<pre>
$ git checkout &lt;branch&gt;
</pre>

The branch names follow the following format:

<pre>
DOGTAG_&lt;major&gt;_&lt;minor&gt;_BRANCH
</pre>

## Installing the Dependencies

During development PKI may require dependencies that are only available in [PKI COPR](https://www.dogtagpki.org/wiki/PKI_COPR) repository.

To enable PKI COPR repository:

<pre>
$ dnf copr -y enable @pki/&lt;major&gt;.&lt;minor&gt;
</pre>

To install PKI dependencies:

<pre>
$ dnf builddep -y --spec pki.spec
</pre>

## Building PKI Packages

To build PKI packages:

<pre>
$ ./build.sh [OPTIONS] &lt;target&gt;
</pre>

Available packages:
* base
* server
* ca
* kra
* ocsp
* tks
* tps
* javadoc
* console
* theme
* meta
* debug

Available targets:
* src: build RPM sources (tarball and patch)
* spec: build RPM spec and everything above
* srpm: build SRPM package and everything above
* rpm: build RPM packages and everything above (default)

The default working directory is $HOME/build/pki. During the build process the following subfolders will be created:
* BUILD: contains unpacked source code
* BUILDROOT: contains installed binaries
* RPMS: contains the binary packages
* SOURCES: contains the tarball and patch files
* SPECS: contains the spec file
* SRPMS: contains the source package

To start the build process:

<pre>
$ ./build.sh
</pre>

It will build all packages with the current files in the source directory.

The package version number and release number will be determined by the Version and Release attributes in the [pki.spec](../../pki.spec).

### Changing Working Directory

To change the working directory:

<pre>
$ ./build.sh --work-dir=&lt;working directory&gt;
</pre>

### Adding Timestamp and Commit ID

To add the current timestamp and the latest commit ID of the current branch into the release number:

<pre>
$ ./build.sh --with-timestamp --with-commit-id
</pre>

### Changing Distribution Name

The default distribution name can be obtained with the following command:

<pre>
$ rpm --eval '%{dist}' | cut -c 2-
</pre>

To change the distribution name:

<pre>
$ ./build.sh --dist=&lt;distribution name&gt;
</pre>

**Note:** The distribution name should not be prefixed with a dot (e.g. fc28).

### Building with Checked-in Source Code

To build with the source code already checked into the current branch:

<pre>
$ ./build.sh --source-tag=HEAD
</pre>

This will produce the following source:
* pki-&lt;version&gt;.tar.gz: tarball containing the source code up to the HEAD of the branch

### Building with Patched Tarball

To build with a tarball and a patch file:

<pre>
$ ./build.sh --source-tag=&lt;tag&gt;
</pre>

This will produce the following sources:
* pki-&lt;version&gt;.tar.gz: a tarball containing the source code tagged with &lt;tag&gt;
* pki-&lt;version&gt;-&lt;release&gt;.patch: a combined patch containing all changes after &lt;tag&gt; up to HEAD

### Building Select Packages

To build specified packages only:

<pre>
$ ./build.sh --with-pkgs=base,server,ca,kra
</pre>

To build everything except the specified packages:

<pre>
$ ./build.sh --without-pkgs=base,server,ca,kra
</pre>

It is equivalent to:

<pre>
$ ./build.sh --with-pkgs=ocsp,tks,tps,javadoc,console,theme,meta,debug
</pre>

## Installing PKI Packages

To install the newly built packages:

<pre>
$ dnf install $HOME/build/pki/RPMS/*
</pre>
