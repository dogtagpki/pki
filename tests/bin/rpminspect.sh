#!/bin/bash -e

echo "Running RPMInspect on SRPM"
rpminspect-fedora -p pki-rpminspect build/SRPMS/*.rpm

# Run RPMInspect on RPMs
for f in build/RPMS/*rpm; do
  echo "::group::Running RPMInspect on $f"
  rpminspect-fedora -p pki-rpminspect "$f"
  echo "::endgroup::"
done
