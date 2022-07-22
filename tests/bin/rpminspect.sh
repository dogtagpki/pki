#!/bin/bash -e

# Don't run metadata check as we can't know the build host subdomain
# of CI runners in advance to add to an allow list

echo "Running RPMInspect on SRPM"
rpminspect-fedora -E metadata build/SRPMS/*.rpm

# Run RPMInspect on RPMs
for f in build/RPMS/*rpm; do

  echo "::group::Running RPMInspect on $f"
  if [[ "$f" == *"dogtag-pki-tools-"[0-9]* ]]
  then
    # "Don't run runpath test for dogtag-pki-tools as expect it to fail."
    # "dogtag-pki-tools utilizes internal libraries located under '%{_libdir}/tps'"
    rpminspect-fedora -E runpath,metadata,javabytecode "$f"
  else
    rpminspect-fedora -E metadata,javabytecode "$f"
  fi
  echo "::endgroup::"
  done
