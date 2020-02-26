#!/bin/bash -ex

PACKAGES=`find ${BUILDDIR}/packages/RPMS/ -name '*.rpm' -and -not -name '*debuginfo*'`

# To list all packages that are available. Useful for debug purposes
echo -e ${PACKAGES}

dnf install -y --best --allowerasing ${PACKAGES}

# Remove the RPMs once installed. They are not required anymore. This will ensure
# that there is no issue generating next set of RPMs
rm ${PACKAGES}
