// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.selftests.common;

import java.util.Locale;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.logging.ILogEventListener;
import com.netscape.certsrv.selftests.EDuplicateSelfTestException;
import com.netscape.certsrv.selftests.EInvalidSelfTestException;
import com.netscape.certsrv.selftests.EMissingSelfTestException;
import com.netscape.certsrv.selftests.ESelfTestException;
import com.netscape.certsrv.selftests.ISelfTestSubsystem;
import com.netscape.cms.selftests.ASelfTest;
import com.netscape.cms.servlet.base.PKIService;

public class BannerVerification extends ASelfTest {

    public void initSelfTest(
            ISelfTestSubsystem subsystem,
            String instanceName,
            IConfigStore parameters)
            throws EDuplicateSelfTestException,
            EInvalidSelfTestException,
            EMissingSelfTestException {

        super.initSelfTest(subsystem, instanceName, parameters);
    }

    public void startupSelfTest() throws ESelfTestException {
    }

    public void shutdownSelfTest() {
    }

    public String getSelfTestDescription(Locale locale) {
        return "This self test is used to verify access banner.";
    }

    public void runSelfTest(ILogEventListener logger) throws Exception {

        try {
            boolean bannerEnabled = PKIService.isBannerEnabled();

            if (!bannerEnabled) {
                mSelfTestSubsystem.log(logger, "BannerVerification: Banner disabled");
                return;
            }

            PKIService.getBanner();

            mSelfTestSubsystem.log(logger, "BannerVerification: Banner valid");

        } catch (Exception e) {
            mSelfTestSubsystem.log(logger, "BannerVerification: " + e);
            throw e;
        }
    }
}
