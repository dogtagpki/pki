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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.legacy.kra;

import org.dogtagpki.legacy.core.policy.GenericPolicyProcessor;
import org.dogtagpki.legacy.policy.IPolicyProcessor;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * KRA Policy.
 *
 * @version $Revision$, $Date$
 */
public class KRAPolicy implements IPolicy {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAPolicy.class);

    IConfigStore mConfig = null;
    KeyRecoveryAuthority mKRA = null;

    public GenericPolicyProcessor mPolicies;

    public KRAPolicy() {
    }

    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mKRA = (KeyRecoveryAuthority) owner;
        mConfig = config;

        mPolicies = new GenericPolicyProcessor(false);
        mPolicies.init(mKRA, mConfig);
    }

    public IPolicyProcessor getPolicyProcessor() {
        return mPolicies;
    }

    /**
     */
    public PolicyResult apply(IRequest r) {
        logger.debug("KRA applies policies");
        mKRA.log(ILogger.LL_INFO, "KRA applies policies");
        PolicyResult result = mPolicies.apply(r);

        if (result.equals(PolicyResult.DEFERRED)) {
            // For KRA request, there is deferred
            logger.debug("KRA policies return DEFERRED");
            return PolicyResult.REJECTED;
        } else {
            logger.debug("KRA policies return ACCEPTED");
            return mPolicies.apply(r);
        }
    }

}
