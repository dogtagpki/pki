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
package org.dogtagpki.legacy.ca;

import org.dogtagpki.legacy.core.policy.GenericPolicyProcessor;
import org.dogtagpki.legacy.policy.IPolicyProcessor;
import org.dogtagpki.server.ca.ICertificateAuthority;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.request.IPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.profile.common.IProfile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.profile.ProfileSubsystem;

/**
 * XXX Just inherit 'GenericPolicyProcessor' (from RA) for now.
 * This really bad. need to make a special case just for connector.
 * would like a much better way of doing this to handle both EE and
 * connectors.
 * XXX2 moved to just implement IPolicy since GenericPolicyProcessor is
 * unuseable for CA.
 *
 * @version $Revision$, $Date$
 */
public class CAPolicy implements IPolicy {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAPolicy.class);

    IConfigStore mConfig = null;
    ICertificateAuthority mCA = null;

    public static String PROP_PROCESSOR =
            "processor";
    // These are the different types of policy that are
    // allowed for the "processor" property
    public static String PR_TYPE_CLASSIC = "classic";

    // XXX this way for now since generic just works for EE.
    public GenericPolicyProcessor mPolicies = null;

    public CAPolicy() {
    }

    public IPolicyProcessor getPolicyProcessor() {
        return mPolicies;
    }

    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mCA = (ICertificateAuthority) owner;
        mConfig = config;

        String processorType = // XXX - need to upgrade 4.2
        config.getString(PROP_PROCESSOR, PR_TYPE_CLASSIC);

        logger.debug("selected policy processor = " + processorType);
        if (processorType.equals(PR_TYPE_CLASSIC)) {
            mPolicies = new GenericPolicyProcessor();
        } else {
            throw new EBaseException("Unknown policy processor type (" +
                    processorType + ")");
        }

        mPolicies.init(mCA, mConfig);
    }

    public boolean isProfileRequest(IRequest request) {
        String profileId = request.getExtDataInString(IRequest.PROFILE_ID);

        if (profileId == null || profileId.equals(""))
            return false;
        else
            return true;
    }

    /**
     */
    public PolicyResult apply(IRequest r) {
        if (r == null) {
            logger.debug("in CAPolicy.apply(request=null)");
            return PolicyResult.REJECTED;
        }

        logger.debug("in CAPolicy.apply(requestType=" +
                r.getRequestType() + ",requestId=" +
                r.getRequestId().toString() + ",requestStatus=" +
                r.getRequestStatus().toString() + ")");

        CMSEngine engine = CMS.getCMSEngine();
        if (isProfileRequest(r)) {
            logger.debug("CAPolicy: Profile-base Request " +
                    r.getRequestId().toString());

            logger.debug("CAPolicy: requestId=" +
                    r.getRequestId().toString());

            String profileId = r.getExtDataInString(IRequest.PROFILE_ID);

            if (profileId == null || profileId.equals("")) {
                return PolicyResult.REJECTED;
            }

            ProfileSubsystem ps = (ProfileSubsystem) engine.getSubsystem(ProfileSubsystem.ID);

            try {
                IProfile profile = ps.getProfile(profileId);

                r.setExtData("dbStatus", "NOT_UPDATED");
                profile.populate(r);
                profile.validate(r);
                return PolicyResult.ACCEPTED;
            } catch (EBaseException e) {
                logger.error("CAPolicy: " + e, e);
                return PolicyResult.REJECTED;
            }
        }
        logger.debug("mPolicies = " + mPolicies.getClass());
        return mPolicies.apply(r);
    }

}
