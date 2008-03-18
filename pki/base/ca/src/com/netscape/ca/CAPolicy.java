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
package com.netscape.ca;


import com.netscape.certsrv.policy.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.ca.*;

import com.netscape.cmscore.policy.*;
import com.netscape.cmscore.util.Debug;


/**
 * XXX Just inherit 'GenericPolicyProcessor' (from RA) for now. 
 * This really bad. need to make a special case just for connector. 
 * would like a much better way of doing this to handle both EE and 
 * connectors.
 * XXX2 moved to just implement IPolicy since GenericPolicyProcessor is 
 * unuseable for CA.
 * 
 * @version $Revision: 14646 $, $Date: 2007-05-04 14:17:27 -0700 (Fri, 04 May 2007) $
 */
public class CAPolicy implements IPolicy {
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

        String processorType =    // XXX - need to upgrade 4.2
            config.getString(PROP_PROCESSOR, PR_TYPE_CLASSIC);

        Debug.trace("selected policy processor = " + processorType);
        if (processorType.equals(PR_TYPE_CLASSIC)) {
            mPolicies = new GenericPolicyProcessor();
        } else {
            throw new EBaseException("Unknown policy processor type (" +
                    processorType + ")");
        }

        mPolicies.init(mCA, mConfig);
    }

    public boolean isProfileRequest(IRequest request) {
        String profileId = request.getExtDataInString("profileId");

        if (profileId == null || profileId.equals(""))
            return false;
        else
            return true;
    }

    /** 
     */
    public PolicyResult apply(IRequest r) {
        if (r == null) {
            Debug.trace("in CAPolicy.apply(request=null)");
            return PolicyResult.REJECTED;
        }

        Debug.trace("in CAPolicy.apply(requestType=" +
            r.getRequestType() + ",requestId=" + 
            r.getRequestId().toString() + ",requestStatus=" +  
            r.getRequestStatus().toString() + ")");

        if (isProfileRequest(r)) { 
            Debug.trace("CAPolicy: Profile-base Request " + 
                r.getRequestId().toString()); 

            CMS.debug("CAPolicy: requestId=" + 
                r.getRequestId().toString());

            String profileId = r.getExtDataInString("profileId");

            if (profileId == null || profileId.equals("")) { 
                return PolicyResult.REJECTED;
            }

            IProfileSubsystem ps = (IProfileSubsystem) 
                CMS.getSubsystem("profile"); 

            try {
                IProfile profile = ps.getProfile(profileId); 

                r.setExtData("dbStatus", "NOT_UPDATED");
                profile.populate(r); 
                profile.validate(r); 
                return PolicyResult.ACCEPTED;
            } catch (EBaseException e) {
                CMS.debug("CAPolicy: " + e.toString());
                return PolicyResult.REJECTED;
            }
        }
        Debug.trace("mPolicies = " + mPolicies.getClass());
        return mPolicies.apply(r);
    }

}

