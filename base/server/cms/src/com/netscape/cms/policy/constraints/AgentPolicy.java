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
package com.netscape.cms.policy.constraints;

import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.policy.EPolicyException;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.request.AgentApprovals;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * AgentPolicy is an enrollment policy wraps another policy module.
 * Requests are sent first to the contained module, but if the
 * policy indicates that the request should be deferred, a check
 * for agent approvals is done. If any are found, the request
 * is approved.
 * <P>
 *
 * <PRE>
 * NOTE:  The Policy Framework has been replaced by the Profile Framework.
 * </PRE>
 * <P>
 *
 * @deprecated
 * @version $Revision$, $Date$
 */
public class AgentPolicy extends APolicyRule
        implements IEnrollmentPolicy {
    public AgentPolicy() {
        NAME = "AgentPolicy";
        DESC = "Agent Approval Policy";
    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries may be of the form:
     *
     * ra.Policy.rule.<ruleName>.implName=AgentPolicy ra.Policy.rule.<ruleName>.enable=true
     * ra.Policy.rule.<ruleName>.predicate= ou == engineering AND o == netscape.com ra.Policy.rule.<ruleName>.class=xxxx
     * ra.Policy.rule.<ruleName>.params.*
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EPolicyException {

        // Create subordinate object
        String className = config.get("class");

        System.err.println("Creating agent policy with class " + className);
        if (className != null) {
            IConfigStore substore = config.getSubStore("params");

            try {
                @SuppressWarnings("unchecked")
                Class<APolicyRule> c = (Class<APolicyRule>) Class.forName(className);

                Object o = c.newInstance();

                if (!(o instanceof APolicyRule)) {
                    throw new EPolicyException(
                            CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_CLASS",
                                    getInstanceName(), className));
                }

                APolicyRule pr = (APolicyRule) o;

                pr.init(owner, substore);
                mPolicy = pr;
            } catch (EPolicyException e) {
                System.err.println("Agent Policy Error: " + e);
                throw e;
            } catch (Exception e) {
                System.err.println("Agent Policy Error: " + e);
                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_LOADING_POLICY_ERROR",
                                getInstanceName(), className));
            }
        }
    }

    /**
     * Applies the policy on the given Request.
     * <P>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {

        // The default is to require manual approval for everything
        PolicyResult result = PolicyResult.DEFERRED;

        // Give the underlying object a chance
        if (mPolicy != null) {
            result = mPolicy.apply(req);
            System.err.println("Subordinate policy returns " + result);
        }

        if (result == PolicyResult.DEFERRED) {
            System.err.println("Checking agent approvals");
            // Try to find an agent approval
            AgentApprovals aa = AgentApprovals.fromStringVector(
                    req.getExtDataInStringVector(AgentApprovals.class.getName()));

            //Object o = req.get("agentApprovals");

            // Any approvals causes success
            if (aa != null && aa.elements().hasMoreElements()) //if (o != null)
            {
                System.err.println("Agent approval found");
                result = PolicyResult.ACCEPTED;
            }
        }
        System.err.println("Agent policy returns " + result);
        return result;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        return null;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        return null;
    }

    APolicyRule mPolicy = null;
}
