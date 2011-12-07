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
package com.netscape.certsrv.policy;

import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;

/**
 * Interface for a policy rule.
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
public interface IPolicyRule extends com.netscape.certsrv.request.IPolicy {
    public static final String PROP_ENABLE = "enable";
    public static final String PROP_PREDICATE = "predicate";
    public static final String PROP_IMPLNAME = "implName";

    /**
     * Initializes the policy rule.
     * <P>
     * 
     * @param config The config store reference
     */
    void init(ISubsystem owner, IConfigStore config) throws EBaseException;

    /**
     * Gets the description for this policy rule.
     * <P>
     * 
     * @return The Description for this rule.
     */
    String getDescription();

    /**
     * Returns the name of the policy rule class.
     * <P>
     * 
     * @return The name of the policy class.
     */
    String getName();

    /**
     * Returns the name of the policy rule instance.
     * <P>
     * 
     * @return The name of the policy rule instance. If none is set the name of
     *         the implementation will be returned.
     * 
     */
    String getInstanceName();

    /**
     * Sets a predicate expression for rule matching.
     * <P>
     * 
     * @param exp The predicate expression for the rule.
     */
    void setPredicate(IExpression exp);

    /**
     * Returns the predicate expression for the rule.
     * <P>
     * 
     * @return The predicate expression for the rule.
     */
    IExpression getPredicate();

    /**
     * Applies the policy on the given Request. This may modify the request
     * appropriately.
     * <P>
     * 
     * @param req The request on which to apply policy.
     * @return The PolicyResult object.
     */
    PolicyResult apply(IRequest req);

    /**
     * Return configured parameters for a policy rule instance.
     * 
     * @return nvPairs A Vector of name/value pairs. Each name/value pair is
     *         constructed as a String in name=value format.
     */
    public Vector getInstanceParams();

    /**
     * Return default parameters for a policy implementation.
     * 
     * @return nvPairs A Vector of name/value pairs. Each name/value pair is
     *         constructed as a String in name=value.
     */
    public Vector getDefaultParams();

    public void setError(IRequest req, String format, Object[] params);

    public void setInstanceName(String instanceName);

    public void setPolicyException(IRequest req, EBaseException ex);
}
