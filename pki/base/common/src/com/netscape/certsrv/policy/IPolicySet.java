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

import java.util.Enumeration;

import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;

/**
 * Represents a set of policy rules. Policy rules are ordered from lowest
 * priority to highest priority. The priority assignment for rules is not
 * enforced by this interface. Various implementation may use different
 * mechanisms such as a linear ordering of rules in a configuration file or
 * explicit assignment of priority levels ..etc. The policy system
 * initialization needs to deal with reading the rules, sorting them in
 * increasing order of priority and presenting an ordered vector of rules via
 * the IPolicySet interface.
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
public interface IPolicySet {

    /**
     * Returns the name of the rule set.
     * <P>
     * 
     * @return The name of the rule set.
     */
    String getName();

    /**
     * Returns the no of rules in a set.
     * <P>
     * 
     * @return the no of rules.
     */
    int count();

    /**
     * Add a policy rule.
     * <P>
     * 
     * @param ruleName The name of the rule to be added.
     * @param rule The rule to be added.
     */
    void addRule(String ruleName, IPolicyRule rule);

    /**
     * Removes a policy rule identified by the given name.
     * 
     * @param ruleName The name of the rule to be removed.
     */
    void removeRule(String ruleName);

    /**
     * Returns the rule identified by a given name.
     * <P>
     * 
     * @param ruleName The name of the rule to be return.
     * @return The rule identified by the given name or null if none exists.
     */
    IPolicyRule getRule(String ruleName);

    /**
     * Returns an enumeration of rules.
     * <P>
     * 
     * @return An enumeration of rules.
     */
    Enumeration getRules();

    /**
     * Apply policy rules on a request. This call may modify the request
     * content.
     * 
     * @param req The request to apply policies on.
     * 
     *            <P>
     * @return The policy result.
     */
    PolicyResult apply(IRequest req);
}
