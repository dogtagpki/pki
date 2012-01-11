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
package com.netscape.certsrv.publish;

import java.util.Enumeration;

import netscape.ldap.LDAPConnection;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.request.IRequest;

/**
 * Represents a set of publishing rules. Publishing rules are ordered from
 * lowest priority to highest priority. The priority assignment for publishing
 * rules is not enforced by this interface. Various implementation may
 * use different mechanisms such as a linear ordering of publishing rules
 * in a configuration file or explicit assignment of priority levels ..etc.
 * The publishing rule initialization needs to deal with reading the
 * publishing rules, sorting them in increasing order of priority and
 * presenting an ordered vector of publishing rules via the IPublishRuleSet
 * interface.
 * When a request comes, the predicates of the publishing rules will be
 * checked in the order to find the first matched publishing rule as the
 * mapping rule to (un)publish the object.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface IPublishRuleSet {
    void init(ISubsystem sys, IConfigStore conf) throws EBaseException;

    /**
     * Returns the name of the publishing rule set.
     * <P>
     * 
     * @return The name of the publishing rule set.
     */
    String getName();

    /**
     * Returns the no of publishing rules in a set.
     * <P>
     * 
     * @return the no of publishing rules.
     */
    int count();

    /**
     * Add a publishing rule
     * <P>
     * 
     * @param aliasName The name of the publishing rule to be added.
     * @param rule rule The publishing rule to be added.
     */
    void addRule(String aliasName, ILdapRule rule);

    /**
     * Removes a publishing rule identified by the given name.
     * 
     * @param ruleName The name of the publishing rule to be removed.
     */
    void removeRule(String ruleName);

    /**
     * Get the publishing rule identified by a given name.
     * <P>
     * 
     * @param ruleName The name of the publishing rule to be return.
     * @return The publishing rule identified by the given name or null if none exists.
     */
    ILdapRule getRule(String ruleName);

    /**
     * Get the publishing rule identified by a corresponding request.
     * <P>
     * 
     * @param req The request from which rule will be identified.
     * @return The publishing rule or null if none exists.
     */
    ILdapRule getRule(IRequest req);

    /**
     * Get an enumeration of publishing rules.
     * <P>
     * 
     * @return An enumeration of publishing rules.
     */
    Enumeration getRules();

    /**
     * Apply publishing rules on a request.
     * The predicates of the publishing rules will be checked in the order
     * to find the first matched publishing rule.
     * Use the mapper to find the dn of the LDAP entry and use the publisher
     * to publish the object in the request.
     * <P>
     * 
     * @param conn The Ldap connection
     * @param req The request to apply policies on.
     * @exception ELdapException publish failed due to Ldap error.
     */
    public void publish(LDAPConnection conn, IRequest req)
            throws ELdapException;
}
