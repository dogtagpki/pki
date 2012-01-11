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
import java.util.Hashtable;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ISubsystem;

/**
 * A generic interface for a policy processor. By making a processor
 * extend the policy interface, we make even the processor a rule -
 * which makes sense because a processor may be based on some rule
 * such as evaluate all policies before returning the final result or
 * return as soon as one of the policies return a failure and so on.
 * 
 * By making both processor and policy rules implement a common
 * interface, one can write rules that are processors as well.
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
public interface IPolicyProcessor extends ISubsystem,
        com.netscape.certsrv.request.IPolicy {

    public final static String PROP_DEF_POLICIES = "systemPolicies";
    public final static String PROP_UNDELETABLE_POLICIES = "undeletablePolicies";
    public final static String PROP_ENABLE = "enable";
    public final static String PROP_RULE = "rule";
    public final static String PROP_CLASS = "class";
    public final static String PROP_IMPL_NAME = "implName";
    public final static String PROP_PREDICATE = "predicate";
    public final static String PROP_IMPL = "impl";
    public final static String PROP_ORDER = "order";

    public ISubsystem getAuthority();

    /**
     * Returns the policy substore id.
     * 
     * @return storeID The policy store id used by this processor.
     */
    String getPolicySubstoreId();

    /**
     * Returns information on Policy impls.
     * 
     * @return An enumeration of strings describing the information
     *         about policy implementations. Currently only the
     *         the implementation id is expected.
     */
    Enumeration<String> getPolicyImplsInfo();

    /**
     * Returns the rule implementations registered with this processor.
     * 
     * @return An Enumeration of uninitialized IPolicyRule
     *         objects.
     */
    Enumeration<IPolicyRule> getPolicyImpls();

    /**
     * Returns an implementation identified by a given id.
     * 
     * @param id The implementation id.
     * @return The uninitialized instance of the policy rule.
     */
    IPolicyRule getPolicyImpl(String id);

    /**
     * Returns configuration for an implmentation.
     * 
     * @param id The implementation id.
     * @return A vector of name/value pairs in the form of
     *         name=value.
     */
    Vector<String> getPolicyImplConfig(String id);

    /**
     * Deletes a policy implementation identified by an impl id.
     * 
     * 
     * @param id The impl id of the policy to be deleted.
     *            There shouldn't be any active instance for this
     *            implementation.
     * @exception EBaseException is thrown if an error occurs in deletion.
     */
    void deletePolicyImpl(String id)
            throws EBaseException;

    /**
     * Adds a policy implementation identified by an impl id.
     * 
     * @param id The impl id of the policy to be added.
     *            The id should be unique.
     * @param classPath The fully qualified path for the implementation.
     * @exception EBaseException is thrown if an error occurs in addition.
     */
    void addPolicyImpl(String id, String classPath)
            throws EBaseException;

    /**
     * Returns information on Policy instances.
     * 
     * @return An Enumeration of Strings describing the information
     *         about policy rule instances.
     */
    Enumeration<String> getPolicyInstancesInfo();

    /**
     * Returns policy instances registered with this processor.
     * 
     * @return An Enumeration of policy instances.
     */
    Enumeration<IPolicyRule> getPolicyInstances();

    /**
     * Returns instance configuration for a given instance id.
     * 
     * @param id The rule id.
     * @return A vector of name/value pairs in the form of
     *         name=value.
     */
    Vector<String> getPolicyInstanceConfig(String id);

    /**
     * Returns instance configuration for a given instance id.
     * 
     * @param id The rule id.
     * @return the policy instance identified by the id.
     */
    IPolicyRule getPolicyInstance(String id);

    /**
     * Deletes a policy instance identified by an instance id.
     * 
     * @param id The instance id of the policy to be deleted.
     * @exception EBaseException is thrown if an error occurs in deletion.
     */
    void deletePolicyInstance(String id)
            throws EBaseException;

    /**
     * Adds a policy instance
     * 
     * @param id The impl id of the policy to be added.
     *            The id should be unique.
     * @param ht a Hashtable of config params.
     * @exception EBaseException is thrown if an error occurs in addition.
     */
    void addPolicyInstance(String id, Hashtable<String, String> ht)
            throws EBaseException;

    /**
     * Modifies a policy instance
     * 
     * @param id The impl id of the policy to be modified.
     *            The policy instance with this id should be present.
     * @param ht a Hashtable of config params.
     * @exception EBaseException is thrown if an error occurs in addition.
     */
    void modifyPolicyInstance(String id, Hashtable<String, String> ht)
            throws EBaseException;

    /**
     * Modifies policy ordering.
     * 
     * @param policyOrderStr The comma separated list of instance ids.
     * 
     */
    void changePolicyInstanceOrdering(String policyOrderStr)
            throws EBaseException;
}
