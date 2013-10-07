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
package com.netscape.cmscore.policy;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.EPolicyException;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.policy.IExpression;
import com.netscape.certsrv.policy.IKeyArchivalPolicy;
import com.netscape.certsrv.policy.IKeyRecoveryPolicy;
import com.netscape.certsrv.policy.IPolicyProcessor;
import com.netscape.certsrv.policy.IPolicyRule;
import com.netscape.certsrv.policy.IPolicySet;
import com.netscape.certsrv.policy.IRenewalPolicy;
import com.netscape.certsrv.policy.IRevocationPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SubsystemRegistry;
import com.netscape.cmscore.request.ARequestQueue;
import com.netscape.cmscore.util.AssertionException;
import com.netscape.cmscore.util.Debug;

/**
 * This is a Generic policy processor. The three main functions of
 * this class are:
 * 1. To initialize policies by reading policy configuration from the
 * config file, and maintain 5 sets of policies - viz Enrollment,
 * Renewal, Revocation and KeyRecovery and KeyArchival.
 * 2. To apply the configured policies on the given request.
 * 3. To enable policy listing/configuration via MCC console.
 *
 * Since the policy processor also implements the IPolicy interface
 * the processor itself presents itself as one big policy to the
 * request processor.
 *
 * @deprecated
 * @author kanda
 * @version $Revision$, $Date$
 */
public class GenericPolicyProcessor implements IPolicyProcessor {
    protected IConfigStore mConfig = null;
    protected IConfigStore mGlobalStore = null;
    protected IAuthority mAuthority = null;

    // Default System Policies
    public final static String[] DEF_POLICIES =
        { "com.netscape.cms.policy.constraints.ManualAuthentication" };

    // Policies that can't be deleted nor disabled.
    public final static Hashtable<String, IExpression> DEF_UNDELETABLE_POLICIES =
            new Hashtable<String, IExpression>();

    private String mId = "Policy";
    private Vector<String> mPolicyOrder = new Vector<String>();
    private Hashtable<String, RegisteredPolicy> mImplTable = new Hashtable<String, RegisteredPolicy>();
    private Hashtable<String, PolicyInstance> mInstanceTable = new Hashtable<String, PolicyInstance>();
    PolicySet mEnrollmentRules = new PolicySet("EnrollmentRules");
    PolicySet mRenewalRules = new PolicySet("RenewalRules");
    PolicySet mRevocationRules = new PolicySet("RevocationRules");
    PolicySet mKeyRecoveryRules = new PolicySet("KeyRecoveryRules");
    PolicySet mKeyArchivalRules = new PolicySet("KeyArchivalRules");
    private String[] mSystemDefaults = null;
    private boolean mInitSystemPolicies;

    // A Table of persistent policies and their predicates.
    // The predicates cannot be changed during configuration.
    private Hashtable<String, IExpression> mUndeletablePolicies = null;

    public GenericPolicyProcessor() {
        mInitSystemPolicies = true; // CA & RA
    }

    public GenericPolicyProcessor(boolean initSystemPolicies) {
        mInitSystemPolicies = initSystemPolicies; // KRA
    }

    public void setId(String id) throws EBaseException {
        mId = id;
    }

    public String getId() {
        return mId;
    }

    public void startup() throws EBaseException {
    }

    /**
     * Shuts down this subsystem.
     * <P>
     */
    public void shutdown() {
    }

    public ISubsystem getAuthority() {
        return mAuthority;
    }

    /**
     * Returns the configuration store.
     * <P>
     *
     * @return configuration store
     */
    public synchronized IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Initializes the PolicyProcessor
     * <P>
     *
     * @param owner owner of this subsystem
     * @param config configuration of this subsystem
     * @exception EBaseException failed to initialize this Subsystem.
     */
    public synchronized void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        // Debug.trace("GenericPolicyProcessor::init");
        CMS.debug("GenericPolicyProcessor::init begins");
        mAuthority = (IAuthority) owner;
        mConfig = config;
        mGlobalStore =
                SubsystemRegistry.getInstance().get("MAIN").getConfigStore();

        try {
            IConfigStore configStore = CMS.getConfigStore();
            String PKI_Subsystem = configStore.getString("subsystem.0.id",
                                                          null);

            // CMS 6.1 began utilizing the "Certificate Profiles" framework
            // instead of the legacy "Certificate Policies" framework.
            //
            // Beginning with CS 8.1, to meet the Common Criteria evaluation
            // performed on this version of the product, it was determined
            // that this legacy "Certificate Policies" framework would be
            // deprecated and disabled by default (see Bugzilla Bug #472597).
            //
            // NOTE:  The "Certificate Policies" framework ONLY applied to
            //        to CA, KRA, and legacy RA (pre-CMS 7.0) subsystems.
            //
            if (PKI_Subsystem.trim().equalsIgnoreCase("ca") ||
                    PKI_Subsystem.trim().equalsIgnoreCase("kra")) {
                String policyStatus = PKI_Subsystem.trim().toLowerCase()
                                    + "." + "Policy"
                                    + "." + IPolicyProcessor.PROP_ENABLE;

                if (configStore.getBoolean(policyStatus, true) == true) {
                    // NOTE:  If "<subsystem>.Policy.enable=<boolean>" is
                    //        missing, then the referenced instance existed
                    //        prior to this name=value pair existing in its
                    //        'CS.cfg' file, and thus we err on the
                    //        side that the user may still need to
                    //        use the policy framework.
                    CMS.debug("GenericPolicyProcessor::init Certificate "
                             + "Policy Framework (deprecated) "
                             + "is ENABLED");
                } else {
                    // CS 8.1 Default:  <subsystem>.Policy.enable=false
                    CMS.debug("GenericPolicyProcessor::init Certificate "
                             + "Policy Framework (deprecated) "
                             + "is DISABLED");
                    return;
                }
            }
        } catch (EBaseException e) {
            throw e;
        }

        // Initialize default policies system that would be
        // present in the system always.
        if (mInitSystemPolicies) {
            initSystemPolicies(mConfig);
        }

        // Read listing of undeletable policies if any.
        initUndeletablePolicies(mConfig);

        // Read all registered policies first..
        IConfigStore c;

        c = config.getSubStore(PROP_IMPL);
        Enumeration<String> mImpls = c.getSubStoreNames();

        while (mImpls.hasMoreElements()) {
            String id = mImpls.nextElement();

            // The implementation id should be unique
            if (mImplTable.containsKey(id))
                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_DUPLICATE_IMPL_ID", id));

            String clPath = c.getString(id + "." + PROP_CLASS);

            // We should n't let the CatchAll policies to be configurable.
            if (isSystemDefaultPolicy(clPath))
                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_SYSTEM_POLICY_CONFIG_ERROR", clPath));

            // Verify if the class is a valid implementation of
            // IPolicyRule
            try {
                Object o = Class.forName(clPath).newInstance();

                if (!(o instanceof IEnrollmentPolicy) &&
                        !(o instanceof IRenewalPolicy) &&
                        !(o instanceof IRevocationPolicy) &&
                        !(o instanceof IKeyRecoveryPolicy) &&
                        !(o instanceof IKeyArchivalPolicy))
                    throw new EPolicyException(
                            CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_IMPL", clPath));
            } catch (EBaseException e) {
                throw e;
            } catch (Exception e) {
                Debug.printStackTrace(e);
                throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_NO_POLICY_IMPL",
                            id));
            }

            // Register the implementation.
            RegisteredPolicy regPolicy =
                    new RegisteredPolicy(id, clPath);

            mImplTable.put(id, regPolicy);
        }

        // Now read the priority ordering of rule configurations.
        String policyOrder = config.getString(PROP_ORDER, null);

        if (policyOrder == null) {
            return;
            // throw new EPolicyException(PolicyResources.NO_POLICY_ORDERING);
        } else {
            StringTokenizer tokens = new StringTokenizer(policyOrder, ",");

            while (tokens.hasMoreTokens()) {
                mPolicyOrder.addElement(tokens.nextToken().trim());
            }
        }

        // Now Read Policy configurations and construct policy objects
        int numPolicies = mPolicyOrder.size();
        IConfigStore ruleStore = config.getSubStore(PROP_RULE);

        for (int i = 0; i < numPolicies; i++) {
            String instanceName = mPolicyOrder.elementAt(i);

            // The instance id should be unique
            if (mInstanceTable.containsKey(instanceName))
                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_DUPLICATE_INST_ID", instanceName));

            c = ruleStore.getSubStore(instanceName);
            if (c == null || c.size() == 0)
                throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_NO_POLICY_CONFIG",
                            instanceName));
            IPolicyRule rule = null;
            String implName;
            boolean enabled;
            IExpression filterExp;

            // If the policy rule is not enabled, skip it.
            String enabledStr = c.getString(PROP_ENABLE, null);

            if (enabledStr == null || enabledStr.trim().length() == 0 ||
                    enabledStr.trim().equalsIgnoreCase("true"))
                enabled = true;
            else
                enabled = false;

            implName = c.getString(PROP_IMPL_NAME, null);
            if (implName == null) {
                throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_NO_POLICY_CONFIG",
                            instanceName));
            }

            // Make an instance of the specified policy.
            RegisteredPolicy regPolicy = mImplTable.get(implName);

            if (regPolicy == null) {
                String[] params = { implName, instanceName };

                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_IMPL_NOT_FOUND", params));
            }

            String classpath = regPolicy.getClassPath();

            try {
                rule = (IPolicyRule)
                        Class.forName(classpath).newInstance();
                rule.setInstanceName(instanceName);
                rule.init(this, c);
            } catch (Throwable e) {
                mAuthority.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_POLICY_INIT_FAILED", instanceName, e.toString()));
                // disable rule initialized if there is
                // configuration error
                enabled = false;
                c.putString(PROP_ENABLE, "false");
            }

            if (rule == null)
                continue;

            // Read the predicate expression if any associated
            // with the rule
            String exp = c.getString(GenericPolicyProcessor.PROP_PREDICATE, null);

            if (exp != null)
                exp = exp.trim();
            if (exp != null && exp.length() > 0) {
                filterExp = PolicyPredicateParser.parse(exp);
                rule.setPredicate(filterExp);
            }

            // Add the rule to the instance table
            mInstanceTable.put(instanceName,
                    new PolicyInstance(instanceName, implName, rule, enabled));

            if (!enabled)
                continue;

            // Add the rule to the policy set according to category if a
            // rule is enabled.
            addRule(instanceName, rule);
        }

        // Verify that the default policies are present and enabled.
        verifyDefaultPolicyConfig();

        // printPolicies();
    }

    public boolean isProfileRequest(IRequest request) {
        String profileId = request.getExtDataInString("profileId");

        if (profileId == null || profileId.equals(""))
            return false;
        else
            return true;
    }

    /**
     * Apply policies on the given request.
     *
     * @param IRequest The given request
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        IPolicySet rules = null;
        String op = req.getRequestType();

        CMS.debug("GenericPolicyProcessor: apply begins");
        if (op == null) {
            CMS.debug("GenericPolicyProcessor: apply op null");
            // throw new AssertionException("Missing operation type in request. Can't happen!");
            // Return ACCEPTED for now. Looks like even get CA chain
            // is being passed in here with request type set elsewhere
            // on the request.
            return PolicyResult.ACCEPTED;
        }
        if (isProfileRequest(req)) {
            Debug.trace("GenericPolicyProcessor: Profile-base Request " +
                    req.getRequestId().toString());
            return PolicyResult.ACCEPTED;
        }
        CMS.debug("GenericPolicyProcessor: apply not ProfileRequest. op=" + op);

        if (op.equalsIgnoreCase(IRequest.ENROLLMENT_REQUEST))
            rules = mEnrollmentRules;
        else if (op.equalsIgnoreCase(IRequest.RENEWAL_REQUEST))
            rules = mRenewalRules;
        else if (op.equalsIgnoreCase(IRequest.REVOCATION_REQUEST))
            rules = mRevocationRules;
        else if (op.equalsIgnoreCase(IRequest.KEY_RECOVERY_REQUEST))
            rules = mKeyRecoveryRules;
        else if (op.equalsIgnoreCase(IRequest.KEY_ARCHIVAL_REQUEST))
            rules = mKeyArchivalRules;
        else {
            // It aint' a CMP request. We don't care.
            return PolicyResult.ACCEPTED;
            // throw new AssertionException("Invalid request type. Can't Happen!");
        }

        // ((PolicySet)rules).printPolicies();
        // If there are no rules, then it is a serious error.
        if (rules.count() == 0) {
            CMS.debug("GenericPolicyProcessor: apply: rule count 0");
            // if no policy is specified, just accept the request.
            // KRA has no policy configured by default
            return PolicyResult.ACCEPTED;

            /**
             * setError(req, PolicyResources.NO_RULES_CONFIGURED, op);
             * return PolicyResult.REJECTED;
             **/
        }
        CMS.debug("GenericPolicyProcessor: apply: rules.count=" + rules.count());

        // request must be up to date or can't process it.
        PolicyResult res = PolicyResult.ACCEPTED;
        String mVersion = ARequestQueue.REQUEST_VERSION;
        String vers = req.getRequestVersion();

        if (vers == null || !vers.equals(mVersion)) {
            if (vers == null || vers.length() == 0)
                vers = "none";
            res = PolicyResult.REJECTED;
        }

        if (res == PolicyResult.REJECTED)
            return res;

        CMS.debug("GenericPolicyProcessor: apply: calling rules.apply()");
        // Apply the policy rules.
        return rules.apply(req);
    }

    public void printPolicies() {
        mEnrollmentRules.printPolicies();
        mRenewalRules.printPolicies();
        mRevocationRules.printPolicies();
        mKeyRecoveryRules.printPolicies();
        mKeyArchivalRules.printPolicies();
    }

    public String getPolicySubstoreId() {
        return mAuthority.getId() + ".Policy";
    }

    public Enumeration<IPolicyRule> getPolicyImpls() {
        Vector<IPolicyRule> impls = new Vector<IPolicyRule>();
        Enumeration<RegisteredPolicy> enum1 = mImplTable.elements();
        Enumeration<IPolicyRule> ret = null;

        try {
            while (enum1.hasMoreElements()) {
                RegisteredPolicy regPolicy = enum1.nextElement();

                // Make an Instance of it
                IPolicyRule ruleImpl = (IPolicyRule)
                        Class.forName(regPolicy.getClassPath()).newInstance();

                impls.addElement(ruleImpl);
            }
            ret = impls.elements();
        } catch (Exception e) {
            Debug.printStackTrace(e);
        }
        return ret;
    }

    public Enumeration<String> getPolicyImplsInfo() {
        Vector<String> impls = new Vector<String>();
        Enumeration<RegisteredPolicy> enum1 = mImplTable.elements();
        Enumeration<String> ret = null;

        try {
            while (enum1.hasMoreElements()) {
                RegisteredPolicy regPolicy = enum1.nextElement();
                impls.addElement(regPolicy.getId());
            }
            ret = impls.elements();
        } catch (Exception e) {
            Debug.printStackTrace(e);
        }
        return ret;
    }

    public IPolicyRule getPolicyImpl(String id) {
        RegisteredPolicy regImpl = mImplTable.get(id);

        if (regImpl == null)
            return null;
        IPolicyRule impl = null;

        try {
            impl =
                    (IPolicyRule) Class.forName(regImpl.getClassPath()).newInstance();
        } catch (Exception e) {
            Debug.printStackTrace(e);
        }
        return impl;
    }

    public Vector<String> getPolicyImplConfig(String id) {
        IPolicyRule rp = getPolicyImpl(id);

        if (rp == null)
            return null;
        Vector<String> v = rp.getDefaultParams();

        if (v == null)
            v = new Vector<String>();
        v.insertElementAt(IPolicyRule.PROP_ENABLE + "=" + "true", 0);
        v.insertElementAt(IPolicyRule.PROP_PREDICATE + "=" + " ", 1);
        return v;
    }

    public void deletePolicyImpl(String id)
            throws EBaseException {
        // First check if the id is valid;
        RegisteredPolicy regPolicy = mImplTable.get(id);

        if (regPolicy == null)
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_NO_POLICY_IMPL", id));

        // If any instance exists for this impl, can't delete it.
        boolean instanceExist = false;
        Enumeration<PolicyInstance> e = mInstanceTable.elements();

        for (; e.hasMoreElements();) {
            PolicyInstance inst = e.nextElement();

            if (inst.isInstanceOf(id)) {
                instanceExist = true;
                break;
            }
        }
        if (instanceExist) // we found an instance
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_ACTIVE_POLICY_RULES_EXIST", id));

        // Else delete the implementation
        mImplTable.remove(id);
        IConfigStore policyStore =
                mGlobalStore.getSubStore(getPolicySubstoreId());
        IConfigStore implStore =
                policyStore.getSubStore(PROP_IMPL);

        implStore.removeSubStore(id);

        // committing
        try {
            mGlobalStore.commit(true);
        } catch (Exception ex) {
            Debug.printStackTrace(ex);
            String[] params = { "implementation", id };

            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_DELETING_POLICY_ERROR", params));
        }
    }

    public void addPolicyImpl(String id, String classPath)
            throws EBaseException {
        // See if the id is unique
        if (mImplTable.containsKey(id))
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_DUPLICATE_IMPL_ID", id));

        // See if the classPath is ok
        Object impl = null;

        try {
            impl = Class.forName(classPath).newInstance();
        } catch (Exception e) {
            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_NO_POLICY_IMPL",
                        id));
        }

        // Does the class implement one of the four interfaces?
        if (!(impl instanceof IEnrollmentPolicy) &&
                !(impl instanceof IRenewalPolicy) &&
                !(impl instanceof IRevocationPolicy) &&
                !(impl instanceof IKeyRecoveryPolicy) &&
                !(impl instanceof IKeyArchivalPolicy))
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_IMPL", classPath));

        // Add the implementation to the registry
        RegisteredPolicy regPolicy =
                new RegisteredPolicy(id, classPath);

        mImplTable.put(id, regPolicy);

        // Store the impl in the configuration.
        IConfigStore policyStore =
                mGlobalStore.getSubStore(getPolicySubstoreId());
        IConfigStore implStore =
                policyStore.getSubStore(PROP_IMPL);
        IConfigStore newStore = implStore.makeSubStore(id);

        newStore.put(PROP_CLASS, classPath);
        try {
            mGlobalStore.commit(true);
        } catch (Exception e) {
            String[] params = { "implementation", id };

            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_ADDING_POLICY_ERROR", params));
        }
    }

    public Enumeration<IPolicyRule> getPolicyInstances() {
        Vector<IPolicyRule> rules = new Vector<IPolicyRule>();
        Enumeration<String> enum1 = mPolicyOrder.elements();
        Enumeration<IPolicyRule> ret = null;

        try {
            while (enum1.hasMoreElements()) {
                PolicyInstance instance = mInstanceTable.get(enum1.nextElement());

                rules.addElement(instance.getRule());

            }
            ret = rules.elements();
        } catch (Exception e) {
            Debug.printStackTrace(e);
        }
        return ret;
    }

    public Enumeration<String> getPolicyInstancesInfo() {
        Vector<String> rules = new Vector<String>();
        Enumeration<String> enum1 = mPolicyOrder.elements();
        Enumeration<String> ret = null;

        try {
            while (enum1.hasMoreElements()) {
                String ruleName = enum1.nextElement();
                PolicyInstance instance = mInstanceTable.get(ruleName);
                rules.addElement(instance.getRuleInfo());
            }
            ret = rules.elements();
        } catch (Exception e) {
            Debug.printStackTrace(e);
        }
        return ret;
    }

    public IPolicyRule getPolicyInstance(String id) {
        PolicyInstance policyInstance = mInstanceTable.get(id);

        return (policyInstance == null) ? null : policyInstance.getRule();
    }

    public Vector<String> getPolicyInstanceConfig(String id) {
        PolicyInstance policyInstance = mInstanceTable.get(id);

        if (policyInstance == null)
            return null;
        Vector<String> v = policyInstance.getRule().getInstanceParams();

        if (v == null)
            v = new Vector<String>();
        v.insertElementAt(PROP_IMPL_NAME + "=" + policyInstance.getImplId(), 0);
        v.insertElementAt(PROP_ENABLE + "=" + policyInstance.isActive(), 1);
        String predicate = " ";

        if (policyInstance.getRule().getPredicate() != null)
            predicate = policyInstance.getRule().getPredicate().toString();
        v.insertElementAt(PROP_PREDICATE + "=" + predicate, 2);
        return v;
    }

    public void deletePolicyInstance(String id)
            throws EBaseException {
        // If the rule is a persistent rule, we can't delete it.
        if (mUndeletablePolicies.containsKey(id))
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_CANT_DELETE_PERSISTENT_POLICY", id));

        // First check if the instance is present.
        PolicyInstance instance = mInstanceTable.get(id);

        if (instance == null)
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_INSTANCE", id));

        IConfigStore policyStore =
                mGlobalStore.getSubStore(getPolicySubstoreId());
        IConfigStore instanceStore =
                policyStore.getSubStore(PROP_RULE);

        instanceStore.removeSubStore(id);

        // Remove the rulename from the rder list
        int index = mPolicyOrder.indexOf(id);

        mPolicyOrder.removeElement(id);

        // Now change the ordering in the config file.
        policyStore.put(PROP_ORDER, getRuleOrderString(mPolicyOrder));

        // Commit changes to file.
        try {
            mGlobalStore.commit(true);
        } catch (Exception e) {
            // Put the rule back in the rule order vector.
            mPolicyOrder.insertElementAt(id, index);

            Debug.printStackTrace(e);
            String[] params = { "instance", id };

            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_DELETING_POLICY_ERROR", params));
        }

        IPolicyRule rule = instance.getRule();

        if (rule instanceof IEnrollmentPolicy)
            mEnrollmentRules.removeRule(id);
        if (rule instanceof IRenewalPolicy)
            mRenewalRules.removeRule(id);
        if (rule instanceof IRevocationPolicy)
            mRevocationRules.removeRule(id);
        if (rule instanceof IKeyRecoveryPolicy)
            mKeyRecoveryRules.removeRule(id);
        if (rule instanceof IKeyArchivalPolicy)
            mKeyArchivalRules.removeRule(id);

        // Delete the instance
        mInstanceTable.remove(id);
    }

    public void addPolicyInstance(String id, Hashtable<String, String> ht)
            throws EBaseException {
        // The instance id should be unique
        if (getPolicyInstance(id) != null)
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_DUPLICATE_INST_ID", id));
        // There should be an implmentation for this rule.
        String implName = ht.get(IPolicyRule.PROP_IMPLNAME);

        // See if there is an implementation with this name.
        IPolicyRule rule = getPolicyImpl(implName);

        if (rule == null)
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_NO_POLICY_IMPL", implName));

        // Prepare config file entries.
        IConfigStore policyStore =
                mGlobalStore.getSubStore(getPolicySubstoreId());
        IConfigStore instanceStore =
                policyStore.getSubStore(PROP_RULE);
        IConfigStore newStore = instanceStore.makeSubStore(id);

        for (Enumeration<String> keys = ht.keys(); keys.hasMoreElements();) {
            String key = keys.nextElement();
            String val = ht.get(key);

            newStore.put(key, val);
        }

        // Set the order string.
        policyStore.put(PROP_ORDER,
                getRuleOrderString(mPolicyOrder, id));

        // Try to initialize this rule.
        rule.init(this, newStore);

        // Add the rule to the table.
        String enabledStr = ht.get(IPolicyRule.PROP_ENABLE);
        boolean active = false;

        if (enabledStr == null || enabledStr.trim().length() == 0 ||
                enabledStr.equalsIgnoreCase("true"))
            active = true;

        // Set the predicate if any present on the rule.
        String predicate = ht.get(IPolicyRule.PROP_PREDICATE).trim();
        IExpression exp = null;

        if (predicate.trim().length() > 0)
            exp = PolicyPredicateParser.parse(predicate.trim());
        rule.setPredicate(exp);

        // Store the changes in the file.
        try {
            mGlobalStore.commit(true);
        } catch (Exception e) {
            String[] params = { "instance", id };

            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_ADDING_POLICY_ERROR", params));
        }

        // Add the rule to the instance table.
        PolicyInstance policyInst = new PolicyInstance(id, implName,
                rule, active);

        mInstanceTable.put(id, policyInst);

        // Add the rule to the end of order table.
        mPolicyOrder.addElement(id);

        // If the rule is not active, return.
        if (!active)
            return;

        addRule(id, rule);
    }

    public void modifyPolicyInstance(String id, Hashtable<String, String> ht)
            throws EBaseException {
        // The instance id should be there already
        PolicyInstance policyInstance = mInstanceTable.get(id);

        if (policyInstance == null)
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_INSTANCE", id));
        IPolicyRule rule = policyInstance.getRule();

        // The impl id shouldn't change
        String implId = ht.get(IPolicyRule.PROP_IMPLNAME);

        if (!implId.equals(policyInstance.getImplId()))
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_IMPLCHANGE_ERROR", id));

        // Make a new rule instance
        IPolicyRule newRule = getPolicyImpl(implId);

        if (newRule == null) // Can't happen, but just in case..
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_IMPL", implId));

        // Try to init this rule.
        IConfigStore policyStore =
                mGlobalStore.getSubStore(getPolicySubstoreId());
        IConfigStore instanceStore =
                policyStore.getSubStore(PROP_RULE);
        IConfigStore oldStore = instanceStore.getSubStore(id);
        IConfigStore newStore = new PropConfigStore(id);

        // See if the rule is disabled.
        String enabledStr = ht.get(IPolicyRule.PROP_ENABLE);
        boolean active = false;

        if (enabledStr == null || enabledStr.trim().length() == 0 ||
                enabledStr.equalsIgnoreCase("true"))
            active = true;

        // Set the predicate expression.
        String predicate = ht.get(IPolicyRule.PROP_PREDICATE).trim();
        IExpression exp = null;

        if (predicate.trim().length() > 0)
            exp = PolicyPredicateParser.parse(predicate.trim());

        // See if this a persistent rule.
        if (mUndeletablePolicies.containsKey(id)) {
            // A persistent rule can't be disabled.
            if (!active) {
                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_PERSISTENT_RULE_INACTIVE", id));
            }

            IExpression defPred = mUndeletablePolicies.get(id);

            if (defPred == SimpleExpression.NULL_EXPRESSION)
                defPred = null;
            if (exp == null && defPred != null) {
                String[] params = { id, defPred.toString(),
                        "null" };

                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_PERSISTENT_RULE_MISCONFIG", params));
            } else if (exp != null && defPred == null) {
                String[] params = { id, "null", exp.toString() };

                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_PERSISTENT_RULE_MISCONFIG", params));
            } else if (exp != null && defPred != null) {
                if (!defPred.toString().equals(exp.toString())) {
                    String[] params = { id, defPred.toString(),
                            exp.toString() };

                    throw new EPolicyException(
                            CMS.getUserMessage("CMS_POLICY_PERSISTENT_RULE_MISCONFIG", params));
                }
            }
        }

        // Predicate for the persistent rule can't be changed.
        ht.put(IPolicyRule.PROP_ENABLE, String.valueOf(active));

        // put old config store parameters first.
        for (Enumeration<String> oldkeys = oldStore.keys(); oldkeys.hasMoreElements();) {
            String k = oldkeys.nextElement();
            String v = oldStore.getString(k);

            newStore.put(k, v);
        }

        // put modified params.
        for (Enumeration<String> newkeys = ht.keys(); newkeys.hasMoreElements();) {
            String k = newkeys.nextElement();
            String v = ht.get(k);

            Debug.trace("newstore key " + k + "=" + v);
            if (v != null) {
                if (!k.equals(Constants.OP_TYPE) && !k.equals(Constants.OP_SCOPE) &&
                        !k.equals(Constants.RS_ID) && !k.equals("RULENAME")) {
                    Debug.trace("newstore.put(" + k + "=" + v + ")");
                    newStore.put(k, v);
                }
            }
        }

        // include impl default params in case we missed any.

        /*
         for (Enumeration keys = ht.keys(); keys.hasMoreElements();)
         {
         String key = (String)keys.nextElement();
         String val = (String)ht.get(key);
         newStore.put(key, val);
         }
         */

        // Try to initialize this rule.
        newRule.init(this, newStore);

        // If we are successfully initialized, replace the rule
        // instance
        policyInstance.setRule(newRule);
        policyInstance.setActive(active);

        // Set the predicate expression.
        if (exp != null)
            newRule.setPredicate(exp);

        // Store the changes in the file.
        try {
            for (Enumeration<String> e = newStore.keys(); e.hasMoreElements();) {
                String key = e.nextElement();

                if (key != null) {
                    Debug.trace(
                            "oldstore.put(" + key + "," +
                                    newStore.getString(key) + ")");
                    oldStore.put(key, newStore.getString(key));
                }
            }
            mGlobalStore.commit(true);
        } catch (Exception e) {
            String[] params = { "instance", id };

            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_ADDING_POLICY_ERROR", params));
        }

        // If rule is disabled, we need to remove it from the
        // policy set.
        if (!active) {
            if (rule instanceof IEnrollmentPolicy)
                mEnrollmentRules.removeRule(id);
            if (rule instanceof IRenewalPolicy)
                mRenewalRules.removeRule(id);
            if (rule instanceof IRevocationPolicy)
                mRevocationRules.removeRule(id);
            if (rule instanceof IKeyRecoveryPolicy)
                mKeyRecoveryRules.removeRule(id);
            if (rule instanceof IKeyArchivalPolicy)
                mKeyArchivalRules.removeRule(id);
        } else // replace the rule
        {
            if (rule instanceof IEnrollmentPolicy)
                mEnrollmentRules.replaceRule(id, newRule);
            if (rule instanceof IRenewalPolicy)
                mRenewalRules.replaceRule(id, newRule);
            if (rule instanceof IRevocationPolicy)
                mRevocationRules.replaceRule(id, newRule);
            if (rule instanceof IKeyRecoveryPolicy)
                mKeyRecoveryRules.replaceRule(id, newRule);
            if (rule instanceof IKeyArchivalPolicy)
                mKeyArchivalRules.replaceRule(id, newRule);
        }
    }

    public synchronized void changePolicyInstanceOrdering(
            String policyOrderStr)
            throws EBaseException {
        Vector<String> policyOrder = new Vector<String>();
        StringTokenizer tokens = new StringTokenizer(policyOrderStr, ",");

        // Get all the elements
        while (tokens.hasMoreTokens()) {
            String instanceId = tokens.nextToken().trim();

            // Check if we have that instance configured.
            if (!mInstanceTable.containsKey(instanceId))
                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_INSTANCE", instanceId));
            policyOrder.addElement(instanceId);
        }

        // Now enforce the new ordering
        // First if the order is the same as what we have,
        // return.
        if (policyOrder.size() == mPolicyOrder.size()) {
            if (areSameVectors(policyOrder, mPolicyOrder))
                return;
        }
        PolicySet enrollmentRules = new PolicySet("EnrollmentRules");
        PolicySet renewalRules = new PolicySet("RenewalRules");
        PolicySet revocationRules = new PolicySet("RevocationRules");
        PolicySet keyRecoveryRules = new PolicySet("KeyRecoveryRules");
        PolicySet keyArchivalRules = new PolicySet("KeyArchivalRules");

        // add system default rules first.
        try {
            for (int i = 0; i < mSystemDefaults.length; i++) {
                String defRuleName = mSystemDefaults[i].substring(
                        mSystemDefaults[i].lastIndexOf('.') + 1);
                IPolicyRule defRule = (IPolicyRule)
                        Class.forName(mSystemDefaults[i]).newInstance();
                IConfigStore ruleConfig =
                        mConfig.getSubStore(PROP_DEF_POLICIES + "." + defRuleName);

                defRule.init(this, ruleConfig);
                if (defRule instanceof IEnrollmentPolicy)
                    enrollmentRules.addRule(defRuleName, defRule);
                else if (defRule instanceof IRenewalPolicy)
                    renewalRules.addRule(defRuleName, defRule);
                else if (defRule instanceof IRevocationPolicy)
                    revocationRules.addRule(defRuleName, defRule);
                else if (defRule instanceof IKeyRecoveryPolicy)
                    keyRecoveryRules.addRule(defRuleName, defRule);
                else if (defRule instanceof IKeyArchivalPolicy)
                    keyArchivalRules.addRule(defRuleName, defRule);
                // else ignore the darned rule.
            }
        } catch (Throwable e) {
            Debug.printStackTrace(e);
            EBaseException ex = new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                        "Cannot create default policy rule. Error: " + e.getMessage()));

            mAuthority.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_POLICY_DEF_CREATE", e.toString()));
            throw ex;
        }

        // add rules specified in the new order.
        for (Enumeration<String> enum1 = policyOrder.elements(); enum1.hasMoreElements();) {
            String instanceName = enum1.nextElement();
            PolicyInstance pInstance = mInstanceTable.get(instanceName);

            if (!pInstance.isActive())
                continue;

            // Add the rule to the policy set according to category if a
            // rule is enabled.
            IPolicyRule rule = pInstance.getRule();

            if (rule instanceof IEnrollmentPolicy)
                enrollmentRules.addRule(instanceName, rule);
            else if (rule instanceof IRenewalPolicy)
                renewalRules.addRule(instanceName, rule);
            else if (rule instanceof IRevocationPolicy)
                revocationRules.addRule(instanceName, rule);
            else if (rule instanceof IKeyRecoveryPolicy)
                keyRecoveryRules.addRule(instanceName, rule);
            else if (rule instanceof IKeyArchivalPolicy)
                keyArchivalRules.addRule(instanceName, rule);
            // else ignore the darned rule.
        }

        mEnrollmentRules = enrollmentRules;
        mRenewalRules = renewalRules;
        mRevocationRules = revocationRules;
        mKeyRecoveryRules = keyRecoveryRules;
        mKeyArchivalRules = keyArchivalRules;
        mPolicyOrder = policyOrder;

        // Now change the ordering in the config file.
        IConfigStore policyStore =
                mGlobalStore.getSubStore(getPolicySubstoreId());

        policyStore.put(PROP_ORDER, policyOrderStr);

        // committing
        try {
            mGlobalStore.commit(true);
        } catch (Exception ex) {
            Debug.printStackTrace(ex);
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_ORDER_ERROR", policyOrderStr));
        }
    }

    private boolean areSameVectors(Vector<String> v1, Vector<String> v2) {
        if (v1.size() != v2.size())
            return false;
        int size = v1.size();
        int i = 0;

        for (; i < size; i++)
            if (v2.indexOf(v1.elementAt(i)) != i)
                break;
        return (i == size ? true : false);
    }

    private String getRuleOrderString(Vector<String> rules) {
        StringBuffer sb = new StringBuffer();

        for (Enumeration<String> e = rules.elements(); e.hasMoreElements();) {
            sb.append(e.nextElement());
            sb.append(",");
        }
        if (sb.length() > 0)
            sb.setLength(sb.length() - 1);
        return new String(sb);
    }

    private String getRuleOrderString(Vector<String> rules, String newRule) {
        String currentRules = getRuleOrderString(rules);

        if (currentRules == null || currentRules.length() == 0)
            return newRule;
        else
            return currentRules + "," + newRule;
    }

    /**
     * Initializes the default system policies. Currently there is only
     * one policy - ManualAuthentication. More may be added later on.
     *
     * The default policies may be disabled - for example to over-ride
     * agent approval for testing the system by setting the following
     * property in the config file:
     *
     * <subsystemId>.Policy.systemPolicies.enable=false
     *
     * By default the value for this property is true.
     *
     * Users can over-ride the default system policies by listing their
     * 'custom' system policies under the following property:
     *
     * <subsystemId>.Policy.systemPolicies=<system policy1 class path>,
     * <system policy2 class path>
     *
     * There can only be one instance of the system policy in the system
     * and will apply to all requests, and hence predicates are not used
     * for a system policy. Due to the same reason, these properties are
     * not configurable using the Console.
     *
     * A System policy may read config properties from a subtree under
     * <subsystemId>.Policy.systemPolicies.<ClassName>. An example is
     * ra.Policy.systemPolicies.ManualAuthentication.param1=value
     */
    private void initSystemPolicies(IConfigStore mConfig)
            throws EBaseException {
        // If system policies are disabled, return. No Deferral of
        // requests may be done.
        String enable = mConfig.getString(PROP_DEF_POLICIES + "." +
                PROP_ENABLE, "true").trim();

        if (enable.equalsIgnoreCase("false")) {
            mSystemDefaults = DEF_POLICIES;
            return;
        }

        // Load default policies that are always present.
        String configuredDefaults = mConfig.getString(PROP_DEF_POLICIES,
                null);

        if (configuredDefaults == null ||
                configuredDefaults.trim().length() == 0)
            mSystemDefaults = DEF_POLICIES;
        else {
            Vector<String> rules = new Vector<String>();
            StringTokenizer tokenizer = new
                    StringTokenizer(configuredDefaults.trim(), ",");

            while (tokenizer.hasMoreTokens()) {
                String rule = tokenizer.nextToken().trim();

                rules.addElement(rule);
            }
            if (rules.size() > 0) {
                mSystemDefaults = new String[rules.size()];
                rules.copyInto(mSystemDefaults);
            } else
                mSystemDefaults = DEF_POLICIES;
        }

        // Now Initialize the rules. These defaults have only one
        // instance and the rule name is the name of the class itself.
        // Any configuration parameters required could be read from
        // <subsystemId>.Policy.default.RuleName.
        for (int i = 0; i < mSystemDefaults.length; i++) {
            // Load the class and make an instance.
            // Verify if the class is a valid implementation of
            // IPolicyRule
            String ruleName = null;

            try {
                Object o = Class.forName(mSystemDefaults[i]).newInstance();

                if (!(o instanceof IEnrollmentPolicy) &&
                        !(o instanceof IRenewalPolicy) &&
                        !(o instanceof IRevocationPolicy) &&
                        !(o instanceof IKeyRecoveryPolicy) &&
                        !(o instanceof IKeyArchivalPolicy))
                    throw new EPolicyException(
                            CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_IMPL",
                                    mSystemDefaults[i]));

                IPolicyRule rule = (IPolicyRule) o;

                // Initialize the rule.
                ruleName = mSystemDefaults[i].substring(
                            mSystemDefaults[i].lastIndexOf('.') + 1);
                IConfigStore ruleConfig = mConfig.getSubStore(
                        PROP_DEF_POLICIES + "." + ruleName);

                rule.init(this, ruleConfig);

                // Add the rule to the appropriate PolicySet.
                addRule(ruleName, rule);
            } catch (EBaseException e) {
                throw e;
            } catch (Exception e) {
                Debug.printStackTrace(e);
                throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_NO_POLICY_IMPL",
                            ruleName));
            }
        }
    }

    /**
     * Read list of undeletable policies if any configured in the
     * system.
     *
     * These are required to protect the system from being misconfigured
     * to the point that the requests wouldn't serialize or certain
     * fields in the certificate(s) being checked will go unchecked
     * ..etc.
     *
     * For now the following policies are undeletable:
     *
     * DirAuthRule: This is a default DirectoryAuthentication policy
     * for user certificates that interprets directory
     * credentials. The presence of this policy is needed
     * if the OOTB DirectoryAuthentication-based automatic
     * certificate issuance is supported.
     *
     * DefaultUserNameRule: This policy verifies/sets subjectDn for user
     * certificates.
     *
     * DefaultServerNameRule: This policy verifies/sets subjectDn for
     * server certificates.
     *
     * DefaultValidityRule: Verifies/sets validty for all certificates.
     *
     * DefaultRenewalValidityRule: Verifies/sets validity for certs being
     * renewed.
     *
     * The 'undeletables' cannot be deleted from the config file, nor
     * can the be disabled. If any predicates are associated with them
     * the predicates can't be changed either. But, other config parameters
     * such as maxValidity, renewalInterval ..etc can be changed to suit
     * local policy requirements.
     *
     * During start up the policy processor will verify if the undeletables
     * are present, and that they are enabled and that their predicates are
     * not changed.
     *
     * The rules mentioned above are currently hard coded. If these need to
     * read from the config file, the 'undeletables' can be configured as
     * as follows:
     *
     * <subsystemId>.Policy.undeletablePolicies=<comma separated rule names>
     * Example:
     * ra.Policy.undeletablePolicies=DirAuthRule, DefaultUserNameRule, DefaultServerNameRule, DefaultValidityRule,
     * DefaultRenewalValidityRule
     *
     * The predicates if any associated with them may be configured as
     * follows:
     * <subsystemId>.Policy.undeletablePolicies.DirAuthRule.predicate= certType == client.
     *
     * where subsystemId is ra or ca.
     *
     * If the undeletables are configured in the file,the configured entries
     * take precedence over the hardcoded ones in this file. If you are
     * configuring them in the file, please remember to configure the
     * predicates if applicable.
     *
     * During policy configuration from MCC, the policy processor will not
     * let you delete an 'undeletable', nor will it let you disable it.
     * You will not be able to change the predicate either. Other parameters
     * can be configured as needed.
     *
     * If a particular rule needs to be removed from the 'undeletables',
     * either remove it from the hard coded list above, or configure the
     * rules required rules only via the config file. The former needs
     * recompilation of the source. The later is flexible to be able to
     * make any rule an 'undeletable' or nor an 'undeletable'.
     *
     * Example: We want to use only manual forms for enrollment.
     * We do n't need to burn in DirAuthRule. We need to configure all
     * other rules except the DirAuthRule as follows:
     *
     * ra.Policy.undeletablePolicies = DefaultUserNameRule, DefaultServerNameRule, DefaultValidityRule,
     * DefaultRenewalValidityRule
     *
     * The following predicates are necessary:
     *
     * ra.Policy.undeletablePolicies.DefaultUserNameRule.predicate = certType == client
     * ra.Policy.undeletablePolicies.DefaultServerNameRule.predicate = certType == server
     *
     * The other two rules do not have any predicates.
     */
    private void initUndeletablePolicies(IConfigStore mConfig)
            throws EBaseException {
        // Read undeletable policies if any configured.
        String configuredUndeletables =
                mConfig.getString(PROP_UNDELETABLE_POLICIES, null);

        if (configuredUndeletables == null ||
                configuredUndeletables.trim().length() == 0) {
            mUndeletablePolicies = DEF_UNDELETABLE_POLICIES;
            return;
        }

        Vector<String> rules = new Vector<String>();
        StringTokenizer tokenizer = new
                StringTokenizer(configuredUndeletables.trim(), ",");

        while (tokenizer.hasMoreTokens()) {
            String rule = tokenizer.nextToken().trim();

            rules.addElement(rule);
        }

        if (rules.size() == 0) {
            mUndeletablePolicies = DEF_UNDELETABLE_POLICIES;
            return;
        }

        // For each rule read from the config file, see if any
        // predicate is set.
        mUndeletablePolicies = new Hashtable<String, IExpression>();
        for (Enumeration<String> e = rules.elements(); e.hasMoreElements();) {
            String urn = e.nextElement();

            // See if there is predicate in the file
            String pred = mConfig.getString(PROP_UNDELETABLE_POLICIES +
                    "." + urn + "." + PROP_PREDICATE, null);

            IExpression exp = SimpleExpression.NULL_EXPRESSION;

            if (pred != null)
                exp = PolicyPredicateParser.parse(pred);
            mUndeletablePolicies.put(urn, exp);
        }
    }

    private void addRule(String ruleName, IPolicyRule rule) {
        if (rule instanceof IEnrollmentPolicy)
            mEnrollmentRules.addRule(ruleName, rule);
        if (rule instanceof IRenewalPolicy)
            mRenewalRules.addRule(ruleName, rule);
        if (rule instanceof IRevocationPolicy)
            mRevocationRules.addRule(ruleName, rule);
        if (rule instanceof IKeyRecoveryPolicy)
            mKeyRecoveryRules.addRule(ruleName, rule);
        if (rule instanceof IKeyArchivalPolicy)
            mKeyArchivalRules.addRule(ruleName, rule);
    }

    private boolean isSystemDefaultPolicy(String clPath) {
        boolean ret = false;

        if (mSystemDefaults == null)
            return false;
        for (int i = 0; i < mSystemDefaults.length; i++) {
            if (clPath.equals(mSystemDefaults[i])) {
                ret = true;
                break;
            }
        }
        return ret;
    }

    private void verifyDefaultPolicyConfig()
            throws EPolicyException {
        // For each policy in undeletable list make sure that
        // the policy is present, is not disabled and its predicate
        // is not tampered with.
        for (Enumeration<String> e = mUndeletablePolicies.keys(); e.hasMoreElements();) {
            String urn = e.nextElement();

            // See if the rule is in the instance table.
            PolicyInstance inst = mInstanceTable.get(urn);

            if (inst == null)
                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_MISSING_PERSISTENT_RULE", urn));

            // See if the instance is disabled.
            if (!inst.isActive())
                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_PERSISTENT_RULE_INACTIVE", urn));

            // See if the predicated is misconfigured.
            IExpression defPred = mUndeletablePolicies.get(urn);

            // We used SimpleExpression.NULL_EXPRESSION to indicate a null.
            if (defPred == SimpleExpression.NULL_EXPRESSION)
                defPred = null;
            IExpression confPred = inst.getRule().getPredicate();

            if (defPred == null && confPred != null) {
                String[] params = { urn, "null", confPred.toString() };

                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_PERSISTENT_RULE_MISCONFIG", params));
            } else if (defPred != null && confPred == null) {
                String[] params = { urn, defPred.toString(), "null" };

                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_PERSISTENT_RULE_MISCONFIG", params));
            } else if (defPred != null && confPred != null) {
                if (!defPred.toString().equals(confPred.toString())) {
                    String[] params = { urn, defPred.toString(),
                            confPred.toString() };

                    throw new EPolicyException(
                            CMS.getUserMessage("CMS_POLICY_PERSISTENT_RULE_MISCONFIG", params));
                }
            }
        }
    }
}

/**
 * Class to keep track of various configurable implementations.
 */
class RegisteredPolicy {
    String mId;
    String mClPath;

    public RegisteredPolicy(String id, String clPath) {
        if (id == null || clPath == null)
            throw new AssertionException("Policy id or classpath can't be null");
        mId = id;
        mClPath = clPath;
    }

    public String getClassPath() {
        return mClPath;
    }

    public String getId() {
        return mId;
    }
}

/**
 * @deprecated
 */
class PolicyInstance {
    String mInstanceId;
    String mImplId;
    IPolicyRule mRule;
    boolean mIsEnabled;

    public PolicyInstance(String instanceId, String implId,
            IPolicyRule rule, boolean isEnabled) {
        mInstanceId = instanceId;
        mImplId = implId;
        mRule = rule;
        mIsEnabled = isEnabled;
    }

    public String getInstanceId() {
        return mInstanceId;
    }

    public String getImplId() {
        return mImplId;
    }

    public String getRuleInfo() {
        String enabled = mIsEnabled ? "enabled" : "disabled";

        return mInstanceId + ";" + mImplId + ";visible;" + enabled;
    }

    public IPolicyRule getRule() {
        return mRule;
    }

    public boolean isInstanceOf(String implId) {
        return mImplId.equals(implId);
    }

    public boolean isActive() {
        return mIsEnabled;
    }

    public void setActive(boolean stat) {
        mIsEnabled = stat;
    }

    public void setRule(IPolicyRule newRule) {
        mRule = newRule;
    }
}
