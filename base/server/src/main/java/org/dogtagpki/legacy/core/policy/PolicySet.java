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
package org.dogtagpki.legacy.core.policy;

import java.util.Enumeration;
import java.util.Vector;

import org.dogtagpki.legacy.policy.IExpression;
import org.dogtagpki.legacy.policy.IPolicyRule;
import org.dogtagpki.legacy.policy.IPolicySet;

import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cmscore.apps.CMS;

/**
 * Implements a policy set per IPolicySet interface. This class
 * uses a vector of ordered policies to enforce priority.
 *
 * @author kanda
 * @version $Revision$, $Date$
 */
public class PolicySet implements IPolicySet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PolicySet.class);

    private String mName;
    private Vector<String> mRuleNames = new Vector<>();
    private Vector<IPolicyRule> mRules = new Vector<>();

    public PolicySet(String name) {
        mName = name;
    }

    /**
     * Returns the name of the rule set.
     * <P>
     *
     * @return The name of the rule set.
     */
    @Override
    public String getName() {
        return mName;
    }

    /**
     * Returns the no of rules in a set.
     * <P>
     *
     * @return the no of rules.
     */
    @Override
    public int count() {
        return mRules.size();
    }

    /**
     * Add a policy rule.
     * <P>
     *
     * @param ruleName The name of the rule to be added.
     * @param rule The rule to be added.
     */
    @Override
    public void addRule(String ruleName, IPolicyRule rule) {
        if (mRuleNames.indexOf(ruleName) >= 0)
            return; // XXX - Duplicate - Need to throw an exception.

        if (ruleName != null && rule != null) {
            mRuleNames.addElement(ruleName);
            mRules.addElement(rule);
        }
        // XXX - TODO: else throw an exception.

    }

    /**
     * Remplaces a policy rule identified by the given name.
     *
     * @param ruleName The name of the rule to be replaced.
     * @param rule The rule to be replaced.
     */
    public void replaceRule(String ruleName, IPolicyRule rule) {
        int index = mRuleNames.indexOf(ruleName);

        if (index < 0) {
            addRule(ruleName, rule);
            return;
        }

        mRuleNames.setElementAt(ruleName, index);
        mRules.setElementAt(rule, index);
    }

    /**
     * Removes a policy rule identified by the given name.
     *
     * @param ruleName The name of the rule to be removed.
     */
    @Override
    public void removeRule(String ruleName) {
        int index = mRuleNames.indexOf(ruleName);

        if (index < 0)
            return; // XXX - throw an exception.

        mRuleNames.removeElementAt(index);
        mRules.removeElementAt(index);
    }

    /**
     * Returns the rule identified by a given name.
     * <P>
     *
     * @param ruleName The name of the rule to be return.
     * @return The rule identified by the given name or null if none exists.
     */
    @Override
    public IPolicyRule getRule(String ruleName) {
        int index = mRuleNames.indexOf(ruleName);

        if (index < 0)
            return null;
        return mRules.elementAt(index);
    }

    /**
     * Returns an enumeration of rules.
     * <P>
     *
     * @return An enumeration of rules.
     */
    @Override
    public Enumeration<IPolicyRule> getRules() {
        return mRules.elements();
    }

    /**
     * Apply policies on a given request from a rule set.
     * The rules may modify the request.
     *
     * @param req The request to apply policies on.
     * @return the PolicyResult.
     */
    @Override
    public PolicyResult apply(IRequest req) {
        // If there are no rules, we are done.

        if (mRules.size() == 0)
            return PolicyResult.ACCEPTED;

        // All policies are applied before returning the result. Hence
        // if atleast one of the policies returns a REJECTED, we need to
        // return that status. If none of the policies REJECTED
        // the request, but atleast one of them DEFERRED the request, we
        // need to return DEFERRED.
        boolean rejected = false;
        boolean deferred = false;
        int size = mRules.size();

        for (int index = 0; index < size; index++) {
            String name = mRuleNames.elementAt(index);
            IPolicyRule rule = mRules.elementAt(index);
            IExpression exp = rule.getPredicate();

            try {
                logger.debug("evaluating predicate for rule " + rule.getName());
                logger.debug("PolicySet: apply()- evaluating predicate for rule " + rule.getName());
                if (exp != null && !exp.evaluate(req))
                    continue;
            } catch (Exception e) {
                e.printStackTrace();
            }

            if (!typeMatched(rule, req))
                continue;

            try {
                logger.debug("Policy " + name + " selected");
                logger.debug("Policy " + name + " selected");
                PolicyResult result = rule.apply(req);
                logger.debug("Policy applied");

                logger.debug("Policy " + name + " returned " + result);

                if (result == PolicyResult.REJECTED) {
                    // It is hard to find out the owner at the moment unless
                    // we pass that info down the chain. For now use S_OTHER
                    // as the system id for the log entry.
                    logger.warn(CMS.getLogMessage("CMSCORE_POLICY_REJECT_RESULT", req.getRequestId().toString(), name));
                    rejected = true;
                } else if (result == PolicyResult.DEFERRED) {
                    // It is hard to find out the owner at the moment unless
                    // we pass that info down the chain. For now use S_OTHER
                    // as the system id for the log entry.
                    logger.warn(CMS.getLogMessage("CMSCORE_POLICY_DEFER_RESULT", req.getRequestId().toString(), name));
                    deferred = true;
                } else if (result == PolicyResult.ACCEPTED) {
                    // It is hard to find out the owner at the moment unless
                    // we pass that info down the chain. For now use S_OTHER
                    // as the system id for the log entry.
                } else {
                    // It is hard to find out the owner at the moment unless
                    // we pass that info down the chain. For now use S_OTHER
                    // as the system id for the log entry.
                    logger.warn("policy: Request " + req.getRequestId() + " - Result of applying rule: " + name +
                                    " is: " + getPolicyResult(result));
                }
            } catch (Throwable ex) {
                // Customer can install his own policies.
                // The policy may have bug. We want to
                // catch those problems and report
                // them to the log
                logger.warn(CMS.getLogMessage("CMSCORE_POLICY_ERROR_RESULT", req.getRequestId().toString(), name, ex.toString()), ex);
                // treat as rejected to prevent request from going into
                // a weird state. request queue doesn't handle this case.
                rejected = true;
                rule.setError(
                        req,
                        CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR", rule.getName(), ex.toString()), null);
            }
        }

        if (rejected) {
            return PolicyResult.REJECTED;
        } else if (deferred) {
            return PolicyResult.DEFERRED;
        } else {
            logger.info("Request " + req.getRequestId() + " Policy result: successful");
            return PolicyResult.ACCEPTED;
        }
    }

    public void printPolicies() {
        if (mRules.size() == 0)
            return;
        System.out.println("Policy Set Name: " + mName);
        System.out.println();
        int size = mRules.size();

        for (int index = 0; index < size; index++) {
            String ruleName = mRuleNames.elementAt(index);

            System.out.println("Rule Name: " + ruleName);
            System.out.println("Implementation: " +
                    mRules.elementAt(index).getClass().getName());
        }
    }

    String getPolicyResult(PolicyResult res) {
        if (res == PolicyResult.ACCEPTED)
            return "accepted";
        else if (res == PolicyResult.DEFERRED)
            return "deferred";
        else if (res == PolicyResult.REJECTED)
            return "rejected";
        else
            return "unknown";
    }

    boolean typeMatched(IPolicyRule rule, IRequest req) {

        if (req.getExtDataInCertInfoArray(IRequest.CERT_INFO) != null) {
            return true;
        }

        if (req.getExtDataInCertArray(IRequest.OLD_CERTS) != null) {
            return true;
        }

        return false;
    }
}
