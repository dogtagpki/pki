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
package com.netscape.cms.policy;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Vector;

import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.KeyIdentifier;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.EPolicyException;
import com.netscape.certsrv.policy.IExpression;
import com.netscape.certsrv.policy.IPolicyRule;
import com.netscape.certsrv.request.AgentApprovals;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;

/**
 * The abstract policy rule that concrete implementations will
 * extend.
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
public abstract class APolicyRule implements IPolicyRule {
    protected String NAME = null;
    protected String DESC = null;
    protected IExpression mFilterExp = null;
    protected String mInstanceName = null;
    protected ILogger mLogger = CMS.getLogger();

    public APolicyRule() {
    }

    /**
     * Initializes the policy rule.
     * <P>
     *
     * @param config The config store reference
     */
    public abstract void init(ISubsystem owner, IConfigStore config)
            throws EBaseException;

    /**
     * Gets the description for this policy rule.
     * <P>
     *
     * @return The Description for this rule.
     */
    public String getDescription() {
        return DESC;
    }

    /**
     * Sets a predicate expression for rule matching.
     * <P>
     *
     * @param exp The predicate expression for the rule.
     */
    public void setPredicate(IExpression exp) {
        mFilterExp = exp;
    }

    /**
     * Returns the predicate expression for the rule.
     * <P>
     *
     * @return The predicate expression for the rule.
     */
    public IExpression getPredicate() {
        return mFilterExp;
    }

    /**
     * Returns the name of the policy rule.
     * <P>
     *
     * @return The name of the policy class.
     */
    public String getName() {
        return NAME;
    }

    /**
     * Sets the instance name for a policy rule.
     * <P>
     *
     * @param instanceName The name of the rule instance.
     */
    public void setInstanceName(String instanceName) {
        mInstanceName = instanceName;
    }

    /**
     * Returns the name of the policy rule instance.
     * <P>
     *
     * @return The name of the policy rule instance if set, else
     *         the name of the rule class.
     */
    public String getInstanceName() {
        return mInstanceName != null ? mInstanceName : NAME;
    }

    /**
     * Applies the policy on the given Request.
     * <P>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public abstract PolicyResult apply(IRequest req);

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public abstract Vector<String> getInstanceParams();

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public abstract Vector<String> getDefaultParams();

    public void setError(IRequest req, String format, Object[] params) {
        setPolicyException(req, format, params);
    }

    public void setError(IRequest req, String format, String arg1,
            String arg2) {
        Object[] np = new Object[2];

        np[0] = arg1;
        np[1] = arg2;
        setPolicyException(req, format, np);
    }

    public void setError(IRequest req, String format, String arg) {
        Object[] np = new Object[1];

        np[0] = arg;
        setPolicyException(req, format, np);
    }

    public void setPolicyException(IRequest req, EBaseException ex) {
        Vector<String> ev = req.getExtDataInStringVector(IRequest.ERRORS);
        if (ev == null) {
            ev = new Vector<String>();
        }
        ev.addElement(ex.toString());
        req.setExtData(IRequest.ERRORS, ev);

    }

    /**
     * determines whether a DEFERRED policy result should be returned
     * by checking the contents of the AgentApprovals attribute. This
     * call should be used by policy modules instead of returning
     * PolicyResult.DEFERRED directly.
     * <p>
     */
    protected PolicyResult deferred(IRequest req) {
        // Try to find an agent approval
        AgentApprovals aa = AgentApprovals.fromStringVector(
                req.getExtDataInStringVector(AgentApprovals.class.getName()));

        // Any approvals causes success
        if (aa != null && aa.elements().hasMoreElements()) {
            return PolicyResult.ACCEPTED;
        } else {
            return PolicyResult.DEFERRED;
        }
    }

    /**
     * request has previously been approved by an agent
     */
    protected boolean agentApproved(IRequest req) {
        // Try to find an agent approval
        AgentApprovals aa = AgentApprovals.fromStringVector(
                req.getExtDataInStringVector(AgentApprovals.class.getName()));

        // Any approvals causes success
        if (aa != null && aa.elements().hasMoreElements()) {
            return true;
        } else {
            return false;
        }
    }

    public void setPolicyException(IRequest req, String format,
            Object[] params) {
        if (format == null)
            return;

        EPolicyException ex;

        if (params == null)
            ex = new EPolicyException(format);
        else
            ex = new EPolicyException(format, params);

        Vector<String> ev = req.getExtDataInStringVector(IRequest.ERRORS);
        if (ev == null) {
            ev = new Vector<String>();
        }
        ev.addElement(ex.toString());
        req.setExtData(IRequest.ERRORS, ev);
    }

    /**
     * log a message for this policy rule.
     */
    protected void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER, level,
                "APolicyRule " + NAME + ": " + msg);
    }

    public static KeyIdentifier createKeyIdentifier(X509Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");

        md.update(key.getEncoded());
        return new KeyIdentifier(md.digest());
    }

    /**
     * Form a byte array of octet string key identifier from the sha-1 hash of
     * the Subject Public Key INFO. (including algorithm ID, etc.)
     * <p>
     *
     * @param certInfo cert info of the certificate.
     * @return A Key identifier with the sha-1 hash of subject public key.
     */
    protected KeyIdentifier formSpkiSHA1KeyId(X509CertInfo certInfo)
            throws EBaseException {
        KeyIdentifier keyId = null;

        try {
            CertificateX509Key certKey =
                    (CertificateX509Key) certInfo.get(X509CertInfo.KEY);

            if (certKey == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_MISSING_KEY_1", ""));
                throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_MISSING_KEY", NAME));
            }
            X509Key key = (X509Key) certKey.get(CertificateX509Key.KEY);

            if (key == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_MISSING_KEY_1", ""));
                throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_MISSING_KEY", NAME));
            }
            keyId = createKeyIdentifier(key);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME));
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME));
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME));
        } catch (NoSuchAlgorithmException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME));
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME));
        } catch (InvalidKeyException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME));
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME));
        }
        return keyId;
    }

    /**
     * Form a byte array of octet string key identifier from the sha-1 hash of
     * the Subject Public Key BIT STRING.
     * <p>
     *
     * @param certInfo cert info of the certificate.
     * @return A Key identifier with the sha-1 hash of subject public key.
     */
    protected KeyIdentifier formSHA1KeyId(X509CertInfo certInfo)
            throws EBaseException {
        KeyIdentifier keyId = null;

        try {
            CertificateX509Key certKey =
                    (CertificateX509Key) certInfo.get(X509CertInfo.KEY);

            if (certKey == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_MISSING_KEY_1", ""));
                throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_MISSING_KEY", NAME));
            }
            X509Key key = (X509Key) certKey.get(CertificateX509Key.KEY);

            if (key == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_MISSING_KEY_1", ""));
                throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_MISSING_KEY", NAME));
            }
            byte[] rawKey = key.getKey();

            MessageDigest md = MessageDigest.getInstance("SHA-1");

            md.update(rawKey);
            keyId = new KeyIdentifier(md.digest());
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME));
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME));
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME));
        } catch (NoSuchAlgorithmException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME));
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME));
        }
        return keyId;
    }
}
