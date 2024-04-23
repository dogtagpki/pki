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
package org.dogtagpki.legacy.server.policy;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Vector;

import org.dogtagpki.legacy.policy.EPolicyException;
import org.dogtagpki.legacy.policy.IExpression;
import org.dogtagpki.legacy.policy.PolicyProcessor;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.AgentApprovals;
import com.netscape.certsrv.request.Policy;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

/**
 * The abstract policy rule that concrete implementations will
 * extend.
 *
 * NOTE:  The Policy Framework has been replaced by the Profile Framework.
 */
public abstract class PolicyRule extends Policy {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PolicyRule.class);

    public static final String PROP_ENABLE = "enable";
    public static final String PROP_PREDICATE = "predicate";
    public static final String PROP_IMPLNAME = "implName";

    protected String NAME = null;
    protected String DESC = null;
    protected IExpression mFilterExp = null;
    protected String mInstanceName = null;

    public PolicyRule() {
    }

    /**
     * Initializes the policy rule.
     *
     * @param config The config store reference
     */
    public abstract void init(PolicyProcessor owner, ConfigStore config) throws EBaseException;

    /**
     * Gets the description for this policy rule.
     *
     * @return The Description for this rule.
     */
    public String getDescription() {
        return DESC;
    }

    /**
     * Sets a predicate expression for rule matching.
     *
     * @param exp The predicate expression for the rule.
     */
    public void setPredicate(IExpression exp) {
        mFilterExp = exp;
    }

    /**
     * Returns the predicate expression for the rule.
     *
     * @return The predicate expression for the rule.
     */
    public IExpression getPredicate() {
        return mFilterExp;
    }

    /**
     * Returns the name of the policy rule.
     *
     * @return The name of the policy class.
     */
    public String getName() {
        return NAME;
    }

    /**
     * Sets the instance name for a policy rule.
     *
     * @param instanceName The name of the rule instance.
     */
    public void setInstanceName(String instanceName) {
        mInstanceName = instanceName;
    }

    /**
     * Returns the name of the policy rule instance.
     *
     * @return The name of the policy rule instance if set, else
     *         the name of the rule class.
     */
    public String getInstanceName() {
        return mInstanceName != null ? mInstanceName : NAME;
    }

    /**
     * Applies the policy on the given Request.
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public abstract PolicyResult apply(Request req);

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

    public void setError(Request req, String format, Object[] params) {
        setPolicyException(req, format, params);
    }

    public void setError(Request req, String format, String arg1,
            String arg2) {
        Object[] np = new Object[2];

        np[0] = arg1;
        np[1] = arg2;
        setPolicyException(req, format, np);
    }

    public void setError(Request req, String format, String arg) {
        Object[] np = new Object[1];

        np[0] = arg;
        setPolicyException(req, format, np);
    }

    public void setPolicyException(Request req, EBaseException ex) {
        Vector<String> ev = req.getExtDataInStringVector(Request.ERRORS);
        if (ev == null) {
            ev = new Vector<>();
        }
        ev.addElement(ex.toString());
        req.setExtData(Request.ERRORS, ev);

    }

    /**
     * determines whether a DEFERRED policy result should be returned
     * by checking the contents of the AgentApprovals attribute. This
     * call should be used by policy modules instead of returning
     * PolicyResult.DEFERRED directly.
     */
    protected PolicyResult deferred(Request req) {
        // Try to find an agent approval
        AgentApprovals aa = AgentApprovals.fromStringVector(
                req.getExtDataInStringVector(AgentApprovals.class.getName()));

        // Any approvals causes success
        return aa != null && aa.elements().hasMoreElements() ? PolicyResult.ACCEPTED : PolicyResult.DEFERRED;
    }

    /**
     * request has previously been approved by an agent
     */
    protected boolean agentApproved(Request req) {
        // Try to find an agent approval
        AgentApprovals aa = AgentApprovals.fromStringVector(
                req.getExtDataInStringVector(AgentApprovals.class.getName()));

        // Any approvals causes success
        return aa != null && aa.elements().hasMoreElements();
    }

    public void setPolicyException(Request req, String format,
            Object[] params) {
        if (format == null)
            return;

        EPolicyException ex;

        if (params == null)
            ex = new EPolicyException(format);
        else
            ex = new EPolicyException(format, params);

        Vector<String> ev = req.getExtDataInStringVector(Request.ERRORS);
        if (ev == null) {
            ev = new Vector<>();
        }
        ev.addElement(ex.toString());
        req.setExtData(Request.ERRORS, ev);
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
                logger.error(CMS.getLogMessage("POLICY_MISSING_KEY_1", ""));
                throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_MISSING_KEY", NAME));
            }
            X509Key key = (X509Key) certKey.get(CertificateX509Key.KEY);

            if (key == null) {
                logger.error(CMS.getLogMessage("POLICY_MISSING_KEY_1", ""));
                throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_MISSING_KEY", NAME));
            }
            keyId = createKeyIdentifier(key);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME), e);
            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME), e);
        } catch (CertificateException e) {
            logger.error(CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME), e);
            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME), e);
        } catch (NoSuchAlgorithmException e) {
            logger.error(CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME), e);
            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME), e);
        } catch (InvalidKeyException e) {
            logger.error(CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME), e);
            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME), e);
        }
        return keyId;
    }

    /**
     * Form a byte array of octet string key identifier from the sha-1 hash of
     * the Subject Public Key BIT STRING.
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
                logger.error(CMS.getLogMessage("POLICY_MISSING_KEY_1", ""));
                throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_MISSING_KEY", NAME));
            }
            X509Key key = (X509Key) certKey.get(CertificateX509Key.KEY);

            if (key == null) {
                logger.error(CMS.getLogMessage("POLICY_MISSING_KEY_1", ""));
                throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_MISSING_KEY", NAME));
            }
            byte[] rawKey = key.getKey();

            MessageDigest md = MessageDigest.getInstance("SHA-1");

            md.update(rawKey);
            keyId = new KeyIdentifier(md.digest());
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME), e);
            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME), e);
        } catch (CertificateException e) {
            logger.error(CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME), e);
            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME), e);
        } catch (NoSuchAlgorithmException e) {
            logger.error(CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME), e);
            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME), e);
        }
        return keyId;
    }
}
