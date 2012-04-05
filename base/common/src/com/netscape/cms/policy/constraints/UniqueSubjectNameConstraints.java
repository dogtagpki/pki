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

import java.io.IOException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.KeyUsageExtension;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.policy.IPolicyProcessor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Checks the uniqueness of the subject name. This policy
 * can only be used (installed) in Certificate Authority
 * subsystem.
 *
 * This policy can perform pre-agent-approval checking or
 * post-agent-approval checking based on configuration
 * setting.
 *
 * In some situations, user may want to have 2 certificates with
 * the same subject name. For example, one key for encryption,
 * and one for signing. This policy does not deal with this case
 * directly. But it can be easily extended to do that.
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
public class UniqueSubjectNameConstraints extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    protected static final String PROP_PRE_AGENT_APPROVAL_CHECKING =
            "enablePreAgentApprovalChecking";
    protected static final String PROP_KEY_USAGE_EXTENSION_CHECKING =
            "enableKeyUsageExtensionChecking";

    public ICertificateAuthority mCA = null;

    public boolean mPreAgentApprovalChecking = false;
    public boolean mKeyUsageExtensionChecking = true;

    public UniqueSubjectNameConstraints() {
        NAME = "UniqueSubjectName";
        DESC = "Ensure the uniqueness of the subject name.";
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_PRE_AGENT_APPROVAL_CHECKING
                        + ";boolean;If checked, check subject name uniqueness BEFORE agent approves, (else checks AFTER approval)",
                PROP_KEY_USAGE_EXTENSION_CHECKING
                        + ";boolean;If checked, allow non-unique subject names if Key Usage Extension differs",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-uniquesubjectname",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Rejects a request if there exists an unrevoked, unexpired " +
                        "certificate with the same subject name"
        };

        return params;

    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries probably are of the form:
     *
     * ca.Policy.rule.<ruleName>.implName=UniqueSubjectName ca.Policy.rule.<ruleName>.enable=true
     * ca.Policy.rule.<ruleName>.enable=true ca.Policy.rule.<ruleName>.enablePreAgentApprovalChecking=true
     * ca.Policy.rule.<ruleName>.enableKeyUsageExtensionChecking=true
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        // get CA's public key to create authority key id.
        ICertAuthority certAuthority = (ICertAuthority)
                ((IPolicyProcessor) owner).getAuthority();

        if (certAuthority == null) {
            // should never get here.
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CANT_FIND_MANAGER"));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                    "Cannot find the Certificate Manager or Registration Manager"));
        }
        if (!(certAuthority instanceof ICertificateAuthority)) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CANT_FIND_MANAGER"));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                    "Cannot find the Certificate Manager"));
        }

        mCA = (ICertificateAuthority) certAuthority;
        try {
            mPreAgentApprovalChecking =
                    config.getBoolean(PROP_PRE_AGENT_APPROVAL_CHECKING, false);
        } catch (EBaseException e) {
        }
        try {
            mKeyUsageExtensionChecking =
                    config.getBoolean(PROP_KEY_USAGE_EXTENSION_CHECKING, true);
        } catch (EBaseException e) {
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
        if (!mPreAgentApprovalChecking) {
            // post agent approval checking
            if (!agentApproved(req))
                return PolicyResult.ACCEPTED;
        }
        PolicyResult result = PolicyResult.ACCEPTED;

        try {

            // Get the certificate templates
            X509CertInfo[] certInfos = req.getExtDataInCertInfoArray(
                    IRequest.CERT_INFO);

            if (certInfos == null) {
                setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO",
                        getInstanceName()), "");
                return PolicyResult.REJECTED;
            }

            // retrieve the subject name and check its unqiueness
            for (int i = 0; i < certInfos.length; i++) {
                CertificateSubjectName subName = (CertificateSubjectName)
                        certInfos[i].get(X509CertInfo.SUBJECT);

                // if there is no name set, set one here.
                if (subName == null) {
                    setError(req, CMS.getUserMessage("CMS_POLICY_NO_SUBJECT_NAME",
                            getInstanceName()), "");
                    return PolicyResult.REJECTED;
                }
                String certSubjectName = subName.toString();
                String filter = "x509Cert.subject=" + certSubjectName;
                // subject name is indexed, so we only use subject name
                // in the filter
                Enumeration<ICertRecord> matched =
                        mCA.getCertificateRepository().findCertRecords(filter);

                while (matched.hasMoreElements()) {
                    ICertRecord rec = matched.nextElement();
                    String status = rec.getStatus();

                    if (status.equals(ICertRecord.STATUS_REVOKED)
                            || status.equals(ICertRecord.STATUS_EXPIRED)
                            || status.equals(ICertRecord.STATUS_REVOKED_EXPIRED)) {
                        // accept this only if we have a REVOKED,
                        // EXPIRED or REVOKED_EXPIRED certificate
                        continue;

                    }
                    // you already have an VALID or INVALID (not yet valid) certificate
                    if (mKeyUsageExtensionChecking && agentApproved(req)) {
                        // This request is agent approved which
                        // means all requested extensions are finalized
                        // to the request,
                        // We will accept duplicated subject name with
                        // different keyUsage extension if
                        // keyUsageExtension is different.
                        if (!sameKeyUsageExtension(rec, certInfos[i])) {
                            continue;
                        }
                    }

                    setError(req, CMS.getUserMessage("CMS_POLICY_SUBJECT_NAME_EXIST",
                            getInstanceName() + " " + certSubjectName), "");
                    return PolicyResult.REJECTED;
                }
            }
        } catch (Exception e) {
            String params[] = { getInstanceName(), e.toString() };

            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR",
                    params), "");
            result = PolicyResult.REJECTED;
        }
        return result;
    }

    /**
     * Checks if the key extension in the issued certificate
     * is the same as the one in the certificate template.
     */
    private boolean sameKeyUsageExtension(ICertRecord rec,
            X509CertInfo certInfo) {
        X509CertImpl impl = rec.getCertificate();
        boolean bits[] = impl.getKeyUsage();

        CertificateExtensions extensions = null;

        try {
            extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);
        } catch (IOException e) {
        } catch (java.security.cert.CertificateException e) {
        }
        KeyUsageExtension ext = null;

        if (extensions == null) {
            if (bits != null)
                return false;
        } else {
            try {
                ext = (KeyUsageExtension) extensions.get(
                            KeyUsageExtension.NAME);
            } catch (IOException e) {
                // extension isn't there.
            }

            if (ext == null) {
                if (bits != null)
                    return false;
            } else {
                boolean[] InfoBits = ext.getBits();

                if (InfoBits == null) {
                    if (bits != null)
                        return false;
                } else {
                    if (bits == null)
                        return false;
                    if (InfoBits.length != bits.length) {
                        return false;
                    }
                    for (int i = 0; i < InfoBits.length; i++) {
                        if (InfoBits[i] != bits[i])
                            return false;
                    }
                }
            }
        }
        return true;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        Vector<String> confParams = new Vector<String>();

        confParams.addElement(PROP_PRE_AGENT_APPROVAL_CHECKING +
                "=" + mPreAgentApprovalChecking);
        confParams.addElement(PROP_KEY_USAGE_EXTENSION_CHECKING +
                "=" + mKeyUsageExtensionChecking);
        return confParams;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        Vector<String> defParams = new Vector<String>();

        defParams.addElement(PROP_PRE_AGENT_APPROVAL_CHECKING + "=");
        defParams.addElement(PROP_KEY_USAGE_EXTENSION_CHECKING + "=");
        return defParams;
    }
}
