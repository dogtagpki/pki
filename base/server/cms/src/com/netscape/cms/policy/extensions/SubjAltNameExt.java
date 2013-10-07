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
package com.netscape.cms.policy.extensions;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Locale;
import java.util.Vector;

import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.GeneralNames;
import netscape.security.x509.RFC822Name;
import netscape.security.x509.SubjectAlternativeNameExtension;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 *
 * THIS POLICY HAS BEEN DEPRECATED SINCE CMS 4.2.
 * New Policy is com.netscape.certsrv.policy.SubjectAltNameExt.
 * <p>
 *
 * Subject Alternative Name extension policy in CMS 4.1.
 *
 * Adds the subject alternative name extension depending on the certificate type requested.
 *
 * Two forms are supported. 1) For S/MIME certificates, email addresses are copied from data stored in the request by
 * the authentication component. Both 'e' and 'altEmail' are supported so that both the primary address and alternative
 * forms may be certified. Only the primary goes in the subjectName position (which should be phased out).
 *
 * e mailAlternateAddress
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
public class SubjAltNameExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    // for future use. currently always allow.
    protected static final String PROP_AGENT_OVERR = "allowAgentOverride";
    protected static final String PROP_EE_OVERR = "AllowEEOverride";
    protected static final String PROP_ENABLE_MANUAL_VALUES =
            "enableManualValues";

    // for future use. currently always non-critical
    // (standard says SHOULD be marked critical if included.)
    protected static final String PROP_CRITICAL = "critical";

    // for future use to allow overrides from forms.
    // request must be agent approved or authenticated.
    protected boolean mAllowAgentOverride = false;
    protected boolean mAllowEEOverride = false;
    protected boolean mEnableManualValues = false;

    // for future use. currently always critical
    // (standard says SHOULD be marked critical if included.)
    protected boolean mCritical = false;

    public SubjAltNameExt() {
        NAME = "SubjAltNameExt";
        DESC = "Sets alternative subject names for certificates";
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_CRITICAL
                        + ";boolean;RFC 2459 recommendation: If the certificate subject field contains an empty sequence, the subjectAltName extension MUST be marked critical.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-subjaltname",
                IExtendedPluginInfo.HELP_TEXT +
                        ";This policy inserts the Subject Alternative Name " +
                        "Extension into the certificate. See RFC 2459 (4.2.1.7). " +
                        "* Note: you probably want to use this policy in " +
                        "conjunction with an authentication manager which sets " +
                        "the 'mail' or 'mailalternateaddress' values in the authToken. " +
                        "See the 'ldapStringAttrs' parameter in the Directory-based " +
                        "authentication plugin"
        };

        return params;

    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries may be of the form:
     *
     * ra.Policy.rule.<ruleName>.implName=SubjAltNameExt ra.Policy.rule.<ruleName>.enable=true
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        // future use.
        mAllowAgentOverride = config.getBoolean(PROP_AGENT_OVERR, false);
        mAllowEEOverride = config.getBoolean(PROP_EE_OVERR, false);
        mCritical = config.getBoolean(PROP_CRITICAL, false);
        // mEnableManualValues = config.getBoolean(PROP_ENABLE_MANUAL_VALUES, false);
    }

    /**
     * Adds the subject alternative names extension if not set already.
     *
     * <P>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        PolicyResult res = PolicyResult.ACCEPTED;

        // Find the X509CertInfo object in the request
        X509CertInfo[] ci =
                req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        if (ci == null || ci[0] == null) {
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO"), NAME);

            return PolicyResult.REJECTED; // unrecoverable error.
        }

        for (int i = 0; i < ci.length; i++) {
            PolicyResult certRes = applyCert(req, ci[i]);

            if (certRes == PolicyResult.REJECTED)
                return certRes;
        }
        return res;
    }

    public PolicyResult applyCert(IRequest req, X509CertInfo certInfo) {
        PolicyResult res = PolicyResult.ACCEPTED;

        //
        // General error handling block
        //
        apply: try {

            // Find the extensions in the certInfo
            CertificateExtensions extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);

            if (extensions != null) {
                //
                // Remove any previously computed version of the extension
                //
                try {
                    extensions.delete(SubjectAlternativeNameExtension.NAME);
                } catch (IOException e) {
                    // extension isn't there
                }
            }

            //
            // Determine the type of the request.  For future expansion
            // this test should dispatch to a specialized object to
            // handle each particular type.  For now just return for
            // non-client certs, and implement client certs directly here.
            //
            String certType =
                    req.getExtDataInString(IRequest.HTTP_PARAMS, IRequest.CERT_TYPE);

            if (certType == null ||
                    !certType.equals(IRequest.CLIENT_CERT) ||
                    !req.getExtDataInBoolean(IRequest.SMIME, false)) {
                break apply;
            }

            // Create a list of email addresses that should be added
            // to the certificate

            IAuthToken tok = findAuthToken(req, null);

            if (tok == null)
                break apply;

            Vector<String> emails = getEmailList(tok);

            if (emails == null)
                break apply;

            // Create the extension
            SubjectAlternativeNameExtension subjAltNameExt = mkExt(emails);

            if (extensions == null)
                extensions = createCertificateExtensions(certInfo);

            extensions.set(SubjectAlternativeNameExtension.NAME,
                    subjAltNameExt);

        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_IO_ERROR", e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                    NAME, e.getMessage());
            return PolicyResult.REJECTED; // unrecoverable error.
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CERT_INFO_ERROR", e.toString()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                    NAME, "Certificate Info Error");
            return PolicyResult.REJECTED; // unrecoverable error.
        }

        return res;
    }

    /**
     * Find a particular authentication token by manager name.
     * If the token is not present return null
     */
    protected IAuthToken
            findAuthToken(IRequest req, String authMgrName) {

        return req.getExtDataInAuthToken(IRequest.AUTH_TOKEN);
    }

    /**
     * Generate a String Vector containing all the email addresses
     * found in this Authentication token
     * @throws IOException
     */
    protected Vector<String> getEmailList(IAuthToken tok) throws IOException {

        Vector<String> v = new Vector<String>();

        addValues(tok, "mail", v);
        addValues(tok, "mailalternateaddress", v);

        if (v.size() == 0)
            return null;

        return v;
    }

    /**
     * Add attribute values from an LDAP attribute to a vector
     * @throws IOException
     */
    protected void
            addValues(IAuthToken tok, String attrName, Vector<String> v) throws IOException {
        String attr[] = tok.getInStringArray(attrName);

        if (attr == null)
            return;

        for (int i = 0; i < attr.length; i++) {
            v.addElement(attr[i]);
        }
    }

    /**
     * Make a Subject name extension given a list of email addresses
     */
    protected SubjectAlternativeNameExtension
            mkExt(Vector<String> emails)
                    throws IOException {
        SubjectAlternativeNameExtension sa;
        GeneralNames gns = new GeneralNames();

        for (int i = 0; i < emails.size(); i++) {
            String email = emails.elementAt(i);

            gns.addElement(new RFC822Name(email));
        }

        sa = new SubjectAlternativeNameExtension(gns);

        return sa;
    }

    /**
     * Create a new SET of extensions in the certificate info
     * object.
     *
     * This should be a method in the X509CertInfo object
     */
    protected CertificateExtensions
            createCertificateExtensions(X509CertInfo certInfo)
                    throws IOException, CertificateException {
        CertificateExtensions extensions;

        // Force version to V3
        certInfo.set(X509CertInfo.VERSION,
                new CertificateVersion(CertificateVersion.V3));

        extensions = new CertificateExtensions();
        certInfo.set(X509CertInfo.EXTENSIONS, extensions);

        return extensions;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        Vector<String> params = new Vector<String>();

        //params.addElement("PROP_AGENT_OVERR = " + mAllowAgentOverride);
        //params.addElement("PROP_EE_OVERR = " + mAllowEEOverride);
        params.addElement(PROP_CRITICAL + "=" + mCritical);
        // params.addElement(PROP_ENABLE_MANUAL_VALUES + " = " +
        //	mEnableManualValues);
        return params;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        Vector<String> defParams = new Vector<String>();

        //defParams.addElement("PROP_AGENT_OVERR = " + DEF_AGENT_OVERR);
        //defParams.addElement("PROP_EE_OVERR = " + DEF_EE_OVERR);
        defParams.addElement(PROP_CRITICAL + "=false");
        // defParams.addElement(PROP_ENABLE_MANUAL_VALUES + "= false");

        return defParams;
    }
}
