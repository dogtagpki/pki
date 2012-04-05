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

import netscape.security.extensions.CertificateScopeEntry;
import netscape.security.extensions.CertificateScopeOfUseExtension;
import netscape.security.util.BigInt;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.GeneralName;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.policy.IGeneralNameUtil;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Certificate Scope Of Use extension policy. This extension
 * is defined in draft-thayes-cert-scope-00.txt
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
public class CertificateScopeOfUseExt extends APolicyRule implements
        IEnrollmentPolicy, IExtendedPluginInfo {
    protected static final String PROP_CRITICAL =
            "critical";
    protected static final String PROP_ENTRY =
            "entry";
    protected static final String PROP_NAME =
            "name";
    protected static final String PROP_NAME_TYPE =
            "name_type";
    protected static final String PROP_PORT_NUMBER =
            "port_number";

    public static final int MAX_ENTRY = 5;

    public IConfigStore mConfig = null;

    public CertificateScopeOfUseExt() {
        NAME = "CertificateScopeOfUseExt";
        DESC = "Sets scope of use extension for certificates";
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        Vector<String> v = new Vector<String>();

        v.addElement(PROP_CRITICAL +
                ";boolean; This extension may be either critical or non-critical.");
        v.addElement(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-policyrules-certificatescopeofuse");
        v.addElement(IExtendedPluginInfo.HELP_TEXT +
                ";Adds Certificate Scope of Use Extension.");

        for (int i = 0; i < MAX_ENTRY; i++) {
            v.addElement(PROP_ENTRY + Integer.toString(i) + "_" + PROP_NAME + ";" + IGeneralNameUtil.GENNAME_VALUE_INFO);
            v.addElement(PROP_ENTRY
                    + Integer.toString(i) + "_" + PROP_NAME_TYPE + ";" + IGeneralNameUtil.GENNAME_CHOICE_INFO);
            v.addElement(PROP_ENTRY
                    + Integer.toString(i) + "_" + PROP_PORT_NUMBER + ";string;" + "The port number (optional).");
        }
        return com.netscape.cmsutil.util.Utils.getStringArrayFromVector(v);
    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries may be of the form:
     *
     * ca.Policy.rule.<ruleName>.implName=AuthInfoAccessExt ca.Policy.rule.<ruleName>.enable=true
     * ca.Policy.rule.<ruleName>.predicate=
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mConfig = config;
    }

    /**
     * Returns a sequence of scope entry.
     */
    private Vector<CertificateScopeEntry> getScopeEntries() throws EBaseException {
        Vector<CertificateScopeEntry> entries = new Vector<CertificateScopeEntry>();

        //
        // read until there is *NO* ad<NUM>_method
        //
        for (int i = 0;; i++) {
            // get port number (optional)
            String port = mConfig.getString(PROP_ENTRY +
                    Integer.toString(i) + "_" + PROP_PORT_NUMBER, null);
            BigInt portNumber = null;

            if (port != null && !port.equals("")) {
                portNumber = new BigInt(Integer.parseInt(port));
            }

            //
            // location ::= <TAG> : <VALUE>
            // TAG ::= uriName | dirName
            // VALUE ::= [value defined by TAG]
            //
            String name_type = mConfig.getString(PROP_ENTRY +
                    Integer.toString(i) +
                    "_" + PROP_NAME_TYPE, null);
            String name = mConfig.getString(PROP_ENTRY +
                    Integer.toString(i) +
                    "_" + PROP_NAME, null);

            if (name == null || name.equals(""))
                break;
            GeneralName gn = CMS.form_GeneralNameAsConstraints(name_type, name);

            entries.addElement(new CertificateScopeEntry(gn, portNumber));
        }
        return entries;
    }

    /**
     * If this policy is enabled, add the authority information
     * access extension to the certificate.
     * <P>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        PolicyResult res = PolicyResult.ACCEPTED;

        X509CertInfo certInfo;
        X509CertInfo[] ci = req.getExtDataInCertInfoArray(
                IRequest.CERT_INFO);

        if (ci == null) {
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO"), NAME);
            return PolicyResult.REJECTED; // unrecoverable error.
        }

        for (int j = 0; j < ci.length; j++) {

            certInfo = ci[j];
            if (certInfo == null) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CA_CERT_INFO_ERROR", NAME));
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                        NAME, "Configuration Info Error");
                return PolicyResult.REJECTED; // unrecoverable error.
            }

            try {
                // Find the extensions in the certInfo
                CertificateExtensions extensions = (CertificateExtensions)
                        certInfo.get(X509CertInfo.EXTENSIONS);

                // add access descriptions
                Vector<CertificateScopeEntry> entries = getScopeEntries();

                if (entries.size() == 0) {
                    return res;
                }

                if (extensions == null) {
                    // create extension if not exist
                    certInfo.set(X509CertInfo.VERSION,
                            new CertificateVersion(CertificateVersion.V3));
                    extensions = new CertificateExtensions();
                    certInfo.set(X509CertInfo.EXTENSIONS, extensions);
                } else {
                    // check to see if AIA is already exist
                    try {
                        extensions.delete(CertificateScopeOfUseExtension.NAME);
                        log(ILogger.LL_INFO, "Previous extension deleted: " + CertificateScopeOfUseExtension.NAME);
                    } catch (IOException ex) {
                    }
                }

                // Create the extension
                CertificateScopeOfUseExtension suExt = new
                        CertificateScopeOfUseExtension(mConfig.getBoolean(
                                PROP_CRITICAL, false), entries);

                extensions.set(CertificateScopeOfUseExtension.NAME, suExt);

            } catch (IOException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_IO_ERROR", e.getMessage()));
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                        NAME, e.getMessage());
                return PolicyResult.REJECTED; // unrecoverable error.
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE,
                        "Configuration Info Error encountered: " +
                                e.getMessage());
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                        NAME, "Configuration Info Error");
                return PolicyResult.REJECTED; // unrecoverable error.
            } catch (CertificateException e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CA_CERT_INFO_ERROR", e.getMessage()));
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                        NAME, "Certificate Info Error");
                return PolicyResult.REJECTED; // unrecoverable error.
            }
        }

        return res;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        Vector<String> params = new Vector<String>();

        try {
            params.addElement(PROP_CRITICAL + "=" +
                    mConfig.getBoolean(PROP_CRITICAL, false));
        } catch (EBaseException e) {
        }

        for (int i = 0;; i++) {
            String name_type = null;

            try {
                name_type = mConfig.getString(PROP_ENTRY +
                            Integer.toString(i) + "_" + PROP_NAME_TYPE,
                            null);
            } catch (EBaseException e) {
            }
            if (name_type == null)
                break;
            params.addElement(PROP_ENTRY +
                    Integer.toString(i) +
                    "_" + PROP_NAME_TYPE + "=" + name_type);
            String name = null;

            try {
                name = mConfig.getString(PROP_ENTRY +
                            Integer.toString(i) + "_" + PROP_NAME,
                            null);
            } catch (EBaseException e) {
            }
            if (name == null)
                break;
            params.addElement(PROP_ENTRY +
                    Integer.toString(i) +
                    "_" + PROP_NAME + "=" + name);
            String port = null;

            try {
                port = mConfig.getString(PROP_ENTRY +
                            Integer.toString(i) + "_" + PROP_PORT_NUMBER,
                            "");
            } catch (EBaseException e) {
            }
            params.addElement(PROP_ENTRY +
                    Integer.toString(i) +
                    "_" + PROP_PORT_NUMBER + "=" + port);
        }
        return params;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        Vector<String> defParams = new Vector<String>();

        defParams.addElement(PROP_CRITICAL + "=false");

        //
        // By default, we create MAX_AD access descriptions.
        // If this is not enough, admin can manually edit
        // the CMS.cfg
        //
        for (int i = 0; i < MAX_ENTRY; i++) {
            defParams.addElement(PROP_ENTRY + Integer.toString(i) +
                    "_" + PROP_NAME_TYPE + "=");
            defParams.addElement(PROP_ENTRY + Integer.toString(i) +
                    "_" + PROP_NAME + "=");
            defParams.addElement(PROP_ENTRY + Integer.toString(i) +
                    "_" + PROP_PORT_NUMBER + "=");
        }
        return defParams;
    }
}
