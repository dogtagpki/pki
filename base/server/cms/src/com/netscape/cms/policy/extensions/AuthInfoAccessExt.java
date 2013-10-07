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
import java.io.Serializable;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import netscape.security.extensions.AuthInfoAccessExtension;
import netscape.security.util.ObjectIdentifier;
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
 * Authority Information Access extension policy.
 * If this policy is enabled, it adds an authority
 * information access extension to the certificate.
 *
 * The following listed sample configuration parameters:
 *
 * ca.Policy.impl.AuthInfoAccess.class=com.netscape.certsrv.policy.AuthInfoAccessExt
 * ca.Policy.rule.aia.ad0_location=uriName:http://ocsp1.netscape.com
 * ca.Policy.rule.aia.ad0_method=ocsp
 * ca.Policy.rule.aia.ad1_location_type=URI
 * ca.Policy.rule.aia.ad1_location=http://ocsp2.netscape.com
 * ca.Policy.rule.aia.ad1_method=ocsp
 * ca.Policy.rule.aia.ad2_location=
 * ca.Policy.rule.aia.ad2_method=
 * ca.Policy.rule.aia.ad3_location=
 * ca.Policy.rule.aia.ad3_method=
 * ca.Policy.rule.aia.ad4_location=
 * ca.Policy.rule.aia.ad4_method=
 * ca.Policy.rule.aia.critical=true
 * ca.Policy.rule.aia.enable=true
 * ca.Policy.rule.aia.implName=AuthInfoAccess
 * ca.Policy.rule.aia.predicate=
 *
 * Currently, this policy only supports the following location:
 * uriName:[URI], dirName:[DN]
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
public class AuthInfoAccessExt extends APolicyRule implements
        IEnrollmentPolicy, IExtendedPluginInfo {
    protected static final String PROP_CRITICAL =
            "critical";
    protected static final String PROP_AD =
            "ad";
    protected static final String PROP_METHOD =
            "method";
    protected static final String PROP_LOCATION =
            "location";
    protected static final String PROP_LOCATION_TYPE =
            "location_type";

    protected static final String PROP_NUM_ADS =
            "numADs";

    public static final int MAX_AD = 5;

    public IConfigStore mConfig = null;

    public AuthInfoAccessExt() {
        NAME = "AuthInfoAccessExt";
        DESC = "Sets authority information access extension for certificates";
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        Vector<String> v = new Vector<String>();

        v.addElement(PROP_CRITICAL +
                ";boolean;RFC 2459 recommendation: This extension MUST be non-critical.");
        v.addElement(PROP_NUM_ADS +
                ";number;The total number of access descriptions.");
        v.addElement(IExtendedPluginInfo.HELP_TEXT +
                ";Adds Authority Info Access Extension. Defined in RFC 2459 " + "(4.2.2.1)");
        v.addElement(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-policyrules-authinfoaccess");

        for (int i = 0; i < MAX_AD; i++) {
            v.addElement(PROP_AD
                    + Integer.toString(i)
                    + "_"
                    + PROP_METHOD
                    + ";string;"
                    + "A unique,valid OID specified in dot-separated numeric component notation. e.g. 1.3.6.1.5.5.7.48.1 (ocsp), 1.3.6.1.5.5.7.48.2 (caIssuers), 2.16.840.1.113730.1.16.1 (renewal)");
            v.addElement(PROP_AD
                    + Integer.toString(i) + "_" + PROP_LOCATION_TYPE + ";" + IGeneralNameUtil.GENNAME_CHOICE_INFO);
            v.addElement(PROP_AD
                    + Integer.toString(i) + "_" + PROP_LOCATION + ";" + IGeneralNameUtil.GENNAME_VALUE_INFO);
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
     * Returns a sequence of access descriptions.
     */
    private Enumeration<Vector<Serializable>> getAccessDescriptions() throws EBaseException {
        Vector<Vector<Serializable>> ads = new Vector<Vector<Serializable>>();

        //
        // read until there is *NO* ad<NUM>_method
        //
        for (int i = 0;; i++) {
            ObjectIdentifier methodOID = null;
            String method = mConfig.getString(PROP_AD +
                    Integer.toString(i) + "_" + PROP_METHOD, null);

            if (method == null)
                break;
            method = method.trim();
            if (method.equals(""))
                break;

            //
            // method ::= ocsp | caIssuers | <OID>
            // OID ::= [object identifier]
            //
            try {
                if (method.equalsIgnoreCase("ocsp")) {
                    methodOID = ObjectIdentifier.getObjectIdentifier("1.3.6.1.5.5.7.48.1");
                } else if (method.equalsIgnoreCase("caIssuers")) {
                    methodOID = ObjectIdentifier.getObjectIdentifier("1.3.6.1.5.5.7.48.2");
                } else if (method.equalsIgnoreCase("renewal")) {
                    methodOID = ObjectIdentifier.getObjectIdentifier("2.16.840.1.113730.1.16.1");
                } else {
                    // it could be an object identifier, test it
                    methodOID = ObjectIdentifier.getObjectIdentifier(method);
                }
            } catch (IOException e) {
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NAME_CAN_NOT_BE_RESOLVED", method));
            }

            //
            // location ::= <TAG> : <VALUE>
            // TAG ::= uriName | dirName
            // VALUE ::= [value defined by TAG]
            //
            String location_type = mConfig.getString(PROP_AD +
                    Integer.toString(i) +
                    "_" + PROP_LOCATION_TYPE, null);
            String location = mConfig.getString(PROP_AD +
                    Integer.toString(i) +
                    "_" + PROP_LOCATION, null);

            if (location == null)
                break;
            GeneralName gn = CMS.form_GeneralName(location_type, location);
            Vector<Serializable> e = new Vector<Serializable>();

            e.addElement(methodOID);
            e.addElement(gn);
            ads.addElement(e);
        }
        return ads.elements();
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
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO", NAME), "");
            return PolicyResult.REJECTED; // unrecoverable error.
        }

        for (int j = 0; j < ci.length; j++) {

            certInfo = ci[j];
            if (certInfo == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_UNEXPECTED_POLICY_ERROR", NAME, ""));
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR",
                        NAME, "Configuration Info Error"), "");
                return PolicyResult.REJECTED; // unrecoverable error.
            }

            try {
                // Find the extensions in the certInfo
                CertificateExtensions extensions = (CertificateExtensions)
                        certInfo.get(X509CertInfo.EXTENSIONS);

                // add access descriptions
                Enumeration<Vector<Serializable>> e = getAccessDescriptions();

                if (!e.hasMoreElements()) {
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
                        extensions.delete(AuthInfoAccessExtension.NAME);
                        log(ILogger.LL_WARN,
                                "Previous extension deleted: " + AuthInfoAccessExtension.NAME);
                    } catch (IOException ex) {
                    }
                }

                // Create the extension
                AuthInfoAccessExtension aiaExt = new
                        AuthInfoAccessExtension(mConfig.getBoolean(
                                PROP_CRITICAL, false));

                while (e.hasMoreElements()) {
                    Vector<Serializable> ad = e.nextElement();
                    ObjectIdentifier oid = (ObjectIdentifier) ad.elementAt(0);
                    GeneralName gn = (GeneralName) ad.elementAt(1);

                    aiaExt.addAccessDescription(oid, gn);
                }
                extensions.set(AuthInfoAccessExtension.NAME, aiaExt);

            } catch (IOException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_UNEXPECTED_POLICY_ERROR", NAME, e.getMessage()));
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR",
                        NAME, e.getMessage()), "");
                return PolicyResult.REJECTED; // unrecoverable error.
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_UNEXPECTED_POLICY_ERROR", NAME, e.getMessage()));
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR",
                        NAME, "Configuration Info Error"), "");
                return PolicyResult.REJECTED; // unrecoverable error.
            } catch (CertificateException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_UNEXPECTED_POLICY_ERROR", NAME, e.getMessage()));
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR",
                        NAME, "Certificate Info Error"), "");
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
            params.addElement(PROP_CRITICAL + "=false");
        }

        int numADs = MAX_AD;

        try {
            numADs = mConfig.getInteger(PROP_NUM_ADS, MAX_AD);
            params.addElement(PROP_NUM_ADS + "=" + numADs);
        } catch (EBaseException e) {
            params.addElement(PROP_NUM_ADS + "=" + MAX_AD);
        }

        for (int i = 0; i < numADs; i++) {
            String method = null;

            try {
                method = mConfig.getString(PROP_AD +
                            Integer.toString(i) + "_" + PROP_METHOD,
                            "");
            } catch (EBaseException e) {
            }
            params.addElement(PROP_AD +
                    Integer.toString(i) +
                    "_" + PROP_METHOD + "=" + method);
            String location_type = null;

            try {
                location_type = mConfig.getString(PROP_AD +
                            Integer.toString(i) + "_" + PROP_LOCATION_TYPE,
                            IGeneralNameUtil.GENNAME_CHOICE_URL);
            } catch (EBaseException e) {
            }
            params.addElement(PROP_AD +
                    Integer.toString(i) +
                    "_" + PROP_LOCATION_TYPE + "=" + location_type);
            String location = null;

            try {
                location = mConfig.getString(PROP_AD +
                            Integer.toString(i) + "_" + PROP_LOCATION,
                            "");
            } catch (EBaseException e) {
            }
            params.addElement(PROP_AD +
                    Integer.toString(i) +
                    "_" + PROP_LOCATION + "=" + location);
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
        defParams.addElement(PROP_NUM_ADS + "=" + MAX_AD);

        //
        // By default, we create MAX_AD access descriptions.
        // If this is not enough, admin can manually edit
        // the CMS.cfg
        //
        for (int i = 0; i < MAX_AD; i++) {
            defParams.addElement(PROP_AD + Integer.toString(i) +
                    "_" + PROP_METHOD + "=");
            defParams.addElement(PROP_AD + Integer.toString(i) +
                    "_" + PROP_LOCATION_TYPE + "=" + IGeneralNameUtil.GENNAME_CHOICE_URL);
            defParams.addElement(PROP_AD + Integer.toString(i) +
                    "_" + PROP_LOCATION + "=");
        }
        return defParams;
    }
}
