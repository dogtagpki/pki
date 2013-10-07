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

import netscape.security.x509.AuthorityKeyIdentifierExtension;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.KeyIdentifier;
import netscape.security.x509.SubjectKeyIdentifierExtension;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.policy.IPolicyProcessor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Authority Public Key Extension Policy
 * Adds the subject public key id extension to certificates.
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
public class AuthorityKeyIdentifierExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    protected static final String PROP_CRITICAL = "critical";
    protected static final String PROP_ALT_KEYID_TYPE = "AltKeyIdType";

    protected static final String ALT_KEYID_TYPE_SPKISHA1 = "SpkiSHA1";
    protected static final String ALT_KEYID_TYPE_NONE = "None";
    protected static final String ALT_KEYID_TYPE_EMPTY = "Empty";

    protected static final boolean DEF_CRITICAL = false;
    protected static final String DEF_ALT_KEYID_TYPE = ALT_KEYID_TYPE_SPKISHA1;

    protected boolean mEnabled = false;
    protected IConfigStore mConfig = null;

    // config params.
    protected boolean mCritical = DEF_CRITICAL;
    protected String mAltKeyIdType = DEF_ALT_KEYID_TYPE;

    // the extension to add to certs.
    protected AuthorityKeyIdentifierExtension mTheExtension = null;

    // instance params for console
    protected Vector<String> mInstanceParams = new Vector<String>();

    // default params for console.
    protected static Vector<String> mDefaultParams = new Vector<String>();
    static {
        // form static default params.
        mDefaultParams.addElement(PROP_CRITICAL + "=" + DEF_CRITICAL);
        mDefaultParams.addElement(PROP_ALT_KEYID_TYPE + "=" + DEF_ALT_KEYID_TYPE);
    }

    public AuthorityKeyIdentifierExt() {
        NAME = "AuthorityKeyIdentifierExt";
        DESC = "Adds Authority Key Idenifier Extension to certs";
    }

    /**
     * Initializes this policy rule.
     * Reads configuration file and creates a authority key identifier
     * extension to add. Key identifier inside the extension is constructed as
     * the CA's subject key identifier extension if it exists.
     * If it does not exist this can be configured to use:
     * (1) sha-1 hash of the CA's subject public key info
     * (what communicator expects if the CA does not have a subject key
     * identifier extension) or (2) No extension set (3) Empty sequence
     * in Authority Key Identifier extension.
     *
     * <P>
     *
     * The entries may be of the form:
     *
     * ca.Policy.rule.<ruleName>.predicate= ca.Policy.rule.<ruleName>.implName= ca.Policy.rule.<ruleName>.enable=true
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mConfig = config;

        mEnabled = mConfig.getBoolean(
                    IPolicyProcessor.PROP_ENABLE, false);
        mCritical = mConfig.getBoolean(PROP_CRITICAL, DEF_CRITICAL);

        mAltKeyIdType = mConfig.getString(
                    PROP_ALT_KEYID_TYPE, DEF_ALT_KEYID_TYPE);

        if (mAltKeyIdType.equalsIgnoreCase(ALT_KEYID_TYPE_SPKISHA1))
            mAltKeyIdType = ALT_KEYID_TYPE_SPKISHA1;

        /*
         else if (mAltKeyIdType.equalsIgnoreCase(ALT_KEYID_TYPE_EMPTY))
         mAltKeyIdType = ALT_KEYID_TYPE_EMPTY;
         */
        else if (mAltKeyIdType.equalsIgnoreCase(ALT_KEYID_TYPE_NONE))
            mAltKeyIdType = ALT_KEYID_TYPE_NONE;
        else {
            log(ILogger.LL_FAILURE, NAME +
                    CMS.getLogMessage("CA_UNKNOWN_ALT_KEY_ID_TYPE", mAltKeyIdType));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE", PROP_ALT_KEYID_TYPE,
                        "value must be one of " + ALT_KEYID_TYPE_SPKISHA1 + ", " + ALT_KEYID_TYPE_NONE));
        }

        // create authority key id extension.
        ICertAuthority certAuthority = (ICertAuthority)
                ((IPolicyProcessor) owner).getAuthority();

        if (certAuthority == null) {
            // should never get here.
            String msg = NAME + ": " +
                    "Cannot find the Certificate Manager or Registration Manager";

            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CANT_FIND_MANAGER"));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", msg));
        }
        if (!(certAuthority instanceof ICertificateAuthority)) {
            log(ILogger.LL_FAILURE, NAME +
                    CMS.getLogMessage("POLICY_INVALID_POLICY", NAME));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                        NAME + " policy can only be used in a Certificate Authority."));
        }
        //CertificateChain caChain = certAuthority.getCACertChain();
        //X509Certificate caCert = caChain.getFirstCertificate();
        X509CertImpl caCert = certAuthority.getCACert();
        if (caCert == null || CMS.isPreOpMode()) {
            return;
        }
        KeyIdentifier keyId = formKeyIdentifier(caCert);

        if (keyId != null) {
            try {
                mTheExtension = new AuthorityKeyIdentifierExtension(
                            mCritical, keyId, null, null);
            } catch (IOException e) {
                String msg = NAME + ": " +
                        "Error forming Authority Key Identifier extension: " + e;

                log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_ERROR_AUTHORITY_KEY_ID_1", NAME));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", msg));
            }
        } else {
        }

        // form instance params
        mInstanceParams.addElement(PROP_CRITICAL + "=" + mCritical);
        mInstanceParams.addElement(PROP_ALT_KEYID_TYPE + "=" + mAltKeyIdType);
    }

    /**
     * Adds Authority Key Identifier Extension to a certificate.
     * If the extension is already there, accept it if it's from the agent,
     * else replace it.
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        // get certInfo from request.
        X509CertInfo[] ci =
                req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        if (ci == null || ci[0] == null) {
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO", NAME), "");
            return PolicyResult.REJECTED;
        }

        for (int i = 0; i < ci.length; i++) {
            PolicyResult certResult = applyCert(req, ci[i]);

            if (certResult == PolicyResult.REJECTED)
                return certResult;
        }
        return PolicyResult.ACCEPTED;
    }

    public PolicyResult applyCert(IRequest req, X509CertInfo certInfo) {

        try {
            // if authority key id extension already exists, leave it if
            // from agent. else replace it.
            AuthorityKeyIdentifierExtension authorityKeyIdExt = null;
            CertificateExtensions extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);

            try {
                if (extensions != null) {
                    authorityKeyIdExt = (AuthorityKeyIdentifierExtension)
                            extensions.get(AuthorityKeyIdentifierExtension.NAME);
                }
            } catch (IOException e) {
                // extension isn't there.
            }
            if (authorityKeyIdExt != null) {
                if (agentApproved(req)) {
                    CMS.debug(
                            "AuthorityKeyIdentifierKeyExt: agent approved request id " + req.getRequestId() +
                                    " already has authority key id extension with value " +
                                    authorityKeyIdExt);
                    return PolicyResult.ACCEPTED;
                } else {
                    CMS.debug(
                            "AuthorityKeyIdentifierKeyExt: request id from user " + req.getRequestId() +
                                    " had authority key identifier - deleted");
                    extensions.delete(AuthorityKeyIdentifierExtension.NAME);
                }
            }

            // if no authority key identifier should be set b/c CA does not
            // have a subject key identifier, return here.
            if (mTheExtension == null)
                return PolicyResult.ACCEPTED;

            // add authority key id extension.
            if (extensions == null) {
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                extensions = new CertificateExtensions();
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
            }
            extensions.set(
                    AuthorityKeyIdentifierExtension.NAME, mTheExtension);
            CMS.debug(
                    "AuthorityKeyIdentifierKeyExt: added authority key id ext to request " + req.getRequestId());
            return PolicyResult.ACCEPTED;
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_UNEXPECTED_POLICY_ERROR", NAME, e.toString()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR",
                    NAME, e.getMessage()), "");
            return PolicyResult.REJECTED;
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("BASE_INVALID_CERT", e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR",
                    NAME, "Certificate Info Error"), "");
            return PolicyResult.REJECTED;
        }
    }

    /**
     * Form the Key Identifier in the Authority Key Identifier extension.
     * from the CA's cert.
     * <p>
     *
     * @param caCertImpl Certificate Info
     * @return A Key Identifier.
     * @throws com.netscape.certsrv.base.EBaseException on error
     */
    protected KeyIdentifier formKeyIdentifier(X509CertImpl caCertImpl)
            throws EBaseException {
        KeyIdentifier keyId = null;

        // get CA's certInfo.
        X509CertInfo certInfo = null;

        try {
            certInfo = (X509CertInfo) caCertImpl.get(
                        X509CertImpl.NAME + "." + X509CertImpl.INFO);
            if (certInfo == null) {
                String msg = "Bad CA certificate encountered. " +
                        "TBS Certificate missing.";

                log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_INVALID_CERT_FORMAT"));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", NAME + ": " + msg));
            }
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, NAME + ": " +
                    CMS.getLogMessage("BASE_DECODE_CERT_FAILED_1", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                        NAME + " Error decoding the CA Certificate: " + e));
        }

        // get Key Id from CA's Subject Key Id extension in CA's CertInfo.
        keyId = getKeyIdentifier(certInfo);
        if (keyId != null)
            return keyId;

        // if none exists use the configured alternate.
        if (mAltKeyIdType == ALT_KEYID_TYPE_SPKISHA1) {
            keyId = formSpkiSHA1KeyId(certInfo);
        } /*
          else if (mAltKeyIdType == ALT_KEYID_TYPE_EMPTY) {
          keyId = formEmptyKeyId(certInfo);
          }
          */else if (mAltKeyIdType == ALT_KEYID_TYPE_NONE) {
            keyId = null;
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                        mAltKeyIdType,
                        "Unknown Alternate Key Identifier type."));
        }
        return keyId;
    }

    /**
     * Get the Key Identifier in a subject key identifier extension from a
     * CertInfo.
     *
     * @param certInfo the CertInfo structure.
     * @return Key Identifier in a Subject Key Identifier extension if any.
     */
    protected KeyIdentifier getKeyIdentifier(X509CertInfo certInfo)
            throws EBaseException {
        CertificateExtensions exts = null;
        SubjectKeyIdentifierExtension subjKeyIdExt = null;
        KeyIdentifier keyId = null;

        try {
            exts = (CertificateExtensions) certInfo.get(X509CertInfo.EXTENSIONS);
        } catch (IOException e) {
            // extension isn't there.
            CMS.debug(NAME + ": " + "No extensions found. Error " + e);
            return null;
        } catch (CertificateException e) {
            // extension isn't there.
            CMS.debug(NAME + ": " + "No extensions found. Error " + e);
            return null;
        }
        if (exts == null)
            return null;

        try {
            subjKeyIdExt = (SubjectKeyIdentifierExtension)
                    exts.get(SubjectKeyIdentifierExtension.NAME);
        } catch (IOException e) {
            // extension isn't there.
            CMS.debug(
                    "AuthorityKeyIdentifierKeyExt: No Subject Key Identifier Extension found. Error: " + e);
            return null;
        }
        if (subjKeyIdExt == null)
            return null;

        try {
            keyId = (KeyIdentifier) subjKeyIdExt.get(
                        SubjectKeyIdentifierExtension.KEY_ID);
        } catch (IOException e) {
            // no key identifier in subject key id extension.
            String msg = NAME + ": " +
                    "Bad Subject Key Identifier Extension found. Error: " + e;

            log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_ERROR_AUTHORITY_KEY_ID_1", NAME));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", msg));
        }
        return keyId;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        return mInstanceParams;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        return mDefaultParams;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_CRITICAL + ";boolean;" +
                        "RFC 2459 recommendation: MUST NOT be marked critical.",
                PROP_ALT_KEYID_TYPE + ";" +
                        "choice(" + ALT_KEYID_TYPE_SPKISHA1 + "," + ALT_KEYID_TYPE_NONE + ");" +
                        "Specifies whether to use a SHA1 hash of the CA's subject " +
                        "public key info for key identifier or leave out the " +
                        "authority key identifier extension if the CA certificate " +
                        "does not have a Subject Key Identifier extension.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-authkeyid",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Adds Authority Key Identifier Extension. " +
                        "See RFC 2459 (4.2.1.1)"
            };

        return params;
    }
}
