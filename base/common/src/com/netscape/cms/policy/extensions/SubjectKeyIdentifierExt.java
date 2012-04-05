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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Locale;
import java.util.Vector;

import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.KeyIdentifier;
import netscape.security.x509.SubjectKeyIdentifierExtension;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.EPolicyException;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.policy.IPolicyProcessor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Subject Public Key Extension Policy
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
public class SubjectKeyIdentifierExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    protected static final String PROP_CRITICAL = "critical";
    protected static final String PROP_KEYID_TYPE = "keyIdentifierType";
    protected static final String PROP_REQATTR_NAME = "requestAttrName";

    protected static final String KEYID_TYPE_SHA1 = "SHA1";
    protected static final String KEYID_TYPE_TYPEFIELD = "TypeField";
    protected static final String KEYID_TYPE_SPKISHA1 = "SpkiSHA1";
    protected static final String KEYID_TYPE_REQATTR = "RequestAttribute";

    protected static final boolean DEF_CRITICAL = false;
    protected static final String DEF_KEYID_TYPE = KEYID_TYPE_SHA1;
    protected static final String DEF_REQATTR_NAME = "KeyIdentifier";

    protected boolean mEnabled = false;
    protected IConfigStore mConfig = null;

    protected boolean mCritical = DEF_CRITICAL;
    protected String mKeyIdType = DEF_KEYID_TYPE;;
    protected String mReqAttrName = DEF_REQATTR_NAME;

    protected Vector<String> mInstanceParams = new Vector<String>();

    protected static Vector<String> mDefaultParams = new Vector<String>();
    static {
        // form static default params.
        mDefaultParams.addElement(PROP_CRITICAL + "=" + DEF_CRITICAL);
        mDefaultParams.addElement(PROP_KEYID_TYPE + "=" + DEF_KEYID_TYPE);

        /*
         mDefaultParams.addElement(PROP_REQATTR_NAME+"="+DEF_REQATTR_NAME);
         */
    }

    public SubjectKeyIdentifierExt() {
        NAME = "SubjectKeyIdentifierExt";
        DESC = "Adds Subject Key Idenifier Extension to certs";
    }

    /**
     * Initializes this policy rule.
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

        mKeyIdType = mConfig.getString(PROP_KEYID_TYPE, DEF_KEYID_TYPE);

        /*
         mReqAttrName = mConfig.getString(PROP_REQATTR_NAME, DEF_REQATTR_NAME);
         */

        // parse key id type
        if (mKeyIdType.equalsIgnoreCase(KEYID_TYPE_SHA1))
            mKeyIdType = KEYID_TYPE_SHA1;
        else if (mKeyIdType.equalsIgnoreCase(KEYID_TYPE_TYPEFIELD))
            mKeyIdType = KEYID_TYPE_TYPEFIELD;

        /*
         else if (mKeyIdType.equalsIgnoreCase(KEYID_TYPE_REQATTR)
         mKeyIdType = KEYID_TYPE_REQATTR;
         */
        else if (mKeyIdType.equalsIgnoreCase(KEYID_TYPE_SPKISHA1))
            mKeyIdType = KEYID_TYPE_SPKISHA1;
        else {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("KRA_UNKNOWN_KEY_ID_TYPE", mKeyIdType));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                        PROP_KEYID_TYPE,
                        "value must be one of " +
                                KEYID_TYPE_SHA1 + ", " +
                                KEYID_TYPE_TYPEFIELD + ", " +
                                KEYID_TYPE_SPKISHA1));
        }

        // form instance params
        mInstanceParams.addElement(PROP_CRITICAL + "=" + mCritical);
        mInstanceParams.addElement(PROP_KEYID_TYPE + "=" + mKeyIdType);

        /*
         mInstanceParams.addElement(PROP_REQATTR_NAME+"="+mReqAttrName);
         */
    }

    /**
     * Adds Subject Key identifier Extension to a certificate.
     * If the extension is already there, accept it.
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        // get certInfo from request.
        X509CertInfo[] ci =
                req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        if (ci == null || ci[0] == null) {
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO"), NAME);
            return PolicyResult.REJECTED;
        }

        for (int i = 0; i < ci.length; i++) {
            PolicyResult certRes = applyCert(req, ci[i]);

            if (certRes == PolicyResult.REJECTED)
                return certRes;
        }
        return PolicyResult.ACCEPTED;
    }

    public PolicyResult applyCert(IRequest req, X509CertInfo certInfo) {

        try {
            // if subject key id extension already exists, leave it if approved.
            SubjectKeyIdentifierExtension subjectKeyIdExt = null;
            CertificateExtensions extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);

            try {
                if (extensions != null) {
                    subjectKeyIdExt = (SubjectKeyIdentifierExtension)
                            extensions.get(SubjectKeyIdentifierExtension.NAME);
                }
            } catch (IOException e) {
                // extension isn't there.
            }
            if (subjectKeyIdExt != null) {
                if (agentApproved(req)) {
                    CMS.debug(
                            "SubjectKeyIdentifierExt: agent approved request id " + req.getRequestId() +
                                    " already has subject key id extension with value " +
                                    subjectKeyIdExt);
                    return PolicyResult.ACCEPTED;
                } else {
                    CMS.debug(
                            "SubjectKeyIdentifierExt: request id from user " + req.getRequestId() +
                                    " had subject key identifier - deleted to be replaced");
                    extensions.delete(SubjectKeyIdentifierExtension.NAME);
                }
            }

            // create subject key id extension.
            KeyIdentifier keyId = null;

            try {
                keyId = formKeyIdentifier(certInfo, req);
            } catch (EBaseException e) {
                setPolicyException(req, e);
                return PolicyResult.REJECTED;
            }
            subjectKeyIdExt =
                    new SubjectKeyIdentifierExtension(
                            mCritical, keyId.getIdentifier());

            // add subject key id extension.
            if (extensions == null) {
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                extensions = new CertificateExtensions();
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
            }
            extensions.set(
                    SubjectKeyIdentifierExtension.NAME, subjectKeyIdExt);
            CMS.debug(
                    "SubjectKeyIdentifierExt: added subject key id ext to request " + req.getRequestId());
            return PolicyResult.ACCEPTED;
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_UNEXPECTED_POLICY_ERROR,NAME", e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                    NAME, e.getMessage());
            return PolicyResult.REJECTED;
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CERT_INFO_ERROR", e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                    NAME, "Certificate Info Error");
            return PolicyResult.REJECTED;
        }
    }

    /**
     * Form the Key Identifier in the Subject Key Identifier extension.
     * <p>
     *
     * @param certInfo Certificate Info
     * @param req request
     * @return A Key Identifier.
     */
    protected KeyIdentifier formKeyIdentifier(
            X509CertInfo certInfo, IRequest req) throws EBaseException {
        KeyIdentifier keyId = null;

        if (mKeyIdType == KEYID_TYPE_SHA1) {
            keyId = formSHA1KeyId(certInfo);
        } else if (mKeyIdType == KEYID_TYPE_TYPEFIELD) {
            keyId = formTypeFieldKeyId(certInfo);
        } /*
          else if (mKeyIdType == KEYID_TYPE_REQATTR) {
          keyId = formReqAttrKeyId(certInfo, req);
          }
          */else if (mKeyIdType == KEYID_TYPE_SPKISHA1) {
            keyId = formSpkiSHA1KeyId(certInfo);
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                        mKeyIdType, "Unknown Key Identifier type."));
        }
        return keyId;
    }

    /**
     * Form key identifier from a type field value of 0100 followed by
     * the least significate 60 bits of the sha-1 hash of the subject
     * public key BIT STRING in accordance with RFC 2459.
     * <p>
     *
     * @param certInfo - certificate info
     * @return A Key Identifier with value formulatd as described.
     */

    protected KeyIdentifier formTypeFieldKeyId(X509CertInfo certInfo)
            throws EBaseException {
        KeyIdentifier keyId = null;
        X509Key key = null;

        try {
            CertificateX509Key certKey =
                    (CertificateX509Key) certInfo.get(X509CertInfo.KEY);

            if (certKey == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_MISSING_KEY_1", NAME));
                throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_MISSING_KEY", NAME));
            }
            key = (X509Key) certKey.get(CertificateX509Key.KEY);
            if (key == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_MISSING_KEY_1", NAME));
                throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_MISSING_KEY", NAME));
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_GET_KEY_FROM_CERT", e.toString()));
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_GET_KEY_FROM_CERT", e.toString()));
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME));
        }
        try {
            byte[] octetString = new byte[8];
            MessageDigest md = MessageDigest.getInstance("SHA-1");

            md.update(key.getKey());
            byte[] hash = md.digest();

            System.arraycopy(hash, hash.length - 8, octetString, 0, 8);
            octetString[0] &= (0x08f & octetString[0]);
            keyId = new KeyIdentifier(octetString);
        } catch (NoSuchAlgorithmException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_SUBJECT_KEY_ID_1", NAME));
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR", NAME));
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

    /**
     * Gets extended plugin info for pretty Console displays.
     */
    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_CRITICAL + ";boolean;RFC 2459 recommendation: MUST NOT be marked critical.",
                PROP_KEYID_TYPE + ";" +
                        "choice(" + KEYID_TYPE_SHA1 + "," +
                        KEYID_TYPE_TYPEFIELD + "," +
                        KEYID_TYPE_SPKISHA1 + ");" +
                        "Method to derive the Key Identifier.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-subjectkeyidentifier",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Adds the Subject Key Identifier extension. See RFC 2459 (4.2.1.2)"
            };

        return params;
    }
}
