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
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Vector;

import netscape.security.x509.CertificateChain;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.KeyUsageExtension;
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
 * Policy to add Key Usage Extension.
 * Adds the key usage extension based on what's requested.
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
public class KeyUsageExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {

    private final static String HTTP_INPUT = "HTTP_INPUT";
    protected static final boolean[] DEF_BITS =
            new boolean[KeyUsageExtension.NBITS];
    protected int mCAPathLen = -1;
    protected IConfigStore mConfig = null;
    protected static final String PROP_CRITICAL = "critical";
    protected static final String PROP_DIGITAL_SIGNATURE = "digitalSignature";
    protected static final String PROP_NON_REPUDIATION = "nonRepudiation";
    protected static final String PROP_KEY_ENCIPHERMENT = "keyEncipherment";
    protected static final String PROP_DATA_ENCIPHERMENT = "dataEncipherment";
    protected static final String PROP_KEY_AGREEMENT = "keyAgreement";
    protected static final String PROP_KEY_CERTSIGN = "keyCertsign";
    protected static final String PROP_CRL_SIGN = "crlSign";
    protected static final String PROP_ENCIPHER_ONLY = "encipherOnly";
    protected static final String PROP_DECIPHER_ONLY = "decipherOnly";

    protected boolean mCritical;
    protected String mDigitalSignature;
    protected String mNonRepudiation;
    protected String mKeyEncipherment;
    protected String mDataEncipherment;
    protected String mKeyAgreement;
    protected String mKeyCertsign;
    protected String mCrlSign;
    protected String mEncipherOnly;
    protected String mDecipherOnly;

    protected KeyUsageExtension mKeyUsage;

    public KeyUsageExt() {
        NAME = "KeyUsageExtPolicy";
        DESC = "Sets Key Usage Extension in certificates.";
    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries may be of the form:
     *
     * ca.Policy.rule.<ruleName>.implName=KeyUsageExt ca.Policy.rule.<ruleName>.enable=true ca.Policy.rule.<ruleName>.
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mConfig = config;

        ICertAuthority certAuthority = (ICertAuthority)
                ((IPolicyProcessor) owner).getAuthority();

        if (certAuthority == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CANT_FIND_MANAGER"));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                        "Cannot find the Certificate Manager or Registration Manager"));
        }

        if (certAuthority instanceof ICertificateAuthority) {
            CertificateChain caChain = certAuthority.getCACertChain();
            X509Certificate caCert = null;

            // Note that in RA the chain could be null if CA was not up when
            // RA was started. In that case just set the length to -1 and let
            // CA reject if it does not allow any subordinate CA certs.
            if (caChain != null) {
                caCert = caChain.getFirstCertificate();
                mCAPathLen = caCert.getBasicConstraints();
            }
        }

        mCritical = mConfig.getBoolean(PROP_CRITICAL, true);
        mDigitalSignature = mConfig.getString(PROP_DIGITAL_SIGNATURE, HTTP_INPUT);
        mNonRepudiation = mConfig.getString(PROP_NON_REPUDIATION, HTTP_INPUT);
        mKeyEncipherment = mConfig.getString(PROP_KEY_ENCIPHERMENT, HTTP_INPUT);
        mDataEncipherment = mConfig.getString(PROP_DATA_ENCIPHERMENT, HTTP_INPUT);
        mKeyAgreement = mConfig.getString(PROP_KEY_AGREEMENT, HTTP_INPUT);
        mKeyCertsign = mConfig.getString(PROP_KEY_CERTSIGN, HTTP_INPUT);
        mCrlSign = mConfig.getString(PROP_CRL_SIGN, HTTP_INPUT);
        mEncipherOnly = mConfig.getString(PROP_ENCIPHER_ONLY, HTTP_INPUT);
        mDecipherOnly = mConfig.getString(PROP_DECIPHER_ONLY, HTTP_INPUT);
    }

    /**
     * Adds the key usage extension if not set already.
     * (CRMF, agent, authentication (currently) or PKCS#10 (future)
     * or RA could have set the extension.)
     * If not set, set from http input parameters or use default if
     * no http input parameters are set.
     *
     * Note: this allows any bits requested - does not check if user
     * authenticated is allowed to have a Key Usage Extension with
     * those bits. Unless the CA's certificate path length is 0, then
     * we do not allow CA sign or CRL sign bits in any request.
     *
     * <P>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {

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
        return PolicyResult.ACCEPTED;
    }

    public PolicyResult applyCert(IRequest req, X509CertInfo certInfo) {
        try {
            CertificateExtensions extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);
            KeyUsageExtension ext = null;

            if (extensions != null) {
                try {
                    ext = (KeyUsageExtension)
                            extensions.get(KeyUsageExtension.NAME);
                } catch (IOException e) {
                    // extension isn't there.
                    ext = null;
                }
                // check if CA does not allow subordinate CA certs.
                // otherwise accept existing key usage extension.
                if (ext != null) {
                    if (mCAPathLen == 0) {
                        boolean[] bits = ext.getBits();

                        if ((bits.length > KeyUsageExtension.KEY_CERTSIGN_BIT &&
                                bits[KeyUsageExtension.KEY_CERTSIGN_BIT] == true) ||
                                (bits.length > KeyUsageExtension.CRL_SIGN_BIT &&
                                bits[KeyUsageExtension.CRL_SIGN_BIT] == true)) {
                            setError(req,
                                    CMS.getUserMessage("CMS_POLICY_NO_SUB_CA_CERTS_ALLOWED"),
                                    NAME);
                            return PolicyResult.REJECTED;
                        }
                    }
                    return PolicyResult.ACCEPTED;
                }
            } else {
                // create extensions set if none.
                if (extensions == null) {
                    certInfo.set(X509CertInfo.VERSION,
                            new CertificateVersion(CertificateVersion.V3));
                    extensions = new CertificateExtensions();
                    certInfo.set(X509CertInfo.EXTENSIONS, extensions);
                }
            }

            boolean[] bits = new boolean[KeyUsageExtension.NBITS];

            bits[KeyUsageExtension.DIGITAL_SIGNATURE_BIT] = getBit("digital_signature",
                        mDigitalSignature, req);
            bits[KeyUsageExtension.NON_REPUDIATION_BIT] = getBit("non_repudiation",
                        mNonRepudiation, req);
            bits[KeyUsageExtension.KEY_ENCIPHERMENT_BIT] = getBit("key_encipherment",
                        mKeyEncipherment, req);
            bits[KeyUsageExtension.DATA_ENCIPHERMENT_BIT] = getBit("data_encipherment",
                        mDataEncipherment, req);
            bits[KeyUsageExtension.KEY_AGREEMENT_BIT] = getBit("key_agreement",
                        mKeyAgreement, req);
            bits[KeyUsageExtension.KEY_CERTSIGN_BIT] = getBit("key_certsign",
                        mKeyCertsign, req);
            bits[KeyUsageExtension.CRL_SIGN_BIT] = getBit("crl_sign", mCrlSign, req);
            bits[KeyUsageExtension.ENCIPHER_ONLY_BIT] = getBit("encipher_only",
                        mEncipherOnly, req);
            bits[KeyUsageExtension.DECIPHER_ONLY_BIT] = getBit("decipher_only",
                        mDecipherOnly, req);

            // don't allow no bits set or the extension does not
            // encode/decode properlly.
            boolean bitset = false;

            for (int i = 0; i < bits.length; i++) {
                if (bits[i]) {
                    bitset = true;
                    break;
                }
            }
            if (!bitset) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_NO_KEYUSAGE_EXTENSION_BITS_SET", NAME));
                setError(req, CMS.getUserMessage("CMS_POLICY_NO_KEYUSAGE_EXTENSION_BITS_SET"),
                        NAME);
                return PolicyResult.REJECTED;
            }

            // create the extension.
            try {
                mKeyUsage = new KeyUsageExtension(mCritical, bits);
            } catch (IOException e) {
            }
            extensions.set(KeyUsageExtension.NAME, mKeyUsage);
            return PolicyResult.ACCEPTED;
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_IO_ERROR", e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                    NAME, e.getMessage());
            return PolicyResult.REJECTED; // unrecoverable error.
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CERT_INFO_ERROR", e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                    NAME, "Certificate Info Error");
            return PolicyResult.REJECTED; // unrecoverable error.
        }
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        Vector<String> params = new Vector<String>();

        params.addElement(PROP_CRITICAL + "=" + mCritical);
        params.addElement(PROP_DIGITAL_SIGNATURE + "=" + mDigitalSignature);
        params.addElement(PROP_NON_REPUDIATION + "=" + mNonRepudiation);
        params.addElement(PROP_KEY_ENCIPHERMENT + "=" + mKeyEncipherment);
        params.addElement(PROP_DATA_ENCIPHERMENT + "=" + mDataEncipherment);
        params.addElement(PROP_KEY_AGREEMENT + "=" + mKeyAgreement);
        params.addElement(PROP_KEY_CERTSIGN + "=" + mKeyCertsign);
        params.addElement(PROP_CRL_SIGN + "=" + mCrlSign);
        params.addElement(PROP_ENCIPHER_ONLY + "=" + mEncipherOnly);
        params.addElement(PROP_DECIPHER_ONLY + "=" + mDecipherOnly);
        return params;
    }

    private static Vector<String> mDefParams = new Vector<String>();
    static {
        mDefParams.addElement(PROP_CRITICAL + "=true");
        mDefParams.addElement(PROP_DIGITAL_SIGNATURE + "=");
        mDefParams.addElement(PROP_NON_REPUDIATION + "=");
        mDefParams.addElement(PROP_KEY_ENCIPHERMENT + "=");
        mDefParams.addElement(PROP_DATA_ENCIPHERMENT + "=");
        mDefParams.addElement(PROP_KEY_AGREEMENT + "=");
        mDefParams.addElement(PROP_KEY_CERTSIGN + "=");
        mDefParams.addElement(PROP_CRL_SIGN + "=");
        mDefParams.addElement(PROP_ENCIPHER_ONLY + "=");
        mDefParams.addElement(PROP_DECIPHER_ONLY + "=");
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_CRITICAL + ";boolean;RFC 2459 recommendation: SHOULD be critical",
                PROP_DIGITAL_SIGNATURE
                        + ";choice(true,false,HTTP_INPUT);true means always set this bit, false means don't set this bit, HTTP_INPUT means get this bit from the HTTP input",
                PROP_NON_REPUDIATION
                        + ";choice(true,false,HTTP_INPUT);true means always set this bit, false means don't set this bit, HTTP_INPUT means get this bit from the HTTP input",
                PROP_KEY_ENCIPHERMENT
                        + ";choice(true,false,HTTP_INPUT);true means always set this bit, false means don't set this bit, HTTP_INPUT means get this bit from the HTTP input",
                PROP_DATA_ENCIPHERMENT
                        + ";choice(true,false,HTTP_INPUT);true means always set this bit, false means don't set this bit, HTTP_INPUT means get this bit from the HTTP input",
                PROP_KEY_AGREEMENT
                        + ";choice(true,false,HTTP_INPUT);true means always set this bit, false means don't set this bit, HTTP_INPUT means get this bit from the HTTP input",
                PROP_KEY_CERTSIGN
                        + ";choice(true,false,HTTP_INPUT);true means always set this bit, false means don't set this bit, HTTP_INPUT means get this bit from the HTTP input",
                PROP_CRL_SIGN
                        + ";choice(true,false,HTTP_INPUT);true means always set this bit, false means don't set this bit, HTTP_INPUT means get this bit from the HTTP input",
                PROP_ENCIPHER_ONLY
                        + ";choice(true,false,HTTP_INPUT);true means always set this bit, false means don't set this bit, HTTP_INPUT means get this bit from the HTTP input",
                PROP_DECIPHER_ONLY
                        + ";choice(true,false,HTTP_INPUT);true means always set this bit, false means don't set this bit, HTTP_INPUT means get this bit from the HTTP input",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-keyusage",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Adds Key Usage Extension; See in RFC 2459 (4.2.1.3)"

        };

        return params;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        return mDefParams;
    }

    private boolean getBit(String usage, String choice, IRequest req) {
        if (choice.equals(HTTP_INPUT)) {
            choice = req.getExtDataInString(IRequest.HTTP_PARAMS, usage);
            if (choice == null)
                choice = "false";
        }
        return Boolean.valueOf(choice).booleanValue();
    }
}
