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

import netscape.security.extensions.NSCertTypeExtension;
import netscape.security.x509.CertificateChain;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.KeyUsageExtension;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
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
 * NS Cert Type policy.
 * Adds the ns cert type extension depending on cert type requested.
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
public class NSCertTypeExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    protected static final String PROP_SET_DEFAULT_BITS = "setDefaultBits";
    protected static final boolean DEF_SET_DEFAULT_BITS = true;
    protected static final String DEF_SET_DEFAULT_BITS_VAL =
            Boolean.valueOf(DEF_SET_DEFAULT_BITS).toString();

    protected static final int DEF_PATHLEN = -1;

    protected static final boolean[] DEF_BITS =
            new boolean[NSCertTypeExtension.NBITS];

    // XXX for future use. currenlty always allow.
    protected static final String PROP_AGENT_OVERR = "allowAgentOverride";
    protected static final String PROP_EE_OVERR = "AllowEEOverride";

    // XXX for future use. currently always critical
    // (standard says SHOULD be marked critical if included.)
    protected static final String PROP_CRITICAL = "critical";

    // XXX for future use to allow overrides from forms.
    // request must be agent approved or authenticated.
    protected boolean mAllowAgentOverride = false;
    protected boolean mAllowEEOverride = false;

    // XXX for future use. currently always non-critical
    protected boolean mCritical = false;

    protected int mCAPathLen = -1;

    protected IConfigStore mConfig = null;
    protected boolean mSetDefaultBits = false;

    static {
        // set default bits used when request missing ns cert type info.
        // default is a client cert
        DEF_BITS[NSCertTypeExtension.SSL_CLIENT_BIT] = true;
        DEF_BITS[NSCertTypeExtension.SSL_SERVER_BIT] = false;
        DEF_BITS[NSCertTypeExtension.EMAIL_BIT] = true;
        DEF_BITS[NSCertTypeExtension.OBJECT_SIGNING_BIT] = true;
        DEF_BITS[NSCertTypeExtension.SSL_CA_BIT] = false;
        DEF_BITS[NSCertTypeExtension.EMAIL_CA_BIT] = false;
        DEF_BITS[NSCertTypeExtension.OBJECT_SIGNING_CA_BIT] = false;
    }

    public NSCertTypeExt() {
        NAME = "NSCertType";
        DESC = "Sets Netscape Cert Type on all certs";
    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries may be of the form:
     *
     * ra.Policy.rule.<ruleName>.implName=nsCertTypeExt ra.Policy.rule.<ruleName>.enable=true
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mConfig = config;

        // XXX future use.
        //mAllowAgentOverride = config.getBoolean(PROP_AGENT_OVERR, false);
        //mAllowEEOverride = config.getBoolean(PROP_EE_OVERR, false);
        mCritical = config.getBoolean(PROP_CRITICAL, false);

        ICertAuthority certAuthority = (ICertAuthority)
                ((IPolicyProcessor) owner).getAuthority();

        if (certAuthority instanceof ICertificateAuthority) {
            CertificateChain caChain = certAuthority.getCACertChain();
            X509Certificate caCert = null;

            // Note that in RA the chain could be null if CA was not up when
            // RA was started. In that case just set the length to -1 and let
            // CA reject if it does not allow any subordinate CA certs.
            if (caChain != null) {
                caCert = caChain.getFirstCertificate();
                if (caCert != null)
                    mCAPathLen = caCert.getBasicConstraints();
            }
        }

        mSetDefaultBits = mConfig.getBoolean(
                    PROP_SET_DEFAULT_BITS, DEF_SET_DEFAULT_BITS);
    }

    /**
     * Adds the ns cert type if not set already.
     * reads ns cert type choices from form. If no choices from form
     * will defaults to all.
     * <P>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        CMS.debug("NSCertTypeExt: Impl: " + NAME + ", Instance: " + getInstanceName() + "::apply()");

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
            String certType =
                    req.getExtDataInString(IRequest.HTTP_PARAMS, IRequest.CERT_TYPE);
            CertificateExtensions extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);
            NSCertTypeExtension nsCertTypeExt = null;

            if (extensions != null) {
                // See if extension is already set and contains correct values.
                try {
                    nsCertTypeExt = (NSCertTypeExtension)
                            extensions.get(NSCertTypeExtension.NAME);
                } catch (IOException e) {
                    // extension isn't there.
                    nsCertTypeExt = null;
                }
                // XXX agent servlet currently sets this. it should be
                // delayed to here.
                if (nsCertTypeExt != null &&
                        extensionIsGood(nsCertTypeExt, req)) {
                    CMS.debug(
                            "NSCertTypeExt: already has correct ns cert type ext");
                    return PolicyResult.ACCEPTED;
                } else if ((nsCertTypeExt != null) &&
                        (certType.equals("ocspResponder"))) {
                    // Fix for #528732 : Always delete
                    // this extension from OCSP signing cert
                    extensions.delete(NSCertTypeExtension.NAME);
                    return PolicyResult.ACCEPTED;
                }
            } else {
                // create extensions set if none.
                if (extensions == null) {
                    certInfo.set(X509CertInfo.VERSION,
                            new CertificateVersion(CertificateVersion.V3));
                    extensions = new CertificateExtensions();
                    certInfo.set(X509CertInfo.EXTENSIONS, extensions);
                    CMS.debug(
                            "NSCertTypeExt: Created extensions for adding ns cert type..");
                }
            }
            // add ns cert type extension if not set or not set correctly.
            boolean[] bits = null;

            bits = getBitsFromRequest(req, mSetDefaultBits);

            // check if ca doesn't allow any subordinate ca
            if (mCAPathLen == 0 && bits != null) {
                if (bits[NSCertTypeExtension.SSL_CA_BIT] ||
                        bits[NSCertTypeExtension.EMAIL_CA_BIT] ||
                        bits[NSCertTypeExtension.OBJECT_SIGNING_CA_BIT]) {
                    setError(req,
                            CMS.getUserMessage("CMS_POLICY_NO_SUB_CA_CERTS_ALLOWED"), NAME);
                    return PolicyResult.REJECTED;
                }
            }

            if (nsCertTypeExt != null) {
                // replace with correct bits to comply to policy.
                // take all that are true.
                extensions.delete(NSCertTypeExtension.NAME);
            }

            int j;

            for (j = 0; bits != null && j < bits.length; j++)
                if (bits[j])
                    break;
            if (bits == null || j == bits.length) {
                if (!mSetDefaultBits) {
                    CMS.debug(
                            "NSCertTypeExt: no bits requested, not setting default.");
                    return PolicyResult.ACCEPTED;
                } else
                    bits = DEF_BITS;
            }

            nsCertTypeExt = new NSCertTypeExtension(mCritical, bits);
            extensions.set(NSCertTypeExtension.NAME, nsCertTypeExt);
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
     * check if ns cert type extension is set correctly,
     * correct bits if not.
     * if not authorized to set extension, bits will be replaced.
     */
    protected boolean extensionIsGood(
            NSCertTypeExtension nsCertTypeExt, IRequest req)
            throws IOException, CertificateException {
        // always return false for now to make sure minimum is set.
        // agents and ee can add others.

        // must be agent approved or authenticated for allowing extensions
        // which is always the case if we get to this point.
        IAuthToken token = req.getExtDataInAuthToken(IRequest.AUTH_TOKEN);

        if (!agentApproved(req) && token == null) {
            // don't know where this came from.
            // set all bits to false to reset.
            CMS.debug(
                    "NSCertTypeExt: unknown origin: setting ns cert type bits to false");
            boolean[] bits = new boolean[8];

            for (int i = bits.length - 1; i >= 0; i--) {
                nsCertTypeExt.set(i, false);
            }
            return false;
        } else {
            // check for min bits, set default if not there.
            String certType = req.getExtDataInString(IRequest.HTTP_PARAMS,
                    IRequest.CERT_TYPE);

            if ((certType != null) && certType.equals("ocspResponder")) {
                return false;
            }
            if (certType == null || certType.length() == 0) {
                // if don't know cert type let agent override anything.
                return true;
            }
            if (certType.equals(IRequest.CA_CERT)) {
                if (!nsCertTypeExt.isSet(NSCertTypeExtension.SSL_CA_BIT) &&
                        !nsCertTypeExt.isSet(NSCertTypeExtension.EMAIL_CA_BIT) &&
                        !nsCertTypeExt.isSet(
                                NSCertTypeExtension.OBJECT_SIGNING_CA_BIT)) {
                    // min not set so set all.
                    CMS.debug(
                            "NSCertTypeExt: is extension good: no ca bits set. set all");

                    nsCertTypeExt.set(NSCertTypeExtension.SSL_CA,
                            Boolean.valueOf(true));
                    nsCertTypeExt.set(NSCertTypeExtension.EMAIL_CA,
                            Boolean.valueOf(true));
                    nsCertTypeExt.set(NSCertTypeExtension.OBJECT_SIGNING_CA,
                            Boolean.valueOf(true));
                }
                return true;
            } else if (certType.equals(IRequest.CLIENT_CERT)) {
                if (!nsCertTypeExt.isSet(NSCertTypeExtension.SSL_CLIENT_BIT) &&
                        !nsCertTypeExt.isSet(NSCertTypeExtension.EMAIL_BIT) &&
                        !nsCertTypeExt.isSet(NSCertTypeExtension.SSL_SERVER_BIT) &&
                        !nsCertTypeExt.isSet(
                                NSCertTypeExtension.OBJECT_SIGNING_BIT)) {
                    // min not set so set all.
                    CMS.debug(
                            "NSCertTypeExt: is extension good: no cl bits set. set all");
                    nsCertTypeExt.set(NSCertTypeExtension.SSL_CLIENT,
                            new Boolean(true));
                    nsCertTypeExt.set(NSCertTypeExtension.EMAIL,
                            new Boolean(true));
                    nsCertTypeExt.set(NSCertTypeExtension.OBJECT_SIGNING,
                            new Boolean(true));
                }
                return true;
            } else if (certType.equals(IRequest.SERVER_CERT)) {
                // this bit must be true.
                nsCertTypeExt.set(NSCertTypeExtension.SSL_SERVER_BIT, true);
                return true;
            }
        }
        return false;
    }

    /**
     * Gets ns cert type bits from request.
     * If none set, use cert type to determine correct bits.
     * If no cert type, use default.
     */

    protected boolean[] getBitsFromRequest(IRequest req, boolean setDefault) {
        boolean[] bits = null;

        CMS.debug("NSCertTypeExt: ns cert type getting ns cert type vars");
        bits = getNSCertTypeBits(req);
        if (bits == null && setDefault) {
            // no ns cert type bits set in request. go with cert type.
            CMS.debug("NSCertTypeExt: ns cert type getting cert type vars");
            bits = getCertTypeBits(req);

            if (bits == null && setDefault) {
                CMS.debug("NSCertTypeExt: ns cert type getting def bits");
                bits = DEF_BITS;
            }
        }
        return bits;
    }

    /**
     * get ns cert type bits from actual sets in the request
     */
    protected boolean[] getNSCertTypeBits(IRequest req) {
        boolean[] bits = new boolean[NSCertTypeExtension.NBITS];

        bits[NSCertTypeExtension.SSL_CLIENT_BIT] =
                // XXX should change this to is ns cert type ssl_client defn.
                req.getExtDataInBoolean(IRequest.HTTP_PARAMS,
                        NSCertTypeExtension.SSL_CLIENT, false);

        bits[NSCertTypeExtension.SSL_SERVER_BIT] =
                req.getExtDataInBoolean(IRequest.HTTP_PARAMS,
                        NSCertTypeExtension.SSL_SERVER, false);

        bits[NSCertTypeExtension.EMAIL_BIT] =
                // XXX should change this to is ns cert type ssl_client defn.
                req.getExtDataInBoolean(IRequest.HTTP_PARAMS,
                        NSCertTypeExtension.EMAIL, false);

        bits[NSCertTypeExtension.OBJECT_SIGNING_BIT] =
                // XXX should change this to is ns cert type ssl_client defn.
                req.getExtDataInBoolean(IRequest.HTTP_PARAMS,
                        NSCertTypeExtension.OBJECT_SIGNING, false);

        bits[NSCertTypeExtension.SSL_CA_BIT] =
                req.getExtDataInBoolean(IRequest.HTTP_PARAMS,
                        NSCertTypeExtension.SSL_CA, false);

        bits[NSCertTypeExtension.EMAIL_CA_BIT] =
                req.getExtDataInBoolean(IRequest.HTTP_PARAMS,
                        NSCertTypeExtension.EMAIL_CA, false);

        bits[NSCertTypeExtension.OBJECT_SIGNING_CA_BIT] =
                req.getExtDataInBoolean(IRequest.HTTP_PARAMS,
                        NSCertTypeExtension.OBJECT_SIGNING_CA, false);

        // if nothing set, return null.
        int i;

        for (i = bits.length - 1; i >= 0; i--) {
            if (bits[i] == true) {
                CMS.debug("NSCertTypeExt: bit " + i + " is set.");
                break;
            }
        }
        if (i < 0) {
            // nothing was set.
            CMS.debug("NSCertTypeExt: No bits were set.");
            bits = null;
        }
        return bits;
    }

    /**
     * get cert type bits according to cert type.
     */
    protected boolean[] getCertTypeBits(IRequest req) {
        String certType =
                req.getExtDataInString(IRequest.HTTP_PARAMS, IRequest.CERT_TYPE);

        if (certType == null || certType.length() == 0)
            return null;

        boolean[] bits = new boolean[KeyUsageExtension.NBITS];

        for (int i = bits.length - 1; i >= 0; i--)
            bits[i] = false;

        if (certType.equals(IRequest.CLIENT_CERT)) {
            CMS.debug("NSCertTypeExt: setting bits for client cert");
            // we can only guess here when it's client.
            // sets all client bit for default.
            bits[NSCertTypeExtension.SSL_CLIENT_BIT] = true;
            bits[NSCertTypeExtension.EMAIL_BIT] = true;
            //bits[NSCertTypeExtension.OBJECT_SIGNING_BIT] = true;
        } else if (certType.equals(IRequest.SERVER_CERT)) {
            CMS.debug("NSCertTypeExt: setting bits for server cert");
            bits[NSCertTypeExtension.SSL_SERVER_BIT] = true;
        } else if (certType.equals(IRequest.CA_CERT)) {
            CMS.debug("NSCertType: setting bits for ca cert");
            bits[NSCertTypeExtension.SSL_CA_BIT] = true;
            bits[NSCertTypeExtension.EMAIL_CA_BIT] = true;
            bits[NSCertTypeExtension.OBJECT_SIGNING_CA_BIT] = true;
        } else if (certType.equals(IRequest.RA_CERT)) {
            CMS.debug("NSCertType: setting bits for ra cert");
            bits[NSCertTypeExtension.SSL_CLIENT_BIT] = true;
        } else {
            CMS.debug("NSCertTypeExt: no other cert bits set");
            // return null to use default.
            bits = DEF_BITS;
        }
        return bits;
    }

    /**
     * merge bits with those set from form.
     * make sure required minimum is set. Agent or auth can set others.
     * XXX form shouldn't set the extension
     */
    public void mergeBits(NSCertTypeExtension nsCertTypeExt, boolean[] bits) {
        for (int i = bits.length - 1; i >= 0; i--) {
            if (bits[i] == true) {
                CMS.debug("NSCertTypeExt: ns cert type merging bit " + i);
                nsCertTypeExt.set(i, true);
            }
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
        params.addElement(PROP_SET_DEFAULT_BITS + "=" + mSetDefaultBits);
        //new Boolean(mSetDefaultBits).toString());
        return params;
    }

    private static Vector<String> mDefParams = new Vector<String>();
    static {
        mDefParams.addElement(
                PROP_CRITICAL + "=false");
        mDefParams.addElement(
                PROP_SET_DEFAULT_BITS + "=" + DEF_SET_DEFAULT_BITS);
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_CRITICAL + ";boolean;Netscape recommendation: non-critical.",
                PROP_SET_DEFAULT_BITS + ";boolean;Specify whether to set the Netscape certificate " +
                        "type extension with default bits ('ssl client' and 'email') in certificates " +
                        "specified by the predicate " +
                        "expression.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-nscerttype",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Adds Netscape Certificate Type extension."
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
}
