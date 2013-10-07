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

import netscape.security.x509.BasicConstraintsExtension;
import netscape.security.x509.CertificateChain;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotDefined;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.EPolicyException;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.policy.IPolicyProcessor;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Basic Constraints policy.
 * Adds the Basic constraints extension.
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
public class BasicConstraintsExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    protected static final String PROP_MAXPATHLEN = "maxPathLen";
    protected static final String PROP_IS_CA = "isCA";
    protected static final String PROP_IS_CRITICAL = "critical";

    protected static final String ARG_PATHLEN = "BasicConstraintsPathLen";

    protected int mMaxPathLen = 0; // < 0 means unlimited
    protected String mOrigMaxPathLen = ""; // for UI display only
    protected boolean mCritical = true;
    protected int mDefaultMaxPathLen = 0; // depends on the CA's path length.
    protected int mCAPathLen = 0;
    protected boolean mRemoveExt = true;
    protected boolean mIsCA = true;

    public static final boolean DEFAULT_CRITICALITY = true;

    /**
     * Adds the basic constraints extension as a critical extension in
     * CA certificates i.e. certype is ca, with either a requested
     * or configured path len.
     * The requested or configured path length cannot be greater than
     * or equal to the CA's basic constraints path length.
     * If the CA path length is 0, all requests for CA certs are rejected.
     */
    public BasicConstraintsExt() {
        NAME = "BasicConstraintsExt";
        DESC =
                "Sets critical basic constraints extension in subordinate CA certs";
    }

    /**
     * Initializes this policy rule.
     * <p>
     * The entries may be of the form:
     *
     * ca.Policy.rule.<ruleName>.implName=BasicConstraintsExtImpl ca.Policy.rule.<ruleName>.pathLen=<n>, -1 for
     * undefined. ca.Policy.rule.<ruleName>.enable=true
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {

        // get the CA's path len to check against configured max path len.
        ICertAuthority certAuthority = (ICertAuthority)
                ((IPolicyProcessor) owner).getAuthority();

        if (certAuthority == null) {
            // should never get here.
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CANT_FIND_MANAGER"));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                        "Cannot find the Certificate Manager or Registration Manager"));
        }
        if (certAuthority instanceof IRegistrationAuthority) {
            log(ILogger.LL_WARN,
                    "default basic constraints extension path len to -1.");
            mCAPathLen = -1;
        } else {
            CertificateChain caChain = certAuthority.getCACertChain();
            if (caChain == null || CMS.isPreOpMode()) {
                return;
            }
            X509Certificate caCert = caChain.getFirstCertificate();

            mCAPathLen = caCert.getBasicConstraints();
        }
        // set default to one less than the CA's pathlen or 0 if CA's
        // pathlen is 0.
        // If it's unlimited default the max pathlen also to unlimited.
        if (mCAPathLen < 0)
            mDefaultMaxPathLen = -1;
        else if (mCAPathLen > 0)
            mDefaultMaxPathLen = mCAPathLen - 1;
        else // (mCAPathLen == 0)
        {
            log(ILogger.LL_WARN,
                    CMS.getLogMessage("POLICY_PATHLEN_ZERO"));
            //return;
        }

        // get configured max path len, use defaults if not configured.
        boolean pathLenConfigured = true;

        try {
            mCritical = config.getBoolean(PROP_IS_CRITICAL, true);
            mIsCA = config.getBoolean(PROP_IS_CA, true);
            mMaxPathLen = config.getInteger(PROP_MAXPATHLEN);
            if (mMaxPathLen < 0) {
                log(ILogger.LL_MISCONF,
                        CMS.getLogMessage("POLICY_INVALID_MAXPATHLEN_4", "",
                                String.valueOf(mMaxPathLen)));
                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_INVALID_MAXPATHLEN_1",
                                NAME, String.valueOf(mMaxPathLen)));
            }
            mOrigMaxPathLen = Integer.toString(mMaxPathLen);
        } catch (EBaseException e) {
            if (!(e instanceof EPropertyNotFound) &&
                    !(e instanceof EPropertyNotDefined)) {
                log(ILogger.LL_MISCONF,
                        CMS.getLogMessage("POLICY_INVALID_MAXPATHLEN"));
                throw e;
            }

            // Set the max path len to default if not configured.
            pathLenConfigured = false;
            mMaxPathLen = mDefaultMaxPathLen;
            mOrigMaxPathLen = "";
        }

        // check if configured path len is valid.
        if (pathLenConfigured) {
            // if CA's pathlen is unlimited, any max pathlen is ok.
            // else maxPathlen must be at most one less than the CA's
            // pathlen or 0 if CA's pathlen is 0.

            if (mCAPathLen > 0 &&
                    (mMaxPathLen >= mCAPathLen || mMaxPathLen < 0)) {
                String maxStr = (mMaxPathLen < 0) ?
                        String.valueOf(mMaxPathLen) + "(unlimited)" :
                        String.valueOf(mMaxPathLen);

                log(ILogger.LL_MISCONF,
                        CMS.getLogMessage("POLICY_MAXPATHLEN_TOO_BIG_3", "",
                                maxStr,
                                String.valueOf(mCAPathLen)));
                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_MAXPATHLEN_TOO_BIG_1",
                                NAME, maxStr, Integer.toString(mCAPathLen)));
            } else if (mCAPathLen == 0 && mMaxPathLen != 0) {
                log(ILogger.LL_MISCONF,
                        CMS.getLogMessage("POLICY_INVALID_MAXPATHLEN_2", "", String.valueOf(mMaxPathLen)));
                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_INVALID_MAXPATHLEN",
                                NAME, String.valueOf(mMaxPathLen)));
            }
        }

    }

    /**
     * Checks if the basic contraints extension in certInfo is valid and
     * add the basic constraints extension for CA certs if none exists.
     * Non-CA certs do not get a basic constraints extension.
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {

        // get cert info.
        X509CertInfo[] ci =
                req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        X509CertInfo certInfo = null;

        if (ci == null || (certInfo = ci[0]) == null) {
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO", NAME), "");
            return PolicyResult.REJECTED; // unrecoverable error.
        }

        // get cert type
        boolean isCA = mIsCA;

        /**
         * boolean isCA = false;
         * String type = (String)req.get(IRequest.HTTP_PARAMS, IRequest.CERT_TYPE);
         * if (type != null && type.equalsIgnoreCase(IRequest.CA_CERT)) {
         * isCA = true;
         * }
         **/

        for (int i = 0; i < ci.length; i++) {
            PolicyResult certResult = applyCert(req, isCA, certInfo);

            if (certResult == PolicyResult.REJECTED)
                return certResult;
        }
        return PolicyResult.ACCEPTED;
    }

    public PolicyResult applyCert(
            IRequest req, boolean isCA, X509CertInfo certInfo) {

        // get basic constraints extension from cert info if any.
        CertificateExtensions extensions = null;
        BasicConstraintsExtension basicExt = null;

        try {
            // get basic constraints extension if any.
            extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);
            if (extensions != null) {
                basicExt = (BasicConstraintsExtension)
                        extensions.get(BasicConstraintsExtension.NAME);
            }
        } catch (IOException e) {
            // no extensions or basic constraints extension.
        } catch (CertificateException e) {
            // no extensions or basic constraints extension.
        }

        // for non-CA certs, pkix says it SHOULD NOT have the extension
        // so remove it.
        if (!isCA) {
            if (extensions == null) {
                try {
                    // create extensions set if none.
                    certInfo.set(X509CertInfo.VERSION,
                            new CertificateVersion(CertificateVersion.V3));
                    extensions = new CertificateExtensions();
                    certInfo.set(X509CertInfo.EXTENSIONS, extensions);
                } catch (CertificateException e) {
                } catch (IOException e) {
                    // not possible
                }
            }
            if (basicExt != null) {
                try {
                    extensions.delete(BasicConstraintsExtension.NAME);
                } catch (IOException e) {
                }
            }

            BasicConstraintsExtension critExt;

            try {
                critExt = new BasicConstraintsExtension(isCA, mCritical, mMaxPathLen);
            } catch (IOException e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("POLICY_ERROR_BASIC_CONSTRAINTS_2",
                                e.toString()));
                setError(req,
                        CMS.getUserMessage("CMS_POLICY_BASIC_CONSTRAINTS_ERROR", NAME), "");
                return PolicyResult.REJECTED; // unrecoverable error.
            }

            try {
                extensions.set(BasicConstraintsExtension.NAME, critExt);
            } catch (IOException e) {
            }
            CMS.debug(
                    "BasicConstraintsExt: PolicyRule BasicConstraintsExt: added the extension to request " +
                            req.getRequestId());
            return PolicyResult.ACCEPTED;
        }

        // For CA certs, check if existing extension is valid, and adjust.
        // Extension must be marked critial and pathlen must be < CA's pathlen.
        // if CA's pathlen is 0 all ca certs are rejected.

        if (mCAPathLen == 0) {
            // reject all subordinate CA cert requests because CA's
            // path length is 0.
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_NO_SUB_CA_CERTS_ALLOWED_1", NAME));
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_SUB_CA_CERTS_ALLOWED", NAME), "");
            return PolicyResult.REJECTED;
        }

        if (basicExt != null) {
            try {
                boolean extIsCA =
                        ((Boolean) basicExt.get(BasicConstraintsExtension.IS_CA)).booleanValue();
                int pathLen =
                        ((Integer) basicExt.get(BasicConstraintsExtension.PATH_LEN)).intValue();

                if (mMaxPathLen > -1) {
                    if (pathLen > mMaxPathLen || pathLen < 0) {
                        log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("POLICY_MAXPATHLEN_TOO_BIG_3", NAME, "unlimited",
                                        String.valueOf(pathLen)));
                        if (pathLen < 0)
                            setError(req, CMS.getUserMessage("CMS_POLICY_MAXPATHLEN_TOO_BIG",
                                    NAME, "unlimited", Integer.toString(mMaxPathLen)), "");
                        else
                            setError(req, CMS.getUserMessage("CMS_POLICY_MAXPATHLEN_TOO_BIG",
                                    NAME, Integer.toString(pathLen),
                                    Integer.toString(mMaxPathLen)), "");
                        return PolicyResult.REJECTED;
                    }
                }

                // adjust isCA field
                if (!extIsCA) {
                    basicExt.set(BasicConstraintsExtension.IS_CA,
                            Boolean.valueOf(true));
                }

                // adjust path length field.
                if (mMaxPathLen == 0) {
                    if (pathLen != 0) {
                        basicExt.set(BasicConstraintsExtension.PATH_LEN,
                                Integer.valueOf(0));
                        pathLen = 0;
                    }
                } else if (mMaxPathLen > 0 && pathLen > mMaxPathLen) {
                    basicExt.set(BasicConstraintsExtension.PATH_LEN,
                            Integer.valueOf(mMaxPathLen));
                    pathLen = mMaxPathLen;
                }

                // adjust critical field.
                if (!basicExt.isCritical()) {
                    BasicConstraintsExtension critExt;

                    try {
                        critExt = new BasicConstraintsExtension(isCA, mCritical, pathLen);
                    } catch (IOException e) {
                        log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("POLICY_ERROR_BASIC_CONSTRAINTS_1", NAME));
                        setError(req,
                                CMS.getUserMessage("CMS_POLICY_BASIC_CONSTRAINTS_ERROR", NAME), "");
                        return PolicyResult.REJECTED; // unrecoverable error.
                    }
                    extensions.delete(BasicConstraintsExtension.NAME);
                    extensions.set(BasicConstraintsExtension.NAME, critExt);
                }
            } catch (IOException e) {
                // not possible in these cases.
            }
            CMS.debug(
                    "BasicConstraintsExt: PolicyRule BasicConstraintsExt: added the extension to request " +
                            req.getRequestId());
            return PolicyResult.ACCEPTED;
        }

        // add the extension for the CA cert.
        if (extensions == null) {
            try {
                // create extensions set if none.
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                extensions = new CertificateExtensions();
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
            } catch (CertificateException e) {
                // not possible
            } catch (IOException e) {
                // not possible
            }
        }

        // set path len to requested path len if it's valid.
        // if no path len requested set path len to max allowed path len.
        String reqPathLenStr = req.getExtDataInString(ARG_PATHLEN);
        int reqPathLen;

        if (reqPathLenStr == null) {
            reqPathLen = mMaxPathLen;
        } else {
            try {
                reqPathLen = Integer.parseInt(reqPathLenStr);
                if ((mMaxPathLen == 0 && reqPathLen != 0) ||
                        (mMaxPathLen > 0 &&
                        (reqPathLen > mMaxPathLen || reqPathLen < 0))) {
                    String plenStr =
                            ((reqPathLen < 0) ?
                                    reqPathLenStr + "(unlimited)" : reqPathLenStr);

                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("POLICY_PATHLEN_TOO_BIG_3", plenStr,
                                    String.valueOf(mMaxPathLen)));
                    setError(req,
                            CMS.getUserMessage("CMS_POLICY_PATHLEN_TOO_BIG",
                                    NAME, plenStr, String.valueOf(mMaxPathLen)), "");
                    return PolicyResult.REJECTED;
                }
            } catch (NumberFormatException e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("POLICY_INVALID_PATHLEN_FORMAT_2", NAME, reqPathLenStr));
                setError(req, CMS.getUserMessage("CMS_POLICY_INVALID_PATHLEN_FORMAT",
                        NAME, reqPathLenStr), "");
                return PolicyResult.REJECTED;
            }
        }
        BasicConstraintsExtension newExt;

        try {
            newExt = new BasicConstraintsExtension(isCA, mCritical, reqPathLen);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_BASIC_CONSTRAINTS_2", e.toString()));
            setError(req,
                    CMS.getUserMessage("CMS_POLICY_BASIC_CONSTRAINTS_ERROR", NAME), "");
            return PolicyResult.REJECTED; // unrecoverable error.
        }
        try {
            extensions.set(BasicConstraintsExtension.NAME, newExt);
        } catch (IOException e) {
            // doesn't happen.
        }
        CMS.debug(
                "BasicConstraintsExt: added the extension to request " +
                        req.getRequestId());
        return PolicyResult.ACCEPTED;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        Vector<String> params = new Vector<String>();

        // Because of one of the UI bugs 385273, we should leave the empty space
        // as is. Do not convert the space to some definite numbers.
        params.addElement(PROP_MAXPATHLEN + "=" + mOrigMaxPathLen);
        params.addElement(PROP_IS_CRITICAL + "=" + mCritical);
        params.addElement(PROP_IS_CA + "=" + mIsCA);
        return params;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        Vector<String> defParams = new Vector<String>();

        defParams.addElement(PROP_IS_CRITICAL + "=true");
        defParams.addElement(PROP_MAXPATHLEN + "=");
        defParams.addElement(PROP_IS_CA + "=true");
        return defParams;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_MAXPATHLEN
                        + ";number;'0' means : no subordinates allowed, 'n' means : at most n subordinates allowed.",
                PROP_IS_CRITICAL + ";boolean;" +
                        "RFC 2459 recommendation: MUST be critical in CA certs, SHOULD NOT appear in EE certs.",
                PROP_IS_CA + ";boolean;" +
                        "Identifies the subject of the certificate is a CA or not.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-basicconstraints",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Adds the Basic Constraints extension. See RFC 2459 (4.2.1.10)"
        };

        return params;
    }

}
