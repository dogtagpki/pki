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
import java.util.Hashtable;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.security.util.BitArray;
import netscape.security.x509.CRLDistributionPoint;
import netscape.security.x509.CRLDistributionPointsExtension;
import netscape.security.x509.CRLDistributionPointsExtension.Reason;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.GeneralName;
import netscape.security.x509.GeneralNames;
import netscape.security.x509.GeneralNamesException;
import netscape.security.x509.RDN;
import netscape.security.x509.URIName;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
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
 * The type of the distribution point or issuer name. The name is expressed
 * as a simple string in the configuration file, so this attribute is needed
 * to tell whether the simple string should be stored in an X.500 Name,
 * a URL, or an RDN.
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
class NameType {
    private NameType() {
    } // no default constructor

    private String stringRep; // string representation of this type

    private NameType(String s) {
        map.put(s, this);
        stringRep = s;
    }

    private static Hashtable<String, NameType> map = new Hashtable<String, NameType>();

    /**
     * Looks up a NameType from its string representation. Returns null
     * if no matching NameType was found.
     */
    public static NameType fromString(String s) {
        return map.get(s);
    }

    public String toString() {
        return stringRep;
    }

    public static final NameType DIRECTORY_NAME = new NameType("DirectoryName");
    public static final NameType URI = new NameType("URI");
    public static final NameType RELATIVE_TO_ISSUER =
            new NameType("RelativeToIssuer");
}

/**
 * These are the parameters that may be given in the configuration file
 * for each distribution point. They are parsed by DPParamsToDP().
 * Any of them may be null.
 */
class DistPointParams {
    public String pointName;
    public String pointType;

    public String reasons;

    public String issuerName;
    public String issuerType;

    public DistPointParams() {
    }

    public DistPointParams(DistPointParams old) {
        pointName = old.pointName;
        pointType = old.pointType;
        reasons = old.reasons;
        issuerName = old.issuerName;
        issuerType = old.issuerType;
    }

}

/**
 * CRL Distribution Points policy.
 * Adds the CRL Distribution Points extension to the certificate.
 */
public class CRLDistributionPointsExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {

    public static final String PROP_IS_CRITICAL = "critical";
    public static final String PROP_NUM_POINTS = "numPoints";
    public static final String PROP_POINT_TYPE = "pointType";
    public static final String PROP_POINT_NAME = "pointName";
    public static final String PROP_REASONS = "reasons";
    public static final String PROP_ISSUER_NAME = "issuerName";
    public static final String PROP_ISSUER_TYPE = "issuerType";

    private static final int MAX_POINTS = 10;
    private static final int DEFAULT_NUM_BLANK_POINTS = 3;
    private int mNumPoints = DEFAULT_NUM_BLANK_POINTS;

    // PKIX specifies the that the extension SHOULD NOT be critical
    public static final boolean DEFAULT_CRITICALITY = false;

    private Vector<String> defaultParams = new Vector<String>();

    private Vector<String> mParams = new Vector<String>();
    private String mExtParams[] = null;
    private CRLDistributionPointsExtension mCrldpExt = null;

    public CRLDistributionPointsExt() {
        NAME = "CRLDistributionPointsExt";
        DESC = "Sets CRL distribution points extension";
        defaultParams.addElement(PROP_IS_CRITICAL + "=" + DEFAULT_CRITICALITY);
        defaultParams.addElement(PROP_NUM_POINTS + "=0");
        for (int i = 0; i < DEFAULT_NUM_BLANK_POINTS; i++) {
            defaultParams.addElement(PROP_POINT_NAME + i + "=");
            defaultParams.addElement(PROP_POINT_TYPE + i + "=");
            defaultParams.addElement(PROP_REASONS + i + "=");
            defaultParams.addElement(PROP_ISSUER_NAME + i + "=");
            defaultParams.addElement(PROP_ISSUER_TYPE + i + "=");
        }
    }

    private void setExtendedPluginInfo() {
        Vector<String> v = new Vector<String>();

        // should replace MAX_POINTS with mNumPoints if bug 385118 is fixed
        for (int i = 0; i < MAX_POINTS; i++) {
            v.addElement(PROP_POINT_TYPE + Integer.toString(i) + ";choice(" +
                    "DirectoryName,URI,RelativeToIssuer);" +
                    "The type of the CRL distribution point.");
            v.addElement(PROP_POINT_NAME + Integer.toString(i) + ";string;" +
                    "The name of the CRL distribution point depending on the CRLDP type.");
            v.addElement(PROP_REASONS
                    + Integer.toString(i)
                    + ";string;"
                    +
                    "The revocation reasons for the CRL maintained at this distribution point. It's a comma-seperated list of the following constants: unused, keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold.");
            v.addElement(PROP_ISSUER_TYPE + Integer.toString(i) + ";choice(" +
                    "DirectoryName,URI);" +
                    "The type of the issuer that has signed the CRL maintained at this distribution point.");
            v.addElement(PROP_ISSUER_NAME
                    + Integer.toString(i)
                    + ";string;"
                    +
                    "The name of the issuer that has signed the CRL maintained at this distribution point. The value depends on the issuer type.");
        }

        v.addElement(PROP_NUM_POINTS +
                ";number;The total number of CRL distribution points to be contained or allowed in the extension.");
        v.addElement(PROP_IS_CRITICAL
                +
                ";boolean;RFC 2459 recommendation: SHOULD be non-critical. But recommends support for this extension by CAs and applications.");
        v.addElement(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-policyrules-crldistributionpoints");
        v.addElement(IExtendedPluginInfo.HELP_TEXT +
                ";This policy inserts the CRL Distribution Points " +
                "Extension into the certificate. See RFC 2459 (4.2.1.14). "
                );

        mExtParams = com.netscape.cmsutil.util.Utils.getStringArrayFromVector(v);
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        if (mExtParams == null) {
            setExtendedPluginInfo();
        }
        return mExtParams;

    }

    /**
     * Performs one-time initialization of the policy.
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        // Register the CRL Distribution Points extension.
        try {
            netscape.security.x509.OIDMap.addAttribute(
                    CRLDistributionPointsExtension.class.getName(),
                    CRLDistributionPointsExtension.OID,
                    CRLDistributionPointsExtension.NAME);
        } catch (CertificateException e) {
            // ignore, just means it has already been added
        }

        // assemble the list of Distribution Points from the config file
        int numPoints = config.getInteger(PROP_NUM_POINTS, 0);

        mParams.addElement(PROP_NUM_POINTS + "=" + numPoints);
        mNumPoints = numPoints;

        for (int i = 0; i < numPoints; i++) {
            // construct a distribution point from the parameters
            DistPointParams params = new DistPointParams();

            params.pointType = config.getString(PROP_POINT_TYPE + i, "");
            params.pointName = config.getString(PROP_POINT_NAME + i, "");
            params.reasons = config.getString(PROP_REASONS + i, "");
            params.issuerType = config.getString(PROP_ISSUER_TYPE + i, "");
            params.issuerName = config.getString(PROP_ISSUER_NAME + i, "");

            DistPointParams configparams = new DistPointParams(params);
            CRLDistributionPoint crldp = DPParamsToDP(params);

            mParams.addElement(PROP_POINT_TYPE + i + "=" + configparams.pointType);
            mParams.addElement(PROP_POINT_NAME + i + "=" + configparams.pointName);
            mParams.addElement(PROP_REASONS + i + "=" + configparams.reasons);
            mParams.addElement(PROP_ISSUER_TYPE + i + "=" + configparams.issuerType);
            mParams.addElement(PROP_ISSUER_NAME + i + "=" + configparams.issuerName);

            // add the distribution point to the extension
            if (mCrldpExt == null) {
                mCrldpExt = new CRLDistributionPointsExtension(crldp);
            } else {
                mCrldpExt.addPoint(crldp);
            }
        }

        boolean crit = config.getBoolean(PROP_IS_CRITICAL,
                DEFAULT_CRITICALITY);

        mParams.addElement(PROP_IS_CRITICAL + "=" + crit);
        if (mCrldpExt != null) {
            // configure the extension itself
            mCrldpExt.setCritical(crit);
        }
        setExtendedPluginInfo();

    }

    /**
     * Parses the parameters in the config file to create an
     * actual CRL Distribution Point object.
     */
    private CRLDistributionPoint DPParamsToDP(DistPointParams params)
            throws EBaseException {
        CRLDistributionPoint crlDP = new CRLDistributionPoint();

        try {

            if (params.pointName != null && params.pointName.length() == 0) {
                params.pointName = null;
            }
            if (params.pointType != null && params.pointType.length() == 0) {
                params.pointType = null;
            }
            if (params.reasons != null && params.reasons.length() == 0) {
                params.reasons = null;
            }
            if (params.issuerName != null && params.issuerName.length() == 0) {
                params.issuerName = null;
            }
            if (params.issuerType != null && params.issuerType.length() == 0) {
                params.issuerType = null;
            }

            // deal with the distribution point name
            if (params.pointName != null && params.pointType != null) {
                // decode the type of the name
                NameType nType = NameType.fromString(params.pointType);

                if (nType == null) {
                    String err = "Unknown name type: " + params.pointType;

                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_UNKNOWN_NAME_TYPE", params.pointType));
                    throw new EBaseException(err);
                }

                if (nType == NameType.DIRECTORY_NAME) {
                    GeneralNames gen = new GeneralNames();

                    gen.addElement(new GeneralName(new X500Name(params.pointName)));
                    crlDP.setFullName(gen);
                } else if (nType == NameType.URI) {
                    GeneralNames gen = new GeneralNames();

                    gen.addElement(new GeneralName(new URIName(params.pointName)));
                    crlDP.setFullName(gen);
                } else if (nType == NameType.RELATIVE_TO_ISSUER) {
                    crlDP.setRelativeName(new RDN(params.pointName));
                } else {
                    String err = "Unknown name type: " + nType.toString();

                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_UNKNOWN_NAME_TYPE", nType.toString()));
                    throw new EBaseException(err);
                }
            }

            // deal with the reasons
            if (params.reasons != null) {
                StringTokenizer tok = new StringTokenizer(params.reasons, ", \t");
                byte reasonBits = 0;

                while (tok.hasMoreTokens()) {
                    String s = tok.nextToken();
                    Reason r = Reason.fromString(s);

                    if (r == null) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_UNKNOWN_REASON", s));
                        throw new EBaseException("Unknown reason: " + s);
                    } else {
                        reasonBits |= r.getBitMask();
                    }
                }
                if (reasonBits != 0) {
                    BitArray ba = new BitArray(8, new byte[] { reasonBits }
                            );

                    crlDP.setReasons(ba);
                }
            }

            // deal with the issuer name
            if (params.issuerName != null && params.issuerType != null) {
                // decode the type of the name
                NameType nType = NameType.fromString(params.issuerType);

                if (nType == null) {
                    String err = "Unknown name type: " + params.issuerType;

                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_UNKNOWN_NAME_TYPE", params.issuerType));
                    throw new EBaseException(err);
                }

                if (nType == NameType.DIRECTORY_NAME) {
                    GeneralNames gen = new GeneralNames();

                    gen.addElement(new GeneralName(new X500Name(params.issuerName)));
                    crlDP.setCRLIssuer(gen);
                } else if (nType == NameType.URI) {
                    GeneralNames gen = new GeneralNames();

                    gen.addElement(new GeneralName(new URIName(params.issuerName)));
                    crlDP.setCRLIssuer(gen);
                } else {
                    String err = "Unknown name type: " + nType.toString();

                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_UNKNOWN_NAME_TYPE", nType.toString()));
                    throw new EBaseException(err);
                }
            }

        } catch (GeneralNamesException e) {
            throw new EBaseException(e.getMessage());
        } catch (IOException e) {
            throw new EBaseException(e.getMessage());
        }

        // done, return this distribution point
        return crlDP;
    }

    /**
     * Applies the policy to the given request.
     */
    public PolicyResult apply(IRequest req) {

        // if the extension was not configured correctly, just skip it
        if (mCrldpExt == null) {
            return PolicyResult.ACCEPTED;
        }

        X509CertInfo[] ci = req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

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
            // find the extensions in the certInfo
            CertificateExtensions extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);

            // prepare the extensions data structure
            if (extensions == null) {
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                extensions = new CertificateExtensions();
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
            } else {
                // remove any previously computed version of the extension
                try {
                    extensions.delete(CRLDistributionPointsExtension.NAME);
                } catch (IOException e) {
                    // extension isn't there
                }
            }
            extensions.set(CRLDistributionPointsExtension.NAME, mCrldpExt);

            return PolicyResult.ACCEPTED;

        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_UNEXPECTED_POLICY_ERROR", NAME, e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"), NAME,
                    e.getMessage());
            return PolicyResult.REJECTED;
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CERT_INFO_ERROR",
                    e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"), NAME,
                    e.getMessage());
            return PolicyResult.REJECTED;
        }
    }

    // parameters must be entered in the config file
    public Vector<String> getDefaultParams() {
        for (int i = DEFAULT_NUM_BLANK_POINTS; i < mNumPoints; i++) {
            defaultParams.addElement(PROP_POINT_NAME + i + "=");
            defaultParams.addElement(PROP_POINT_TYPE + i + "=");
            defaultParams.addElement(PROP_REASONS + i + "=");
            defaultParams.addElement(PROP_ISSUER_NAME + i + "=");
            defaultParams.addElement(PROP_ISSUER_TYPE + i + "=");
        }
        return defaultParams;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        return mParams;
    }
}
