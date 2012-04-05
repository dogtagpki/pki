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

import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertificateAlgorithmId;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.authority.ICertAuthority;
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
 * SigningAlgorithmConstraints enforces that only a supported
 * signing algorithm be requested.
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
public class SigningAlgorithmConstraints extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    private String[] mAllowedAlgs = null; // algs allowed by this policy
    static String[] mDefaultAllowedAlgs = null; // default algs allowed by this policy based on CA's key
    private String[] mConfigAlgs = null; // algs listed in config file
    private boolean winnowedByKey = false;
    IAuthority mAuthority = null;
    private final static String PROP_ALGORITHMS = "algorithms";

    private final static Vector<String> defConfParams = new Vector<String>();

    static {
        StringBuffer sb = new StringBuffer();
        sb.append(PROP_ALGORITHMS);
        sb.append("=");
        int i = 0;
        boolean first = true;

        mDefaultAllowedAlgs = new String[AlgorithmId.ALL_SIGNING_ALGORITHMS.length];
        for (i = 0; i < AlgorithmId.ALL_SIGNING_ALGORITHMS.length; i++) {
            mDefaultAllowedAlgs[i] = AlgorithmId.ALL_SIGNING_ALGORITHMS[i];
            if (first == true) {
                sb.append(AlgorithmId.ALL_SIGNING_ALGORITHMS[i]);
                first = false;
            } else {
                sb.append(",");
                sb.append(AlgorithmId.ALL_SIGNING_ALGORITHMS[i]);
            }
        }
        defConfParams.addElement(sb.toString());
    }

    public SigningAlgorithmConstraints() {
        NAME = "SigningAlgorithmConstraints";
        DESC = "Enforces Signing Algorithm Constraints.";
    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries probably are of the form ra.Policy.rule.<ruleName>.implName=SigningAlgorithmConstraints
     * ra.Policy.rule.<ruleName>.algorithms=SHA-1WithRSA, SHA-1WithDSA ra.Policy.rule.<ruleName>.enable=true
     * ra.Policy.rule.<ruleName>.predicate=ou==Sales
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mAuthority = (IAuthority) ((IPolicyProcessor) owner).getAuthority();

        // Get allowed algorithms from config file
        if (config != null) {
            String algNames = null;

            try {
                algNames = config.getString(PROP_ALGORITHMS, null);
            } catch (Exception e) {
                String[] params = { getInstanceName(), e.toString(), PROP_ALGORITHMS };

                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_PARAM_CONFIG_ERROR", params));
            }

            if (algNames != null) {
                // parse alg names into Vector
                StringTokenizer tok = new StringTokenizer(algNames, ",");
                Vector<String> algs = new Vector<String>();

                while (tok.hasMoreTokens()) {
                    algs.addElement(tok.nextToken().trim());
                }

                // convert to array for speedy traversals during apply()
                int itemCount = algs.size();

                mAllowedAlgs = new String[itemCount];
                for (int i = 0; i < itemCount; i++) {
                    mAllowedAlgs[i] = algs.elementAt(i);
                }

            }

        }

        // these are the algorithms from the config file
        mConfigAlgs = mAllowedAlgs;
        if (mConfigAlgs == null) {
            mConfigAlgs = new String[0];
        }

        if (mAllowedAlgs != null) {
            // winnow out unknown algorithms
            winnowAlgs(AlgorithmId.ALL_SIGNING_ALGORITHMS,
                    "CMS_POLICY_UNKNOWN_SIGNING_ALG", true);
        } else {
            // if nothing was in the config file, allow all known algs
            mAllowedAlgs = AlgorithmId.ALL_SIGNING_ALGORITHMS;
        }

        // winnow out algorithms that don't make sense for the key
        winnowByKey();

        if (mAllowedAlgs.length == 0) {
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_SIGNALG_NOT_MATCH_CAKEY", NAME));
        }

    }

    /**
     * winnow out algorithms that don't make sense for the CA's key
     */
    private synchronized void winnowByKey() throws EBaseException {
        // only do this successfully once
        if (winnowedByKey) {
            return;
        }

        // don't do this ever for DRM
        if (!(mAuthority instanceof ICertAuthority)) {
            winnowedByKey = true;
            return;
        }

        // get list of algorithms allowed for the key
        String[] allowedByKey =
                ((ICertAuthority) mAuthority).getCASigningAlgorithms();

        if (allowedByKey != null) {
            // don't show algorithms that don't match CA's key in UI.
            mDefaultAllowedAlgs = new String[allowedByKey.length];
            for (int i = 0; i < allowedByKey.length; i++)
                mDefaultAllowedAlgs[i] = allowedByKey[i];
            // winnow out algorithms that don't match CA's signing key
            winnowAlgs(allowedByKey,
                    "CMS_POLICY_SIGNALG_NOT_MATCH_CAKEY_1", false);
            winnowedByKey = true;
        } else {
            // We don't know the CA's signing algorithms.  Maybe we're
            // an RA that hasn't talked to the CA yet? Try again later.
        }
    }

    /**
     * Winnows out of mAllowedAlgorithms those algorithms that aren't allowed
     * for some reason.
     *
     * @param allowed An array of allowed algorithms. Only algorithms in this
     *            list will survive the winnowing process.
     * @param reason A string describing the problem with an algorithm
     *            that is not allowed by this list. Must be a predefined string in PolicyResources.
     */
    private void winnowAlgs(String[] allowed, String reason, boolean isError)
            throws EBaseException {
        int i, j, goodSize;

        // validate the currently-allowed algorithms
        Vector<String> goodAlgs = new Vector<String>();

        for (i = 0; i < mAllowedAlgs.length; i++) {
            for (j = 0; j < allowed.length; j++) {
                if (mAllowedAlgs[i].equals(allowed[j])) {
                    goodAlgs.addElement(mAllowedAlgs[i]);
                    break;
                }
            }
            // if algorithm is not allowed, log a warning
            if (j == allowed.length) {
                EPolicyException e = new EPolicyException(CMS.getUserMessage(reason, NAME, mAllowedAlgs[i]));

                if (isError) {
                    log(ILogger.LL_FAILURE, e.toString());
                    throw new EPolicyException(CMS.getUserMessage(reason,
                                NAME, mAllowedAlgs[i]));
                } else {
                    log(ILogger.LL_WARN, e.toString());
                }
            }
        }

        // convert back into an array
        goodSize = goodAlgs.size();
        if (mAllowedAlgs.length != goodSize) {
            mAllowedAlgs = new String[goodSize];
            for (i = 0; i < goodSize; i++) {
                mAllowedAlgs[i] = goodAlgs.elementAt(i);
            }
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
        int i, j;

        PolicyResult result = PolicyResult.ACCEPTED;

        try {

            // Get the certificate info from the request
            //X509CertInfo certInfo[] = (X509CertInfo[])
            //    req.get(IRequest.CERT_INFO);
            X509CertInfo certInfo[] = req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

            // We need to have a certificate info set
            if (certInfo == null) {
                setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO",
                        getInstanceName()), "");
                return PolicyResult.REJECTED;
            }

            // Else check if the key algorithm is supported.
            for (i = 0; i < certInfo.length; i++) {
                // make sure our list of allowed algorithms makes
                // sense for our key. Do this each time.
                if (!winnowedByKey) {
                    winnowByKey();
                }

                CertificateAlgorithmId certAlgId = (CertificateAlgorithmId)
                        certInfo[i].get(X509CertInfo.ALGORITHM_ID);

                AlgorithmId algId = (AlgorithmId)
                        certAlgId.get(CertificateAlgorithmId.ALGORITHM);
                String alg = algId.getName();

                // test against the list of allowed algorithms
                for (j = 0; j < mAllowedAlgs.length; j++) {
                    if (mAllowedAlgs[j].equals(alg)) {
                        break;
                    }
                }
                if (j == mAllowedAlgs.length) {
                    // if the algor doesn't match the CA's key replace
                    // it with one that does.
                    if (mAllowedAlgs[0].equals("SHA1withDSA") ||
                            alg.equals("SHA1withDSA")) {
                        certInfo[i].set(X509CertInfo.ALGORITHM_ID,
                                new CertificateAlgorithmId(
                                        AlgorithmId.get(mAllowedAlgs[0])));
                        return PolicyResult.ACCEPTED;
                    }

                    // didn't find a match, alg not allowed
                    setError(req, CMS.getUserMessage("CMS_POLICY_SIGNING_ALG_VIOLATION",
                            getInstanceName(), alg), "");
                    result = PolicyResult.REJECTED;
                }
            }
        } catch (Exception e) {
            // e.printStackTrace();
            String params[] = { getInstanceName(), e.toString() };

            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR",
                    params), "");
            result = PolicyResult.REJECTED;
        }
        return result;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        Vector<String> confParams = new Vector<String>();
        StringBuffer sb = new StringBuffer();

        for (int i = 0; i < mConfigAlgs.length; i++) {
            sb.append(mConfigAlgs[i]);
            sb.append(",");
        }
        if (sb.length() > 0)
            sb.setLength(sb.length() - 1);
        confParams.addElement(PROP_ALGORITHMS + "=" + sb.toString());
        return confParams;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        StringBuffer sb = new StringBuffer();
        sb.append(PROP_ALGORITHMS);
        sb.append("=");
        boolean first = true;

        defConfParams.removeAllElements();

        for (int i = 0; i < mDefaultAllowedAlgs.length; i++) {
            if (first == true) {
                sb.append(mDefaultAllowedAlgs[i]);
                first = false;
            } else {
                sb.append(",");
                sb.append(mDefaultAllowedAlgs[i]);
            }
        }
        defConfParams.addElement(sb.toString());

        return defConfParams;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        if (!winnowedByKey) {
            try {
                winnowByKey();
            } catch (Exception e) {
            }
        }

        String[] params = null;

        String[] params_BOTH = {
                PROP_ALGORITHMS
                        + ";"
                        + "choice(MD2withRSA\\,MD5withRSA\\,SHA1withRSA\\,SHA256withRSA\\,SHA512withRSA\\,SHA1withDSA,"
                        +
                        "MD2withRSA\\,MD5withRSA\\,SHA1withRSA\\,SHA1withDSA," +
                        "MD2withRSA\\,MD5withRSA\\,SHA1withRSA," +
                        "MD2withRSA\\,SHA1withRSA\\,SHA1withDSA," +
                        "MD5withRSA\\,SHA1withRSA\\,SHA1withDSA," +
                        "MD2withRSA\\,MD5withRSA\\,SHA1withDSA," +
                        "MD2withRSA\\,MD5withRSA," +
                        "MD2withRSA\\,SHA1withRSA," +
                        "MD2withRSA\\,SHA1withDSA," +
                        "MD5withRSA\\,SHA1withRSA," +
                        "MD5withRSA\\,SHA1withDSA," +
                        "SHA1withRSA\\,SHA1withDSA," +
                        "MD2withRSA," +
                        "MD5withRSA," +
                        "SHA1withRSA," +
                        "SHA1withDSA);List of algorithms to restrict the requested signing algorithm " +
                        "to be one of the algorithms supported by Certificate System",
                IExtendedPluginInfo.HELP_TOKEN + ";configuration-policyrules-signingalgconstraints",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Restricts the requested signing algorithm to be one of" +
                        " the algorithms supported by Certificate System"
        };

        String[] params_RSA = {
                PROP_ALGORITHMS + ";" + "choice(MD2withRSA\\,MD5withRSA\\,SHA1withRSA," +
                        "MD2withRSA\\,MD5withRSA," +
                        "MD2withRSA\\,SHA1withRSA," +
                        "MD5withRSA\\,SHA1withRSA," +
                        "MD2withRSA," +
                        "MD5withRSA," +
                        "SHA1withRSA);Restrict the requested signing algorithm to be " +
                        "one of the algorithms supported by Certificate System",
                IExtendedPluginInfo.HELP_TOKEN + ";configuration-policyrules-signingalgconstraints",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Restricts the requested signing algorithm to be one of" +
                        " the algorithms supported by Certificate System"
        };

        String[] params_DSA = {
                PROP_ALGORITHMS + ";" + "choice(SHA1withDSA);Restrict the requested signing " +
                        "algorithm to be one of the algorithms supported by Certificate " +
                        "System",
                IExtendedPluginInfo.HELP_TOKEN + ";configuration-policyrules-signingalgconstraints",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Restricts the requested signing algorithm to be one of" +
                        " the algorithms supported by Certificate System"
        };

        switch (mDefaultAllowedAlgs.length) {
        case 1:
            params = params_DSA;
            break;

        case 3:
            params = params_RSA;
            break;

        case 4:
        default:
            params = params_BOTH;
            break;

        }

        return params;
    }

}
