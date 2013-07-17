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
package com.netscape.cms.servlet.cert;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.provider.RSAPublicKey;
import netscape.security.x509.CRLExtensions;
import netscape.security.x509.CRLReasonExtension;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.Extension;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509Key;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.dbs.certdb.IRevocationInfo;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * Search for certificates matching complex query filter
 *
 * @version $Revision$, $Date$
 */
public class SrchCerts extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -5876805830088921643L;
    private final static String TPL_FILE = "srchCert.template";
    private final static String PROP_MAX_SEARCH_RETURNS = "maxSearchReturns";

    private final static String CURRENT_TIME = "currentTime";
    private final static int MAX_RESULTS = 1000;

    private ICertificateRepository mCertDB = null;
    private X500Name mAuthName = null;
    private String mFormPath = null;
    private int mMaxReturns = MAX_RESULTS;
    private int mTimeLimits = 30; /* in seconds */
    private boolean mUseClientFilter = false;

    /**
     * Constructs query key servlet.
     */
    public SrchCerts() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses srchCert.template
     * to render the response
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override success to render own template.
        mTemplates.remove(ICMSRequest.SUCCESS);

        if (mAuthority instanceof ISubsystem) {
            ISubsystem sub = mAuthority;
            IConfigStore authConfig = sub.getConfigStore();

            if (authConfig != null) {
                try {
                    mMaxReturns = authConfig.getInteger(PROP_MAX_SEARCH_RETURNS, MAX_RESULTS);
                } catch (EBaseException e) {
                    // do nothing
                }
            }
        }
        if (mAuthority instanceof ICertificateAuthority) {
            ICertificateAuthority ca = (ICertificateAuthority) mAuthority;

            mCertDB = ca.getCertificateRepository();
            mAuthName = ca.getX500Name();
        }

        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;

        /* Server-Side time limit */
        try {
            int maxResults = Integer.parseInt(sc.getInitParameter("maxResults"));
            if (maxResults < mMaxReturns)
                mMaxReturns = maxResults;
        } catch (Exception e) {
            /* do nothing, just use the default if integer parsing failed */
        }
        try {
            mTimeLimits = Integer.parseInt(sc.getInitParameter("timeLimits"));
        } catch (Exception e) {
            /* do nothing, just use the default if integer parsing failed */
        }

        /* useClientFilter should be off by default. We keep
           this parameter around so that we do not break
           the client applications that submits raw LDAP
           filter into this servlet.  */
        if (sc.getInitParameter("useClientFilter") != null &&
                sc.getInitParameter("useClientFilter").equalsIgnoreCase("true")) {
            mUseClientFilter = true;
        }
    }

    private boolean isOn(HttpServletRequest req, String name) {
        String inUse = req.getParameter(name);
        if (inUse == null) {
            return false;
        }
        if (inUse.equals("on")) {
            return true;
        }
        return false;
    }

    private boolean isOff(HttpServletRequest req, String name) {
        String inUse = req.getParameter(name);
        if (inUse == null) {
            return false;
        }
        if (inUse.equals("off")) {
            return true;
        }
        return false;
    }

    private void buildCertStatusFilter(HttpServletRequest req, StringBuffer filter) {
        if (!isOn(req, "statusInUse")) {
            return;
        }
        String status = req.getParameter("status");
        filter.append("(certStatus=");
        filter.append(status);
        filter.append(")");
    }

    private void buildProfileFilter(HttpServletRequest req, StringBuffer filter) {
        if (!isOn(req, "profileInUse")) {
            return;
        }
        String profile = req.getParameter("profile");
        filter.append("(certMetaInfo=profileId:");
        filter.append(profile);
        filter.append(")");
    }

    private void buildBasicConstraintsFilter(HttpServletRequest req, StringBuffer filter) {
        if (!isOn(req, "basicConstraintsInUse")) {
            return;
        }
        filter.append("(x509cert.BasicConstraints.isCA=on)");
    }

    private void buildSerialNumberRangeFilter(HttpServletRequest req, StringBuffer filter) {
        if (!isOn(req, "serialNumberRangeInUse")) {
            return;
        }
        boolean changed = false;
        String serialFrom = req.getParameter("serialFrom");
        if (serialFrom != null && !serialFrom.equals("")) {
            filter.append("(certRecordId>=" + serialFrom + ")");
            changed = true;
        }
        String serialTo = req.getParameter("serialTo");
        if (serialTo != null && !serialTo.equals("")) {
            filter.append("(certRecordId<=" + serialTo + ")");
            changed = true;
        }
        if (!changed) {
            filter.append("(certRecordId=*)");
        }
    }

    private void buildAVAFilter(HttpServletRequest req, String paramName,
                                 String avaName, StringBuffer lf, String match) {
        String val = req.getParameter(paramName);
        if (val != null && !val.equals("")) {
            if (match != null && match.equals("exact")) {
                lf.append("(|");
                lf.append("(x509cert.subject=*");
                lf.append(avaName);
                lf.append("=");
                lf.append(LDAPUtil.escapeFilter(LDAPUtil.escapeRDNValue(val)));
                lf.append(",*)");
                lf.append("(x509cert.subject=*");
                lf.append(avaName);
                lf.append("=");
                lf.append(LDAPUtil.escapeFilter(LDAPUtil.escapeRDNValue(val)));
                lf.append(")");
                lf.append(")");
            } else {
                lf.append("(x509cert.subject=*");
                lf.append(avaName);
                lf.append("=");
                lf.append("*");
                lf.append(LDAPUtil.escapeFilter(LDAPUtil.escapeRDNValue(val)));
                lf.append("*)");
            }
        }
    }

    private void buildSubjectFilter(HttpServletRequest req, StringBuffer filter) {
        if (!isOn(req, "subjectInUse")) {
            return;
        }
        StringBuffer lf = new StringBuffer();
        String match = req.getParameter("match");

        buildAVAFilter(req, "eMail", "E", lf, match);
        buildAVAFilter(req, "commonName", "CN", lf, match);
        buildAVAFilter(req, "userID", "UID", lf, match);
        buildAVAFilter(req, "orgUnit", "OU", lf, match);
        buildAVAFilter(req, "org", "O", lf, match);
        buildAVAFilter(req, "locality", "L", lf, match);
        buildAVAFilter(req, "state", "ST", lf, match);
        buildAVAFilter(req, "country", "C", lf, match);

        if (lf.length() == 0) {
            filter.append("(x509cert.subject=*)");
            return;
        }
        if (match.equals("exact")) {
            filter.append("(&");
            filter.append(lf);
            filter.append(")");
        } else {
            filter.append("(|");
            filter.append(lf);
            filter.append(")");
        }
    }

    private void buildRevokedByFilter(HttpServletRequest req,
                                      StringBuffer filter) {
        if (!isOn(req, "revokedByInUse")) {
            return;
        }
        String revokedBy = req.getParameter("revokedBy");
        if (revokedBy == null || revokedBy.equals("")) {
            filter.append("(certRevokedBy=*)");
        } else {
            filter.append("(certRevokedBy=");
            filter.append(revokedBy);
            filter.append(")");
        }
    }

    private void buildDateFilter(HttpServletRequest req, String prefix,
                                   String outStr, long adjustment,
                                   StringBuffer filter) {
        long epoch = 0;
        try {
            epoch = Long.parseLong(req.getParameter(prefix));
        } catch (NumberFormatException e) {
            // exception safely ignored
        }
        Calendar from = Calendar.getInstance();
        from.setTimeInMillis(epoch);
        CMS.debug("buildDateFilter epoch=" + req.getParameter(prefix));
        CMS.debug("buildDateFilter from=" + from);
        filter.append("(");
        filter.append(outStr);
        filter.append(Long.toString(from.getTimeInMillis() + adjustment));
        filter.append(")");
    }

    private void buildRevokedOnFilter(HttpServletRequest req,
                                      StringBuffer filter) {
        if (!isOn(req, "revokedOnInUse")) {
            return;
        }
        buildDateFilter(req, "revokedOnFrom", "certRevokedOn>=", 0, filter);
        buildDateFilter(req, "revokedOnTo", "certRevokedOn<=", 86399999,
                        filter);
    }

    private void buildRevocationReasonFilter(HttpServletRequest req,
                                             StringBuffer filter) {
        if (!isOn(req, "revocationReasonInUse")) {
            return;
        }
        String reasons = req.getParameter("revocationReason");
        if (reasons == null) {
            return;
        }
        String queryCertFilter = null;
        StringTokenizer st = new StringTokenizer(reasons, ",");
        if (st.hasMoreTokens()) {
            filter.append("(|");
            while (st.hasMoreTokens()) {
                String token = st.nextToken();
                if (queryCertFilter == null) {
                    queryCertFilter = "";
                }
                filter.append("(x509cert.certRevoInfo=");
                filter.append(token);
                filter.append(")");
            }
            filter.append(")");
        }
    }

    private void buildIssuedByFilter(HttpServletRequest req,
                                      StringBuffer filter) {
        if (!isOn(req, "issuedByInUse")) {
            return;
        }
        String issuedBy = req.getParameter("issuedBy");
        if (issuedBy == null || issuedBy.equals("")) {
            filter.append("(certIssuedBy=*)");
        } else {
            filter.append("(certIssuedBy=");
            filter.append(issuedBy);
            filter.append(")");
        }
    }

    private void buildIssuedOnFilter(HttpServletRequest req,
                                      StringBuffer filter) {
        if (!isOn(req, "issuedOnInUse")) {
            return;
        }
        buildDateFilter(req, "issuedOnFrom", "certCreateTime>=", 0, filter);
        buildDateFilter(req, "issuedOnTo", "certCreateTime<=", 86399999,
                        filter);
    }

    private void buildValidNotBeforeFilter(HttpServletRequest req,
                                      StringBuffer filter) {
        if (!isOn(req, "validNotBeforeInUse")) {
            return;
        }
        buildDateFilter(req, "validNotBeforeFrom", "x509cert.notBefore>=",
                        0, filter);
        buildDateFilter(req, "validNotBeforeTo", "x509cert.notBefore<=",
                        86399999, filter);
    }

    private void buildValidNotAfterFilter(HttpServletRequest req,
                                      StringBuffer filter) {
        if (!isOn(req, "validNotAfterInUse")) {
            return;
        }
        buildDateFilter(req, "validNotAfterFrom", "x509cert.notAfter>=",
                        0, filter);
        buildDateFilter(req, "validNotAfterTo", "x509cert.notAfter<=",
                        86399999, filter);
    }

    private void buildValidityLengthFilter(HttpServletRequest req,
                                      StringBuffer filter) {
        if (!isOn(req, "validityLengthInUse")) {
            return;
        }
        String op = req.getParameter("validityOp");
        long count = 0;
        try {
            count = Long.parseLong(req.getParameter("count"));
        } catch (NumberFormatException e) {
            // safely ignore
        }
        long unit = 0;
        try {
            unit = Long.parseLong(req.getParameter("unit"));
        } catch (NumberFormatException e) {
            // safely ignore
        }
        filter.append("(");
        filter.append("x509cert.duration");
        filter.append(op);
        filter.append(count * unit);
        filter.append(")");
    }

    private void buildCertTypeFilter(HttpServletRequest req,
                                      StringBuffer filter) {
        if (!isOn(req, "certTypeInUse")) {
            return;
        }
        if (isOn(req, "SSLClient")) {
            filter.append("(x509cert.nsExtension.SSLClient=on)");
        } else if (isOff(req, "SSLClient")) {
            filter.append("(x509cert.nsExtension.SSLClient=off)");
        }
        if (isOn(req, "SSLServer")) {
            filter.append("(x509cert.nsExtension.SSLServer=on)");
        } else if (isOff(req, "SSLServer")) {
            filter.append("(x509cert.nsExtension.SSLServer=off)");
        }
        if (isOn(req, "SecureEmail")) {
            filter.append("(x509cert.nsExtension.SecureEmail=on)");
        } else if (isOff(req, "SecureEmail")) {
            filter.append("(x509cert.nsExtension.SecureEmail=off)");
        }
        if (isOn(req, "SubordinateSSLCA")) {
            filter.append("(x509cert.nsExtension.SubordinateSSLCA=on)");
        } else if (isOff(req, "SubordinateSSLCA")) {
            filter.append("(x509cert.nsExtension.SubordinateSSLCA=off)");
        }
        if (isOn(req, "SubordinateEmailCA")) {
            filter.append("(x509cert.nsExtension.SubordinateEmailCA=on)");
        } else if (isOff(req, "SubordinateEmailCA")) {
            filter.append("(x509cert.nsExtension.SubordinateEmailCA=off)");
        }
    }

    public String buildFilter(HttpServletRequest req) {
        String queryCertFilter = req.getParameter("queryCertFilter");

        StringBuffer filter = new StringBuffer();
        buildSerialNumberRangeFilter(req, filter);
        buildSubjectFilter(req, filter);
        buildRevokedByFilter(req, filter);
        buildRevokedOnFilter(req, filter);
        buildRevocationReasonFilter(req, filter);
        buildIssuedByFilter(req, filter);
        buildIssuedOnFilter(req, filter);
        buildValidNotBeforeFilter(req, filter);
        buildValidNotAfterFilter(req, filter);
        buildValidityLengthFilter(req, filter);
        buildCertTypeFilter(req, filter);
        buildCertStatusFilter(req, filter);
        buildProfileFilter(req, filter);
        buildBasicConstraintsFilter(req, filter);

        if (mUseClientFilter) {
            CMS.debug("useClientFilter=true");
        } else {
            CMS.debug("useClientFilter=false");
            CMS.debug("client queryCertFilter = " + queryCertFilter);
            queryCertFilter = "(&" + filter.toString() + ")";
        }
        CMS.debug("queryCertFilter = " + queryCertFilter);
        return queryCertFilter;
    }

    /**
     * Serves HTTP request. This format of this request is as follows:
     * queryCert?
     * [maxCount=<number>]
     * [queryFilter=<filter>]
     * [revokeAll=<filter>]
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "list");
        } catch (EAuthzAccessDenied e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        }

        if (authzToken == null) {
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        String revokeAll = null;
        EBaseException error = null;
        int maxResults = -1;
        int timeLimit = -1;

        IArgBlock header = CMS.createArgBlock();
        IArgBlock ctx = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        try {
            revokeAll = req.getParameter("revokeAll");

            String maxResultsStr = req.getParameter("maxResults");

            if (maxResultsStr != null && maxResultsStr.length() > 0)
                maxResults = Integer.parseInt(maxResultsStr);
            String timeLimitStr = req.getParameter("timeLimit");

            if (timeLimitStr != null && timeLimitStr.length() > 0)
                timeLimit = Integer.parseInt(timeLimitStr);

            String queryCertFilter = buildFilter(req);
            process(argSet, header, queryCertFilter,
                    revokeAll, maxResults, timeLimit, req, resp, locale[0]);
        } catch (NumberFormatException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_INVALID_NUMBER_FORMAT"));
            error = new EBaseException(CMS.getUserMessage(getLocale(req), "CMS_BASE_INVALID_NUMBER_FORMAT"));
        } catch (EBaseException e) {
            error = e;
        }

        try {
            ServletOutputStream out = resp.getOutputStream();

            if (error == null) {
                String xmlOutput = req.getParameter("xml");
                if (xmlOutput != null && xmlOutput.equals("true")) {
                    outputXML(resp, argSet);
                } else {
                    cmsReq.setStatus(ICMSRequest.SUCCESS);
                    resp.setContentType("text/html");
                    form.renderOutput(out, argSet);
                }
            } else {
                cmsReq.setStatus(ICMSRequest.ERROR);
                cmsReq.setError(error);
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
    }

    /**
     * Process the key search.
     */
    private void process(CMSTemplateParams argSet, IArgBlock header,
            String filter, String revokeAll,
            int maxResults, int timeLimit,
            HttpServletRequest req, HttpServletResponse resp,
            Locale locale)
            throws EBaseException {
        try {
            long startTime = CMS.getCurrentDate().getTime();

            if (filter.indexOf(CURRENT_TIME, 0) > -1) {
                filter = insertCurrentTime(filter);
            }

            // xxx the filter includes serial number range???
            if (maxResults == -1 || maxResults > mMaxReturns) {
                CMS.debug("Resetting maximum of returned results from " + maxResults + " to " + mMaxReturns);
                maxResults = mMaxReturns;
            }
            if (timeLimit == -1 || timeLimit > mTimeLimits) {
                CMS.debug("Resetting timelimit from " + timeLimit + " to " + mTimeLimits);
                timeLimit = mTimeLimits;
            }
            CMS.debug("Start searching ... "
                    + "filter=" + filter + " maxreturns=" + maxResults + " timelimit=" + timeLimit);
            Enumeration<ICertRecord> e = mCertDB.searchCertificates(filter, maxResults, timeLimit);

            int count = 0;

            while (e != null && e.hasMoreElements()) {
                ICertRecord rec = e.nextElement();

                if (rec != null) {
                    count++;
                    IArgBlock rarg = CMS.createArgBlock();

                    fillRecordIntoArg(rec, rarg);
                    argSet.addRepeatRecord(rarg);
                }
            }

            long endTime = CMS.getCurrentDate().getTime();

            header.addStringValue("op", req.getParameter("op"));
            if (mAuthName != null)
                header.addStringValue("issuerName", mAuthName.toString());
            header.addStringValue("time", Long.toString(endTime - startTime));
            header.addStringValue("serviceURL", req.getRequestURI());
            header.addStringValue("queryFilter", filter);
            if (revokeAll != null)
                header.addStringValue("revokeAll", revokeAll);
            header.addIntegerValue("totalRecordCount", count);
            header.addIntegerValue("maxSize", maxResults);
        } catch (EBaseException e) {
            CMS.getLogMessage("CMSGW_ERROR_LISTCERTS", e.toString());
            throw e;
        }
        return;
    }

    private String insertCurrentTime(String filter) {
        Date now = null;
        StringBuffer newFilter = new StringBuffer();
        int k = 0;
        int i = filter.indexOf(CURRENT_TIME, k);

        while (i > -1) {
            if (now == null)
                now = new Date();
            newFilter.append(filter.substring(k, i));
            newFilter.append(now.getTime());
            k = i + CURRENT_TIME.length();
            i = filter.indexOf(CURRENT_TIME, k);
        }
        if (k > 0) {
            newFilter.append(filter.substring(k, filter.length()));
        }
        return newFilter.toString();
    }

    /**
     * Fills cert record into argument block.
     */
    private void fillRecordIntoArg(ICertRecord rec, IArgBlock rarg)
            throws EBaseException {

        X509CertImpl xcert = rec.getCertificate();

        if (xcert != null) {
            fillX509RecordIntoArg(rec, rarg);
        }
    }

    private void fillX509RecordIntoArg(ICertRecord rec, IArgBlock rarg)
            throws EBaseException {

        X509CertImpl cert = rec.getCertificate();

        rarg.addIntegerValue("version", cert.getVersion());
        rarg.addStringValue("serialNumber", cert.getSerialNumber().toString(16));
        rarg.addStringValue("serialNumberDecimal", cert.getSerialNumber().toString());

        String subject = cert.getSubjectDN().toString();

        if (subject.equals("")) {
            rarg.addStringValue("subject", " ");
        } else {
            rarg.addStringValue("subject", subject);

        }

        rarg.addStringValue("type", "X.509");

        try {
            PublicKey pKey = cert.getPublicKey();
            X509Key key = null;

            if (pKey instanceof CertificateX509Key) {
                CertificateX509Key certKey = (CertificateX509Key) pKey;

                key = (X509Key) certKey.get(CertificateX509Key.KEY);
            }
            if (pKey instanceof X509Key) {
                key = (X509Key) pKey;
            }
            rarg.addStringValue("subjectPublicKeyAlgorithm", key.getAlgorithmId().getOID().toString());
            if (key.getAlgorithmId().toString().equalsIgnoreCase("RSA")) {
                RSAPublicKey rsaKey = new RSAPublicKey(key.getEncoded());

                rarg.addIntegerValue("subjectPublicKeyLength", rsaKey.getKeySize());
            }
        } catch (Exception e) {
            rarg.addStringValue("subjectPublicKeyAlgorithm", null);
            rarg.addIntegerValue("subjectPublicKeyLength", 0);
        }

        rarg.addLongValue("validNotBefore", cert.getNotBefore().getTime() / 1000);
        rarg.addLongValue("validNotAfter", cert.getNotAfter().getTime() / 1000);
        rarg.addStringValue("signatureAlgorithm", cert.getSigAlgOID());
        String issuedBy = rec.getIssuedBy();

        if (issuedBy == null)
            issuedBy = "";
        rarg.addStringValue("issuedBy", issuedBy); // cert.getIssuerDN().toString()
        rarg.addLongValue("issuedOn", rec.getCreateTime().getTime() / 1000);

        rarg.addStringValue("revokedBy",
                ((rec.getRevokedBy() == null) ? "" : rec.getRevokedBy()));
        if (rec.getRevokedOn() == null) {
            rarg.addStringValue("revokedOn", null);
        } else {
            rarg.addLongValue("revokedOn", rec.getRevokedOn().getTime() / 1000);

            IRevocationInfo revocationInfo = rec.getRevocationInfo();

            if (revocationInfo != null) {
                CRLExtensions crlExts = revocationInfo.getCRLEntryExtensions();

                if (crlExts != null) {
                    Enumeration<Extension> enum1 = crlExts.getElements();
                    int reason = 0;

                    while (enum1.hasMoreElements()) {
                        Extension ext = enum1.nextElement();

                        if (ext instanceof CRLReasonExtension) {
                            reason = ((CRLReasonExtension) ext).getReason().toInt();
                            break;
                        }
                    }
                    rarg.addIntegerValue("revocationReason", reason);
                }
            }
        }
    }
}
