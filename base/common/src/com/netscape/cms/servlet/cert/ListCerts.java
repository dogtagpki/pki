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
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

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

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertRecordList;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.dbs.certdb.IRevocationInfo;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Retrieve a paged list of certs matching the specified query
 *
 * @version $Revision$, $Date$
 */
public class ListCerts extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -3568155814023099576L;
    private final static String TPL_FILE = "queryCert.template";
    private final static BigInteger MINUS_ONE = new BigInteger("-1");

    private final static String USE_CLIENT_FILTER = "useClientFilter";
    private final static String ALLOWED_CLIENT_FILTERS = "allowedClientFilters";

    private ICertificateRepository mCertDB = null;
    private X500Name mAuthName = null;
    private String mFormPath = null;
    private boolean mReverse = false;
    private boolean mHardJumpTo = false; //jump to the end
    private String mDirection = null;
    private boolean mUseClientFilter = false;
    private Vector<String> mAllowedClientFilters = new Vector<String>();
    private int mMaxReturns = 2000;

    /**
     * Constructs query key servlet.
     */
    public ListCerts() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "queryCert.template" to render the response
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override success to render own template.
        mTemplates.remove(ICMSRequest.SUCCESS);

        if (mAuthority instanceof ICertificateAuthority) {
            ICertificateAuthority ca = (ICertificateAuthority) mAuthority;

            mCertDB = ca.getCertificateRepository();
            mAuthName = ca.getX500Name();
        }

        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;

        try {
            mMaxReturns = Integer.parseInt(sc.getInitParameter("maxResults"));
        } catch (Exception e) {
            /* do nothing, just use the default if integer parsing failed */
        }

        /* useClientFilter should be off by default. We keep
           this parameter around so that we do not break
           the client applications that submits raw LDAP
           filter into this servlet.  */
        if (sc.getInitParameter(USE_CLIENT_FILTER) != null &&
                sc.getInitParameter(USE_CLIENT_FILTER).equalsIgnoreCase("true")) {
            mUseClientFilter = true;
        }
        if (sc.getInitParameter(ALLOWED_CLIENT_FILTERS) == null
                || sc.getInitParameter(ALLOWED_CLIENT_FILTERS).equals("")) {
            mAllowedClientFilters.addElement("(certStatus=*)");
            mAllowedClientFilters.addElement("(certStatus=VALID)");
            mAllowedClientFilters.addElement("(|(certStatus=VALID)(certStatus=INVALID)(certStatus=EXPIRED))");
            mAllowedClientFilters.addElement("(|(certStatus=VALID)(certStatus=REVOKED))");
        } else {
            StringTokenizer st = new StringTokenizer(sc.getInitParameter(ALLOWED_CLIENT_FILTERS), ",");
            while (st.hasMoreTokens()) {
                mAllowedClientFilters.addElement(st.nextToken());
            }
        }
    }

    public String buildFilter(HttpServletRequest req) {
        String queryCertFilter = req.getParameter("queryCertFilter");

        com.netscape.certsrv.apps.CMS.debug("client queryCertFilter=" + queryCertFilter);

        if (mUseClientFilter) {
            com.netscape.certsrv.apps.CMS.debug("useClientFilter=true");
            Enumeration<String> filters = mAllowedClientFilters.elements();
            // check to see if the filter is allowed
            while (filters.hasMoreElements()) {
                String filter = filters.nextElement();
                com.netscape.certsrv.apps.CMS.debug("Comparing filter="
                        + filter + " queryCertFilter=" + queryCertFilter);
                if (filter.equals(queryCertFilter)) {
                    return queryCertFilter;
                }
            }
            com.netscape.certsrv.apps.CMS.debug("Requested filter '"
                    + queryCertFilter + "' is not allowed. Please check the " + ALLOWED_CLIENT_FILTERS + "parameter");
            return null;
        } else {
            com.netscape.certsrv.apps.CMS.debug("useClientFilter=false");
        }

        boolean skipRevoked = false;
        boolean skipNonValid = false;
        if (req.getParameter("skipRevoked") != null &&
                req.getParameter("skipRevoked").equals("on")) {
            skipRevoked = true;
        }
        if (req.getParameter("skipNonValid") != null &&
                req.getParameter("skipNonValid").equals("on")) {
            skipNonValid = true;
        }

        if (!skipRevoked && !skipNonValid) {
            queryCertFilter = "(certStatus=*)";
        } else if (skipRevoked && skipNonValid) {
            queryCertFilter = "(certStatus=VALID)";
        } else if (skipRevoked) {
            queryCertFilter = "(|(certStatus=VALID)(certStatus=INVALID)(certStatus=EXPIRED))";
        } else if (skipNonValid) {
            queryCertFilter = "(|(certStatus=VALID)(certStatus=REVOKED))";
        }
        return queryCertFilter;
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param maxCount Number of certificates to show
     * <li>http.param queryFilter and ldap style filter specifying the certificates to show
     * <li>http.param querySentinelDown the serial number of the first certificate to show (default decimal, or hex if
     * prefixed with 0x) when paging down
     * <li>http.param querySentinelUp the serial number of the first certificate to show (default decimal, or hex if
     * prefixed with 0x) when paging up
     * <li>http.param direction "up", "down", "begin", or "end"
     * </ul>
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "list");
        } catch (Exception e) {
        }

        if (authzToken == null) {
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        String revokeAll = null;
        EBaseException error = null;

        int maxCount = -1;
        BigInteger sentinel = new BigInteger("0");

        IArgBlock header = com.netscape.certsrv.apps.CMS.createArgBlock();
        IArgBlock ctx = com.netscape.certsrv.apps.CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    com.netscape.certsrv.apps.CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()));
            throw new ECMSGWException(
                    com.netscape.certsrv.apps.CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        mHardJumpTo = false;
        try {

            if (req.getParameter("direction") != null) {
                mDirection = req.getParameter("direction").trim();
                mReverse = mDirection.equals("up");
                if (mReverse)
                    com.netscape.certsrv.apps.CMS.debug("reverse is true");
                else
                    com.netscape.certsrv.apps.CMS.debug("reverse is false");

            }

            if (req.getParameter("maxCount") != null) {
                maxCount = Integer.parseInt(req.getParameter("maxCount"));
            }
            if (maxCount == -1 || maxCount > mMaxReturns) {
                com.netscape.certsrv.apps.CMS.debug("Resetting page size from " + maxCount + " to " + mMaxReturns);
                maxCount = mMaxReturns;
            }

            String sentinelStr = "";
            if (mReverse) {
                sentinelStr = req.getParameter("querySentinelUp");
            } else if (mDirection.equals("end")) {
                // this servlet will figure out the end
                sentinelStr = "0";
                mReverse = true;
                mHardJumpTo = true;
            } else if (mDirection.equals("down")) {
                sentinelStr = req.getParameter("querySentinelDown");
            } else
                sentinelStr = "0";
            //begin and non-specified have sentinel default "0"

            if (sentinelStr != null) {
                if (sentinelStr.trim().startsWith("0x")) {
                    sentinel = new BigInteger(sentinelStr.trim().substring(2), 16);
                } else {
                    sentinel = new BigInteger(sentinelStr, 10);
                }
            }

            revokeAll = req.getParameter("revokeAll");

            if (mAuthority instanceof ICertificateAuthority) {
                X509CertImpl caCert = ((ICertificateAuthority) mAuthority).getSigningUnit().getCertImpl();

                //if (isCertFromCA(caCert))
                header.addStringValue("caSerialNumber",
                        caCert.getSerialNumber().toString(16));
            }

            // constructs the ldap filter on the server side
            String queryCertFilter = buildFilter(req);

            if (queryCertFilter == null) {
                cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
                return;
            }

            com.netscape.certsrv.apps.CMS.debug("queryCertFilter=" + queryCertFilter);

            int totalRecordCount = -1;

            try {
                totalRecordCount = Integer.parseInt(req.getParameter("totalRecordCount"));
            } catch (Exception e) {
            }
            processCertFilter(argSet, header, maxCount,
                    sentinel,
                    totalRecordCount,
                    req.getParameter("serialTo"),
                    queryCertFilter,
                    req, resp, revokeAll, locale[0]);
        } catch (NumberFormatException e) {
            log(ILogger.LL_FAILURE, com.netscape.certsrv.apps.CMS.getLogMessage("BASE_INVALID_NUMBER_FORMAT"));

            error =
                    new EBaseException(com.netscape.certsrv.apps.CMS.getUserMessage(getLocale(req),
                            "CMS_BASE_INVALID_NUMBER_FORMAT"));
        } catch (EBaseException e) {
            error = e;
        }

        ctx.addIntegerValue("maxCount", maxCount);

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
                    com.netscape.certsrv.apps.CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    com.netscape.certsrv.apps.CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
    }

    private void processCertFilter(CMSTemplateParams argSet,
            IArgBlock header,
            int maxCount,
            BigInteger sentinel,
            int totalRecordCount,
            String serialTo,
            String filter,
            HttpServletRequest req,
            HttpServletResponse resp,
            String revokeAll,
            Locale locale
            ) throws EBaseException {
        BigInteger serialToVal = MINUS_ONE;

        try {
            if (serialTo != null) {
                serialTo = serialTo.trim();
                if (serialTo.startsWith("0x")) {
                    serialToVal = new BigInteger
                            (serialTo.substring(2), 16);
                    serialTo = serialToVal.toString();
                } else {
                    serialToVal = new BigInteger(serialTo);
                }
            }
        } catch (Exception e) {
        }

        String jumpTo = sentinel.toString();
        int pSize = 0;
        if (mReverse) {
            if (!mHardJumpTo) //reverse gets one more
                pSize = -1 * maxCount - 1;
            else
                pSize = -1 * maxCount;
        } else
            pSize = maxCount;

        ICertRecordList list = mCertDB.findCertRecordsInList(
                filter, (String[]) null, jumpTo, mHardJumpTo, "serialno",
                pSize);
        // retrive maxCount + 1 entries

        Enumeration<ICertRecord> e = list.getCertRecords(0, maxCount);

        ICertRecordList tolist = null;
        int toCurIndex = 0;

        if (!serialToVal.equals(MINUS_ONE)) {
            // if user specify a range, we need to
            // calculate the totalRecordCount
            tolist = mCertDB.findCertRecordsInList(
                        filter,
                        (String[]) null, serialTo,
                        "serialno", maxCount);
            Enumeration<ICertRecord> en = tolist.getCertRecords(0, 0);

            if (en == null || (!en.hasMoreElements())) {
                toCurIndex = list.getSize() - 1;
            } else {
                toCurIndex = tolist.getCurrentIndex();
                ICertRecord rx = en.nextElement();
                BigInteger curToSerial = rx.getSerialNumber();

                if (curToSerial.compareTo(serialToVal) == -1) {
                    toCurIndex = list.getSize() - 1;
                } else {
                    if (!rx.getSerialNumber().toString().equals(serialTo.trim())) {
                        toCurIndex = toCurIndex - 1;
                    }
                }
            }
        }

        int curIndex = list.getCurrentIndex();

        int count = 0;
        BigInteger firstSerial = new BigInteger("0");
        BigInteger curSerial = new BigInteger("0");
        ICertRecord[] recs = new ICertRecord[maxCount];
        int rcount = 0;

        if (e != null) {
            /* in reverse (page up), because the sentinel is the one after the
             * last item to be displayed, we need to skip it
             */
            while ((count < ((mReverse && !mHardJumpTo) ? (maxCount + 1) : maxCount)) && e.hasMoreElements()) {
                ICertRecord rec = e.nextElement();

                if (rec == null) {
                    com.netscape.certsrv.apps.CMS.debug("record " + count + " is null");
                    break;
                }
                curSerial = rec.getSerialNumber();
                com.netscape.certsrv.apps.CMS.debug("record " + count + " is serial#" + curSerial);

                if (count == 0) {
                    firstSerial = curSerial;
                    if (mReverse && !mHardJumpTo) {//reverse got one more, skip
                        count++;
                        continue;
                    }
                }

                // DS has a problem where last record will be returned
                // even though the filter is not matched.
                /*cfu -  is this necessary?  it breaks when paging up
                if (curSerial.compareTo(sentinel) == -1) {
                	com.netscape.certsrv.apps.CMS.debug("curSerial compare sentinel -1 break...");

                	break;
                    }
                */
                if (!serialToVal.equals(MINUS_ONE)) {
                    // check if we go over the limit
                    if (curSerial.compareTo(serialToVal) == 1) {
                        com.netscape.certsrv.apps.CMS.debug("curSerial compare serialToVal 1 breaking...");
                        break;
                    }
                }

                if (mReverse) {
                    recs[rcount++] = rec;
                } else {

                    IArgBlock rarg = com.netscape.certsrv.apps.CMS.createArgBlock();

                    fillRecordIntoArg(rec, rarg);
                    argSet.addRepeatRecord(rarg);
                }
                count++;
            }
        } else {
            com.netscape.certsrv.apps.CMS.debug(
                    "ListCerts::processCertFilter() - no Cert Records found!");
            return;
        }

        if (mReverse) {
            // fill records into arg block and argSet
            for (int ii = rcount - 1; ii >= 0; ii--) {
                if (recs[ii] != null) {
                    IArgBlock rarg = com.netscape.certsrv.apps.CMS.createArgBlock();
                    //com.netscape.certsrv.apps.CMS.debug("item "+ii+" is serial # "+ recs[ii].getSerialNumber());
                    fillRecordIntoArg(recs[ii], rarg);
                    argSet.addRepeatRecord(rarg);
                }
            }
        }

        // peek ahead
        ICertRecord nextRec = null;

        if (e.hasMoreElements()) {
            nextRec = e.nextElement();
        }

        header.addStringValue("op", req.getParameter("op"));
        if (revokeAll != null)
            header.addStringValue("revokeAll", revokeAll);
        if (mAuthName != null)
            header.addStringValue("issuerName", mAuthName.toString());
        if (!serialToVal.equals(MINUS_ONE))
            header.addStringValue("serialTo", serialToVal.toString());
        header.addStringValue("serviceURL", req.getRequestURI());
        header.addStringValue("queryCertFilter", filter);
        header.addStringValue("templateName", "queryCert");
        header.addStringValue("queryFilter", filter);
        header.addIntegerValue("maxCount", maxCount);
        if (totalRecordCount == -1) {
            if (!serialToVal.equals(MINUS_ONE)) {
                totalRecordCount = toCurIndex - curIndex + 1;
                com.netscape.certsrv.apps.CMS.debug("totalRecordCount=" + totalRecordCount);
            } else {
                totalRecordCount = list.getSize() -
                        list.getCurrentIndex();
                com.netscape.certsrv.apps.CMS.debug("totalRecordCount=" + totalRecordCount);
            }
        }

        header.addIntegerValue("totalRecordCount", totalRecordCount);
        header.addIntegerValue("currentRecordCount", list.getSize() -
                list.getCurrentIndex());

        String qs = "";
        if (mReverse)
            qs = "querySentinelUp";
        else
            qs = "querySentinelDown";

        if (mHardJumpTo) {
            com.netscape.certsrv.apps.CMS.debug("curSerial added to querySentinelUp:" + curSerial.toString());

            header.addStringValue("querySentinelUp", curSerial.toString());
        } else {
            if (nextRec == null) {
                header.addStringValue(qs, null);
                com.netscape.certsrv.apps.CMS.debug("nextRec is null");
                if (mReverse) {
                    com.netscape.certsrv.apps.CMS.debug("curSerial added to querySentinelUp:" + curSerial.toString());

                    header.addStringValue("querySentinelUp", curSerial.toString());
                }
            } else {
                BigInteger nextRecNo = nextRec.getSerialNumber();

                if (serialToVal.equals(MINUS_ONE)) {
                    header.addStringValue(
                            qs, nextRecNo.toString());
                } else {
                    if (nextRecNo.compareTo(serialToVal) <= 0) {
                        header.addStringValue(
                                qs, nextRecNo.toString());
                    } else {
                        header.addStringValue(qs,
                                null);
                    }
                }
                com.netscape.certsrv.apps.CMS.debug("querySentinel " + qs + " = " + nextRecNo.toString());
            }
        } // !mHardJumpto

        header.addStringValue(!mReverse ? "querySentinelUp" : "querySentinelDown",
                  firstSerial.toString());

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

        if (cert.getSubjectDN().toString().equals("")) {
            rarg.addStringValue("subject", " ");
        } else
            rarg.addStringValue("subject", cert.getSubjectDN().toString());

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
