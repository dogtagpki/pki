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
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.provider.RSAPublicKey;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertRecordList;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RevocationInfo;

/**
 * Retrieve a paged list of certs matching the specified query
 */
@WebServlet(
        name = "caListCerts",
        urlPatterns = "/ee/ca/listCerts",
        initParams = {
                @WebInitParam(name="GetClientCert", value="false"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="authority",     value="ca"),
                @WebInitParam(name="templatePath",  value="/ee/ca/queryCert.template"),
                @WebInitParam(name="ID",            value="caListCerts"),
                @WebInitParam(name="resourceID",    value="certServer.ee.certificates"),
                @WebInitParam(name="interface",     value="ee"),
                @WebInitParam(name="maxResults",    value="1000")
        }
)
public class ListCerts extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ListCerts.class);

    private static final long serialVersionUID = -3568155814023099576L;
    private final static String TPL_FILE = "queryCert.template";
    private final static BigInteger MINUS_ONE = new BigInteger("-1");

    private final static String USE_CLIENT_FILTER = "useClientFilter";
    private final static String ALLOWED_CLIENT_FILTERS = "allowedClientFilters";

    private CertificateRepository mCertDB;
    private X500Name mAuthName = null;
    private String mFormPath = null;
    private boolean mUseClientFilter = false;
    private Vector<String> mAllowedClientFilters = new Vector<>();
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
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        CAEngine engine = CAEngine.getInstance();

        // override success to render own template.
        mTemplates.remove(CMSRequest.SUCCESS);

        CertificateAuthority ca = engine.getCA();

        mCertDB = engine.getCertificateRepository();
        mAuthName = ca.getX500Name();

        mFormPath = "/ca/" + TPL_FILE;
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
        logger.debug("ListCerts: queryCertFilter: " + queryCertFilter);

        logger.debug("ListCerts: useClientFilter: " + mUseClientFilter);
        if (mUseClientFilter) {
            Enumeration<String> filters = mAllowedClientFilters.elements();
            // check to see if the filter is allowed
            while (filters.hasMoreElements()) {
                String filter = filters.nextElement();
                logger.debug("ListCerts: Comparing with filter " + filter);
                if (filter.equals(queryCertFilter)) {
                    return queryCertFilter;
                }
            }
            logger.debug("ListCerts: Requested filter '"
                    + queryCertFilter + "' is not allowed. Please check the " + ALLOWED_CLIENT_FILTERS + "parameter");
            return null;
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
    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        AuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "list");
        } catch (Exception e) {
        }

        if (authzToken == null) {
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        String revokeAll = null;
        EBaseException error = null;

        int maxCount = -1;
        BigInteger sentinel = new BigInteger("0");

        ArgBlock header = new ArgBlock();
        ArgBlock ctx = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }

        String direction = null;
        boolean reverse = false;
        boolean hardJumpTo = false; //jump to the end
        try {

            if (req.getParameter("direction") != null) {
                direction = req.getParameter("direction").trim();
                reverse = direction.equals("up");
                logger.debug("ListCerts: reverse: " + reverse);
            }

            if (req.getParameter("maxCount") != null) {
                maxCount = Integer.parseInt(req.getParameter("maxCount"));
            }
            if (maxCount == -1 || maxCount > mMaxReturns) {
                logger.debug("ListCerts: Resetting page size from " + maxCount + " to " + mMaxReturns);
                maxCount = mMaxReturns;
            }

            String sentinelStr = "";
            if (reverse) {
                sentinelStr = req.getParameter("querySentinelUp");
            } else if (direction.equals("end")) {
                // this servlet will figure out the end
                sentinelStr = "0";
                reverse = true;
                hardJumpTo = true;
            } else if (direction.equals("down")) {
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

            CAEngine engine = CAEngine.getInstance();
            CertificateAuthority ca = engine.getCA();
            X509CertImpl caCert = ca.getSigningUnit().getCertImpl();

            //if (isCertFromCA(caCert))
            header.addStringValue("caSerialNumber",
                    caCert.getSerialNumber().toString(16));

            // constructs the ldap filter on the server side
            String queryCertFilter = buildFilter(req);

            if (queryCertFilter == null) {
                cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
                return;
            }

            logger.debug("ListCerts: queryCertFilter: " + queryCertFilter);

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
                    reverse,
                    hardJumpTo,
                    req, resp, revokeAll, locale[0]);

        } catch (NumberFormatException e) {
            logger.error(CMS.getLogMessage("BASE_INVALID_NUMBER_FORMAT"), e);
            error = new EBaseException(CMS.getUserMessage(getLocale(req), "CMS_BASE_INVALID_NUMBER_FORMAT"), e);
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
                    cmsReq.setStatus(CMSRequest.SUCCESS);
                    resp.setContentType("text/html");
                    form.renderOutput(out, argSet);
                }
            } else {
                cmsReq.setStatus(CMSRequest.ERROR);
                cmsReq.setError(error);
            }
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }
    }

    private void processCertFilter(
            CMSTemplateParams argSet,
            ArgBlock header,
            int maxCount,
            BigInteger sentinel,
            int totalRecordCount,
            String serialTo,
            String filter,
            boolean reverse,
            boolean hardJumpTo,
            HttpServletRequest req,
            HttpServletResponse resp,
            String revokeAll,
            Locale locale
            ) throws EBaseException {

        logger.debug("ListCerts.processCertFilter()");
        logger.debug("ListCerts: max count: " + maxCount);
        logger.debug("ListCerts: sentinel: " + sentinel);
        logger.debug("ListCerts: total record count: " + totalRecordCount);
        logger.debug("ListCerts: serialTo: " + serialTo);
        logger.debug("ListCerts: filter: " + filter);

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

        logger.debug("ListCerts: serialToVal: " + serialToVal);
        logger.debug("ListCerts: reverse: " + reverse);
        logger.debug("ListCerts: hardJumpTo: " + hardJumpTo);

        String jumpTo = sentinel.toString();
        int pSize = 0;
        if (reverse) {
            if (!hardJumpTo) //reverse gets one more
                pSize = -1 * maxCount - 1;
            else
                pSize = -1 * maxCount;
        } else
            pSize = maxCount;

        logger.debug("ListCerts: pSize: " + pSize);

        logger.debug("ListCerts: calling findCertRecordsInList() with jumpTo");
        CertRecordList list = mCertDB.findCertRecordsInList(
                filter, (String[]) null, jumpTo, hardJumpTo, "serialno",
                pSize);
        // retrive maxCount + 1 entries
        logger.debug("ListCerts: list size: " + list.getSize());

        Enumeration<CertRecord> e = list.getCertRecords(0, maxCount);

        CertRecordList tolist = null;
        int toCurIndex = 0;

        if (!serialToVal.equals(MINUS_ONE)) {
            // if user specify a range, we need to
            // calculate the totalRecordCount
            logger.debug("ListCerts: calling findCertRecordsInList() with serialTo");
            tolist = mCertDB.findCertRecordsInList(
                        filter,
                        (String[]) null, serialTo,
                        "serialno", maxCount);
            logger.debug("ListCerts: tolist size: " + tolist.getSize());

            Enumeration<CertRecord> en = tolist.getCertRecords(0, 0);

            if (en == null || (!en.hasMoreElements())) {
                logger.debug("ListCerts: no results");
                toCurIndex = list.getSize() - 1;

            } else {
                toCurIndex = tolist.getCurrentIndex();
                CertRecord rx = en.nextElement();
                BigInteger curToSerial = rx.getSerialNumber();
                logger.debug("ListCerts: curToSerial: " + curToSerial);

                if (curToSerial.compareTo(serialToVal) == -1) {
                    toCurIndex = list.getSize() - 1;
                } else {
                    if (!rx.getSerialNumber().toString().equals(serialTo.trim())) {
                        toCurIndex = toCurIndex - 1;
                    }
                }
            }
            logger.debug("ListCerts: toCurIndex: " + toCurIndex);
        }

        int curIndex = list.getCurrentIndex();
        logger.debug("ListCerts: curIndex: " + curIndex);

        BigInteger firstSerial = new BigInteger("0");
        BigInteger curSerial = new BigInteger("0");
        CertRecord[] recs = new CertRecord[maxCount];
        int rcount = 0;

        if (e != null) {
            /* in reverse (page up), because the sentinel is the one after the
             * last item to be displayed, we need to skip it
             */
            logger.debug("ListCerts: records:");
            int count = 0;
            while ((count < ((reverse && !hardJumpTo) ? (maxCount + 1) : maxCount)) && e.hasMoreElements()) {
                CertRecord rec = e.nextElement();

                if (rec == null) {
                    //logger.debug("ListCerts: * record " + count + " is null");
                    break;
                }
                curSerial = rec.getSerialNumber();
                //logger.debug("ListCerts: * record " + count + ": " + curSerial);

                if (count == 0) {
                    firstSerial = curSerial;
                    if (reverse && !hardJumpTo) {//reverse got one more, skip
                        logger.debug("ListCerts:   skipping record");
                        count++;
                        continue;
                    }
                }

                // DS has a problem where last record will be returned
                // even though the filter is not matched.
                /*cfu -  is this necessary?  it breaks when paging up
                if (curSerial.compareTo(sentinel) == -1) {
                        logger.debug("curSerial compare sentinel -1 break...");
                        break;
                    }
                */
                if (!serialToVal.equals(MINUS_ONE)) {
                    // check if we go over the limit
                    if (curSerial.compareTo(serialToVal) == 1) {
                        logger.debug("ListCerts: curSerial compare serialToVal 1 breaking...");
                        break;
                    }
                }

                if (reverse) {
                    //logger.debug("ListCerts: returning with rcount: " + rcount);
                    recs[rcount++] = rec;

                } else {
                    //logger.debug("ListCerts: returning with arg block");
                    ArgBlock rarg = new ArgBlock();
                    fillRecordIntoArg(rec, rarg);
                    argSet.addRepeatRecord(rarg);
                }

                count++;
            }
        } else {
            logger.debug("ListCerts: no records found");
            return;
        }

        if (reverse) {
            logger.debug("ListCerts: fill records into arg block and argSet");
            for (int ii = rcount - 1; ii >= 0; ii--) {
                if (recs[ii] != null) {
                    //logger.debug("ListCerts: processing recs[" + ii + "]");
                    ArgBlock rarg = new ArgBlock();
                    // logger.debug("item " + ii + " is serial #" + recs[ii].getSerialNumber());
                    fillRecordIntoArg(recs[ii], rarg);
                    argSet.addRepeatRecord(rarg);
                }
            }
        }

        // peek ahead
        CertRecord nextRec = null;

        if (e.hasMoreElements()) {
            nextRec = e.nextElement();
            logger.debug("ListCerts: next record: " + nextRec.getSerialNumber());

        } else {
            logger.debug("ListCerts: no next record");
        }

        header.addStringValue("op", CMSTemplate.escapeJavaScriptString(req.getParameter("op")));
        if (revokeAll != null)
            header.addStringValue("revokeAll", CMSTemplate.escapeJavaScriptString(revokeAll));

        if (mAuthName != null)
            header.addStringValue("issuerName", mAuthName.toString());

        if (!serialToVal.equals(MINUS_ONE))
            header.addStringValue("serialTo", serialToVal.toString());

        header.addStringValue("serviceURL", req.getRequestURI());
        header.addStringValue("queryCertFilter", filter);

        String skipRevoked = req.getParameter("skipRevoked");
        header.addStringValue("skipRevoked", skipRevoked == null ? "" : (skipRevoked.equals("on") ? "on" : "off"));

        String skipNonValid = req.getParameter("skipNonValid");
        header.addStringValue("skipNonValid", skipNonValid == null ? "" : (skipNonValid.equals("on") ? "on" : "off"));

        header.addStringValue("templateName", "queryCert");
        header.addStringValue("queryFilter", filter);
        header.addIntegerValue("maxCount", maxCount);

        if (totalRecordCount == -1) {
            if (!serialToVal.equals(MINUS_ONE)) {
                totalRecordCount = toCurIndex - curIndex + 1;
                logger.debug("ListCerts: totalRecordCount: " + totalRecordCount);
            } else {
                totalRecordCount = list.getSize() -
                        list.getCurrentIndex();
                logger.debug("ListCerts: totalRecordCount: " + totalRecordCount);
            }
        }

        int currentRecordCount = list.getSize() - list.getCurrentIndex();
        logger.debug("ListCerts: totalRecordCount: " + totalRecordCount);
        logger.debug("ListCerts: currentRecordCount: " + currentRecordCount);

        header.addIntegerValue("totalRecordCount", totalRecordCount);
        header.addIntegerValue("currentRecordCount", currentRecordCount);

        String qs = "";
        if (reverse)
            qs = "querySentinelUp";
        else
            qs = "querySentinelDown";
        logger.debug("ListCerts: qs: " + qs);

        if (hardJumpTo) {
            logger.debug("ListCerts: curSerial added to querySentinelUp: " + curSerial);
            header.addStringValue("querySentinelUp", curSerial.toString());

        } else {
            if (nextRec == null) {
                header.addStringValue(qs, null);
                logger.debug("ListCerts: nextRec is null");

                if (reverse) {
                    logger.debug("ListCerts: curSerial added to querySentinelUp: " + curSerial);
                    header.addStringValue("querySentinelUp", curSerial.toString());
                }

            } else {
                BigInteger nextRecNo = nextRec.getSerialNumber();
                logger.debug("ListCerts: nextRecNo: " + nextRecNo);

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
                logger.debug("ListCerts: querySentinel " + qs + ": " + nextRecNo);
            }
        } // !hardJumpto

        header.addStringValue(!reverse ? "querySentinelUp" : "querySentinelDown",
                  firstSerial.toString());

    }

    /**
     * Fills cert record into argument block.
     */
    private void fillRecordIntoArg(CertRecord rec, ArgBlock rarg)
            throws EBaseException {

        X509CertImpl xcert = rec.getCertificate();

        if (xcert != null) {
            fillX509RecordIntoArg(rec, rarg);
        }
    }

    private void fillX509RecordIntoArg(CertRecord rec, ArgBlock rarg)
            throws EBaseException {

        X509CertImpl cert = rec.getCertificate();

        rarg.addIntegerValue("version", cert.getVersion());
        rarg.addStringValue("serialNumber", cert.getSerialNumber().toString(16));
        rarg.addStringValue("serialNumberDecimal", cert.getSerialNumber().toString());

        if (cert.getSubjectName().toString().equals("")) {
            rarg.addStringValue("subject", " ");
        } else
            rarg.addStringValue("subject", CMSTemplate.escapeJavaScriptString(cert.getSubjectName().toString()));

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
        rarg.addStringValue("issuedBy", CMSTemplate.escapeJavaScriptString(issuedBy)); // cert.getIssuerDN().toString()
        rarg.addLongValue("issuedOn", rec.getCreateTime().getTime() / 1000);

        rarg.addStringValue("revokedBy",
                ((rec.getRevokedBy() == null) ? "" : CMSTemplate.escapeJavaScriptString(rec.getRevokedBy())));
        if (rec.getRevokedOn() == null) {
            rarg.addStringValue("revokedOn", null);
        } else {
            rarg.addLongValue("revokedOn", rec.getRevokedOn().getTime() / 1000);

            RevocationInfo revocationInfo = rec.getRevocationInfo();

            if (revocationInfo != null) {
                CRLExtensions crlExts = revocationInfo.getCRLEntryExtensions();

                if (crlExts != null) {
                    Enumeration<Extension> enum1 = crlExts.getElements();
                    int reason = 0;

                    while (enum1.hasMoreElements()) {
                        Extension ext = enum1.nextElement();

                        if (ext instanceof CRLReasonExtension) {
                            reason = ((CRLReasonExtension) ext).getReason().getCode();
                            break;
                        }
                    }
                    rarg.addIntegerValue("revocationReason", reason);
                }
            }
        }
    }
}
