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
package com.netscape.cms.servlet.request;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import org.mozilla.jss.netscape.security.extensions.NSCertTypeExtension;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.CertificateAlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.CertificateValidity;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IPrettyPrintFormat;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.RawJS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.cert.CertPrettyPrint;
import com.netscape.cmscore.cert.ExtPrettyPrint;
import com.netscape.cmscore.cert.PrettyPrintFormat;

/**
 * Output a 'pretty print' of a certificate request
 *
 * @version $Revision$, $Date$
 */
public class CertReqParser extends ReqParser {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertReqParser.class);

    public static final CertReqParser DETAIL_PARSER = new CertReqParser(true);
    public static final CertReqParser NODETAIL_PARSER = new CertReqParser(false);

    private boolean mDetails = true;
    private IPrettyPrintFormat pp = null;

    /**
     * Constructs a certificate request parser.
     */
    public CertReqParser() {
        pp = new PrettyPrintFormat(":");
    }

    /**
     * Constructs a certificate request parser.
     *
     * @param details return detailed information (this can be time consuming)
     */
    public CertReqParser(boolean details) {
        mDetails = details;
        pp = new PrettyPrintFormat(":");
    }

    private static final String EXT_PRETTYPRINT = "ext_prettyprint";

    private static final String LB = "[";
    private static final String RB = "]";
    private static final String EQ = " = ";

    /**
     * Fills in certificate specific request attributes.
     */
    @Override
    public void fillRequestIntoArg(Locale l, IRequest req, CMSTemplateParams argSet, IArgBlock arg)
            throws EBaseException {

        // in case x509CertInfo is missing, at least add the subject for display
        if (req.getExtDataInCertInfo("req_x509info"/*IRequest.CERT_INFO*/) == null
                && req.getExtDataInCertInfo(IRequest.CERT_INFO) == null
                && arg.getValueAsString("subject", "").equals("")) {
            //logger.debug("CertReqParser.fillRequestIntoArg: filling subject due to missing x509CertInfo in request");
            try {
                String subjectnamevalue = req.getExtDataInString("req_subject_name");
                if (subjectnamevalue != null && !subjectnamevalue.equals("")) {
                    X500Name name = new X500Name(Utils.base64decode(subjectnamevalue));
                    CertificateSubjectName sbjName = new CertificateSubjectName(name);
                    if (sbjName != null) {
                        arg.addStringValue("subject", sbjName.toString());
                    }
                }
            } catch (Exception ee) {
                logger.warn("CertReqParser.fillRequestIntoArg: Exception:" + ee.getMessage(), ee);
            }
        }

        if (req.getExtDataInCertInfoArray(IRequest.CERT_INFO) != null) {
            fillX509RequestIntoArg(l, req, argSet, arg);
        } else if (req.getExtDataInRevokedCertArray(IRequest.CERT_INFO) != null) {
            fillRevokeRequestIntoArg(l, req, argSet, arg);
        } else {
            //o = req.get(IRequest.OLD_CERTS);
            //if (o != null)
            fillRevokeRequestIntoArg(l, req, argSet, arg);
        }
    }

    private void fillX509RequestIntoArg(Locale l, IRequest req, CMSTemplateParams argSet, IArgBlock arg)
            throws EBaseException {

        // fill in the standard attributes
        super.fillRequestIntoArg(l, req, argSet, arg);

        arg.addStringValue("certExtsEnabled", "yes");

        int saCounter = 0;
        Enumeration<String> enum1 = req.getExtDataKeys();

        // gross hack
        String prefix = "record.";

        if (argSet.getHeader() == arg)
            prefix = "header.";

        while (enum1.hasMoreElements()) {
            String name = enum1.nextElement();

            if (mDetails) {
                // show all http parameters stored in request.
                if (name.equalsIgnoreCase(IRequest.HTTP_PARAMS)) {
                    Hashtable<String, String> http_params = req.getExtDataInHashtable(name);
                    // show certType specially
                    String certType = http_params.get(IRequest.CERT_TYPE);

                    if (certType != null) {
                        arg.addStringValue(IRequest.CERT_TYPE, certType);
                    }
                    String presenceServerExt = http_params.get("PresenceServerExtension");

                    if (presenceServerExt != null) {
                        arg.addStringValue("PresenceServerExtension", presenceServerExt);
                    }
                    // show all http parameters in request
                    int counter = 0;
                    Enumeration<String> elms = http_params.keys();

                    while (elms.hasMoreElements()) {
                        String parami =
                                IRequest.HTTP_PARAMS + LB + String.valueOf(counter++) + RB;
                        // hack
                        String n = elms.nextElement();
                        String rawJS = "new Object;\n\r" +
                                prefix + parami + ".name=\"" +
                                CMSTemplate.escapeJavaScriptString(n) + "\";\n\r" +
                                prefix + parami + ".value=\"" +
                                CMSTemplate.escapeJavaScriptStringHTML(
                                        http_params.get(n).toString()) + "\"";

                        arg.set(parami, new RawJS(rawJS));
                    }
                } // show all http headers stored in request.
                else if (name.equalsIgnoreCase(IRequest.HTTP_HEADERS)) {
                    Hashtable<String, String> http_hdrs = req.getExtDataInHashtable(name);
                    Enumeration<String> elms = http_hdrs.keys();
                    int counter = 0;

                    while (elms.hasMoreElements()) {
                        String parami =
                                IRequest.HTTP_HEADERS + LB + String.valueOf(counter++) + RB;
                        // hack
                        String n = elms.nextElement();
                        String rawJS = "new Object;\n\r" +
                                prefix + parami + ".name=\"" +
                                CMSTemplate.escapeJavaScriptString(n) + "\";\n\r" +
                                prefix + parami + ".value=\"" +
                                CMSTemplate.escapeJavaScriptStringHTML(
                                        http_hdrs.get(n).toString()) + "\"";

                        arg.set(parami, new RawJS(rawJS));
                    }
                } // show all auth token stored in request.
                else if (name.equalsIgnoreCase(IRequest.AUTH_TOKEN)) {
                    IAuthToken auth_token = req.getExtDataInAuthToken(name);
                    Enumeration<String> elms = auth_token.getElements();
                    int counter = 0;

                    while (elms.hasMoreElements()) {
                        String parami =
                                IRequest.AUTH_TOKEN + LB + String.valueOf(counter++) + RB;
                        // hack
                        String n = elms.nextElement();
                        Object authTokenValue = auth_token.getInStringArray(n);
                        if (authTokenValue == null) {
                            authTokenValue = auth_token.getInString(n);
                        }
                        String v = expandValue(prefix + parami + ".value",
                                authTokenValue);
                        String rawJS = "new Object;\n\r" +
                                prefix + parami + ".name=\"" +
                                CMSTemplate.escapeJavaScriptString(n) + "\";\n" + v;

                        arg.set(parami, new RawJS(rawJS));
                    }
                } // all others are request attrs from policy or internal modules.
                else {
                    Object val;
                    if (req.isSimpleExtDataValue(name)) {
                        val = req.getExtDataInString(name);
                    } else {
                        val = req.getExtDataInStringArray(name);
                        if (val == null) {
                            val = req.getExtDataInHashtable(name);
                        }
                    }
                    String valstr = "";
                    // hack
                    String parami =
                            IRequest.SERVER_ATTRS + LB + String.valueOf(saCounter++) + RB;

                    if (name.equalsIgnoreCase(IRequest.ISSUED_CERTS) && mDetails &&
                            (req.getRequestStatus() == RequestStatus.COMPLETE ||
                            req.getRequestType().equals(IRequest.GETREVOCATIONINFO_REQUEST))) {
                        X509CertImpl issuedCert[] =
                                req.getExtDataInCertArray(IRequest.ISSUED_CERTS);
                        if (issuedCert != null && issuedCert[0] != null) {
                            val = "<pre>" + new CertPrettyPrint(issuedCert[0]).toString(l) + "</pre>";
                        }
                    } else if (name.equalsIgnoreCase(IRequest.CERT_INFO) && mDetails) {
                        X509CertInfo[] certInfo =
                                req.getExtDataInCertInfoArray(IRequest.CERT_INFO);
                        if (certInfo != null && certInfo[0] != null) {
                            val = "<pre>" + certInfo[0].toString() + "</pre>";
                        }
                    }

                    valstr = expandValue(prefix + parami + ".value", val);
                    String rawJS = "new Object;\n\r" +
                            prefix + parami + ".name=\"" +
                            CMSTemplate.escapeJavaScriptString(name) + "\";\n" +
                            valstr; // java string already escaped in expandValue.

                    arg.set(parami, new RawJS(rawJS));
                }
            }

            if (name.equalsIgnoreCase(IRequest.REQUESTOR_PHONE)
                    || name.equalsIgnoreCase(IRequest.REQUESTOR_EMAIL)
                    || name.equalsIgnoreCase(IRequest.REQUESTOR_COMMENTS)
                    || name.equalsIgnoreCase(IRequest.RESULT)
                    || name.equalsIgnoreCase(IRequest.REQUEST_TRUSTEDMGR_PRIVILEGE)) {
                arg.addStringValue(name, req.getExtDataInString(name));
            }

            if (name.equalsIgnoreCase(IRequest.REQUESTOR_NAME)) {
                String requestorName = req.getExtDataInString(name);

                requestorName = requestorName.trim();
                if (requestorName.length() > 0) {
                    arg.addStringValue(name, requestorName);
                }
            }

            if (name.equalsIgnoreCase(IRequest.ERRORS)) {
                Vector<String> errorStrings = req.getExtDataInStringVector(name);
                if (errorStrings != null) {
                    StringBuffer errInfo = new StringBuffer();

                    for (int i = 0; i < errorStrings.size(); i++) {
                        errInfo.append(errorStrings.elementAt(i));
                        errInfo.append("\n");
                    }
                    arg.addStringValue(IRequest.ERRORS, errInfo.toString());
                }
            }
            if (name.equalsIgnoreCase(IRequest.ERROR)) {
                arg.addStringValue(IRequest.ERRORS, req.getExtDataInString(name));
            }

            if (name.equalsIgnoreCase(IRequest.CERT_INFO)) {
                // Get the certificate info from the request
                X509CertInfo[] certInfo =
                        req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

                if (certInfo != null && certInfo[0] != null) {
                    // Get the subject name if any set.
                    CertificateSubjectName subjectName = null;
                    String signatureAlgorithm = null;
                    String signatureAlgorithmName = null;

                    try {
                        subjectName = (CertificateSubjectName) certInfo[0].get(X509CertInfo.SUBJECT);
                    } catch (IOException e) {
                        // XXX raise exception
                    } catch (CertificateException e) {
                        // XXX raise exception
                    }
                    if (subjectName != null) {
                        String sn;

                        try {
                            sn = subjectName.toString();
                        } catch (java.lang.IllegalArgumentException e) {
                            sn = "* * Malformed Subject Name * *";
                        }
                        String subjectnamevalue = sn;

                        arg.addStringValue("subject", subjectnamevalue);
                    }

                    if (mDetails) {
                        try {
                            CertificateAlgorithmId certAlgId = (CertificateAlgorithmId)
                                    certInfo[0].get(X509CertInfo.ALGORITHM_ID);
                            AlgorithmId algId = (AlgorithmId)
                                    certAlgId.get(CertificateAlgorithmId.ALGORITHM);

                            signatureAlgorithm = (algId.getOID()).toString();
                            signatureAlgorithmName = algId.getName();
                        } catch (Exception e) {
                            // XXX raise exception
                        }
                        if (signatureAlgorithm != null) {
                            arg.addStringValue("signatureAlgorithm", signatureAlgorithm);
                        }
                        if (signatureAlgorithmName != null) {
                            arg.addStringValue("signatureAlgorithmName", signatureAlgorithmName);
                        }

                        CertificateExtensions extensions = null;

                        try {
                            extensions = (CertificateExtensions) certInfo[0].get(X509CertInfo.EXTENSIONS);
                        } catch (Exception e) {
                        }
                        if (extensions != null) {
                            Enumeration<Extension> exts = extensions.getAttributes();

                            while (exts.hasMoreElements()) {
                                Extension ext = exts.nextElement();

                                // only know about ns cert type
                                if (ext instanceof NSCertTypeExtension) {
                                    NSCertTypeExtension nsExtensions =
                                            (NSCertTypeExtension) ext;

                                    try {
                                        arg.addStringValue("ext_" + NSCertTypeExtension.SSL_SERVER,
                                                nsExtensions.get(NSCertTypeExtension.SSL_SERVER).toString());

                                        arg.addStringValue("ext_" + NSCertTypeExtension.SSL_CLIENT,
                                                nsExtensions.get(NSCertTypeExtension.SSL_CLIENT).toString());

                                        arg.addStringValue("ext_" + NSCertTypeExtension.EMAIL,
                                                nsExtensions.get(NSCertTypeExtension.EMAIL).toString());

                                        arg.addStringValue("ext_" + NSCertTypeExtension.OBJECT_SIGNING,
                                                nsExtensions.get(NSCertTypeExtension.OBJECT_SIGNING).toString());

                                        arg.addStringValue("ext_" + NSCertTypeExtension.SSL_CA,
                                                nsExtensions.get(NSCertTypeExtension.SSL_CA).toString());

                                        arg.addStringValue("ext_" + NSCertTypeExtension.EMAIL_CA,
                                                nsExtensions.get(NSCertTypeExtension.EMAIL_CA).toString());

                                        arg.addStringValue("ext_" + NSCertTypeExtension.OBJECT_SIGNING_CA,
                                                nsExtensions.get(NSCertTypeExtension.OBJECT_SIGNING_CA).toString());

                                    } catch (Exception e) {
                                    }
                                } else if (ext instanceof BasicConstraintsExtension) {
                                    BasicConstraintsExtension bcExt =
                                            (BasicConstraintsExtension) ext;
                                    Integer pathLength = null;
                                    Boolean isCA = null;

                                    try {
                                        pathLength = (Integer) bcExt.get(BasicConstraintsExtension.PATH_LEN);
                                        isCA = (Boolean) bcExt.get(BasicConstraintsExtension.IS_CA);
                                    } catch (IOException e) {
                                    }
                                    if (pathLength != null)
                                        arg.addIntegerValue("pathLenBasicConstraints", pathLength.intValue());
                                    if (isCA != null)
                                        arg.addBooleanValue("isCABasicConstraints", isCA.booleanValue());
                                } // pretty print all others.
                                else {
                                    if (argSet != null) {
                                        ArgBlock rr = new ArgBlock();

                                        rr.addStringValue(
                                                EXT_PRETTYPRINT,
                                                new ExtPrettyPrint(ext, 0).toString());
                                        argSet.addRepeatRecord(rr);
                                    }
                                }
                            }

                        }

                        // Get the public key
                        CertificateX509Key certKey = null;

                        try {
                            certKey = (CertificateX509Key) certInfo[0].get(X509CertInfo.KEY);
                        } catch (IOException e) {
                            // XXX raise exception
                        } catch (CertificateException e) {
                            // XXX raise exception
                        }

                        X509Key key = null;

                        try {
                            key = (X509Key) certKey.get(CertificateX509Key.KEY);
                        } catch (IOException e) {
                            // XXX raise exception
                        }

                        if (key != null) {
                            arg.addStringValue("subjectPublicKeyInfo",
                                    key.getAlgorithm() + " - " + key.getAlgorithmId().getOID().toString());
                            arg.addStringValue("subjectPublicKey",
                                    pp.toHexString(key.getKey(), 0, 16));
                        }

                        // Get the validity period
                        CertificateValidity validity = null;

                        try {
                            validity =
                                    (CertificateValidity)
                                    certInfo[0].get(X509CertInfo.VALIDITY);
                            if (validity != null) {
                                long validityLength = (((Date) validity.get(CertificateValidity.NOT_AFTER)).getTime() -
                                        ((Date) validity.get(CertificateValidity.NOT_BEFORE)).getTime()) / 1000;
                                arg.addLongValue("validityLength", validityLength);
                            }
                        } catch (IOException e) {
                            // XXX raise exception
                        } catch (CertificateException e) {
                            // XXX raise exception
                        }
                    }
                }
            }

            if (name.equalsIgnoreCase(IRequest.OLD_SERIALS) && mDetails) {
                BigInteger oldSerialNo[] = req.getExtDataInBigIntegerArray(IRequest.OLD_SERIALS);

                if (oldSerialNo != null) {
                    if (argSet != null) {
                        for (int i = 0; i < oldSerialNo.length; i++) {
                            ArgBlock rarg = new ArgBlock();

                            rarg.addBigIntegerValue("serialNumber",
                                    oldSerialNo[i], 16);
                            argSet.addRepeatRecord(rarg);
                        }
                    }
                }
            }

            if (name.equalsIgnoreCase(IRequest.ISSUED_CERTS) && mDetails &&
                    (req.getRequestStatus() == RequestStatus.COMPLETE ||
                    req.getRequestType().equals(IRequest.GETREVOCATIONINFO_REQUEST))) {
                X509CertImpl issuedCert[] =
                        req.getExtDataInCertArray(IRequest.ISSUED_CERTS);

                arg.addBigIntegerValue("serialNumber", issuedCert[0].getSerialNumber(), 16);
                // Set Serial No for 2nd certificate
                if (issuedCert.length == 2)
                    arg.addBigIntegerValue("serialNumber2", issuedCert[1].getSerialNumber(), 16);
            }
            if (name.equalsIgnoreCase(IRequest.OLD_CERTS) && mDetails) {
                X509CertImpl oldCert[] =
                        req.getExtDataInCertArray(IRequest.OLD_CERTS);

                if (oldCert != null && oldCert.length > 0) {
                    arg.addBigIntegerValue("serialNumber", oldCert[0].getSerialNumber(), 16);
                    arg.addStringValue("subject", oldCert[0].getSubjectDN().toString());
                    if (req.getRequestType().equals(IRequest.GETCERTS_REQUEST)) {
                        for (int i = 0; i < oldCert.length; i++) {
                            ArgBlock rarg = new ArgBlock();

                            rarg.addBigIntegerValue("serialNumber",
                                    oldCert[i].getSerialNumber(), 16);
                            argSet.addRepeatRecord(rarg);
                        }
                    }
                }
            }

            if (name.equalsIgnoreCase(IRequest.CACERTCHAIN) && mDetails) {
                byte[] certChainData = req.getExtDataInByteArray(
                        IRequest.CACERTCHAIN);
                if (certChainData != null) {
                    CertificateChain certChain = new CertificateChain();
                    try {
                        certChain.decode(new ByteArrayInputStream(certChainData));

                        X509Certificate cert[] = certChain.getChain();

                        for (int i = 0; i < cert.length; i++) {
                            ArgBlock rarg = new ArgBlock();

                            rarg.addBigIntegerValue("serialNumber",
                                    cert[i].getSerialNumber(), 16);
                            argSet.addRepeatRecord(rarg);
                        }
                    } catch (IOException e) {
                        // XXX
                    }
                }
            }
            if (name.equalsIgnoreCase(IRequest.FINGERPRINTS) && mDetails) {
                Hashtable<String, String> fingerprints =
                        req.getExtDataInHashtable(IRequest.FINGERPRINTS);

                if (fingerprints != null) {
                    String namesAndHashes = null;
                    Enumeration<String> enumFingerprints = fingerprints.keys();

                    while (enumFingerprints.hasMoreElements()) {
                        String hashname = enumFingerprints.nextElement();
                        String hashvalue = fingerprints.get(hashname);
                        byte[] fingerprint = Utils.base64decode(hashvalue);
                        String ppFingerprint = pp.toHexString(fingerprint, 0);

                        if (hashname != null && ppFingerprint != null) {
                            if (namesAndHashes != null) {
                                namesAndHashes += "+" + hashname + "+" + ppFingerprint;
                            } else {
                                namesAndHashes = hashname + "+" + ppFingerprint;
                            }
                        }
                    }
                    if (namesAndHashes != null) {
                        arg.addStringValue("fingerprints", namesAndHashes);
                    }
                }
            }
        }
    }

    /**
     * print value out nicely in request attributes.
     */
    protected String expandValue(String valuename, Object v) {
        try {
            String valstr = "";

            // if it's a vector
            if (v instanceof Vector) {
                valstr = valuename + "= new Array";
                int j = 0;

                StringBuffer sb = new StringBuffer();
                for (@SuppressWarnings("unchecked")
                Enumeration<String> n = ((Vector<String>) v).elements(); n.hasMoreElements(); j++) {
                    sb.append(";\n");
                    sb.append(valuename);
                    sb.append(LB);
                    sb.append(j);
                    sb.append(RB);
                    sb.append(EQ);
                    sb.append("\"");
                    sb.append(
                            CMSTemplate.escapeJavaScriptStringHTML(
                                    n.nextElement().toString()));
                    sb.append("\";\n");
                }
                sb.append("\n");
                valstr = sb.toString();
                return valstr;
            }

            // if an array.
            int len = -1;

            try {
                len = Array.getLength(v);
            } catch (IllegalArgumentException e) {
            }
            if (len >= 0) { // is an array; access each object in array.
                valstr = valuename + "= new Array";
                int i;

                for (i = 0; i < len; i++) {
                    if (Array.get(v, i) != null)
                        valstr += ";\n" + valuename + LB + i + RB + EQ + "\"" +
                                CMSTemplate.escapeJavaScriptStringHTML(
                                        Array.get(v, i).toString()) + "\";\n";
                }
                return valstr;
            }
        } catch (Throwable e) {
        }

        // if string or unrecognized type, just call its toString method.
        return valuename + "=\"" +
                CMSTemplate.escapeJavaScriptStringHTML(v.toString()) + "\"";
    }

    public String getCertSubjectDN(IRequest request) {
        try {
            String cert = request.getExtDataInString("cert");
            if (cert == null) {
                cert = request.getExtDataInString("req_issued_cert");
            }

            if (cert != null) {

                X509CertImpl theCert = null;
                try {
                    theCert = new X509CertImpl(Utils.base64decode(cert));
                } catch (CertificateException e) {
                }

                if (theCert != null) {
                    String subject = theCert.getSubjectDN().toString();
                    return subject;
                }
            }
        } catch (Exception e) {
            logger.warn("CertReqParser: getCertSubjectDN " + e.getMessage(), e);
        }
        return null;
    }

    public String getRequestorDN(IRequest request) {
        try {
            X509CertInfo info = request.getExtDataInCertInfo(EnrollProfile.REQUEST_CERTINFO);
            if (info == null) return null;
            // retrieve the subject name
            CertificateSubjectName sn = (CertificateSubjectName)
                    info.get(X509CertInfo.SUBJECT);

            return sn.toString();
        } catch (Exception e) {
            logger.warn("CertReqParser: getRequestorDN " + e.getMessage(), e);
        }
        return null;
    }

    public String getKeyID(IRequest request) {
        try {
            String kid = null;

            String cid = request.getExtDataInString(IRequest.NETKEY_ATTR_CUID);
            if (cid == null) {
                cid = "";
            }
            String uid = request.getExtDataInString(IRequest.NETKEY_ATTR_USERID);
            if (uid == null) {
                uid = "";
            }
            kid = cid + ":" + uid;
            if (kid.equals(":")) {
                kid = "";
            }

            return kid;
        } catch (Exception e) {
            logger.warn("CertReqParser: getKeyID " + e.getMessage(), e);
        }
        return null;
    }

    private void fillRevokeRequestIntoArg(Locale l, IRequest req, CMSTemplateParams argSet, IArgBlock arg)
            throws EBaseException {
        // fill in the standard attributes
        super.fillRequestIntoArg(l, req, argSet, arg);

        arg.addStringValue("certExtsEnabled", "yes");
        String profile = req.getExtDataInString("profile");
        String reqType = req.getExtDataInString(IRequest.ATTR_REQUEST_TYPE);

        //logger.debug("CertReqParser: profile=" + profile);
        //profile null can mean either recovery case or TMS reqs
        if (profile != null) {
            arg.addStringValue("profile", profile);
            String requestorDN = getRequestorDN(req);
            if (requestorDN == null) {
                requestorDN = getCertSubjectDN(req);
            }

            if (requestorDN != null) {
                arg.addStringValue("subject", requestorDN);
            }
        } else if (IRequest.KEYRECOVERY_REQUEST.equals(reqType)) {
            arg.addStringValue("profile", "false");
            String subjectDN = getCertSubjectDN(req);
            arg.addStringValue("subject", subjectDN);

        } else { //TMS
            arg.addStringValue("profile", "false");
            String keyID = getKeyID(req);

            if (keyID != null && !keyID.isEmpty()) {
                arg.addStringValue("subject", keyID);
            }

        }

        int saCounter = 0;
        Enumeration<String> enum1 = req.getExtDataKeys();

        // gross hack
        String prefix = "record.";

        if (argSet.getHeader() == arg)
            prefix = "header.";

        while (enum1.hasMoreElements()) {
            String name = enum1.nextElement();

            if (mDetails) {
                // show all http parameters stored in request.
                if (name.equalsIgnoreCase(IRequest.HTTP_PARAMS)) {
                    Hashtable<String, String> http_params = req.getExtDataInHashtable(name);
                    // show certType specially
                    String certType = http_params.get(IRequest.CERT_TYPE);

                    if (certType != null) {
                        arg.addStringValue(IRequest.CERT_TYPE, certType);
                    }
                    // show all http parameters in request
                    int counter = 0;
                    Enumeration<String> elms = http_params.keys();

                    while (elms.hasMoreElements()) {
                        String parami =
                                IRequest.HTTP_PARAMS + LB + String.valueOf(counter++) + RB;
                        // hack
                        String n = elms.nextElement();
                        String rawJS = "new Object;\n\r" +
                                prefix + parami + ".name=\"" +
                                CMSTemplate.escapeJavaScriptString(n) + "\";\n\r" +
                                prefix + parami + ".value=\"" +
                                CMSTemplate.escapeJavaScriptStringHTML(
                                        http_params.get(n).toString()) + "\"";

                        arg.set(parami, new RawJS(rawJS));
                    }
                } // show all http headers stored in request.
                else if (name.equalsIgnoreCase(IRequest.HTTP_HEADERS)) {
                    Hashtable<String, String> http_hdrs = req.getExtDataInHashtable(name);
                    Enumeration<String> elms = http_hdrs.keys();
                    int counter = 0;

                    while (elms.hasMoreElements()) {
                        String parami =
                                IRequest.HTTP_HEADERS + LB + String.valueOf(counter++) + RB;
                        // hack
                        String n = elms.nextElement();
                        String rawJS = "new Object;\n\r" +
                                prefix + parami + ".name=\"" +
                                CMSTemplate.escapeJavaScriptString(n) + "\";\n\r" +
                                prefix + parami + ".value=\"" +
                                CMSTemplate.escapeJavaScriptStringHTML(
                                        http_hdrs.get(n).toString()) + "\"";

                        arg.set(parami, new RawJS(rawJS));
                    }
                } // show all auth token stored in request.
                else if (name.equalsIgnoreCase(IRequest.AUTH_TOKEN)) {
                    IAuthToken auth_token = req.getExtDataInAuthToken(name);
                    Enumeration<String> elms = auth_token.getElements();
                    int counter = 0;

                    while (elms.hasMoreElements()) {
                        String parami =
                                IRequest.AUTH_TOKEN + LB + String.valueOf(counter++) + RB;
                        // hack
                        String n = elms.nextElement();
                        String v =
                                expandValue(prefix + parami + ".value",
                                        auth_token.getInString(n));
                        String rawJS = "new Object;\n\r" +
                                prefix + parami + ".name=\"" +
                                CMSTemplate.escapeJavaScriptString(n) + "\";\n" + v;

                        arg.set(parami, new RawJS(rawJS));
                    }
                } // all others are request attrs from policy or internal modules.
                else {
                    Object val;
                    if (req.isSimpleExtDataValue(name)) {
                        val = req.getExtDataInString(name);
                    } else {
                        val = req.getExtDataInStringArray(name);
                        if (val == null) {
                            val = req.getExtDataInHashtable(name);
                        }
                    }
                    String valstr = "";
                    // hack
                    String parami =
                            IRequest.SERVER_ATTRS + LB + String.valueOf(saCounter++) + RB;

                    valstr = expandValue(prefix + parami + ".value", val);
                    String rawJS = "new Object;\n\r" +
                            prefix + parami + ".name=\"" +
                            CMSTemplate.escapeJavaScriptString(name) + "\";\n" +
                            valstr; // java string already escaped in expandValue.

                    arg.set(parami, new RawJS(rawJS));
                }
            }

            if (name.equalsIgnoreCase(IRequest.REQUESTOR_PHONE)
                    || name.equalsIgnoreCase(IRequest.REQUESTOR_EMAIL)
                    || name.equalsIgnoreCase(IRequest.REQUESTOR_COMMENTS)
                    || name.equalsIgnoreCase(IRequest.RESULT)
                    || name.equalsIgnoreCase(IRequest.REQUEST_TRUSTEDMGR_PRIVILEGE)) {
                arg.addStringValue(name, req.getExtDataInString(name));
            }

            if (name.equalsIgnoreCase(IRequest.REQUESTOR_NAME)) {
                String requestorName = req.getExtDataInString(name);

                requestorName = requestorName.trim();
                if (requestorName.length() > 0) {
                    arg.addStringValue(name, requestorName);
                }
            }

            if (name.equalsIgnoreCase(IRequest.ERRORS)) {
                Vector<String> errorsVector = req.getExtDataInStringVector(name);
                if (errorsVector != null) {
                    StringBuffer errInfo = new StringBuffer();

                    for (int i = 0; i < errorsVector.size(); i++) {
                        errInfo.append(errorsVector.elementAt(i));
                        errInfo.append("\n");
                    }
                    arg.addStringValue(IRequest.ERRORS, errInfo.toString());
                }
            }
            if (name.equalsIgnoreCase(IRequest.ERROR)) {
                arg.addStringValue(IRequest.ERRORS, req.getExtDataInString(name));
            }

            if (name.equalsIgnoreCase(IRequest.CERT_INFO)) {
                // Get the certificate info from the request
                RevokedCertImpl revokedCert[] = req.getExtDataInRevokedCertArray(IRequest.CERT_INFO);

                if (mDetails && revokedCert != null) {
                    if (argSet != null) {
                        for (int i = 0; i < revokedCert.length; i++) {
                            ArgBlock rarg = new ArgBlock();

                            rarg.addBigIntegerValue("serialNumber",
                                    revokedCert[i].getSerialNumber(), 16);

                            CRLExtensions crlExtensions = revokedCert[i].getExtensions();

                            if (crlExtensions != null) {
                                for (int k = 0; k < crlExtensions.size(); k++) {
                                    Extension ext = crlExtensions.elementAt(k);

                                    if (ext instanceof CRLReasonExtension) {
                                        rarg.addStringValue("reason",
                                                ((CRLReasonExtension) ext).getReason().toString());
                                    }
                                }
                            } else {
                                rarg.addStringValue("reason",
                                        RevocationReason.UNSPECIFIED.toString());
                            }

                            argSet.addRepeatRecord(rarg);
                        }
                    } else {
                        arg.addBigIntegerValue("serialNumber",
                                revokedCert[0].getSerialNumber(), 16);
                    }
                }
            }

            if (name.equalsIgnoreCase(IRequest.OLD_SERIALS) && mDetails) {
                BigInteger oldSerialNo[] = req.getExtDataInBigIntegerArray(IRequest.OLD_SERIALS);

                if (oldSerialNo != null) {
                    if (argSet != null) {
                        for (int i = 0; i < oldSerialNo.length; i++) {
                            ArgBlock rarg = new ArgBlock();

                            rarg.addBigIntegerValue("serialNumber",
                                    oldSerialNo[i], 16);
                            argSet.addRepeatRecord(rarg);
                        }
                    }
                }
            }

            if (name.equalsIgnoreCase(IRequest.OLD_CERTS) && mDetails) {
                //X509CertImpl oldCert[] =
                //	(X509CertImpl[])req.get(IRequest.OLD_CERTS);
                Certificate oldCert[] =
                        req.getExtDataInCertArray(IRequest.OLD_CERTS);

                if (oldCert != null && oldCert.length > 0) {
                    if (oldCert[0] instanceof X509CertImpl) {
                        X509CertImpl xcert = (X509CertImpl) oldCert[0];

                        arg.addBigIntegerValue("serialNumber", xcert.getSerialNumber(), 16);
                        arg.addStringValue("subject", xcert.getSubjectDN().toString());
                        if (req.getRequestType().equals(IRequest.GETCERTS_REQUEST)) {
                            for (int i = 0; i < oldCert.length; i++) {
                                ArgBlock rarg = new ArgBlock();

                                xcert = (X509CertImpl) oldCert[i];
                                rarg.addBigIntegerValue("serialNumber",
                                        xcert.getSerialNumber(), 16);
                                argSet.addRepeatRecord(rarg);
                            }
                        }
                    }
                }
            }

            if (name.equalsIgnoreCase(IRequest.REVOKED_CERTS) && mDetails &&
                    req.getRequestType().equals("getRevocationInfo")) {
                RevokedCertImpl revokedCert[] =
                        req.getExtDataInRevokedCertArray(IRequest.REVOKED_CERTS);

                if (revokedCert != null && revokedCert[0] != null) {
                    boolean reasonFound = false;
                    CRLExtensions crlExtensions = revokedCert[0].getExtensions();

                    for (int k = 0; k < crlExtensions.size(); k++) {
                        Extension ext = crlExtensions.elementAt(k);

                        if (ext instanceof CRLReasonExtension) {
                            arg.addStringValue("reason",
                                    ((CRLReasonExtension) ext).getReason().toString());
                            reasonFound = true;
                        }
                    }
                    if (reasonFound == false) {
                        arg.addStringValue("reason", "unknown");
                    }
                }
            }
        }
    }

}
