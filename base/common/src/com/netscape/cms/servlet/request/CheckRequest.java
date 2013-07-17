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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.StringTokenizer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.pkcs.PKCS7;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.pkix.cmc.CMCStatusInfo;
import org.mozilla.jss.pkix.cmc.PKIData;
import org.mozilla.jss.pkix.cmc.ResponseBody;
import org.mozilla.jss.pkix.cmc.TaggedAttribute;
import org.mozilla.jss.pkix.cms.EncapsulatedContentInfo;
import org.mozilla.jss.pkix.cms.IssuerAndSerialNumber;
import org.mozilla.jss.pkix.cms.SignedData;
import org.mozilla.jss.pkix.cms.SignerIdentifier;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Check the status of a certificate request
 *
 * @version $Revision$, $Date$
 */
public class CheckRequest extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = 2791195859767119636L;
    // constants
    public static String FULL_RESPONSE = "cmcFullEnrollmentResponse";
    private final static String REQ_ID = "requestId";
    private final static String STATUS = "status";
    private final static String CREATE_ON = "createdOn";
    private final static String UPDATE_ON = "updatedOn";

    private final static String TPL_FILE = "requestStatus.template";

    // variables
    private IRequestQueue mQueue = null;
    private String mFormPath = null;
    private String mAuthorityId = null;

    public CMSRequest newCMSRequest() {
        return new CMSRequest();
    }

    /**
     * Constructs request query servlet.
     */
    public CheckRequest()
            throws EBaseException {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "requestStatus.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mQueue = mAuthority.getRequestQueue();
        mAuthorityId = mAuthority.getId();
        mFormPath = "/" + mAuthorityId + "/" + TPL_FILE;

        mTemplates.remove(ICMSRequest.SUCCESS);
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param requestId ID of the request to check
     * <li>http.param format if 'id', then check the request based on the request ID parameter. If set to CMC, then use
     * the 'queryPending' parameter.
     * <li>http.param queryPending query formatted as a CMC request
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        CMS.debug("checkRequest: in process!");
        SET transIds = null, sNonces = null;
        boolean isCMCReq = false;
        INTEGER bodyPartId = null;

        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "read");
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

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        // Note error is covered in the same template as success.
        EBaseException error = null;

        String requestId = req.getParameter("requestId");
        String format = req.getParameter("format");

        CMS.debug("checkRequest: requestId " + requestId);

        // They may check the status using CMC queryPending
        String queryPending = req.getParameter("queryPending");

        if (format != null && format.equals("cmc") && queryPending != null && !queryPending.equals("")) {
            try {
                isCMCReq = true;
                byte[] cmcBlob = CMS.AtoB(queryPending);
                ByteArrayInputStream cmcBlobIn =
                        new ByteArrayInputStream(cmcBlob);

                org.mozilla.jss.pkix.cms.ContentInfo cii = (org.mozilla.jss.pkix.cms.ContentInfo)
                        org.mozilla.jss.pkix.cms.ContentInfo.getTemplate().decode(cmcBlobIn);
                SignedData cmcFullReq = (SignedData)
                        cii.getInterpretedContent();

                EncapsulatedContentInfo ci = cmcFullReq.getContentInfo();

                OBJECT_IDENTIFIER id = ci.getContentType();

                if (!id.equals(OBJECT_IDENTIFIER.id_cct_PKIData) || !ci.hasContent()) {
                    throw new ECMSGWException(CMS.getUserMessage("CMS_GW_NO_PKIDATA"));
                }
                OCTET_STRING content = ci.getContent();
                ByteArrayInputStream s = new ByteArrayInputStream(content.toByteArray());
                PKIData pkiData = (PKIData) (new PKIData.Template()).decode(s);

                SEQUENCE controlSequence = pkiData.getControlSequence();
                int numControls = controlSequence.size();

                for (int i = 0; i < numControls; i++) {
                    // decode message.
                    TaggedAttribute taggedAttr = (TaggedAttribute) controlSequence.elementAt(i);
                    OBJECT_IDENTIFIER type = taggedAttr.getType();

                    if (type.equals(OBJECT_IDENTIFIER.id_cmc_QueryPending)) {
                        bodyPartId = taggedAttr.getBodyPartID();
                        SET requestIds = taggedAttr.getValues();
                        int numReq = requestIds.size();

                        // We only process one for now.
                        if (numReq > 0) {
                            OCTET_STRING reqId = (OCTET_STRING)
                                    ASN1Util.decode(OCTET_STRING.getTemplate(),
                                            ASN1Util.encode(requestIds.elementAt(0)));

                            requestId = new String(reqId.toByteArray());
                        }
                    } else if (type.equals(OBJECT_IDENTIFIER.id_cmc_transactionId)) {
                        transIds = taggedAttr.getValues();
                    } else if (type.equals(OBJECT_IDENTIFIER.id_cmc_recipientNonce)) {
                        // recipient nonce
                    } else if (type.equals(OBJECT_IDENTIFIER.id_cmc_senderNonce)) {
                        sNonces = taggedAttr.getValues();
                    }
                }
            } catch (Exception e) {
                error = new EBaseException(e.toString());
            }
        }

        IArgBlock httpParams = cmsReq.getHttpParams();
        boolean importCert = httpParams.getValueAsBoolean("importCert",
                false);
        // xxx need to check why this is not available at startup
        X509Certificate mCACerts[] = null;

        try {
            mCACerts = ((ICertAuthority) mAuthority).getCACertChain().getChain();
        } catch (Exception e) {
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CA_CHAIN_NOT_AVAILABLE"));
        }

        if (requestId == null || requestId.trim().equals("")) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_NO_REQUEST_ID_PROVIDED"));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_NO_REQUEST_ID_PROVIDED"));
        }
        try {
            new BigInteger(requestId);
        } catch (NumberFormatException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_INVALID_NUMBER_FORMAT_1", requestId));
            throw new EBaseException(
                    CMS.getUserMessage(getLocale(req), "CMS_BASE_INVALID_NUMBER_FORMAT_1", requestId));
        }

        IRequest r = mQueue.findRequest(new RequestId(requestId));

        if (r == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_REQUEST_ID_NOT_FOUND_1", requestId));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_REQUEST_ID_NOT_FOUND", requestId));
        }

        if (authToken != null) {
            // if RA, requestOwner must match the group
            String group = authToken.getInString("group");
            if ((group != null) && (group != "")) {
                if (group.equals("Registration Manager Agents")) {
                    boolean groupMatched = false;
                    String requestOwner = r.getExtDataInString("requestOwner");
                    if (requestOwner != null) {
                        if (requestOwner.equals(group))
                            groupMatched = true;
                    }
                    if (groupMatched == false) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_INVALID_NUMBER_FORMAT_1", requestId.toString()));
                        throw new EBaseException(
                                CMS.getUserMessage(getLocale(req), "CMS_BASE_INVALID_NUMBER_FORMAT_1", requestId));
                    }
                }
            }
        }

        RequestStatus status = r.getRequestStatus();
        String note = r.getExtDataInString("requestNotes");

        header.addStringValue("authority", mAuthorityId);
        header.addStringValue(REQ_ID, r.getRequestId().toString());
        header.addStringValue(STATUS, status.toString());
        header.addLongValue(CREATE_ON, r.getCreationTime().getTime() / 1000);
        header.addLongValue(UPDATE_ON, r.getModificationTime().getTime() / 1000);
        if (note != null && note.length() > 0)
            header.addStringValue("requestNotes", note);

        String type = r.getRequestType();
        Integer result = r.getExtDataInInteger(IRequest.RESULT);

        /*        if (type.equals(IRequest.ENROLLMENT_REQUEST) && (r.get("profile") != null) && status.equals(RequestStatus.COMPLETE)) {
                    X509CertImpl cert = (X509CertImpl) r.get(IEnrollProfile.REQUEST_ISSUED_CERT);
                    IArgBlock rarg = CMS.createArgBlock();

                    rarg.addBigIntegerValue("serialNumber",
                        cert.getSerialNumber(), 16);
                    argSet.addRepeatRecord(rarg);
                }
        */
        String profileId = r.getExtDataInString("profileId");
        if (profileId != null) {
            result = IRequest.RES_SUCCESS;
        }
        if ((type != null) && (type.equals(IRequest.ENROLLMENT_REQUEST) ||
                type.equals(IRequest.RENEWAL_REQUEST)) && (status != null) &&
                status.equals(RequestStatus.COMPLETE) && (result != null) &&
                result.equals(IRequest.RES_SUCCESS)) {
            Object o = r.getExtDataInCertArray(IRequest.ISSUED_CERTS);

            if (profileId != null) {
                X509CertImpl impl[] = new X509CertImpl[1];
                impl[0] = r.getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);
                o = impl;
            }
            if (o != null && (o instanceof X509CertImpl[])) {
                X509CertImpl[] certs = (X509CertImpl[]) o;

                if (certs != null && certs.length > 0) {
                    for (int i = 0; i < certs.length; i++) {
                        if (certs[i] != null) {
                            IArgBlock rarg = CMS.createArgBlock();

                            rarg.addBigIntegerValue("serialNumber",
                                    certs[i].getSerialNumber(), 16);
                            // add pkcs7 cert for importing
                            if (importCert || isCMCReq) {
                                //byte[] ba = certs[i].getEncoded();
                                X509CertImpl[] certsInChain = new X509CertImpl[1];
                                ;
                                if (mCACerts != null) {
                                    for (int ii = 0; ii < mCACerts.length; ii++) {
                                        if (certs[i].equals(mCACerts[ii])) {
                                            certsInChain = new
                                                    X509CertImpl[mCACerts.length];
                                            break;
                                        }
                                        certsInChain = new X509CertImpl[mCACerts.length + 1];
                                    }
                                }

                                // Set the EE cert
                                certsInChain[0] = certs[i];

                                // Set the Ca certificate chain
                                if (mCACerts != null) {
                                    for (int ii = 0; ii < mCACerts.length; ii++) {
                                        if (!certs[i].equals(mCACerts[ii]))
                                            certsInChain[ii + 1] = (X509CertImpl) mCACerts[ii];
                                    }
                                }
                                // Wrap the chain into a degenerate P7 object
                                String p7Str;

                                try {
                                    PKCS7 p7 = new PKCS7(new AlgorithmId[0],
                                            new netscape.security.pkcs.ContentInfo(new byte[0]),
                                            certsInChain,
                                            new netscape.security.pkcs.SignerInfo[0]);
                                    ByteArrayOutputStream bos = new ByteArrayOutputStream();

                                    p7.encodeSignedData(bos);
                                    byte[] p7Bytes = bos.toByteArray();

                                    p7Str = CMS.BtoA(p7Bytes);

                                    StringTokenizer tokenizer = null;

                                    if (File.separator.equals("\\")) {
                                        char[] nl = new char[2];

                                        nl[0] = 10;
                                        nl[1] = 13;
                                        String nlstr = new String(nl);

                                        tokenizer = new StringTokenizer(p7Str, nlstr);
                                    } else
                                        tokenizer = new StringTokenizer(p7Str, "\n");
                                    StringBuffer res = new StringBuffer();

                                    while (tokenizer.hasMoreTokens()) {
                                        String elem = tokenizer.nextToken();

                                        res.append(elem);
                                    }

                                    header.addStringValue("pkcs7ChainBase64", res.toString());

                                    // compose full response
                                    if (isCMCReq) {
                                        SEQUENCE controlSeq = new SEQUENCE();
                                        int bpid = 1;
                                        SEQUENCE bpids = new SEQUENCE();

                                        if (bodyPartId != null)
                                            bpids.addElement(bodyPartId);
                                        CMCStatusInfo cmcStatusInfo = new
                                                CMCStatusInfo(CMCStatusInfo.SUCCESS, bpids);
                                        TaggedAttribute ta = new TaggedAttribute(new
                                                INTEGER(bpid++),
                                                OBJECT_IDENTIFIER.id_cmc_cMCStatusInfo,
                                                cmcStatusInfo);

                                        controlSeq.addElement(ta);

                                        // copy transactionID, senderNonce,
                                        // create recipientNonce
                                        if (transIds != null) {
                                            ta = new TaggedAttribute(new
                                                        INTEGER(bpid++),
                                                        OBJECT_IDENTIFIER.id_cmc_transactionId,
                                                        transIds);
                                            controlSeq.addElement(ta);
                                        }

                                        if (sNonces != null) {
                                            ta = new TaggedAttribute(new
                                                        INTEGER(bpid++),
                                                        OBJECT_IDENTIFIER.id_cmc_recipientNonce,
                                                        sNonces);
                                            controlSeq.addElement(ta);
                                        }

                                        String salt = CMSServlet.generateSalt();
                                        byte[] dig;

                                        try {
                                            MessageDigest SHA1Digest = MessageDigest.getInstance("SHA1");

                                            dig = SHA1Digest.digest(salt.getBytes());
                                        } catch (NoSuchAlgorithmException ex) {
                                            dig = salt.getBytes();
                                        }
                                        String b64E = CMS.BtoA(dig);
                                        String[] newNonce = { b64E };

                                        ta = new TaggedAttribute(new
                                                    INTEGER(bpid++),
                                                    OBJECT_IDENTIFIER.id_cmc_senderNonce,
                                                    new OCTET_STRING(newNonce[0].getBytes()));
                                        controlSeq.addElement(ta);

                                        ResponseBody rb = new ResponseBody(controlSeq, new
                                                SEQUENCE(), new
                                                SEQUENCE());
                                        EncapsulatedContentInfo ci = new
                                                EncapsulatedContentInfo(OBJECT_IDENTIFIER.id_cct_PKIResponse,
                                                        rb);

                                        org.mozilla.jss.crypto.X509Certificate x509cert = null;

                                        if (mAuthority instanceof ICertificateAuthority) {
                                            x509cert = ((ICertificateAuthority) mAuthority).getCaX509Cert();
                                        } else if (mAuthority instanceof IRegistrationAuthority) {
                                            x509cert = ((IRegistrationAuthority) mAuthority).getRACert();
                                        }
                                        if (x509cert == null)
                                            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_CMC_ERROR",
                                                    "No signing cert found."));

                                        X509CertImpl cert = new X509CertImpl(x509cert.getEncoded());
                                        ByteArrayInputStream issuer1 = new
                                                ByteArrayInputStream(((X500Name) cert.getIssuerDN()).getEncoded());
                                        Name issuer = (Name) Name.getTemplate().decode(issuer1);
                                        IssuerAndSerialNumber ias =
                                                new
                                                IssuerAndSerialNumber(issuer, new INTEGER(cert.getSerialNumber()
                                                        .toString()));
                                        SignerIdentifier si = new
                                                SignerIdentifier(SignerIdentifier.ISSUER_AND_SERIALNUMBER, ias, null);

                                        // SHA1 is the default digest Alg for now.
                                        DigestAlgorithm digestAlg = null;
                                        SignatureAlgorithm signAlg = null;
                                        org.mozilla.jss.crypto.PrivateKey privKey =
                                                CryptoManager.getInstance().findPrivKeyByCert(x509cert);
                                        org.mozilla.jss.crypto.PrivateKey.Type keyType = privKey.getType();

                                        if (keyType.equals(org.mozilla.jss.crypto.PrivateKey.RSA))
                                            signAlg = SignatureAlgorithm.RSASignatureWithSHA1Digest;
                                        else if (keyType.equals(org.mozilla.jss.crypto.PrivateKey.DSA))
                                            signAlg = SignatureAlgorithm.DSASignatureWithSHA1Digest;
                                        MessageDigest SHADigest = null;
                                        byte[] digest = null;

                                        try {
                                            SHADigest = MessageDigest.getInstance("SHA1");
                                            digestAlg = DigestAlgorithm.SHA1;
                                            ByteArrayOutputStream ostream = new ByteArrayOutputStream();

                                            rb.encode(ostream);
                                            digest = SHADigest.digest(ostream.toByteArray());
                                        } catch (NoSuchAlgorithmException ex) {
                                            //log("digest fail");
                                        }

                                        org.mozilla.jss.pkix.cms.SignerInfo signInfo = new
                                                org.mozilla.jss.pkix.cms.SignerInfo(si, null, null,
                                                        OBJECT_IDENTIFIER.id_cct_PKIResponse,
                                                        digest, signAlg,
                                                        privKey);
                                        SET signInfos = new SET();

                                        signInfos.addElement(signInfo);

                                        SET digestAlgs = new SET();

                                        if (digestAlg != null) {
                                            AlgorithmIdentifier ai = new
                                                    AlgorithmIdentifier(digestAlg.toOID(),
                                                            null);

                                            digestAlgs.addElement(ai);
                                        }

                                        SET jsscerts = new SET();

                                        for (int j = 0; j < certsInChain.length; j++) {
                                            ByteArrayInputStream is = new
                                                    ByteArrayInputStream(certsInChain[j].getEncoded());
                                            org.mozilla.jss.pkix.cert.Certificate certJss =
                                                    (org.mozilla.jss.pkix.cert.Certificate)
                                                    org.mozilla.jss.pkix.cert.Certificate.getTemplate().decode(is);

                                            jsscerts.addElement(certJss);
                                        }

                                        SignedData fResponse = new
                                                SignedData(digestAlgs, ci,
                                                        jsscerts, null, signInfos);
                                        org.mozilla.jss.pkix.cms.ContentInfo fullResponse =
                                                new
                                                org.mozilla.jss.pkix.cms.ContentInfo(
                                                        org.mozilla.jss.pkix.cms.ContentInfo.SIGNED_DATA, fResponse);
                                        ByteArrayOutputStream ostream = new
                                                ByteArrayOutputStream();

                                        fullResponse.encode(ostream);
                                        byte[] fr = ostream.toByteArray();

                                        header.addStringValue(FULL_RESPONSE, CMS.BtoA(fr));
                                    }
                                } catch (Exception e) {
                                    e.printStackTrace();
                                    log(ILogger.LL_FAILURE,
                                            CMS.getLogMessage("CMSGW_ERROR_FORMING_PKCS7_1", e.toString()));
                                    throw new ECMSGWException(
                                            CMS.getUserMessage("CMS_GW_FORMING_PKCS7_ERROR"));
                                }
                            }
                            argSet.addRepeatRecord(rarg);
                        }
                    }
                }
            }
        }

        try {
            ServletOutputStream out = resp.getOutputStream();

            if (error == null) {
                String xmlOutput = req.getParameter("xml");
                if (xmlOutput != null && xmlOutput.equals("true")) {
                    outputXML(resp, argSet);
                } else {
                    resp.setContentType("text/html");
                    form.renderOutput(out, argSet);
                    cmsReq.setStatus(ICMSRequest.SUCCESS);
                }
            } else {
                cmsReq.setStatus(ICMSRequest.ERROR);
                cmsReq.setError(error);
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
    }
}
