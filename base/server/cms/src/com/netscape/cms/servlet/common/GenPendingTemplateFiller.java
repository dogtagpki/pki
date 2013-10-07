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
package com.netscape.cms.servlet.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Locale;

import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.pkix.cmc.CMCStatusInfo;
import org.mozilla.jss.pkix.cmc.OtherInfo;
import org.mozilla.jss.pkix.cmc.PendInfo;
import org.mozilla.jss.pkix.cmc.ResponseBody;
import org.mozilla.jss.pkix.cmc.TaggedAttribute;
import org.mozilla.jss.pkix.cms.ContentInfo;
import org.mozilla.jss.pkix.cms.EncapsulatedContentInfo;
import org.mozilla.jss.pkix.cms.IssuerAndSerialNumber;
import org.mozilla.jss.pkix.cms.SignedData;
import org.mozilla.jss.pkix.cms.SignerIdentifier;
import org.mozilla.jss.pkix.cms.SignerInfo;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;

/**
 * default Pending template filler
 *
 * @version $Revision$, $Date$
 */
public class GenPendingTemplateFiller implements ICMSTemplateFiller {
    public static String FULL_RESPONSE = "cmcFullEnrollmentResponse";

    public GenPendingTemplateFiller() {
    }

    /**
     * fill error details and description if any.
     *
     * @param cmsReq CMS Request
     * @param authority this authority
     * @param locale locale of template.
     * @param e unexpected exception e. ignored.
     */
    public CMSTemplateParams getTemplateParams(
            CMSRequest cmsReq, IAuthority authority, Locale locale, Exception e) {
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams params = new CMSTemplateParams(null, fixed);

        if (cmsReq == null) {
            return null;
        }

        // request status if any.
        Integer sts = cmsReq.getStatus();

        if (sts != null)
            fixed.set(ICMSTemplateFiller.REQUEST_STATUS, sts.toString());

        // request id
        IRequest req = cmsReq.getIRequest();

        if (req != null) {
            RequestId reqId = req.getRequestId();

            fixed.set(ICMSTemplateFiller.REQUEST_ID, reqId);
            // set pendInfo, CMCStatusInfo
            IArgBlock httpParams = cmsReq.getHttpParams();

            if (doFullResponse(httpParams)) {
                SEQUENCE controlSeq = new SEQUENCE();
                int bpid = 1;
                PendInfo pendInfo = new PendInfo(reqId.toString(), new
                        Date());
                OtherInfo otherInfo = new
                        OtherInfo(OtherInfo.PEND, null, pendInfo);
                SEQUENCE bpids = new SEQUENCE();
                String[] reqIdArray =
                        req.getExtDataInStringArray(IRequest.CMC_REQIDS);

                for (int i = 0; i < reqIdArray.length; i++) {
                    bpids.addElement(new INTEGER(reqIdArray[i]));
                }
                CMCStatusInfo cmcStatusInfo = new
                        CMCStatusInfo(CMCStatusInfo.PENDING, bpids,
                                (String) null, otherInfo);
                TaggedAttribute ta = new TaggedAttribute(new
                        INTEGER(bpid++),
                        OBJECT_IDENTIFIER.id_cmc_cMCStatusInfo,
                        cmcStatusInfo);

                controlSeq.addElement(ta);
                // copy transactionID, senderNonce,
                // create recipientNonce
                // create responseInfo if regInfo exist
                String[] transIds =
                        req.getExtDataInStringArray(IRequest.CMC_TRANSID);
                SET ids = new SET();

                for (int i = 0; i < transIds.length; i++) {
                    ids.addElement(new INTEGER(transIds[i]));
                }
                ta = new TaggedAttribute(new
                            INTEGER(bpid++),
                            OBJECT_IDENTIFIER.id_cmc_transactionId,
                            ids);
                controlSeq.addElement(ta);

                String[] senderNonce = req.getExtDataInStringArray(IRequest.CMC_SENDERNONCE);
                SET nonces = new SET();

                for (int i = 0; i < senderNonce.length; i++) {
                    nonces.addElement(new OCTET_STRING(senderNonce[i].getBytes()));
                }
                ta = new TaggedAttribute(new
                            INTEGER(bpid++),
                            OBJECT_IDENTIFIER.id_cmc_recipientNonce,
                            nonces);
                controlSeq.addElement(ta);
                req.setExtData(IRequest.CMC_RECIPIENTNONCE, senderNonce);

                Date date = CMS.getCurrentDate();
                String salt = "lala123" + date.toString();
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
                req.setExtData(IRequest.CMC_SENDERNONCE, newNonce);

                ResponseBody rb = new ResponseBody(controlSeq, new
                        SEQUENCE(), new
                        SEQUENCE());
                EncapsulatedContentInfo ci = new
                        EncapsulatedContentInfo(OBJECT_IDENTIFIER.id_cct_PKIResponse,
                                rb);
                org.mozilla.jss.crypto.X509Certificate x509cert = null;

                if (authority instanceof ICertificateAuthority) {
                    x509cert = ((ICertificateAuthority) authority).getCaX509Cert();
                } else if (authority instanceof IRegistrationAuthority) {
                    x509cert = ((IRegistrationAuthority) authority).getRACert();
                }
                if (x509cert == null)
                    return params;
                try {
                    X509CertImpl cert = new X509CertImpl(x509cert.getEncoded());
                    ByteArrayInputStream issuer1 = new
                            ByteArrayInputStream(((X500Name) cert.getIssuerDN()).getEncoded());
                    Name issuer = (Name) Name.getTemplate().decode(issuer1);
                    IssuerAndSerialNumber ias = new
                            IssuerAndSerialNumber(issuer, new INTEGER(cert.getSerialNumber().toString()));
                    SignerIdentifier si = new
                            SignerIdentifier(SignerIdentifier.ISSUER_AND_SERIALNUMBER, ias, null);

                    // SHA1 is the default digest Alg for now.
                    DigestAlgorithm digestAlg = null;
                    SignatureAlgorithm signAlg = null;
                    org.mozilla.jss.crypto.PrivateKey privKey = CryptoManager.getInstance().findPrivKeyByCert(x509cert);
                    org.mozilla.jss.crypto.PrivateKey.Type keyType = privKey.getType();

                    if (keyType.equals(org.mozilla.jss.crypto.PrivateKey.RSA)) {
                        signAlg = SignatureAlgorithm.RSASignatureWithSHA1Digest;
                    } else if (keyType.equals(org.mozilla.jss.crypto.PrivateKey.DSA)) {
                        signAlg = SignatureAlgorithm.DSASignatureWithSHA1Digest;
                    } else {
                        CMS.debug("GenPendingTemplateFiller::getTemplateParams() - "
                                 + "keyType " + keyType.toString()
                                 + " is unsupported!");
                        return null;
                    }

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

                    SignerInfo signInfo = new
                            SignerInfo(si, null, null,
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

                    SignedData fResponse = new
                            SignedData(digestAlgs, ci,
                                    null, null, signInfos);
                    ContentInfo fullResponse = new
                            ContentInfo(ContentInfo.SIGNED_DATA, fResponse);
                    ByteArrayOutputStream ostream = new
                            ByteArrayOutputStream();

                    fullResponse.encode(ostream);
                    byte[] fr = ostream.toByteArray();

                    fixed.set(FULL_RESPONSE, CMS.BtoA(fr));
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
            }
        }
        // this authority
        if (authority != null)
            fixed.set(ICMSTemplateFiller.AUTHORITY,
                    authority.getOfficialName());
        return params;
    }

    /**
     * handy routine to check if client want full enrollment response
     */
    public static boolean doFullResponse(IArgBlock httpParams) {
        if (httpParams.getValueAsBoolean("fullResponse", false))
            return true;
        else
            return false;
    }
}
