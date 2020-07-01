//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

package org.dogtagpki.ct;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.Integer;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import org.apache.commons.net.ntp.TimeStamp;
import org.dogtagpki.ct.CTRequest;
import org.dogtagpki.ct.CTResponse;
import org.dogtagpki.ct.LogServer;
import org.dogtagpki.ct.sct.SCTProcessor;
import com.netscape.certsrv.ca.AuthorityID;
import org.dogtagpki.server.ca.ICertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.http.HttpClient;
import com.netscape.cmsutil.http.HttpRequest;
import com.netscape.cmsutil.http.HttpResponse;

import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;

import com.netscape.cmscore.cert.CertUtils;

/**
 * Certificate Transparency (v1) engine for CA
 *   to issue CT certs with Embedded Signed Certificate Timestamp
 *   - https://tools.ietf.org/html/rfc6962
 *
 * @author Christina Fu
 *
 */
public class CTEngine {
    public static org.slf4j.Logger logger =
            org.slf4j.LoggerFactory.getLogger(CTEngine.class);

    SCTProcessor ctConfig = null;
    public void init()  throws Exception {
        // for getting CT config from CS.cfg
        ctConfig = new SCTProcessor();

        // Initialize CT configuration
        ctConfig.init();
    }

    /**
     * Process cert info for Certificate Transparency
     * 
     * Check to see if certInfo contains Certificate Transparency poison
     * extension (from profile containig certTransparencyExtDefaultImpl);
     *
     * If not, check if global setting is enabled in CS.cfg:
     *    ca.certTransparency.enable
     * and add the poision extension;
     *
     * if it does then reach out to the CT log servers to obtain
     * signed certificate timestamp (SCT) for inclusion of the SCT extension
     * in the cert to be issued.
     *
     */
    public void process(X509CertInfo certi, ICertificateAuthority ctCA, AuthorityID aid, String algname)
            throws EBaseException {

        String method = "CTEngine.process: ";
        ICertificateAuthority ca = ctCA.getCA(aid);
        String errMsg = "";

        try {
            if (ctConfig == null) {
                init();
            }

            CertificateExtensions exts = (CertificateExtensions) certi.get(X509CertInfo.EXTENSIONS);
            logger.debug(method + " about to check CT poison");
            Extension ctPoison = null;
            try {
                ctPoison = (Extension) exts.get("1.3.6.1.4.1.11129.2.4.3");
                logger.debug(method + " CT poison extension found");
            } catch (Exception e) {
                logger.debug(method + e.getMessage() + "-- continue");
                logger.debug(method + " CT poison extension not found");
            }

            /*
             * see CTmode for CT mode config info
             */
            boolean processCT = false;
            SCTProcessor.CTmode ct_mode = ctConfig.getCTmode();
            if (ct_mode == SCTProcessor.CTmode.enabled) {
                logger.debug(method + "ct_mode is enabled");
                if (ctPoison == null) {
                    logger.debug(method + " adding poison ext");
                    CertUtils.addCTv1PoisonExt(certi);
                    logger.debug(method + " returned from addCTpoisonExt");
                }
                processCT = true;
            } else if (ct_mode == SCTProcessor.CTmode.perProfile) {
                logger.debug(method + "ct_mode is perProfile");
                if (ctPoison != null)
                    processCT = true;
            } else if (ct_mode == SCTProcessor.CTmode.disabled) {
                logger.debug(method + "ct_mode is disabled");
                if (ctPoison != null) {
                    exts.delete("1.3.6.1.4.1.11129.2.4.3");
                    // debug print without poison ext
                    CertUtils.printExtensions(exts);
                    certi.delete(X509CertInfo.EXTENSIONS);
                    certi.set(X509CertInfo.EXTENSIONS, exts);
                    logger.debug(method + " ctPoison ext deleted");
                }
            } else { //unlikely, but ...
                errMsg = method + "unknown ct_mode: " + ct_mode;
                logger.error(errMsg);
                throw new EBaseException(errMsg);
            }

            if (!processCT) {
                logger.debug(method + " no CT processing needed");
                return;
            }

            logger.debug(method + " processing CT");
            // debug print with poison ext
            CertUtils.printExtensions(exts);

            logger.debug(method + " About to ca.sign CT pre-cert.");
            X509CertImpl cert = ca.sign(certi, algname);
            // compose CTRequest
            CTRequest ctRequest = createCTRequest(cert, ctCA);

            /*
             * remove the poison extension from certi
             */
            exts.delete("1.3.6.1.4.1.11129.2.4.3");
            logger.debug(method + " ctPoison deleted");
            // debug print without poison ext
            CertUtils.printExtensions(exts);
            certi.delete(X509CertInfo.EXTENSIONS);
            certi.set(X509CertInfo.EXTENSIONS, exts);
            /*
             * tbsCert is the tbsCert after poision ext was deleted
             *
             * It is intended to be used for verifying the SCT signature in the CT response
             * later, if possible (see verifySCT for detail)
             */
            byte[] tbsCert = certi.getEncodedInfo(true);

            List<LogServer> logServers = ctConfig.getLogServerConfig();
            List<String> ctResponses = new ArrayList<>();

            // loop through all CT log servers
            for (LogServer ls : logServers) {
                logger.debug(method + "Processing log server ID: " + ls.getId());

                String ct_host = ls.getUrl().getHost();
                logger.debug(method + "Log server host: " + ct_host);

                int ct_port = ls.getUrl().getPort();
                logger.debug(method + "Log server port: " + ct_port);

                // TODO: Refactor to form right rest API
                String ct_uri = ls.getUrl() + "ct/v1/add-pre-chain";
                logger.debug(method + "Log server URI: " + ct_uri);

                String respS = certTransSendReq(ct_host, ct_port, ct_uri, ctRequest);
                if (respS == null) {
                    errMsg = method + "Response from CT log server null";
                    logger.warn(errMsg);
                    // allow for CT log to fail to respond
                    // skip to next CT log server
                    continue;
                }
                logger.debug(method + "Response from CT log server " + respS);

                // verify the sct

                /* TODO this should be a configurable; hardcoded for now */
                boolean allowFailedSCTVerification = true;

                boolean verified = verifySCT(CTResponse.fromJSON(respS), tbsCert, ls.getPublicKey(), ctCA);
                if (verified) {
                    logger.info(method + "verifySCT returned true; SCT is valid");
                } else {
                    // log at WARN if !verified, regardless of how we are treating
                    // failed verifications, because it is indicative of log server
                    // misbehavoiur
                    logger.warn(method + "verifySCT returns false; SCT failed to verify");
                }
                if (verified || allowFailedSCTVerification) {
                    ctResponses.add(respS);
                } else {
                    throw new EBaseException(errMsg);
                }
            }

            /**
             * Now onto turning the precert into a real cert with the SCT list extension
             */

            // create SCT extension
            Extension sctExt = createSCTextension(ctResponses);
            if (sctExt == null) {
                errMsg = " createSCTextension returns null";
                logger.debug(method + errMsg);
                throw new EBaseException(errMsg);
            }

            // add the SCT extension
            exts.set(sctExt.getExtensionId().toString(), sctExt);

            certi.delete(X509CertInfo.EXTENSIONS);
            certi.set(X509CertInfo.EXTENSIONS, exts);
            CertUtils.printExtensions(exts);
        } catch (Exception e) {
            logger.error(method + "Error occurred: " + e.getMessage(), e);
            throw new EBaseException(e.getMessage());
        }
    }

    /**
     * (Certificate Transparency)
     *
     * timeStampHexStringToByteArray converts timestamp hex string to bytes
     *   - example timestamp: 00000172.71270909
     * @param timeStampString hex string (example above)
     * @return byte[] timestamp in byte array
     */
    public static byte[] timeStampHexStringToByteArray(String timeStampString) {
        String method = "CTEngine.timeStampHexStringToByteArray: ";
        int len = timeStampString.length();
        logger.debug(method + "len =" + len);
        byte[] data = new byte[(len-1) / 2];
        for (int i = 0; i < len; i += 2) {
            if (i == 8 ) {
                i--; // skip the '.' and at i+=2 it will move to next digit
                continue;
            }
            data[i / 2] = (byte) ((Character.digit(timeStampString.charAt(i), 16) << 4)
                             + Character.digit(timeStampString.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * createSCTextension - creates the SCT extension which encompasses
     * SCT returned from each CT log
     *
     * (Certificate Transparency V1)
     *
       https://tools.ietf.org/html/rfc6962
       ...
          a certificate authority MAY submit a Precertificate to
          more than one log, and all obtained SCTs can be directly embedded in
          the final certificate, by encoding the SignedCertificateTimestampList
          structure as an ASN.1 OCTET STRING and inserting the resulting data
          in the TBSCertificate as an X.509v3 certificate extension (OID
          1.3.6.1.4.1.11129.2.4.2).  Upon receiving the certificate, clients
          can reconstruct the original TBSCertificate to verify the SCT
          signature.
       ...

       SCT response:

       struct {
           Version sct_version;
           LogID id;
           uint64 timestamp;
           CtExtensions extensions;
           digitally-signed struct {
               Version sct_version;
               SignatureType signature_type = certificate_timestamp;
               uint64 timestamp;
               LogEntryType entry_type;
               select(entry_type) {
                   case x509_entry: ASN.1Cert;
                   case precert_entry: PreCert;
               } signed_entry;
              CtExtensions extensions;
           };
       } SignedCertificateTimestamp;

    * @param ctResponses: list of CTResponse as input param
    * @return SCT extension
    */
    Extension createSCTextension(List<String> ctResponses) {

        String method = "CTEngine.createSCTextension:";
        logger.debug(method + "begins");
        if (ctResponses.size() == 0) {
            logger.debug(method + "ctResponses size 0; returning null");
            return null;
        }

        boolean ct_sct_critical = false;
        ObjectIdentifier ct_sct_oid = new ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2");

        /*
              TLS encoding:
               [ total len : 2 bytes ]
                   [ sct1 len : 2 bytes ]
                   [ sct1 ]
                   [ sct2 len : 2 bytes ]
                   [ sct2 ]
                   ...
                   [ sctx ...]
        */
        try {
            int tls_len = 0;

            ByteArrayOutputStream sct_ostream = new ByteArrayOutputStream();
            for (int i = 0; i < ctResponses.size(); i++) {
                // loop through each ctResponse
                CTResponse response = CTResponse.fromJSON(ctResponses.get(i));
                byte ct_version[] = new byte[] {0}; // sct_version
                byte ct_id[] = CryptoUtil.base64Decode(response.getId()); // id
                logger.debug(method + " ct_id: " + CertUtils.bytesToHex(ct_id));

                long timestamp_l = response.getTimestamp();
                TimeStamp timestamp_t = new TimeStamp(timestamp_l);
                String timestamp_s = timestamp_t.toString();
                logger.debug(method + " ct_timestamp: " + timestamp_s);
                // timestamp
                byte ct_timestamp[] = timeStampHexStringToByteArray(timestamp_s);

                String extensions_s = response.getExtensions();
                if (extensions_s == null) {
                    extensions_s = "";
                }
                byte[] ct_extensions = CryptoUtil.base64Decode(extensions_s);

                // signature
                byte ct_signature[] = CryptoUtil.base64Decode(response.getSignature());
                logger.debug(method + " ct_signature: " + CertUtils.bytesToHex(ct_signature));

                int sct_len =
                    ct_version.length
                    + ct_id.length
                    + ct_timestamp.length
                    + 2 + ct_extensions.length
                    + ct_signature.length;
                logger.debug(method + " sct_len = "+ sct_len);
                tls_len += (2 + sct_len); // add 2 bytes for sct len itself

                sct_ostream.write(CertUtils.intToFixedWidthBytes(sct_len, 2));
                sct_ostream.write(ct_version);
                sct_ostream.write(ct_id);
                sct_ostream.write(ct_timestamp);

                // 2 bytes for extensions len
                sct_ostream.write(CertUtils.intToFixedWidthBytes(ct_extensions.length, 2));
                sct_ostream.write(ct_extensions);

                sct_ostream.write(ct_signature);
            }

            ByteArrayOutputStream tls_sct_ostream = new ByteArrayOutputStream();
            tls_sct_ostream.write(CertUtils.intToFixedWidthBytes(tls_len, 2));
            sct_ostream.writeTo(tls_sct_ostream);
            byte[] tls_sct_bytes = tls_sct_ostream.toByteArray();

            Extension ct_sct_ext = new Extension();
            try (DerOutputStream out = new DerOutputStream()) {
                out.putOctetString(tls_sct_bytes);
                ct_sct_ext.setExtensionId(ct_sct_oid);
                ct_sct_ext.setCritical(false);
                ct_sct_ext.setExtensionValue(out.toByteArray());
                logger.debug(method + " ct_sct_ext id = " +
                    ct_sct_ext.getExtensionId().toString());
                logger.debug(method + " CT extension constructed");
            } catch (IOException e) {
                logger.debug(method + e.toString());
                return null;
            } catch (Exception e) {
                logger.debug(method + e.toString());
                return null;
            }

            return ct_sct_ext;
        } catch (Exception ex) {
            logger.debug(method + ex.toString());
            return null;
        }
    }

    /**
     * VerifySCT - conducts some verification of the SCT response returned
     * from the CT log
     *
     * Two primary checks are intended to be performed in this method:
     *
     *   1. (works) verify that the log id in the CT response matches the CT log
     *      signer public key hash;
     *      - ToDo: consider putting the hash in CS.cfg to avoid run time
     *        calculation
     *   2. verify the signature in the CT against the SCT in
     *        response
     *      - concern: what if the extensions become out of order
     *        during removal of the poison extension on the CT log server?
     *        This could make it very difficult to check the signature,
     *        since the CT response does not contain the tbsCert it signs.
     *
     * (Certificate Transparency)

           digitally-signed struct {
               Version sct_version;
               SignatureType signature_type = certificate_timestamp; == 0 for ct
               uint64 timestamp;
               LogEntryType entry_type; ===> 1 for precert
               select(entry_type) {
                   case x509_entry: ASN.1Cert;
                   case precert_entry: PreCert;
               } signed_entry;
              CtExtensions extensions;
           };

         struct { ==> 32 bit sha256 hash of issuer pub key + DER of precert
           opaque issuer_key_hash[32];
           TBSCertificate tbs_certificate;
         } PreCert;
    *
    * @param response CT log server response
    * @param tbsCert encoded TBSCert
    * @param logPublicKey public key of log
    * @return boolean true for verified; false for not verified
    */
    boolean verifySCT(CTResponse response, byte[] tbsCert, String logPublicKey, ICertificateAuthority ctCA) {
        String method = "CTEngine.:verifySCT: ";
        String errMsg = "";
        logger.debug(method + "begins");

        try {
            long timestamp_l = response.getTimestamp();
            TimeStamp timestamp_t = new TimeStamp(timestamp_l);
            String timestamp_s = timestamp_t.toString();
            logger.debug(method + " ct_timestamp: " + timestamp_s);
            // timestamp
            byte timestamp[] = timeStampHexStringToByteArray(timestamp_s);

            /* Signature hash and algorithm; values defined in
             * https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
             * and elsewhere.
             *
             * First byte is hash alg.
             * Second byte is sig alg.
             * Bytes 3 and 4 are length of signature data.
             *
             * struct {
             *   SignatureAndHashAlgorithm algorithm;
             *   opaque signature<0..2^16-1>;
             * } DigitallySigned;
             *
             * enum {
             *     none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
             *     sha512(6), (255)
             * } HashAlgorithm;
             *
             * enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
             *   SignatureAlgorithm;
             *
             * struct {
             *       HashAlgorithm hash;
             *       SignatureAlgorithm signature;
             * } SignatureAndHashAlgorithm;
             */
            byte ct_signature[] = CryptoUtil.base64Decode(response.getSignature());
            byte[] signature = Arrays.copyOfRange(ct_signature, 4, ct_signature.length);
            String hashAlg = getHashAlgFromSig(ct_signature);
            if (hashAlg == null) {
                logger.debug(method + "invalid hashing algorithms");
                return false;
            }

            String sigAlg = getSigAlgFromSig(ct_signature);
            if (sigAlg == null) {
                logger.debug(method + "invalid sig algorithms");
                return false;
            }

            /* compose data */
            byte[] version = new byte[] {0}; // 1 byte; v1(0)
            byte[] signature_type = new byte[] {0}; // 1 byte; certificate_timestamp(0)
            byte[] entry_type = new byte[] {0, 1}; // 2 bytes; LogEntryType: precert_entry(1)

            logger.debug(method + "using CT log public key: " + logPublicKey);
            byte logPublicKey_b[] = CryptoUtil.base64Decode(logPublicKey);

            // First, verify the log id
            PublicKey log_pubKey = KeyFactory.getInstance("EC", "Mozilla-JSS").generatePublic(
                    new X509EncodedKeySpec(logPublicKey_b));

            byte[] log_key_hash = null;
            MessageDigest SHA256Digest = MessageDigest.getInstance("SHA256");

            log_key_hash = SHA256Digest.digest(log_pubKey.getEncoded());
            String log_key_hash_s = CryptoUtil.base64Encode(log_key_hash);
            logger.debug(method + "CT log signer key hash: " + log_key_hash_s);
            if (log_key_hash_s.compareTo(response.getId()) == 0) {
                logger.debug(method + "CT log signer key hash matches key id");
            } else {
                errMsg = "CT log signer key hash does not match key id!!";
                logger.error(method +  errMsg);
                return false;
            }

            /** per rfc 6962 -
             * "issuer_key_hash" is the SHA-256 hash of the certificate issuer's
             * public key, calculated over the DER encoding of the key represented
             * as SubjectPublicKeyInfo.  This is needed to bind the issuer to the
             * final certificate.
             */
            X509CertImpl cacert = ctCA.getCACert();
            byte[] issuer_key = cacert.getPublicKey().getEncoded();
            byte[] issuer_key_hash = SHA256Digest.digest(issuer_key);

            String extensions_s = response.getExtensions();
            if (extensions_s == null) {
                extensions_s = "";
            }
            byte[] extensions = CryptoUtil.base64Decode(extensions_s);

            // piece them together
            int data_len = version.length + signature_type.length +
                     timestamp.length + entry_type.length +
                     issuer_key_hash.length
                     + 3 + tbsCert.length
                     + 2 + extensions.length;
            logger.debug(method + " data_len = "+ data_len);

            ByteArrayOutputStream ostream = new ByteArrayOutputStream();

            ostream.write(version);
            ostream.write(signature_type);
            ostream.write(timestamp);

            ostream.write(entry_type);
            ostream.write(issuer_key_hash);

            // 3 bytes for length of tbsCert
            ostream.write(CertUtils.intToFixedWidthBytes(tbsCert.length, 3));
            ostream.write(tbsCert);

            // 2 bytes for extensions len
            ostream.write(CertUtils.intToFixedWidthBytes(extensions.length, 2));
            ostream.write(extensions);

            byte[] data = ostream.toByteArray();
            logger.debug(method + "actual data len = " + data.length);

            Signature signer = Signature.getInstance(
                    hashAlg + "with"+ sigAlg, "Mozilla-JSS");
            signer.initVerify(log_pubKey);
            signer.update(data);

            return signer.verify(signature);
        } catch (Throwable e) {
            logger.debug(method + "Exception thrown: " + e.toString(), e);
            return false;
        } finally {
            logger.debug(method + "ends");
        }
    }

    /**
     * parses and gleans the hashing algorithm from the returned
     * CT signature
     *
     *  enum HashAlgorithm {
     *      none, md5, sha1, sha224, sha256, sha384, sha512};
     */
    enum HashAlgorithm {none, MD5, SHA1, SHA224, SHA256, SHA384, SHA512};
    public String getHashAlgFromSig(byte[] ct_signature) {

        int hashingAlg = Byte.toUnsignedInt(ct_signature[0]);
        if (hashingAlg != 4) // only SHA256 supported for v1
            return null;

        return HashAlgorithm.values()[hashingAlg].name();
    }

    /**
     * parses and gleans the signature algorithm from the returned
     * CT signature
     *
     * enum SignatureAlgorithm { anonymous, rsa, dsa, ecdsa}
     */
    enum SignatureAlgorithm {anonymous, RSA, DSA, EC};
    public String getSigAlgFromSig(byte[] ct_signature) {

        int signingAlg = Byte.toUnsignedInt(ct_signature[1]);
        if (signingAlg < 1 || signingAlg > 3)
            return null;

        return SignatureAlgorithm.values()[signingAlg].name();
    }

    /**
     * (Certificate Transparency)
     * Given a leaf cert, build chain and format a JSON request
     * @param leaf cert
     * @return JSON request in String
     */
    CTRequest createCTRequest(X509CertImpl cert, ICertificateAuthority ctCA)
           throws EBaseException {
        String method = "CTEngine.createCTRequest";

        CTRequest ctRequest = new CTRequest();

        List<String> certChain = new ArrayList<>();

        // Create chain, leaf first
        ByteArrayOutputStream certOut = new ByteArrayOutputStream();
        CertificateChain caCertChain = ctCA.getCACertChain();
        X509Certificate[] caUnsortedCerts = caCertChain.getChain();

        try {
            // first, leaf cert;
            cert.encode(certOut);
            byte[] certBytes = certOut.toByteArray();
            certOut.reset();
            certChain.add(Utils.base64encode(certBytes, false));

            // then add the ca chain, in order (from subCAs to root);
            X509Certificate[] caSortedCerts = Cert.sortCertificateChain(caUnsortedCerts, true);
            for (int n = 0; n < caSortedCerts.length; n++) {
                X509CertImpl caCertInChain = (X509CertImpl) caSortedCerts[n];
                caCertInChain.encode(certOut);
                certBytes = certOut.toByteArray();
                certOut.reset();
                logger.debug(method + "caCertInChain " + n + " = " +
                        Utils.base64encode(certBytes, false));
                certChain.add(Utils.base64encode(certBytes, false));
            }
            certOut.close();

            ctRequest.setCerts(certChain);
            logger.debug(method + " ct_json_request:" + ctRequest.toString());
        } catch (Exception e) {
            logger.debug(method + e.toString());
            throw new EBaseException(e.toString());
        }
        return ctRequest;
    }

    /**
     * (Certificate Transparency)
     * certTransSendReq connects to CT host and send ct request
     * @param ct_host host name
     * @param ct_port port #
     * @param ct_uri uri of the CT log server
     * @param ctReq CT request
     * @return response content from CT log server
     */
    private String certTransSendReq(String ct_host, int ct_port, String ct_uri, CTRequest ctReq) {
        String method = "CTEngine.certTransSendReq: ";
        HttpClient client = new HttpClient();
        HttpRequest req = new HttpRequest();
        HttpResponse resp = null;

        logger.debug(method + "begins");
        try {
            client.connect(ct_host, ct_port);
            req.setMethod("POST");
            req.setURI(ct_uri);
            req.setHeader("Content-Type", "application/json");
            req.setContent(ctReq.toString());
            req.setHeader("Content-Length", Integer.toString(ctReq.toString().length()));

            resp = client.send(req);
            if (resp == null)
                return null;
            logger.debug("version " + resp.getHttpVers());
            logger.debug("status code " + resp.getStatusCode());
            logger.debug("reason " + resp.getReasonPhrase());
            logger.debug("content " + resp.getContent());
            logger.debug("CAService.certTransSendReq ends");
        } catch (Exception e) {
            logger.debug(method + e.toString());
            return null;
        }

        return (resp.getContent());
    }

}
