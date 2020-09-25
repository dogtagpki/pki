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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps.cms;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.util.Hashtable;
import java.util.List;

import org.dogtagpki.server.connector.IRemoteRequest;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.Util;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.connector.HttpConnector;
import com.netscape.cmsutil.http.HttpResponse;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * CARemoteRequestHandler is a class representing remote requests
 * offered by the Certificate Authority (CA)
 *
 * @author cfu
 */
public class CARemoteRequestHandler extends RemoteRequestHandler
{
    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CARemoteRequestHandler.class);

    public CARemoteRequestHandler(String connID)
            throws EBaseException {
        if (connID == null) {
            throw new EBaseException("CARemoteRequestHandler: CARemoteRequestHandler(): connID null.");
        }
        connid = connID;
    }

    /**
     * enrollCertificate enrolls a certificate in the CA
     *
     * @param pubKeybuf public key for enrollment
     * @param uid uid for enrollment
     * @param cuid token id
     *
     * @returns CAEnrollCertResponse
     */
    public CAEnrollCertResponse enrollCertificate(
            TPSBuffer pubKeybuf,
            String uid,
            String cuid,
            String tokenType,
            String keyType)
            throws EBaseException {
        return enrollCertificate(pubKeybuf, uid, null /*subjectdn*/,
                0/*sanNum*/, null /*urlSANext*/,
                cuid, tokenType, keyType);
    }

    public CAEnrollCertResponse enrollCertificate(
            TPSBuffer pubKeybuf,
            String uid,
            String subjectdn,
            int sanNum,
            String urlSANext,
            String cuid,
            String tokenType,
            String keyType)
            throws EBaseException {

        String method = "CARemoteRequestHandler: enrollCertificate()";
        logger.debug(method + ": begins.");
        if (pubKeybuf == null || uid == null || cuid == null) {
            throw new EBaseException(method + ": input parameter null.");
        }

        // tokenType could be null. If it is, make it an empty string.
        if(tokenType == null)
            tokenType = "";

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        EngineConfig conf = engine.getConfig();
        String profileId =
                conf.getString(TPSEngine.OP_ENROLL_PREFIX + "." +
                        tokenType + ".keyGen." +
                        keyType + ".ca.profileId");

        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);
        if (conn == null) {
            throw new EBaseException(method + " to connid: " + connid + ": HttpConnector conn null.");
        }
        logger.debug(method + ": sending request to CA");
        String encodedPubKey = null;
        try {
            encodedPubKey = Util.uriEncode(Utils.base64encode(pubKeybuf.toBytesArray(), true));
        } catch (Exception e) {
            logger.error(method + ": uriEncode of pubkey failed: " + e.getMessage(), e);
            throw new EBaseException(method + ": uriEncode of pubkey failed: " + e);
        }
        String sendMsg = null;
        if (subjectdn == null)
            logger.debug(method + ":subjectdn null");
        if (sanNum == 0)
            logger.debug(method + ":sanNum 0");
        if (subjectdn == null && sanNum == 0) {
            sendMsg = IRemoteRequest.GET_XML + "=" +
                    true +
                    "&" + IRemoteRequest.TOKEN_CUID + "=" +
                    cuid +
                    "&" + IRemoteRequest.CA_ENROLL_screenname + "=" +
                    uid +
                    "&" + IRemoteRequest.CA_ENROLL_publickey + "=" +
                    encodedPubKey +
                    "&" + IRemoteRequest.CA_ProfileId + "=" +
                    profileId +
                    "&" + IRemoteRequest.CA_ENROLL_tokentype + "=" +
                    tokenType;
        } else {
            logger.debug(method + ": before send() with subjectdn and/or url_SAN_ext");
            if (subjectdn != null && sanNum == 0) {
                try {
                    String urlSubjectdn = Util.uriEncode(subjectdn);
                    sendMsg = IRemoteRequest.GET_XML + "=" +
                            true +
                            "&" + IRemoteRequest.TOKEN_CUID + "=" +
                            cuid +
                            "&" + IRemoteRequest.CA_ENROLL_screenname + "=" +
                            uid +
                            "&" + IRemoteRequest.CA_ENROLL_publickey + "=" +
                            encodedPubKey +
                            "&" + IRemoteRequest.CA_ProfileId + "=" +
                            profileId +
                            "&" + IRemoteRequest.CA_ENROLL_subjectdn + "=" +
                            urlSubjectdn +
                            "&" + IRemoteRequest.CA_ENROLL_tokentype + "=" +
                            tokenType;
                } catch (Exception e) {
                    logger.error(method + ": uriEncode of pubkey failed: " + e.getMessage(), e);
                    throw new EBaseException(
                            method + ": uriEncode of subjectdn failed: " + e);
                }
            } else if (subjectdn == null && sanNum != 0) {
                sendMsg = IRemoteRequest.GET_XML + "=" +
                        true +
                        "&" + IRemoteRequest.TOKEN_CUID + "=" +
                        cuid +
                        "&" + IRemoteRequest.CA_ENROLL_screenname + "=" +
                        uid +
                        "&" + IRemoteRequest.CA_ENROLL_publickey + "=" +
                        encodedPubKey +
                        "&" + IRemoteRequest.CA_ProfileId + "=" +
                        profileId +
                        "&" + IRemoteRequest.CA_ENROLL_tokentype + "=" +
                        tokenType +
                        "&" + urlSANext;
            } else if (subjectdn != null && sanNum != 0) {
                try {
                    String urlSubjectdn = Util.uriEncode(subjectdn);
                    sendMsg = IRemoteRequest.GET_XML + "=" +
                            true +
                            "&" + IRemoteRequest.TOKEN_CUID + "=" +
                            cuid +
                            "&" + IRemoteRequest.CA_ENROLL_screenname + "=" +
                            uid +
                            "&" + IRemoteRequest.CA_ENROLL_publickey + "=" +
                            encodedPubKey +
                            "&" + IRemoteRequest.CA_ProfileId + "=" +
                            profileId +
                            "&" + IRemoteRequest.CA_ENROLL_subjectdn + "=" +
                            urlSubjectdn +
                            "&" + IRemoteRequest.CA_ENROLL_tokentype + "=" +
                            tokenType +
                            "&" + urlSANext;
                } catch (Exception e) {
                    logger.error(method + ": uriEncode of pubkey failed: " + e.getMessage(), e);
                    throw new EBaseException(
                            method + ": uriEncode of subjectdn failed: " + e);
                }
            }
        }
        //logger.debug(method + ": sendMsg =" + sendMsg);
        HttpResponse resp =
                conn.send("enrollment", sendMsg);
        if (resp == null) {
            throw new EBaseException(method + " to connid: " + connid + ": response null.");
        }

        String content = resp.getContent();

        if (content != null && !content.equals("")) {
            //logger.debug(method + ": got content = " + content);
            logger.debug(method + ": got content");
            XMLObject xmlResponse =
                    getXMLparser(content);

            Hashtable<String, Object> response =
                    new Hashtable<String, Object>();

            /**
             * When a value is not found in response, keep going so we know
             * what else is missing
             * Note: serverKeygen and !serverKeygen returns different set of
             * response values so "missing" might not be bad
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = xmlResponse.getValue(IRemoteRequest.RESPONSE_STATUS_XML);
            if (value == null) {
                logger.debug(method + ": Status not found.");
                //logger.debug(method + ": got content = " + content);
                logger.debug(method + ": got content");
            } else {
                logger.debug(method + ": got Status = " + value);
                ist = Integer.parseInt(value);
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            value = xmlResponse.getValue("SubjectDN");
            if (value == null) {
                logger.debug(method + ": response missing name-value pair for: " +
                        IRemoteRequest.CA_RESPONSE_Certificate_SubjectDN);
            } else {
                logger.debug(method + ": got IRemoteRequest.CA_RESPONSE_Certificate_SubjectDN = "
                        + value);
                response.put(IRemoteRequest.CA_RESPONSE_Certificate_SubjectDN, value);
            }

            value = xmlResponse.getValue(IRemoteRequest.CA_RESPONSE_Certificate_serial);
            if (value == null) {
                logger.debug(method + ": response missing name-value pair for: " +
                        IRemoteRequest.CA_RESPONSE_Certificate_serial);
            } else {
                logger.debug(method + ": got IRemoteRequest.CA_RESPONSE_Certificate_serial = 0x"
                        + value);
                response.put(IRemoteRequest.CA_RESPONSE_Certificate_serial, value);
            }

            value = xmlResponse.getValue(IRemoteRequest.CA_RESPONSE_Certificate_b64);
            if (value == null) {
                logger.debug(method + ": response missing name-value pair for: " +
                        IRemoteRequest.CA_RESPONSE_Certificate_b64);
            } else {
                try {
                    //logger.debug(method + ": got IRemoteRequest.CA_RESPONSE_Certificate_b64 = "
                    //        + value);
                    logger.debug(method + ": got IRemoteRequest.CA_RESPONSE_Certificate_b64");
                    response.put(IRemoteRequest.CA_RESPONSE_Certificate_b64, value);
                    X509CertImpl newCert = new X509CertImpl(Utils.base64decode(value));
                    response.put(IRemoteRequest.CA_RESPONSE_Certificate_x509, newCert);
                    logger.debug(method + ": new cert parsed successfully");
                } catch (Exception e) {
                    // we don't exit.  Keep going.
                    logger.warn(method + ": exception:" + e.getMessage(), e);
                }
            }

            logger.debug(method + ": ends.");
            return new CAEnrollCertResponse(connid, response);
        } else {
            logger.error(method + ": no response content");
            throw new EBaseException(method + ": no response content.");
        }
    }

    /**
     * retrieveCertificate retrieves a certificate by serial number
     *
     * @param serialno the serial number of the cert to be retrieved
     * @return CARetrieveCertResponse
     */
    public CARetrieveCertResponse retrieveCertificate(
            BigInteger serialno)
            throws EBaseException {

        String method = "CARemoteRequestHandler: retrieveCertificate()";
        logger.debug(method + ": begins.");
        if (serialno == null) {
            throw new EBaseException(method + ": input parameter null.");
        }

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();

        //ToDo: I"m not sure why these are not used, let's check this out.
        //It's working though.

        /*
        IConfigStore conf = CMS.getConfigStore();
        String configName = "tps.connector." + connid + ".uri.getBySerial";
        String servlet = conf.getString(configName, "/ca/ee/ca/displayBySerial");
        */

        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);
        if (conn == null) {
            throw new EBaseException(method + " to connid: " + connid + ": HttpConnector conn null.");
        }
        logger.debug(method + ": sending request to CA");
        HttpResponse resp =
                conn.send("getcert",
                        IRemoteRequest.GET_XML + "=" + true +
                                "&" + IRemoteRequest.CA_GET_CERT_B64CertOnly + "=" + true +
                                "&" + IRemoteRequest.CA_GET_CERT_SERIAL + "=" + serialno.toString());
        if (resp == null) {
            throw new EBaseException(method + " to connid: " + connid + ": response null.");
        }

        String content = resp.getContent();
        if (content != null && !content.equals("")) {
            XMLObject xmlResponse =
                    getXMLparser(content);

            Hashtable<String, Object> response =
                    new Hashtable<String, Object>();

            //logger.debug(method + ": received:" +
            //        content);
            logger.debug(method + ": content received");

            /**
             * When a value is not found in response, keep going so we know
             * what else is missing
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = xmlResponse.getValue(IRemoteRequest.RESPONSE_STATUS_XML);
            if (value == null) {
                logger.debug(method + ": Status not found.");
                //logger.debug(method + ": got content = " + content);
                logger.debug(method + ": got content");
            } else {
                logger.debug(method + ": got Status = " + value);
                ist = Integer.parseInt(value);
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            value = xmlResponse.getValue(IRemoteRequest.CA_RESPONSE_Certificate_chain_b64);
            if (value == null) {
                logger.debug(method + ": response missing name-value pair for: " +
                        IRemoteRequest.CA_RESPONSE_Certificate_chain_b64);
            } else {
                //logger.debug(method + ": got IRemoteRequest.CA_RESPONSE_Certificate_chain_b64 = "
                //        + value);
                logger.debug(method + ": got IRemoteRequest.CA_RESPONSE_Certificate_chain_b64");
                response.put(IRemoteRequest.CA_RESPONSE_Certificate_chain_b64, value);
                try {
                    X509CertImpl newCert = new X509CertImpl(Utils.base64decode(value));
                    response.put(IRemoteRequest.CA_RESPONSE_Certificate_x509, newCert);
                    logger.debug(method + ": retrieved cert parsed successfully");
                } catch (CertificateException e) {
                    // we don't exit.  Keep going.
                    logger.warn(method + ": exception:" + e.getMessage(), e);
                }
            }

            value = xmlResponse.getValue(IRemoteRequest.CA_RESPONSE_Certificate_RevocationReason);
            if (value == null) {
                logger.debug(method + ": response missing name-value pair for: " +
                        IRemoteRequest.CA_RESPONSE_Certificate_RevocationReason);
            } else {
                logger.debug(method + ": got IRemoteRequest.CA_RESPONSE_Certificate_RevocationReason = "
                        + value);
                response.put(IRemoteRequest.CA_RESPONSE_Certificate_RevocationReason, value);
            }

            logger.debug(method + ": ends.");
            return new CARetrieveCertResponse(connid, response);
        } else {
            logger.error(method + ": no response content");
            throw new EBaseException(method + ": no response content.");
        }
    }

    /**
     * renewCertificate renew a certificate by serial number
     *
     * @param serialno the serial number of the cert to be renewed
     * @return CARenewCertResponse
     */
    public CARenewCertResponse renewCertificate(
            BigInteger serialno,
            String tokenType,
            String keyType)
            throws EBaseException {

        String method = "CARemoteRequestHandler: renewCertificate()";
        logger.debug(method + ": begins.");
        if (serialno == null) {
            throw new EBaseException(method + ": input parameter null.");
        }

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        EngineConfig conf = engine.getConfig();

        String profileId =
                conf.getString(TPSEngine.OP_ENROLL_PREFIX + "." +
                        tokenType + ".renewal." +
                        keyType + ".ca.profileId");

        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);
        if (conn == null) {
            throw new EBaseException(method + " to connid: " + connid + ": HttpConnector conn null.");
        }
        logger.debug(method + ": sending request to CA");
        HttpResponse resp =
                conn.send("renewal",
                        IRemoteRequest.GET_XML + "=" + true +
                                "&" + IRemoteRequest.CA_RENEWAL + "=" + true +
                                "&" + IRemoteRequest.CA_RENEWAL_SerialNum + "=" + serialno.toString() +
                                "&" + IRemoteRequest.CA_ProfileId + "=" + profileId);

        if (resp == null) {
            throw new EBaseException(method + " to connid: " + connid + ": response null.");
        }
        String content = resp.getContent();

        if (content != null && !content.equals("")) {
            XMLObject xmlResponse =
                    getXMLparser(content);

            Hashtable<String, Object> response =
                    new Hashtable<String, Object>();

            logger.debug(method + ": received:" +
                    content);

            /**
             * When a value is not found in response, keep going so we know
             * what else is missing
             * Note: serverKeygen and !serverKeygen returns different set of
             * response values so "missing" might not be bad
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = xmlResponse.getValue(IRemoteRequest.RESPONSE_STATUS_XML);
            if (value == null) {
                logger.debug(method + ": Status not found.");
                //logger.debug(method + ": got content = " + content);
                logger.debug(method + ": got content");
            } else {
                logger.debug(method + ": got Status = " + value);
                ist = Integer.parseInt(value);
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            value = xmlResponse.getValue("SubjectDN");
            if (value == null) {
                logger.debug(method + ": response missing name-value pair for: " +
                        IRemoteRequest.CA_RESPONSE_Certificate_SubjectDN);
            } else {
                logger.debug(method + ": got IRemoteRequest.CA_RESPONSE_Certificate_SubjectDN = "
                        + value);
                response.put(IRemoteRequest.CA_RESPONSE_Certificate_SubjectDN, value);
            }

            value = xmlResponse.getValue(IRemoteRequest.CA_RESPONSE_Certificate_serial);
            if (value == null) {
                logger.debug(method + ": response missing name-value pair for: " +
                        IRemoteRequest.CA_RESPONSE_Certificate_serial);
            } else {
                logger.debug(method + ": got IRemoteRequest.CA_RESPONSE_Certificate_serial = 0x"
                        + value);
                response.put(IRemoteRequest.CA_RESPONSE_Certificate_serial, value);
            }

            value = xmlResponse.getValue(IRemoteRequest.CA_RESPONSE_Certificate_b64);
            if (value == null) {
                logger.debug(method + ": response missing name-value pair for: " +
                        IRemoteRequest.CA_RESPONSE_Certificate_b64);
            } else {
                //logger.debug(method + ": got IRemoteRequest.CA_RESPONSE_Certificate_b64 = "
                //        + value);
                logger.debug(method + ": got IRemoteRequest.CA_RESPONSE_Certificate_b64");
                response.put(IRemoteRequest.CA_RESPONSE_Certificate_b64, value);
                try {
                    X509CertImpl newCert = new X509CertImpl(Utils.base64decode(value));
                    response.put(IRemoteRequest.CA_RESPONSE_Certificate_x509, newCert);
                    logger.debug(method + ": new cert parsed successfully");
                } catch (CertificateException e) {
                    // we don't exit.  Keep going.
                    logger.warn(method + ": exception:" + e.getMessage(), e);
                }
            }

            logger.debug(method + ": ends.");
            return new CARenewCertResponse(connid, response);
        } else {
            logger.error(method + ": no response content");
            throw new EBaseException(method + ": no response content.");
        }
    }

    /**
     * revokeCertificate provides the basic revocation of a certificate from
     * the CA
     *
     * @param serialno serial number of the cert to revoke
     * @param reason reason to revoke per definition in RevocationReason
     *
     * @returns CARevokeCertResponse
     */
    private CARevokeCertResponse revokeCertificate(
            String serialno,
            RevocationReason reason)
            throws EBaseException {
        return revokeCertificate(null, serialno, reason);
    }
    private CARevokeCertResponse revokeCertificate(
            String caConn,
            String serialno,
            RevocationReason reason)
            throws EBaseException {

        String method = "CARemoteRequestHandler: revokeCertificate";
        String revCAid = connid;
        if (caConn != null) {
            logger.debug(method +": passed in ca ID: " + caConn);
            revCAid = caConn;
        } else {
            logger.debug(method +": using default ca ID:" + connid);
        }
        logger.debug(method +": begins");
        if (serialno == null || reason == null) {
            throw new EBaseException(method +": input parameter null.");
        }
        logger.debug(method +": revoking serial#:" + serialno + "; reason String:" + reason.toString() + "; reason code:" + reason.getCode());

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        // IConfigStore conf = CMS.getConfigStore();

        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(revCAid);
        if (conn == null) {
            throw new EBaseException(method +" to connid: " + revCAid + ": HttpConnector conn null.");
        }
        logger.debug(method +": sending request to CA");
        HttpResponse resp =
                conn.send("revoke",
                        IRemoteRequest.CA_OP + "=" + IRemoteRequest.CA_REVOKE +
                                "&" + IRemoteRequest.CA_REVOCATION_REASON + "=" + reason.getCode() +
                                "&" + IRemoteRequest.CA_REVOKE_ALL + "=(" +
                                IRemoteRequest.CA_REVOKE_SERIAL + "=" + serialno + ")&" +
                                IRemoteRequest.CA_REVOKE_COUNT + "=1");
        if (resp == null) {
            throw new EBaseException(method +" to connid: " + revCAid + ": response null.");
        }
        String content = resp.getContent();

        if (content != null && !content.equals("")) {
            logger.debug(method +": got content = " + content);
            Hashtable<String, Object> response =
                    parseResponse(content);

            /**
             * When a value is not found in response, keep going so we know
             * what else is missing
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = (String) response.get(IRemoteRequest.RESPONSE_STATUS);

            logger.debug(method +": got status = " + value);
            ist = Integer.parseInt(value);
            if (ist != 0) {
                logger.debug(method +": status not 0, getting error string... ");
                value = (String) response.get(IRemoteRequest.RESPONSE_ERROR_STRING);
                if (value == null) {
                    logger.debug(method +": response missing name-value pair for: " +
                            IRemoteRequest.RESPONSE_ERROR_STRING);
                } else {
                    logger.debug(method +": got IRemoteRequest.RESPONSE_ERROR_STRING = "
                            + value);
                    response.put(IRemoteRequest.RESPONSE_ERROR_STRING, value);
                }
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            logger.debug(method +": ends.");
            return new CARevokeCertResponse(revCAid, response);
        } else {
            logger.error(method +": no response content.");
            throw new EBaseException(method +": no response content.");
        }
    }

    /**
     * unrevokeCertificate provides the basic unrevocation of a certificate from
     * the CA
     *
     * @param serialno serial number of the cert to unrevoke
     *
     * @returns CARevokeCertResponse
     */
    private CARevokeCertResponse unrevokeCertificate(
            String serialno)
            throws EBaseException {
        return unrevokeCertificate(null, serialno);
    }
    private CARevokeCertResponse unrevokeCertificate(
            String caConn,
            String serialno)
            throws EBaseException {

        String method = "CARemoteRequestHandler: unrevokeCertificate()";
        String unrevCAid = connid;
        if (caConn != null) {
            logger.debug(method + ": passed in ca ID: " + caConn);
            unrevCAid = caConn;
        } else {
            logger.debug(method + ": using default ca ID:" + connid);
        }
        logger.debug(method + ": begins on serial#:" + serialno);
        if (serialno == null) {
            throw new EBaseException(method + ": input parameter null.");
        }

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(unrevCAid);
        if (conn == null) {
            throw new EBaseException(method + " to connid: " + unrevCAid + ": HttpConnector conn null.");
        }
        logger.debug(method + ": sending request to CA");
        HttpResponse resp =
                conn.send("unrevoke",
                        IRemoteRequest.CA_UNREVOKE_SERIAL + "=" + serialno);
        if (resp == null) {
            throw new EBaseException(method + " to connid: " + unrevCAid + ": response null.");
        }
        String content = resp.getContent();

        if (content != null && !content.equals("")) {
            logger.debug(method + ": got content = " + content);
            Hashtable<String, Object> response =
                    parseResponse(content);

            /**
             * When a value is not found in response, keep going so we know
             * what else is missing
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = (String) response.get(IRemoteRequest.RESPONSE_STATUS);

            logger.debug(method + ": got status = " + value);
            ist = Integer.parseInt(value);
            if (ist != 0) {
                logger.debug(method + ": status not 0, getting error string... ");
                value = (String) response.get(IRemoteRequest.RESPONSE_ERROR_STRING);
                if (value == null) {
                    logger.debug(method + ": response missing name-value pair for: " +
                            IRemoteRequest.RESPONSE_ERROR_STRING);
                } else {
                    logger.debug(method + ": got IRemoteRequest.RESPONSE_ERROR_STRING = "
                            + value);
                    response.put(IRemoteRequest.RESPONSE_ERROR_STRING, value);
                }
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            logger.debug(method + ": ends.");
            return new CARevokeCertResponse(unrevCAid, response);
        } else {
            logger.error(method + ": no response content.");
            throw new EBaseException(method + ": no response content.");
        }
    }

    /**
     * revokeFromOtherCA searches through all defined ca entries
     * to find the cert's signing ca for revocation / unrevocation.
     * It is called from revokeCertificate() when the cert's
     * AKI does not match that of the current signing ca.
     *
     * @param revoke true to revoke; false to unrevoke
     * @param cert cert to (un)revoke
     * @param serialno parameter for the (Un)RevokeCertificate() functions
     * @param reason RevocationReason for the base revokeCertificate() function
     * @throws IOException
     */
    @SuppressWarnings("unused")
    private CARevokeCertResponse revokeFromOtherCA(
            boolean revoke, // true==revoke; false==unrevoke
            X509CertImpl cert,
            RevocationReason reason)
            throws EBaseException, IOException {

        String method = "CARemoteRequestHandler: revokeFromOtherCA()";
        if (cert == null) {
            throw new EBaseException(method + ": input parameter cert null.");
        }
        String certAkiString = null;
        try {
            certAkiString = Util.getCertAkiString(cert);
        } catch (Exception e) {
            throw new EBaseException(method + ": getCertAkiString failed:" + e);
        }
        return revokeFromOtherCA(revoke, cert.getSerialNumber().toString(), certAkiString, reason);
    }

    private CARevokeCertResponse revokeFromOtherCA(
            boolean revoke, // true==revoke; false==unrevoke
            String serialno,
            String certAkiString,
            RevocationReason reason)
            throws EBaseException {

        String method = "CARemoteRequestHandler: revokeFromOtherCA()";
        logger.debug(method +": begins");

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        List<String> caList =
                subsystem.getConnectionManager().getCAList();

        Exception exception = null;

        for (String ca : caList) {
            logger.debug(method + ": processing caList: ca id:" + ca);
            try {
                String caSkiString = getCaSki(ca);
                if (certAkiString.equals(caSkiString)) {
                    logger.debug(method + " cert AKI and caCert SKI matched");
                    if (revoke) {
                        return revokeCertificate(ca, serialno, reason);
                    } else {
                        return unrevokeCertificate(ca, serialno);
                    }
                } else { // not a match then iterate to next ca in list
                    logger.debug(method + " cert AKI and caCert SKI not matched");
                }
            } catch (Exception e) {
                // any issue then iterate to next ca in list
                logger.warn(method + " issue found, iterate to next ca in list: "
                        + e.getMessage(), e);
                exception = e;
            }
        }
        if (exception == null) {
            throw new EBaseException(method + ": signing ca not found");
        } else {
            throw new EBaseException(method + exception.toString());
        }
    }

    /**
     * getCaSki returns the CA's Subject Key Identifier (ski)
     * associated with the connector id.
     * If the ca's ski has not been calculated, it will do so and
     * save to the connector's caSKI config entry
     *
     * @param conn connector id
     * @returns ca's ski associated with conn
     */
    private String getCaSki(String conn)
            throws EBaseException, IOException {

        String method = "CARemoteRequestHandler: getCaSki()";
        String caSkiString = null;
        if (conn == null) {
            throw new EBaseException(method + ": input parameter conn null.");
        }

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        EngineConfig conf = engine.getConfig();

        /*
         * first, see if ca Subject Key Identifier (SKI) is in
         * config store. If not, put it in, so we don't have to
         * calculate that every time.
         */
        try {
            String configName = "tps.connector." + conn + ".caSKI";
            logger.debug(method + " retriving configName=" + configName);
            return conf.getString(configName);
        } catch (EPropertyNotFound e) {
            // caSKI not yet calculated; proceed to calculate
            logger.warn(method + " caSKI not yet calculated:" + e.getMessage(), e);
        } catch (EBaseException e) {
            throw e;
        }

        try {
            String caNickname =
                    conf.getString("tps.connector." + conn + ".caNickname");
            logger.debug(method + " Calculating caSKI...searching for ca cert in nss db:"
                    + caNickname);
            CryptoManager cm = CryptoManager.getInstance();
            try {
                X509Certificate c = cm.findCertByNickname(caNickname);
                X509CertImpl caCert = new X509CertImpl(c.getEncoded());
                // now retrieve caSKI and store in config
                caSkiString = Util.getCertSkiString(caCert);
                logger.debug(method + " caSKI calculated. Saving it.");
                conf.putString("tps.connector." + conn + ".caSKI", caSkiString);
                conf.commit(false);
            } catch (IOException e) {
                throw e;
            } catch (Exception et) {
                /* ca cert not found in nss db; no match needed */
                logger.error(method + " caSKI calculation failure." + et.getMessage(), et);
                throw new EBaseException(method + ": skip match.");
            }
        } catch (EBaseException e) {
            /*
             *  if it gets here, that means config is missing both:
             *  1. tps.connector.ca<n>.caSKI
             *  2. tps.connector.ca<n>.caNickname
             *  now assume default of just using the issuing ca and
             *  no search performed
             */
            logger.debug(method + " caSKI calculation failure." + e);
            throw e;
        } catch (NotInitializedException e) {
            logger.error(method + " caSKI calculation failure." + e.getMessage(), e);
            throw new EBaseException(method + ": skip match.:" + e);
        }

        return caSkiString;
    }

    /**
     * revokeCertificate() supports revocation routing by providing
     * CA discovery. When needed, it searchs through all listed ca
     * entries to find the cert's signing ca for revocation.
     *
     * Note: in the configuration, the ca signing cert of each ca
     * id must be imported into the db and have its nickname present.
     * e.g. tps.connector.ca1.caNickname=CA1nickname
     *
     * See design:
     * https://www.dogtagpki.org/wiki/TPS_-_Revocation_Routing
     *
     * @param revoke true to revoke; false to unrevoke
     * @param serialno serial number for the (Un)RevokeCertificate() functions
     * @param reason RevocationReason for the base revokeCertificate() function
     */
    public CARevokeCertResponse revokeCertificate(
            boolean revoke, // true==revoke; false==unrevoke
            X509CertImpl cert,
            RevocationReason reason)
            throws EBaseException {

        String method = "CARemoteRequestHandler: revokeCertificate()";
        if (cert == null) {
            throw new EBaseException(method +": input parameter cert null.");
        }
        String certAkiString = null;
        try {
            certAkiString = Util.getCertAkiString(cert);
        } catch (IOException e) {
            throw new EBaseException(method +": getCertAkiString failed:" + e);
        }

        return revokeCertificate(revoke, cert.getSerialNumber().toString(), certAkiString, reason);
    }

    public CARevokeCertResponse revokeCertificate(
            boolean revoke, // true==revoke; false==unrevoke
            String serialno,
            String certAkiString,
            RevocationReason reason)
            throws EBaseException {

        String method = "CARemoteRequestHandler: revokeCertificate()";
        logger.debug(method +" begins with CA discovery");

        if (revoke == true && reason == null) {
            throw new EBaseException(method +": input parameter reason null.");
        }

        boolean skipMatch = false;

        String caSkiString = null;

        try {
            caSkiString = getCaSki(connid);
        } catch (Exception e) {
            logger.warn(method +" exception: " + e.getMessage(), e);
            skipMatch = true;
        }
        if (!skipMatch) {
            /* now compare cert's AKI to the ca's SKI
             *   if matched, continue,
             *   if not, search in the ca list
             */
            logger.debug(method +" cert AKI and caCert SKI matching begins");
            if (certAkiString.equals(caSkiString)) {
                logger.debug(method +" cert AKI and caCert SKI matched");
                if (revoke) {
                    return revokeCertificate(serialno, reason);
                } else {
                    return unrevokeCertificate(serialno);
                }
            } else {
                logger.debug(method +" cert AKI and caCert SKI of the designated issuing ca do not match...calling revokeFromOtherCA to search for another ca");
                return revokeFromOtherCA(revoke, serialno, certAkiString, reason);
            }
        } else {
            if (revoke) {
                return revokeCertificate(serialno, reason);
            } else {
                return unrevokeCertificate(serialno);
            }
        }
    }
}
