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

import java.math.BigInteger;
import java.util.Hashtable;

import org.dogtagpki.server.connector.IRemoteRequest;
import org.dogtagpki.server.tps.TPSSubsystem;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.connector.HttpConnector;
import com.netscape.cmsutil.http.HttpResponse;

/**
 * KRARemoteRequestHandler is a class representing remote requests
 * offered by the Key Recovery Authority (KRA)
 * On a successful return, name/value pairs are provided in a Hashtable where
 * all contents are URL decoded if needed
 *
 * @author cfu
 */
public class KRARemoteRequestHandler extends RemoteRequestHandler
{
    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRARemoteRequestHandler.class);

    public KRARemoteRequestHandler(String connID)
            throws EBaseException {
        if (connID == null) {
            throw new EBaseException("KRARemoteRequestHandler: KRARemoteRequestHandler(): connID null.");
        }

        connid = connID;
    }

    /**
     * serverSideKeyGen generates key pairs on the KRA
     *
     * @param cuid is the token id
     * @param userid is the user id
     * @param sDesKey is the des key provided by the TKS for key encryption
     * @param archive true or false
     *
     * @returns KRAServerSideKeyGenResponse
     */
    public KRAServerSideKeyGenResponse serverSideKeyGen(
            boolean isECC,
            int keysize,
            String cuid,
            String userid,
            String sDesKey,
            boolean archive)
            throws EBaseException {

        logger.debug("KRARemoteRequestHandler: serverSideKeyGen(): begins.");
        if (cuid == null || userid == null || sDesKey == null) {
            throw new EBaseException("KRARemoteRequestHandler: serverSideKeyGen(): input parameter null.");
        }

        CMSEngine engine = CMS.getCMSEngine();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);
        logger.debug("KRARemoteRequestHandler: serverSideKeyGen(): sending request to KRA");
        HttpResponse resp;
        String request;
        if (isECC) {
            String eckeycurve;
            if (keysize == 521) {
                eckeycurve = "nistp521";
            } else if (keysize == 384) {
                eckeycurve = "nistp384";
            } else if (keysize == 256) {
                eckeycurve = "nistp256";
            } else {
                logger.debug("KRARemoteRequestHandler: serverSideKeyGen(): unrecognized ECC keysize" + keysize
                        + ", setting to nistp256");
                keysize = 256;
                eckeycurve = "nistp256";
            }

            request = IRemoteRequest.KRA_KEYGEN_Archive + "=" +
                    archive +
                    "&" + IRemoteRequest.TOKEN_CUID + "=" +
                    cuid +
                    "&" + IRemoteRequest.KRA_UserId + "=" +
                    userid +
                    "&" + IRemoteRequest.KRA_KEYGEN_KeyType + "=" +
                    "EC" +
                    "&" + IRemoteRequest.KRA_KEYGEN_EC_KeyCurve + "=" +
                    eckeycurve +
                    "&" + IRemoteRequest.KRA_Trans_DesKey + "=" +
                    sDesKey;

            //logger.debug("KRARemoteRequestHandler: outgoing request for ECC: " + request);

            resp =
                    conn.send("GenerateKeyPair",
                            request);
        } else { // RSA

            request = IRemoteRequest.KRA_KEYGEN_Archive + "=" +
                    archive +
                    "&" + IRemoteRequest.TOKEN_CUID + "=" +
                    cuid +
                    "&" + IRemoteRequest.KRA_UserId + "=" +
                    userid +
                    "&" + IRemoteRequest.KRA_KEYGEN_KeyType + "=" +
                    "RSA" +
                    "&" + IRemoteRequest.KRA_KEYGEN_KeySize + "=" +
                    keysize +
                    "&" + IRemoteRequest.KRA_Trans_DesKey + "=" +
                    sDesKey;

            //logger.debug("KRARemoteRequestHandler: outgoing request for RSA: " + request);

            resp =
                    conn.send("GenerateKeyPair",
                            request);
        }

        //For some reason the send method can return null and not throw an exception.
        // Check here;

        if (resp == null) {
            throw new EBaseException(
                    "KRARemoteRequestHandler: serverSideKeyGen(): No response object returned from connection.");
        }

        String content = resp.getContent();

        if (content != null && !content.equals("")) {
            logger.debug("KRARemoteRequestHandler: serverSideKeyGen(): got content");
            Hashtable<String, Object> response =
                    parseResponse(content);

            /**
             * When a value is not found in response, keep going so we know
             * what else is missing
             * Note: response values "missing" might not be bad for some cases
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = (String) response.get(IRemoteRequest.RESPONSE_STATUS);

            if (value == null) {
                throw new EBaseException("KRARemoteRequestHandler: serverSideKeyGen(): Invalide status returned!");
            }

            logger.debug("KRARemoteRequestHandler: serverSideKeyGen(): got status = " + value);
            ist = Integer.parseInt(value);
            if (ist != 0) {
                logger.debug("KRARemoteRequestHandler: serverSideKeyGen(): status not 0, getting error string... ");
                value = (String) response.get(IRemoteRequest.RESPONSE_ERROR_STRING);
                if (value == null) {
                    logger.debug("KRARemoteRequestHandler: serverSideKeyGen(): response missing name-value pair for: " +
                            IRemoteRequest.RESPONSE_ERROR_STRING);
                } else {
                    logger.debug("KRARemoteRequestHandler: serverSideKeyGen(): got IRemoteRequest.RESPONSE_ERROR_STRING = "
                            + value);
                    response.put(IRemoteRequest.RESPONSE_ERROR_STRING, value);
                }
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            value = (String) response.get(IRemoteRequest.KRA_RESPONSE_PublicKey);
            if (value == null) {
                logger.debug("KRARemoteRequestHandler: serverSideKeyGen(): response missing name-value pair for: " +
                        IRemoteRequest.KRA_RESPONSE_PublicKey);
            } else {
                //logger.debug("KRARemoteRequestHandler:serverSideKeyGen(): got IRemoteRequest.KRA_RESPONSE_PublicKey= "
                //        + value);
                logger.debug("KRARemoteRequestHandler:serverSideKeyGen(): got IRemoteRequest.KRA_RESPONSE_PublicKey");
                response.put(IRemoteRequest.KRA_RESPONSE_PublicKey, value);
            }

            value = (String) response.get(IRemoteRequest.KRA_RESPONSE_Wrapped_PrivKey);
            if (value == null) {
                logger.debug("KRARemoteRequestHandler: serverSideKeyGen(): response missing name-value pair for: " +
                        IRemoteRequest.KRA_RESPONSE_Wrapped_PrivKey);
            } else {
                logger.debug("KRARemoteRequestHandler:serverSideKeyGen(): got IRemoteRequest.KRA_RESPONSE_Wrapped_PrivKey");
                response.put(IRemoteRequest.KRA_RESPONSE_Wrapped_PrivKey, value);
            }

            value = (String) response.get(IRemoteRequest.KRA_RESPONSE_IV_Param);
            if (value == null) {
                logger.debug("KRARemoteRequestHandler: serverSideKeyGen(): response missing name-value pair for: " +
                        IRemoteRequest.KRA_RESPONSE_IV_Param);
            } else {
                logger.debug("KRARemoteRequestHandler:serverSideKeyGen(): got IRemoteRequest.KRA_RESPONSE_IV_Param");
                response.put(IRemoteRequest.KRA_RESPONSE_IV_Param, value);
            }

            logger.debug("KRARemoteRequestHandler: serverSideKeyGen(): ends.");
            return new KRAServerSideKeyGenResponse(connid, response);
        } else {
            logger.error("KRARemoteRequestHandler: serverSideKeyGen(): no response content.");
            throw new EBaseException("KRARemoteRequestHandler: serverSideKeyGen(): no response content.");
        }

    }

    /**
     * recoverKey recovers keys from KRA
     *
     * @param cuid is the token id
     * @param userid is the user id
     * @param sDesKey is the des key provided by the TKS for key encryption
     * @param b64cert is the Base64 encoding of a certificate used to recover
     *
     * @returns KRARecoverKeyResponse
     */
    public KRARecoverKeyResponse recoverKey(
            String cuid,
            String userid,
            String sDesKey,
            String b64cert)
            throws EBaseException {
        return recoverKey(cuid, userid, sDesKey, b64cert, BigInteger.valueOf(0));
    }

    public KRARecoverKeyResponse recoverKey(
            String cuid,
            String userid,
            String sDesKey,
            String b64cert,
            BigInteger keyid)
            throws EBaseException {

        logger.debug("KRARemoteRequestHandler: recoverKey(): begins.");
        if (b64cert == null && keyid == BigInteger.valueOf(0)) {
            throw new EBaseException("KRARemoteRequestHandler: recoverKey(): one of b64cert or kid has to be a valid value");
        }
        if (cuid == null || userid == null || sDesKey == null) {
            throw new EBaseException("KRARemoteRequestHandler: recoverKey(): input parameter null.");
        }

        CMSEngine engine = CMS.getCMSEngine();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        logger.debug("KRARemoteRequestHandler: getting conn id: " + connid);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);
        if (conn == null) {
            logger.error("KRARemoteRequestHandler: recoverKey(): conn null");
            throw new EBaseException("KRARemoteRequestHandler: recoverKey(): conn null");
        }
        logger.debug("KRARemoteRequestHandler: recoverKey(): sending request to KRA");

        String sendMsg = null;
        try {
            if (b64cert != null) { // recover by cert
                // logger.debug("KRARemoteRequestHandler: recoverKey(): uriEncoded cert= " + b64cert);
                sendMsg = IRemoteRequest.TOKEN_CUID + "=" +
                        cuid +
                        "&" + IRemoteRequest.KRA_UserId + "=" +
                        userid +
                        "&" + IRemoteRequest.KRA_RECOVERY_CERT + "=" +
                        b64cert  +
                        "&" + IRemoteRequest.KRA_Trans_DesKey + "=" +
                        sDesKey;
            } else if (keyid != BigInteger.valueOf(0)) { // recover by keyid ... keyid != BigInteger.valueOf(0)
                logger.debug("KRARemoteRequestHandler: recoverKey(): keyid = " + keyid);
                sendMsg = IRemoteRequest.TOKEN_CUID + "=" +
                        cuid +
                        "&" + IRemoteRequest.KRA_UserId + "=" +
                        userid +
                        "&" + IRemoteRequest.KRA_RECOVERY_KEYID + "=" +
                        keyid.toString() +
                        "&" + IRemoteRequest.KRA_Trans_DesKey + "=" +
                        sDesKey;
            }
        } catch (Exception e) {
            logger.debug("KRARemoteRequestHandler: recoverKey(): uriEncode failed: " + e);
            throw new EBaseException("KRARemoteRequestHandler: recoverKey(): uriEncode failed: " + e);
        }

        //logger.debug("KRARemoteRequestHandler: recoverKey(): sendMsg =" + sendMsg);
        HttpResponse resp =
                conn.send("TokenKeyRecovery",
                        sendMsg);
        if (resp == null) {
            throw new EBaseException(
                    "KRARemoteRequestHandler: recoverKey(): No response object returned from connection.");
        }

        String content = resp.getContent();

        if (content != null && !content.equals("")) {
            logger.debug("KRARemoteRequestHandler: recoverKey(): got content");
            Hashtable<String, Object> response =
                    parseResponse(content);

            /**
             * When a value is not found in response, keep going so we know
             * what else is missing
             * Note: response values "missing" might not be bad for some cases
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = (String) response.get(IRemoteRequest.RESPONSE_STATUS);

            logger.debug("KRARemoteRequestHandler: recoverKey(): got status = " + value);
            ist = Integer.parseInt(value);
            if (ist != 0) {
                logger.debug("KRARemoteRequestHandler: recoverKey(): status not 0, getting error string... ");
                value = (String) response.get(IRemoteRequest.RESPONSE_ERROR_STRING);
                if (value == null) {
                    logger.debug("KRARemoteRequestHandler: recoverKey(): response missing name-value pair for: " +
                            IRemoteRequest.RESPONSE_ERROR_STRING);
                } else {
                    logger.debug("KRARemoteRequestHandler: recoverKey(): got IRemoteRequest.RESPONSE_ERROR_STRING = "
                            + value);
                    response.put(IRemoteRequest.RESPONSE_ERROR_STRING, value);
                }
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            value = (String) response.get(IRemoteRequest.KRA_RESPONSE_PublicKey);
            if (value == null) {
                logger.debug("KRARemoteRequestHandler: recoverKey(): response missing name-value pair for: " +
                        IRemoteRequest.KRA_RESPONSE_PublicKey);
            } else {
                //logger.debug("KRARemoteRequestHandler:recoverKey(): got IRemoteRequest.KRA_RESPONSE_PublicKey= " + value);
                logger.debug("KRARemoteRequestHandler:recoverKey(): got IRemoteRequest.KRA_RESPONSE_PublicKey");
                response.put(IRemoteRequest.KRA_RESPONSE_PublicKey, value);
            }

            value = (String) response.get(IRemoteRequest.KRA_RESPONSE_Wrapped_PrivKey);
            if (value == null) {
                logger.debug("KRARemoteRequestHandler: recoverKey(): response missing name-value pair for: " +
                        IRemoteRequest.KRA_RESPONSE_Wrapped_PrivKey);
            } else {
                logger.debug("KRARemoteRequestHandler:recoverKey(): got IRemoteRequest.KRA_RESPONSE_Wrapped_PrivKey");
                response.put(IRemoteRequest.KRA_RESPONSE_Wrapped_PrivKey, value);
            }

            value = (String) response.get(IRemoteRequest.KRA_RESPONSE_IV_Param);
            if (value == null) {
                logger.debug("KRARemoteRequestHandler: recoverKey(): response missing name-value pair for: " +
                        IRemoteRequest.KRA_RESPONSE_IV_Param);
            } else {
                logger.debug("KRARemoteRequestHandler:recoverKey(): got IRemoteRequest.KRA_RESPONSE_IV_Param");
                response.put(IRemoteRequest.KRA_RESPONSE_IV_Param, value);
            }

            logger.debug("KRARemoteRequestHandler: recoverKey(): ends.");
            return new KRARecoverKeyResponse(connid, response);
        } else {
            logger.error("KRARemoteRequestHandler: recoverKey(): no response content.");
            throw new EBaseException("KRARemoteRequestHandler: recoverKey(): no response content.");
        }
    }
}
