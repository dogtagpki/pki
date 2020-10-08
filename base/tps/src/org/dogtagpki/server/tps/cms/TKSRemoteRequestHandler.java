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

import java.util.Hashtable;

import org.dogtagpki.server.connector.IRemoteRequest;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.channel.SecureChannel;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.Util;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.connector.HttpConnector;
import com.netscape.cmsutil.http.HttpResponse;

/**
 * TKSRemoteRequestHandler is a class representing remote requests
 * offered by the Token Key Service Authority (TKS)
 * On a successful return, name/value pairs are provided in a Hashtable where
 * all contents are URL decoded if needed
 *
 * @author cfu
 */
public class TKSRemoteRequestHandler extends RemoteRequestHandler
{
    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TKSRemoteRequestHandler.class);

    private String keySet;

    public TKSRemoteRequestHandler(String connID)
            throws EBaseException {

        if (connID == null) {
            throw new EBaseException("TKSRemoteRequestHandler: TKSRemoteRequestHandler(): connID null.");
        }

        connid = connID;
    }

    public TKSRemoteRequestHandler(String connID, String inKeySet)
            throws EBaseException {

        if (connID == null) {
            throw new EBaseException("TKSRemoteRequestHandler: TKSRemoteRequestHandler(): connID null.");
        }
        connid = connID;

        this.keySet = inKeySet;

    }

    /*
     * computeSessionKey
     *
     * Usage Example:
     *   TKSRemoteRequestHandler tksReq = new TKSRemoteRequestHandler("tks1");
     *   TKSComputeSessionKeyResponse responseObj =
     *     tksReq.computeSessionKey(
     *      kdd,
     *      cuid,
     *      keyInfo,
     *      card_challenge,
     *      card_cryptogram,
     *      host_challenge
     *      tokenType);
     *   - on success return, one can say
     *    TPSBuffer value = responseObj.getSessionKey();
     *      to get response param value session key
     *
     * @param kdd key derivation data
     * @param cuid token cuid
     * @param keyInfo keyInfo
     * @param card_challenge card challenge
     * @param card_cryptogram card cryptogram
     * @param host_challenge host challenge
     * @param tokenType
     * @return response TKSComputeSessionKeyResponse class object
     */
    public TKSComputeSessionKeyResponse computeSessionKey(
            TPSBuffer kdd,
            TPSBuffer cuid,
            TPSBuffer keyInfo,
            TPSBuffer card_challenge,
            TPSBuffer card_cryptogram,
            TPSBuffer host_challenge,
            String tokenType)
            throws EBaseException {

        String method = "TKSRemoteRequestHandler: computeSessionKey(): ";
        logger.debug(method + " begins.");
        if (cuid == null || kdd == null || keyInfo == null || card_challenge == null
                || card_cryptogram == null || host_challenge == null) {
            throw new EBaseException("TKSRemoteRequestHandler: computeSessionKey(): input parameter null.");
        }

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        EngineConfig conf = engine.getConfig();

        boolean serverKeygen = false;

        //Try out all the currently supported cert types to see if we are doing server side keygen here
        String[] keygenStrings = { "identity", "signing", "encryption", "authentication", "auth"};
        for (String keygenString : keygenStrings) {
            boolean enabled = conf.getBoolean("op.enroll." +
                    tokenType + ".keyGen." +
                    keygenString + ".serverKeygen.enable", false);

            logger.debug(method + "config serverkegGen enabled for " + keygenString + " : " + enabled);
            if (enabled) {
                serverKeygen = true;
                break;
            }
        }
        logger.debug(method + " final serverkegGen enabled? " + serverKeygen);

        if (keySet == null)
            keySet = conf.getString("tps.connector." + connid + ".keySet", "defKeySet");

        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);

        String requestString = IRemoteRequest.SERVER_SIDE_KEYGEN + "=" + serverKeygen +
                "&" + IRemoteRequest.TOKEN_KDD + "=" + Util.specialURLEncode(kdd) +
                "&" + IRemoteRequest.TOKEN_CUID + "=" + Util.specialURLEncode(cuid) +
                "&" + IRemoteRequest.TOKEN_CARD_CHALLENGE + "=" + Util.specialURLEncode(card_challenge) +
                "&" + IRemoteRequest.TOKEN_HOST_CHALLENGE + "=" + Util.specialURLEncode(host_challenge) +
                "&" + IRemoteRequest.TOKEN_KEYINFO + "=" + Util.specialURLEncode(keyInfo) +
                "&" + IRemoteRequest.TOKEN_CARD_CRYPTOGRAM + "="
                + Util.specialURLEncode(card_cryptogram.toBytesArray()) +
                "&" + IRemoteRequest.TOKEN_KEYSET + "=" + keySet;

        //logger.debug("TKSRemoteRequestHandler.computeSessionKey: outgoing message: " + requestString);
        logger.debug("TKSRemoteRequestHandler.computeSessionKey: sending request to TKS");

        HttpResponse resp =
                conn.send("computeSessionKey",
                        requestString
                        );

        String content = resp.getContent();

        if (content != null && !content.equals("")) {
            Hashtable<String, Object> response =
                    parseResponse(content);

            /*
             * When a value is not found in response, keep going so we know
             * what else is missing
             * Note: serverKeygen and !serverKeygen returns different set of
             *     response values so "missing" might not be bad
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = (String) response.get(IRemoteRequest.RESPONSE_STATUS);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: computeSessionKey(): status not found.");
                //logger.debug("TKSRemoteRequestHandler: computeSessionKey(): got content = " + content);
            } else {
                logger.debug("TKSRemoteRequestHandler: computeSessionKey(): got status = " + value);
                ist = Integer.parseInt(value);
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_SessionKey);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: computeSessionKey(): response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_SessionKey);
            } else {
                logger.debug("TKSRemoteRequestHandler: computeSessionKey(): got IRemoteRequest.TKS_RESPONSE_SessionKey");
                response.put(IRemoteRequest.TKS_RESPONSE_SessionKey, Util.specialDecode(value));
            }

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_EncSessionKey);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: computeSessionKey(): response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_EncSessionKey);
            } else {
                logger.debug("TKSRemoteRequestHandler: computeSessionKey(): got IRemoteRequest.TKS_RESPONSE_EncSessionKey");
                response.put(IRemoteRequest.TKS_RESPONSE_EncSessionKey, Util.specialDecode(value));
            }

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: computeSessionKey(): response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey);
            } else {
                logger.debug("TKSRemoteRequestHandler: computeSessionKey(): got IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey");
                response.put(IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey, Util.specialDecode(value));
            }

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_KEK_DesKey);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: computeSessionKey(): response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_KEK_DesKey);
            } else {
                logger.debug("TKSRemoteRequestHandler: computeSessionKey(): got IRemoteRequest.TKS_RESPONSE_KEK_DesKey");
                response.put(IRemoteRequest.TKS_RESPONSE_KEK_DesKey, Util.specialDecode(value));
            }

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_KeyCheck);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: computeSessionKey(): response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_KeyCheck);
            } else {
                logger.debug("TKSRemoteRequestHandler: computeSessionKey(): got IRemoteRequest.TKS_RESPONSE_KeyCheck");
                response.put(IRemoteRequest.TKS_RESPONSE_KeyCheck, Util.specialDecode(value));
            }

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_HostCryptogram);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: computeSessionKey(): response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_HostCryptogram);
            } else {
                logger.debug("TKSRemoteRequestHandler: computeSessionKey(): got IRemoteRequest.TKS_RESPONSE_HostCryptogram");
                response.put(IRemoteRequest.TKS_RESPONSE_HostCryptogram, Util.specialDecode(value));
            }
            logger.debug("TKSRemoteRequestHandler: computeSessionKey(): ends.");

            return new TKSComputeSessionKeyResponse(response);
        } else {
            logger.error("TKSRemoteRequestHandler: computeSessionKey(): no response content.");
            throw new EBaseException("TKSRemoteRequestHandler: computeSessionKey(): no response content.");
        }
    }

    public TKSComputeSessionKeyResponse computeSessionKeysSCP03(
            TPSBuffer kdd
            ,TPSBuffer cuid,
            TPSBuffer keyInfo,
            TPSBuffer card_challenge,
            TPSBuffer card_cryptogram,
            TPSBuffer  host_challenge,
            String tokenType) throws EBaseException {

        String method = "TKSRemoteRequestHandler: computeSessionKeysSCP03()";

        logger.debug(method + " Entering: ");

        if (cuid == null || kdd == null || keyInfo == null || card_challenge == null ||
                card_cryptogram == null || host_challenge == null || tokenType == null

               ) {
            throw new EBaseException(method +  " invalid input!");
        }

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        EngineConfig conf = engine.getConfig();

        boolean serverKeygen = false;

        //Try out all the currently supported cert types to see if we are doing server side keygen here
        String[] keygenStrings = { "identity", "signing", "encryption", "authentication", "auth"};
        for (String keygenString : keygenStrings) {
            boolean enabled = conf.getBoolean("op.enroll." +
                    tokenType + ".keyGen." +
                    keygenString + ".serverKeygen.enable", false);

            logger.debug(method + " serverkegGen enabled for " + keygenString + " : " + enabled);
            if (enabled) {
                serverKeygen = true;
                break;
            }
        }
        logger.debug(method + " final serverkegGen enabled? " + serverKeygen);

        if (keySet == null)
            keySet = conf.getString("tps.connector." + connid + ".keySet", "defKeySet");

        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);

        String requestString = IRemoteRequest.SERVER_SIDE_KEYGEN + "=" + serverKeygen +
                "&" + IRemoteRequest.TOKEN_KDD + "=" + Util.specialURLEncode(kdd) +
                "&" + IRemoteRequest.TOKEN_CUID + "=" + Util.specialURLEncode(cuid) +
                "&" + IRemoteRequest.TOKEN_CARD_CHALLENGE + "=" + Util.specialURLEncode(card_challenge) +
                "&" + IRemoteRequest.TOKEN_HOST_CHALLENGE + "=" + Util.specialURLEncode(host_challenge) +
                "&" + IRemoteRequest.TOKEN_KEYINFO + "=" + Util.specialURLEncode(keyInfo) +
                "&" + IRemoteRequest.CHANNEL_PROTOCOL + "=" + SecureChannel.SECURE_PROTO_03 +
                "&" + IRemoteRequest.TOKEN_CARD_CRYPTOGRAM + "="
                + Util.specialURLEncode(card_cryptogram.toBytesArray()) +
                "&" + IRemoteRequest.TOKEN_KEYSET + "=" + keySet;

        HttpResponse resp =
                conn.send("computeSessionKey",
                        requestString
                        );

        String content = resp.getContent();

        if (content != null && !content.equals("")) {
            Hashtable<String, Object> response =
                    parseResponse(content);

            /*
             * When a value is not found in response, keep going so we know
             * what else is missing
             * Note: serverKeygen and !serverKeygen returns different set of
             *     response values so "missing" might not be bad
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = (String) response.get(IRemoteRequest.RESPONSE_STATUS);
            if (value == null) {
                logger.debug(method + " status not found.");
                //logger.debug("TKSRemoteRequestHandler: computeSessionKeySCP02(): got content = " + content);
            } else {
                logger.debug(method + " got status = " + value);
                ist = Integer.parseInt(value);
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_EncSessionKey);
            if (value == null) {
                logger.debug(method + " response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_EncSessionKey);
            } else {
                logger.debug(method+ "got IRemoteRequest.TKS_RESPONSE_EncSessionKey");
                response.put(IRemoteRequest.TKS_RESPONSE_EncSessionKey, Util.specialDecode(value));
            }

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey);
            if (value == null) {
                logger.debug(method + " response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey);
            } else {
                logger.debug(method + "got IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey");
                response.put(IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey, Util.specialDecode(value));
            }

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_MacSessionKey);
            if (value == null) {
                logger.debug(method + "response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_MacSessionKey);
            } else {
                logger.debug(method + " got IRemoteRequest.TKS_RESPONSE_MacSessionKey");
                response.put(IRemoteRequest.TKS_RESPONSE_MacSessionKey, Util.specialDecode(value));

            }


            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_KekSessionKey);
            if (value == null) {
                logger.debug(method + "response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_KekSessionKey);
            } else {
                logger.debug(method + " got IRemoteRequest.TKS_RESPONSE_KekSessionKey");
                response.put(IRemoteRequest.TKS_RESPONSE_KekSessionKey, Util.specialDecode(value));
            }

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_KEK_DesKey);
            if (value == null) {
                logger.debug(method + "response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_KEK_DesKey);
            } else {
                logger.debug(method + " got IRemoteRequest.TKS_RESPONSE_KEK_DesKey");
                response.put(IRemoteRequest.TKS_RESPONSE_KEK_DesKey, Util.specialDecode(value));

            }

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_KeyCheck);

            if (value == null) {
                logger.debug(method + "response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_KeyCheck);

            } else {
                logger.debug(method + " got IRemoteRequest.TKS_RESPONSE_KeyCheck");
                response.put(IRemoteRequest.TKS_RESPONSE_KeyCheck, Util.specialDecode(value));
            }

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_HostCryptogram);
            if ( value == null ) {
                logger.debug(method + " response missing name-value pair for: " + IRemoteRequest.TKS_RESPONSE_HostCryptogram);
            } else {
                logger.debug(method + " got " + IRemoteRequest.TKS_RESPONSE_HostCryptogram);
                response.put(IRemoteRequest.TKS_RESPONSE_HostCryptogram, Util.specialDecode(value));
            }

            logger.debug(method + " ends.");

            return new TKSComputeSessionKeyResponse(response);

        } else {
            logger.error("TKSRemoteRequestHandler: computeSessionKeySCP02(): no response content.");
            throw new EBaseException("TKSRemoteRequestHandler: computeSessionKeySCP02(): no response content.");
        }

    }

    /*
     * computeSessionKey
     *
     * Usage Example:
     *   TKSRemoteRequestHandler tksReq = new TKSRemoteRequestHandler("tks1");
     *   TKSComputeSessionKeyResponse responseObj =
     *     tksReq.computeSessionKey(
     *      kdd,
     *      cuid,
     *      keyInfo,
     *      sequenceCounter,
     *      derivationConstant,
     *      String tokenType)
     *   - on success return, one can say
     *    TPSBuffer value = responseObj.getSessionKey();
     *      to get response param value session key
     *
     * @param kdd key derivation data
     * @param cuid token cuid
     * @param keyInfo keyInfo
     * @param sequenceCounter
     * @param derivationConstant
     * @param tokenType
     * @return response TKSComputeSessionKeyResponse class object
     */
    public TKSComputeSessionKeyResponse computeSessionKeySCP02(
            TPSBuffer kdd,
            TPSBuffer cuid,
            TPSBuffer keyInfo,
            TPSBuffer sequenceCounter,
            TPSBuffer derivationConstant,
            String tokenType)
            throws EBaseException {

        String method = "TKSRemoteRequestHandler: computeSessionKeySCP02(): ";
        logger.debug(method + " begins.");
        if (cuid == null || kdd == null || keyInfo == null ||
                sequenceCounter == null
                || derivationConstant == null) {
            throw new EBaseException("TKSRemoteRequestHandler: computeSessionKeySCP02(): input parameter null.");
        }

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        EngineConfig conf = engine.getConfig();

        boolean serverKeygen = false;

        //Try out all the currently supported cert types to see if we are doing server side keygen here
        String[] keygenStrings = { "identity", "signing", "encryption", "authentication", "auth"};
        for (String keygenString : keygenStrings) {
            boolean enabled = conf.getBoolean("op.enroll." +
                    tokenType + ".keyGen." +
                    keygenString + ".serverKeygen.enable", false);

            logger.debug(method + " serverkegGen enabled for " + keygenString + " : " + enabled);
            if (enabled) {
                serverKeygen = true;
                break;
            }
        }

        if (keySet == null)
            keySet = conf.getString("tps.connector." + connid + ".keySet", "defKeySet");

        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);

        String requestString = IRemoteRequest.SERVER_SIDE_KEYGEN + "=" + serverKeygen +
                "&" + IRemoteRequest.TOKEN_KDD + "=" + Util.specialURLEncode(kdd) +
                "&" + IRemoteRequest.TOKEN_CUID + "=" + Util.specialURLEncode(cuid) +
                "&" + IRemoteRequest.TOKEN_KEYINFO + "=" + Util.specialURLEncode(keyInfo) +
                "&" + IRemoteRequest.TOKEN_KEYSET + "=" + keySet +
                "&" + IRemoteRequest.CHANNEL_PROTOCOL + "=" + SecureChannel.SECURE_PROTO_02 +
                "&" + IRemoteRequest.SEQUENCE_COUNTER + "=" + Util.specialURLEncode(sequenceCounter) +
                "&" + IRemoteRequest.DERIVATION_CONSTANT + "=" + Util.specialURLEncode(derivationConstant);

        HttpResponse resp =
                conn.send("computeSessionKey",
                        requestString
                        );

        String content = resp.getContent();

        if (content != null && !content.equals("")) {
            Hashtable<String, Object> response =
                    parseResponse(content);

            /*
             * When a value is not found in response, keep going so we know
             * what else is missing
             * Note: serverKeygen and !serverKeygen returns different set of
             *     response values so "missing" might not be bad
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = (String) response.get(IRemoteRequest.RESPONSE_STATUS);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: computeSessionKeySCP02(): status not found.");
                //logger.debug("TKSRemoteRequestHandler: computeSessionKeySCP02(): got content = " + content);
            } else {
                logger.debug("TKSRemoteRequestHandler: computeSessionKeySCP02(): got status = " + value);
                ist = Integer.parseInt(value);
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_SessionKey);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: computeSessionKeySCP02(): response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_SessionKey);
            } else {
                logger.debug("TKSRemoteRequestHandler: computeSessionKeySCP02(): got IRemoteRequest.TKS_RESPONSE_SessionKey");
                response.put(IRemoteRequest.TKS_RESPONSE_SessionKey, Util.specialDecode(value));
            }

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: computeSessionKeySCP02(): response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey);
            } else {
                logger.debug("TKSRemoteRequestHandler: computeSessionKeySCP02(): got IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey");
                response.put(IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey, Util.specialDecode(value));
            }

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_KEK_DesKey);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: computeSessionKeySCP02(): response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_KEK_DesKey);
            } else {
                logger.debug("TKSRemoteRequestHandler: computeSessionKeySCP02(): got IRemoteRequest.TKS_RESPONSE_KEK_DesKey");
                response.put(IRemoteRequest.TKS_RESPONSE_KEK_DesKey, Util.specialDecode(value));

            }

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_KeyCheck);

            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: computeSessionKeySCP02(): response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_KeyCheck);

            } else {
                logger.debug("TKSRemoteRequestHandler: computeSessionKeySCP02(): got IRemoteRequest.TKS_RESPONSE_KeyCheck");
                response.put(IRemoteRequest.TKS_RESPONSE_KeyCheck, Util.specialDecode(value));
            }

            logger.debug("TKSRemoteRequestHandler: computeSessionKeySCP02(): ends.");

            return new TKSComputeSessionKeyResponse(response);

        } else {
            logger.error("TKSRemoteRequestHandler: computeSessionKeySCP02(): no response content.");
            throw new EBaseException("TKSRemoteRequestHandler: computeSessionKeySCP02(): no response content.");
        }
    }

    /*
     * createKeySetData
     *
     * Usage Example:
     *   TKSRemoteRequestHandler tksReq = new TKSRemoteRequestHandler("tks1");
     *   TKSCreateKeySetDataResponse responseObj =
     *     tksReq.createKeySetData(
     *      NewMasterVer,
     *      version,
     *      cuid)
     *   - on success return, one can say
     *    TPSBuffer value = responseObj.getKeySetData();
     *      to get response param value keySetData
     *
     * @param NewMasterVer newKeyInfo
     * @param version keyInfo
     * @param cuid token cuid
     * @return response TKSCreateKeySetDataResponse class object
     */
    public TKSCreateKeySetDataResponse createKeySetData (
            TPSBuffer NewMasterVer,
            TPSBuffer version,
            TPSBuffer cuid, TPSBuffer kdd, int protocol, TPSBuffer wrappedDekSessionKey)
            throws EBaseException {
        logger.debug("TKSRemoteRequestHandler: createKeySetData(): begins.");
        if (cuid == null || NewMasterVer == null || version == null) {
            throw new EBaseException("TKSRemoteRequestHandler: createKeySetData(): input parameter null.");
        }

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        EngineConfig conf = engine.getConfig();
        if (keySet == null)
            keySet = conf.getString("tps.connector." + connid + ".keySet", "defKeySet");

        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);
        logger.debug("TKSRemoteRequestHandler: createKeySetData(): sending request to tks.");

        String command = IRemoteRequest.TOKEN_NEW_KEYINFO + "=" + Util.specialURLEncode(NewMasterVer) +
                "&" + IRemoteRequest.TOKEN_KDD + "=" + Util.specialURLEncode(kdd) +
                "&" + IRemoteRequest.TOKEN_CUID + "=" + Util.specialURLEncode(cuid) +
                "&" + IRemoteRequest.TOKEN_KEYINFO + "=" + Util.specialURLEncode(version) +
                "&" + IRemoteRequest.TOKEN_KEYSET + "=" + keySet +
                "&" + IRemoteRequest.CHANNEL_PROTOCOL + "=" + protocol;

        if (wrappedDekSessionKey != null) { // We have secure channel protocol 02 trying to upgrade the key set.
            command += "&" + IRemoteRequest.WRAPPED_DEK_SESSION_KEY + "=" + Util.specialURLEncode(wrappedDekSessionKey);
        }

        HttpResponse resp =
                conn.send("createKeySetData",
                        command);

        String content = resp.getContent();

        if (content != null && !content.equals("")) {
            Hashtable<String, Object> response =
                    parseResponse(content);
            if (response == null) {
                logger.warn("TKSRemoteRequestHandler: createKeySetData(): parseResponse returned null.");
                return null;
            }

            /*
             * When a value is not found in response, keep going so we know
             * what else is missing
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = (String) response.get(IRemoteRequest.RESPONSE_STATUS);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: createKeySetData(): status not found.");
                //logger.debug("TKSRemoteRequestHandler: createKeySetData(): got content = " + content);
            } else {
                logger.debug("TKSRemoteRequestHandler: createKeySetData(): got status = " + value);
                ist = Integer.parseInt(value);
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_KeySetData);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: createKeySetData(): response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_KeySetData);
            } else {
                logger.debug("TKSRemoteRequestHandler: createKeySetData(): got IRemoteRequest.TKS_RESPONSE_KeySetData");
                response.put(IRemoteRequest.TKS_RESPONSE_KeySetData, Util.specialDecode(value));
            }
            logger.debug("TKSRemoteRequestHandler: createKeySetData(): ends.");

            return new TKSCreateKeySetDataResponse(response);
        } else {
            logger.error("TKSRemoteRequestHandler: createKeySetData(): no response content.");
            throw new EBaseException("TKSRemoteRequestHandler: createKeySetData(): no response content.");
        }
    }

    /*
     * computeRandomData
     *
     * Usage Example:
     *   TKSRemoteRequestHandler tksReq = new TKSRemoteRequestHandler("tks1");
     *   TKSComputeRandomDataResponse responseObj =
     *     tksReq.computeRandomData(
     *      dataSize)
     *   - on success return, one can say
     *     TPSBuffer value = responseObj.getRandomData();
     *      to get response param value random data
     *
     * @param dataSize size of random data to be generated in number of bytes
     * @return response TKSComputeRandomDataResponse class object
     */
    public TKSComputeRandomDataResponse computeRandomData(int dataSize)
            throws EBaseException {
        logger.debug("TKSRemoteRequestHandler: computeRandomData(): begins.");
        /*
         * check for absurd dataSize values
         */
        if (dataSize <= 0 || dataSize > 1024) {
            logger.error("TKSRemoteRequestHandler: computeRandomData(): invalid dataSize requested:" + dataSize);
            throw new EBaseException("TKSRemoteRequestHandler: computeRandomData(): invalid dataSize requested");
        }

        logger.debug("TKSRemoteRequestHandler: computeRandomData(): sending request to tks.");

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);
        HttpResponse resp =
                conn.send("computeRandomData",
                        IRemoteRequest.TOKEN_DATA_NUM_BYTES + "=" + dataSize);

        String content = resp.getContent();

        if (content != null && !content.equals("")) {
            Hashtable<String, Object> response =
                    parseResponse(content);

            /*
             * When a value is not found in response, keep going so we know
             * what else is missing
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = (String) response.get(IRemoteRequest.RESPONSE_STATUS);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: computeRandomData(): status not found.");
                //logger.debug("TKSRemoteRequestHandler: computeRandomData(): got content = " + content);
            } else {
                logger.debug("TKSRemoteRequestHandler: computeRandomData(): got status = " + value);
                ist = Integer.parseInt(value);
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_RandomData);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: computeRandomData(): response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_RandomData);
            } else {
                //logger.debug("TKSRemoteRequestHandler: computeRandomData(): got IRemoteRequest.TKS_RESPONSE_RandomData"
                //        + value);
                logger.debug("TKSRemoteRequestHandler: computeRandomData(): got IRemoteRequest.TKS_RESPONSE_RandomData");
                response.put(IRemoteRequest.TKS_RESPONSE_RandomData, Util.uriDecodeFromHex(value));
            }
            logger.debug("TKSRemoteRequestHandler: computeRandomData(): ends.");

            return new TKSComputeRandomDataResponse(response);
        } else {
            logger.error("TKSRemoteRequestHandler: computeRandomData(): no response content.");
            throw new EBaseException("TKSRemoteRequestHandler: computeRandomData(): no response content.");
        }
    }

    /*
     * encryptData
     *
     * Usage Example:
     *   TKSRemoteRequestHandler tksReq = new TKSRemoteRequestHandler("tks1");
     *   TKSEncryptDataResponse responseObj =
     *     tksReq.encryptData(
     *      dataSize)
     *  - on success return, one can say
     *    TPSBuffer value = responseObj.getEncryptedData();
     *      to get response param value encrypted data
     *
     * @param kdd key derivation data
     * @param cuid token cuid
     * @param version keyInfo
     * @param inData data to be encrypted
     * @return response TKSEncryptDataResponse class object
     */
    public TKSEncryptDataResponse encryptData(
            TPSBuffer kdd,
            TPSBuffer cuid,
            TPSBuffer version,
            TPSBuffer inData,int protocol)
            throws EBaseException {
        logger.debug("TKSRemoteRequestHandler: encryptData(): begins.");
        if (cuid == null || kdd == null || version == null || inData == null) {
            throw new EBaseException("TKSRemoteRequestHandler: encryptData(): input parameter null.");
        }

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        EngineConfig conf = engine.getConfig();

        if (keySet == null)
            keySet = conf.getString("tps.connector." + connid + ".keySet", "defKeySet");

        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);
        logger.debug("TKSRemoteRequestHandler: encryptData(): sending request to tks.");
        HttpResponse resp =
                conn.send("encryptData",
                        IRemoteRequest.TOKEN_DATA + "=" + Util.specialURLEncode(inData) +
                                "&" + IRemoteRequest.TOKEN_CUID + "=" + Util.specialURLEncode(cuid) +
                                "&" + IRemoteRequest.TOKEN_KDD + "=" + Util.specialURLEncode(kdd) +
                                "&" + IRemoteRequest.TOKEN_KEYINFO + "=" + Util.specialURLEncode(version) +
                                "&" + IRemoteRequest.TOKEN_KEYSET + "=" +  keySet +
                                "&" + IRemoteRequest.CHANNEL_PROTOCOL + "=" + protocol
                                );

        String content = resp.getContent();

        if (content != null && !content.equals("")) {
            Hashtable<String, Object> response =
                    parseResponse(content);

            /*
             * When a value is not found in response, keep going so we know
             * what else is missing
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = (String) response.get(IRemoteRequest.RESPONSE_STATUS);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: encryptData(): status not found.");
                //logger.debug("TKSRemoteRequestHandler: encryptData(): got content = " + content);
            } else {
                logger.debug("TKSRemoteRequestHandler: encryptData(): got status = " + value);
                ist = Integer.parseInt(value);
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            value = (String) response.get(IRemoteRequest.TKS_RESPONSE_EncryptedData);
            if (value == null) {
                logger.debug("TKSRemoteRequestHandler: encryptData(): response missing name-value pair for: " +
                        IRemoteRequest.TKS_RESPONSE_EncryptedData);
            } else {
                logger.debug("TKSRemoteRequestHandler: encryptData(): got IRemoteRequest.TKS_RESPONSE_EncryptedData");
                response.put(IRemoteRequest.TKS_RESPONSE_EncryptedData, Util.specialDecode(value));
            }
            logger.debug("TKSRemoteRequestHandler: encryptData(): ends.");

            return new TKSEncryptDataResponse(response);
        } else {
            logger.error("TKSRemoteRequestHandler: encryptData(): no response content.");
            throw new EBaseException("TKSRemoteRequestHandler: encryptData(): no response content.");
        }
    }
}
