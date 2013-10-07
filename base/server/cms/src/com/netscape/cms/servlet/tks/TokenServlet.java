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
package com.netscape.cms.servlet.tks;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.StringTokenizer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11SymKey;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IPrettyPrintFormat;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.symkey.SessionKey;

/**
 * A class representings an administration servlet for Token Key
 * Service Authority. This servlet is responsible to serve
 * tks administrative operation such as configuration
 * parameter updates.
 *
 * @version $Revision$, $Date$
 */
public class TokenServlet extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = 8687436109695172791L;
    protected static final String PROP_ENABLED = "enabled";
    protected static final String TRANSPORT_KEY_NAME = "sharedSecret";
    private final static String INFO = "TokenServlet";
    public static int ERROR = 1;
    String mKeyNickName = null;
    String mNewKeyNickName = null;
    IPrettyPrintFormat pp = CMS.getPrettyPrintFormat(":");

    private final static String LOGGING_SIGNED_AUDIT_COMPUTE_SESSION_KEY_REQUEST =
            "LOGGING_SIGNED_AUDIT_COMPUTE_SESSION_KEY_REQUEST_3";

    private final static String LOGGING_SIGNED_AUDIT_COMPUTE_SESSION_KEY_REQUEST_PROCESSED_SUCCESS =
            "LOGGING_SIGNED_AUDIT_COMPUTE_SESSION_KEY_REQUEST_PROCESSED_SUCCESS_8";

    private final static String LOGGING_SIGNED_AUDIT_COMPUTE_SESSION_KEY_REQUEST_PROCESSED_FAILURE =
            "LOGGING_SIGNED_AUDIT_COMPUTE_SESSION_KEY_REQUEST_PROCESSED_FAILURE_9";

    private final static String LOGGING_SIGNED_AUDIT_DIVERSIFY_KEY_REQUEST =
            "LOGGING_SIGNED_AUDIT_DIVERSIFY_KEY_REQUEST_5";

    private final static String LOGGING_SIGNED_AUDIT_DIVERSIFY_KEY_REQUEST_PROCESSED_SUCCESS =
            "LOGGING_SIGNED_AUDIT_DIVERSIFY_KEY_REQUEST_PROCESSED_SUCCESS_6";

    private final static String LOGGING_SIGNED_AUDIT_DIVERSIFY_KEY_REQUEST_PROCESSED_FAILURE =
            "LOGGING_SIGNED_AUDIT_DIVERSIFY_KEY_REQUEST_PROCESSED_FAILURE_7";

    private final static String LOGGING_SIGNED_AUDIT_ENCRYPT_DATA_REQUEST =
            "LOGGING_SIGNED_AUDIT_ENCRYPT_DATA_REQUEST_4";

    private final static String LOGGING_SIGNED_AUDIT_ENCRYPT_DATA_REQUEST_PROCESSED_SUCCESS =
            "LOGGING_SIGNED_AUDIT_ENCRYPT_DATA_REQUEST_PROCESSED_SUCCESS_7";

    private final static String LOGGING_SIGNED_AUDIT_ENCRYPT_DATA_REQUEST_PROCESSED_FAILURE =
            "LOGGING_SIGNED_AUDIT_ENCRYPT_DATA_REQUEST_PROCESSED_FAILURE_8";

    private final static String LOGGING_SIGNED_AUDIT_COMPUTE_RANDOM_DATA_REQUEST =
            "LOGGING_SIGNED_AUDIT_COMPUTE_RANDOM_DATA_REQUEST_2";

    private final static String LOGGING_SIGNED_AUDIT_COMPUTE_RANDOM_DATA_REQUEST_PROCESSED_SUCCESS =
            "LOGGING_SIGNED_AUDIT_COMPUTE_RANDOM_DATA_REQUEST_PROCESSED_SUCCESS_3";

    private final static String LOGGING_SIGNED_AUDIT_COMPUTE_RANDOM_DATA_REQUEST_PROCESSED_FAILURE =
            "LOGGING_SIGNED_AUDIT_COMPUTE_RANDOM_DATA_REQUEST_PROCESSED_FAILURE_4";

    /**
     * Constructs tks servlet.
     */
    public TokenServlet() {
        super();

    }

    public static String trim(String a) {
        StringBuffer newa = new StringBuffer();
        StringTokenizer tokens = new StringTokenizer(a, "\n");
        while (tokens.hasMoreTokens()) {
            newa.append(tokens.nextToken());
        }
        return newa.toString();
    }

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    }

    /**
     * Returns serlvet information.
     *
     * @return name of this servlet
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Process the HTTP request.
     *
     * @param s The URL to decode.
     */
    protected String URLdecode(String s) {
        if (s == null)
            return null;
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());

        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);

            if (c == '+') {
                out.write(' ');
            } else if (c == '%') {
                int c1 = Character.digit(s.charAt(++i), 16);
                int c2 = Character.digit(s.charAt(++i), 16);

                out.write((char) (c1 * 16 + c2));
            } else {
                out.write(c);
            }
        } // end for
        return out.toString();
    }

    private void setDefaultSlotAndKeyName(HttpServletRequest req) {
        try {

            String keySet = req.getParameter("keySet");
            if (keySet == null || keySet.equals("")) {
                keySet = "defKeySet";
            }
            CMS.debug("keySet selected: " + keySet);

            String masterKeyPrefix = CMS.getConfigStore().getString("tks.master_key_prefix", null);
            String temp = req.getParameter("KeyInfo"); //#xx#xx
            String keyInfoMap = "tks." + keySet + ".mk_mappings." + temp;
            String mappingValue = CMS.getConfigStore().getString(keyInfoMap, null);
            if (mappingValue != null) {
                StringTokenizer st = new StringTokenizer(mappingValue, ":");
                int tokenNumber = 0;
                while (st.hasMoreTokens()) {

                    String currentToken = st.nextToken();
                    if (tokenNumber == 1)
                        mKeyNickName = currentToken;
                    tokenNumber++;

                }
            }
            if (req.getParameter("newKeyInfo") != null) // for diversification
            {
                temp = req.getParameter("newKeyInfo"); //#xx#xx
                String newKeyInfoMap = "tks." + keySet + ".mk_mappings." + temp;
                String newMappingValue = CMS.getConfigStore().getString(newKeyInfoMap, null);
                if (newMappingValue != null) {
                    StringTokenizer st = new StringTokenizer(newMappingValue, ":");
                    int tokenNumber = 0;
                    while (st.hasMoreTokens()) {
                        String currentToken = st.nextToken();
                        if (tokenNumber == 1)
                            mNewKeyNickName = currentToken;
                        tokenNumber++;

                    }
                }
            }

            SessionKey.SetDefaultPrefix(masterKeyPrefix);

        } catch (Exception e) {
            e.printStackTrace();
            CMS.debug("Exception in TokenServlet::setDefaultSlotAndKeyName");
        }

    }

    private void processComputeSessionKey(HttpServletRequest req,
            HttpServletResponse resp) throws EBaseException {
        byte[] card_challenge, host_challenge, keyInfo, xCUID, CUID, session_key;
        byte[] card_crypto, host_cryptogram, input_card_crypto;
        byte[] xcard_challenge, xhost_challenge;
        byte[] enc_session_key, xkeyInfo;
        String auditMessage = null;
        String errorMsg = "";
        String badParams = "";
        String transportKeyName = "";

        String rCUID = req.getParameter("CUID");
        String keySet = req.getParameter("keySet");
        if (keySet == null || keySet.equals("")) {
            keySet = "defKeySet";
        }
        CMS.debug("keySet selected: " + keySet);

        boolean serversideKeygen = false;
        byte[] drm_trans_wrapped_desKey = null;
        PK11SymKey desKey = null;
        //        PK11SymKey kek_session_key;
        PK11SymKey kek_key;

        IConfigStore sconfig = CMS.getConfigStore();
        boolean isCryptoValidate = true;
        boolean missingParam = false;
        session_key = null;
        card_crypto = null;
        host_cryptogram = null;
        enc_session_key = null;
        //        kek_session_key = null;

        SessionContext sContext = SessionContext.getContext();

        String agentId = "";
        if (sContext != null) {
            agentId =
                    (String) sContext.get(SessionContext.USER_ID);
        }

        auditMessage = CMS.getLogMessage(
                         LOGGING_SIGNED_AUDIT_COMPUTE_SESSION_KEY_REQUEST,
                        rCUID,
                        ILogger.SUCCESS,
                        agentId);

        audit(auditMessage);

        String kek_wrapped_desKeyString = null;
        String keycheck_s = null;

        CMS.debug("processComputeSessionKey:");
        String useSoftToken_s = CMS.getConfigStore().getString("tks.useSoftToken", "true");
        if (!useSoftToken_s.equalsIgnoreCase("true"))
            useSoftToken_s = "false";

        String rServersideKeygen = req.getParameter("serversideKeygen");
        if (rServersideKeygen.equals("true")) {
            CMS.debug("TokenServlet: serversideKeygen requested");
            serversideKeygen = true;
        } else {
            CMS.debug("TokenServlet: serversideKeygen not requested");
        }

        try {
            isCryptoValidate = sconfig.getBoolean("cardcryptogram.validate.enable", true);
        } catch (EBaseException eee) {
        }

        transportKeyName = getSharedSecretName(sconfig);

        CMS.debug("TokenServlet: ComputeSessionKey(): tksSharedSymKeyName: " + transportKeyName);

        String rcard_challenge = req.getParameter("card_challenge");
        String rhost_challenge = req.getParameter("host_challenge");
        String rKeyInfo = req.getParameter("KeyInfo");
        String rcard_cryptogram = req.getParameter("card_cryptogram");
        if ((rCUID == null) || (rCUID.equals(""))) {
            CMS.debug("TokenServlet: ComputeSessionKey(): missing request parameter: CUID");
            badParams += " CUID,";
            missingParam = true;
        }

        if ((rcard_challenge == null) || (rcard_challenge.equals(""))) {
            badParams += " card_challenge,";
            CMS.debug("TokenServlet: ComputeSessionKey(): missing request parameter: card challenge");
            missingParam = true;
        }

        if ((rhost_challenge == null) || (rhost_challenge.equals(""))) {
            badParams += " host_challenge,";
            CMS.debug("TokenServlet: ComputeSessionKey(): missing request parameter: host challenge");
            missingParam = true;
        }

        if ((rKeyInfo == null) || (rKeyInfo.equals(""))) {
            badParams += " KeyInfo,";
            CMS.debug("TokenServlet: ComputeSessionKey(): missing request parameter: key info");
            missingParam = true;
        }

        String selectedToken = null;
        String keyNickName = null;
        boolean sameCardCrypto = true;

        if (!missingParam) {

            xCUID = com.netscape.cmsutil.util.Utils.SpecialDecode(rCUID);
            if (xCUID == null || xCUID.length != 10) {
                badParams += " CUID length,";
                CMS.debug("TokenServlet: Invalid CUID length");
                missingParam = true;
            }
            xkeyInfo = com.netscape.cmsutil.util.Utils.SpecialDecode(rKeyInfo);
            if (xkeyInfo == null || xkeyInfo.length != 2) {
                badParams += " KeyInfo length,";
                CMS.debug("TokenServlet: Invalid key info length.");
                missingParam = true;
            }
            xcard_challenge =
                    com.netscape.cmsutil.util.Utils.SpecialDecode(rcard_challenge);
            if (xcard_challenge == null || xcard_challenge.length != 8) {
                badParams += " card_challenge length,";
                CMS.debug("TokenServlet: Invalid card challenge length.");
                missingParam = true;
            }

            xhost_challenge = com.netscape.cmsutil.util.Utils.SpecialDecode(rhost_challenge);
            if (xhost_challenge == null || xhost_challenge.length != 8) {
                badParams += " host_challenge length,";
                CMS.debug("TokenServlet: Invalid host challenge length");
                missingParam = true;
            }

        }

        CUID = null;
        if (!missingParam) {
            card_challenge =
                    com.netscape.cmsutil.util.Utils.SpecialDecode(rcard_challenge);

            host_challenge = com.netscape.cmsutil.util.Utils.SpecialDecode(rhost_challenge);
            keyInfo = com.netscape.cmsutil.util.Utils.SpecialDecode(rKeyInfo);

            CUID = com.netscape.cmsutil.util.Utils.SpecialDecode(rCUID);

            String keyInfoMap = "tks." + keySet + ".mk_mappings." + rKeyInfo; //#xx#xx
            String mappingValue = CMS.getConfigStore().getString(keyInfoMap, null);
            if (mappingValue == null) {
                selectedToken =
                        CMS.getConfigStore().getString("tks.defaultSlot", "internal");
                keyNickName = rKeyInfo;
            } else {
                StringTokenizer st = new StringTokenizer(mappingValue, ":");
                if (st.hasMoreTokens())
                    selectedToken = st.nextToken();
                if (st.hasMoreTokens())
                    keyNickName = st.nextToken();
            }

            if (selectedToken != null && keyNickName != null) {

                try {

                    byte macKeyArray[] =
                            com.netscape.cmsutil.util.Utils.SpecialDecode(sconfig.getString("tks."
                                    + keySet + ".mac_key"));
                    CMS.debug("TokenServlet about to try ComputeSessionKey selectedToken="
                            + selectedToken + " keyNickName=" + keyNickName);
                    session_key = SessionKey.ComputeSessionKey(
                            selectedToken, keyNickName, card_challenge,
                            host_challenge, keyInfo, CUID, macKeyArray, useSoftToken_s, keySet, transportKeyName);

                    if (session_key == null) {
                        CMS.debug("TokenServlet:Tried ComputeSessionKey, got NULL ");
                        throw new Exception("Can't compute session key!");

                    }

                    byte encKeyArray[] =
                            com.netscape.cmsutil.util.Utils.SpecialDecode(sconfig.getString("tks."
                                    + keySet + ".auth_key"));
                    enc_session_key = SessionKey.ComputeEncSessionKey(
                            selectedToken, keyNickName, card_challenge,
                            host_challenge, keyInfo, CUID, encKeyArray, useSoftToken_s, keySet);

                    if (enc_session_key == null) {
                        CMS.debug("TokenServlet:Tried ComputeEncSessionKey, got NULL ");
                        throw new Exception("Can't compute enc session key!");

                    }

                    if (serversideKeygen == true) {

                        /**
                         * 0. generate des key
                         * 1. encrypt des key with kek key
                         * 2. encrypt des key with DRM transport key
                         * These two wrapped items are to be sent back to
                         * TPS. 2nd item is to DRM
                         **/
                        CMS.debug("TokenServlet: calling ComputeKekKey");

                        byte kekKeyArray[] =
                                com.netscape.cmsutil.util.Utils.SpecialDecode(sconfig.getString("tks."
                                        + keySet + ".kek_key"));

                        kek_key = SessionKey.ComputeKekKey(
                                selectedToken, keyNickName, card_challenge,
                                host_challenge, keyInfo, CUID, kekKeyArray, useSoftToken_s, keySet);

                        CMS.debug("TokenServlet: called ComputeKekKey");

                        if (kek_key == null) {
                            CMS.debug("TokenServlet:Tried ComputeKekKey, got NULL ");
                            throw new Exception("Can't compute kek key!");

                        }
                        // now use kek key to wrap kek session key..
                        CMS.debug("computeSessionKey:kek key len =" +
                                kek_key.getLength());

                        // (1) generate DES key
                        /* applet does not support DES3
                        org.mozilla.jss.crypto.KeyGenerator kg =
                            internalToken.getKeyGenerator(KeyGenAlgorithm.DES3);
                            desKey = kg.generate();*/

                        /*
                         * GenerateSymkey firt generates a 16 byte DES2 key.
                         * It then pads it into a 24 byte key with last
                         * 8 bytes copied from the 1st 8 bytes.  Effectively
                         * making it a 24 byte DES2 key.  We need this for
                         * wrapping private keys on DRM.
                         */
                        /*generate it on whichever token the master key is at*/
                        if (useSoftToken_s.equals("true")) {
                            CMS.debug("TokenServlet: key encryption key generated on internal");
                            //cfu audit here? sym key gen
                            desKey = SessionKey.GenerateSymkey("internal");
                            //cfu audit here? sym key gen done
                        } else {
                            CMS.debug("TokenServlet: key encryption key generated on " + selectedToken);
                            desKey = SessionKey.GenerateSymkey(selectedToken);
                        }
                        if (desKey != null)
                            CMS.debug("TokenServlet: key encryption key generated for " + rCUID);
                        else {
                            CMS.debug("TokenServlet: key encryption key generation failed for " + rCUID);
                            throw new Exception("can't generate key encryption key");
                        }

                        /*
                         * ECBencrypt actually takes the 24 byte DES2 key
                         * and discard the last 8 bytes before it encrypts.
                         * This is done so that the applet can digest it
                         */
                        byte[] encDesKey =
                                SessionKey.ECBencrypt(kek_key,
                                        desKey);
                        /*
                        CMS.debug("computeSessionKey:encrypted desKey size = "+encDesKey.length);
                        CMS.debug(encDesKey);
                        */

                        kek_wrapped_desKeyString =
                                com.netscape.cmsutil.util.Utils.SpecialEncode(encDesKey);

                        // get keycheck
                        byte[] keycheck =
                                SessionKey.ComputeKeyCheck(desKey);
                        /*
                        CMS.debug("computeSessionKey:keycheck size = "+keycheck.length);
                        CMS.debug(keycheck);
                        */
                        keycheck_s =
                                com.netscape.cmsutil.util.Utils.SpecialEncode(keycheck);

                        //use DRM transport cert to wrap desKey
                        String drmTransNickname = CMS.getConfigStore().getString("tks.drm_transport_cert_nickname", "");

                        if ((drmTransNickname == null) || (drmTransNickname == "")) {
                            CMS.debug("TokenServlet:did not find DRM transport certificate nickname");
                            throw new Exception("can't find DRM transport certificate nickname");
                        } else {
                            CMS.debug("TokenServlet:drmtransport_cert_nickname=" + drmTransNickname);
                        }

                        X509Certificate drmTransCert = null;
                        drmTransCert = CryptoManager.getInstance().findCertByNickname(drmTransNickname);
                        // wrap kek session key with DRM transport public key
                        CryptoToken token = null;
                        if (useSoftToken_s.equals("true")) {
                            //token = CryptoManager.getInstance().getTokenByName(selectedToken);
                            token = CryptoManager.getInstance().getInternalCryptoToken();
                        } else {
                            token = CryptoManager.getInstance().getTokenByName(selectedToken);
                        }
                        PublicKey pubKey = drmTransCert.getPublicKey();
                        String pubKeyAlgo = pubKey.getAlgorithm();
                        CMS.debug("Transport Cert Key Algorithm: " + pubKeyAlgo);
                        KeyWrapper keyWrapper = null;
                        //For wrapping symmetric keys don't need IV, use ECB
                        if (pubKeyAlgo.equals("EC")) {
                            keyWrapper = token.getKeyWrapper(KeyWrapAlgorithm.AES_ECB);
                            keyWrapper.initWrap(pubKey, null);
                        } else {
                            keyWrapper = token.getKeyWrapper(KeyWrapAlgorithm.RSA);
                            keyWrapper.initWrap(pubKey, null);
                        }
                        CMS.debug("desKey token " + desKey.getOwningToken().getName() + " token: " + token.getName());
                        drm_trans_wrapped_desKey = keyWrapper.wrap(desKey);
                        CMS.debug("computeSessionKey:desKey wrapped with drm transportation key.");

                    } // if (serversideKeygen == true)

                    byte authKeyArray[] =
                            com.netscape.cmsutil.util.Utils.SpecialDecode(sconfig.getString("tks."
                                    + keySet + ".auth_key"));
                    host_cryptogram = SessionKey.ComputeCryptogram(
                            selectedToken, keyNickName, card_challenge,
                            host_challenge, keyInfo, CUID, 0, authKeyArray, useSoftToken_s, keySet);

                    if (host_cryptogram == null) {
                        CMS.debug("TokenServlet:Tried ComputeCryptogram, got NULL ");
                        throw new Exception("Can't compute host cryptogram!");

                    }
                    card_crypto = SessionKey.ComputeCryptogram(
                            selectedToken, keyNickName, card_challenge,
                            host_challenge, keyInfo, CUID, 1, authKeyArray, useSoftToken_s, keySet);

                    if (card_crypto == null) {
                        CMS.debug("TokenServlet:Tried ComputeCryptogram, got NULL ");
                        throw new Exception("Can't compute card cryptogram!");

                    }

                    if (isCryptoValidate) {
                        if (rcard_cryptogram == null) {
                            CMS.debug("TokenServlet: ComputeCryptogram(): missing card cryptogram");
                            throw new Exception("Missing card cryptogram");
                        }
                        input_card_crypto =
                                com.netscape.cmsutil.util.Utils.SpecialDecode(rcard_cryptogram);
                        if (card_crypto.length == input_card_crypto.length) {
                            for (int i = 0; i < card_crypto.length; i++) {
                                if (card_crypto[i] != input_card_crypto[i]) {
                                    sameCardCrypto = false;
                                    break;
                                }
                            }
                        } else {
                            // different length; must be different
                            sameCardCrypto = false;
                        }
                    }

                    CMS.getLogger().log(ILogger.EV_AUDIT,
                            ILogger.S_TKS,
                            ILogger.LL_INFO, "processComputeSessionKey for CUID=" +
                                    trim(pp.toHexString(CUID)));
                } catch (Exception e) {
                    CMS.debug(e);
                    CMS.debug("TokenServlet Computing Session Key: " + e.toString());
                    if (isCryptoValidate)
                        sameCardCrypto = false;
                }
            }
        } // ! missingParam

        String value = "";

        resp.setContentType("text/html");

        String outputString = "";
        String encSessionKeyString = "";
        String drm_trans_wrapped_desKeyString = "";
        String cryptogram = "";
        String status = "0";
        if (session_key != null && session_key.length > 0) {
            outputString =
                    com.netscape.cmsutil.util.Utils.SpecialEncode(session_key);
        } else {

            status = "1";
        }

        if (enc_session_key != null && enc_session_key.length > 0) {
            encSessionKeyString =
                    com.netscape.cmsutil.util.Utils.SpecialEncode(enc_session_key);
        } else {
            status = "1";
        }

        if (serversideKeygen == true) {
            if (drm_trans_wrapped_desKey != null && drm_trans_wrapped_desKey.length > 0)
                drm_trans_wrapped_desKeyString =
                        com.netscape.cmsutil.util.Utils.SpecialEncode(drm_trans_wrapped_desKey);
            else {
                status = "1";
            }
        }

        if (host_cryptogram != null && host_cryptogram.length > 0) {
            cryptogram =
                    com.netscape.cmsutil.util.Utils.SpecialEncode(host_cryptogram);
        } else {
            status = "2";
        }

        if (selectedToken == null || keyNickName == null) {
            status = "4";
        }

        if (!sameCardCrypto) {
            status = "3";
        }

        if (missingParam) {
            status = "3";
        }

        if (!status.equals("0")) {

            if (status.equals("1")) {
                errorMsg = "Problem generating session key info.";
            }

            if (status.equals("2")) {
                errorMsg = "Problem creating host_cryptogram.";
            }

            if (status.equals("4")) {
                errorMsg = "Problem obtaining token information.";
            }

            if (status.equals("3")) {
                if (badParams.endsWith(",")) {
                    badParams = badParams.substring(0, badParams.length() - 1);
                }
                errorMsg = "Missing input parameters :" + badParams;
            }

            value = "status=" + status;
        } else {
            if (serversideKeygen == true) {
                StringBuffer sb = new StringBuffer();
                sb.append("status=0&");
                sb.append("sessionKey=");
                sb.append(outputString);
                sb.append("&hostCryptogram=");
                sb.append(cryptogram);
                sb.append("&encSessionKey=");
                sb.append(encSessionKeyString);
                sb.append("&kek_wrapped_desKey=");
                sb.append(kek_wrapped_desKeyString);
                sb.append("&keycheck=");
                sb.append(keycheck_s);
                sb.append("&drm_trans_wrapped_desKey=");
                sb.append(drm_trans_wrapped_desKeyString);
                value = sb.toString();
            } else {
                StringBuffer sb = new StringBuffer();
                sb.append("status=0&");
                sb.append("sessionKey=");
                sb.append(outputString);
                sb.append("&hostCryptogram=");
                sb.append(cryptogram);
                sb.append("&encSessionKey=");
                sb.append(encSessionKeyString);
                value = sb.toString();
            }

        }
        CMS.debug("TokenServlet:outputString.encode " + value);

        try {
            resp.setContentLength(value.length());
            CMS.debug("TokenServlet:outputString.length " + value.length());
            OutputStream ooss = resp.getOutputStream();
            ooss.write(value.getBytes());
            ooss.flush();
            mRenderResult = false;
        } catch (IOException e) {
            CMS.debug("TokenServlet: " + e.toString());
        }

        if (status.equals("0")) {

            auditMessage = CMS.getLogMessage(
                         LOGGING_SIGNED_AUDIT_COMPUTE_SESSION_KEY_REQUEST_PROCESSED_SUCCESS,
                        rCUID,
                        ILogger.SUCCESS,
                        status,
                        agentId,
                        isCryptoValidate ? "true" : "false",
                        serversideKeygen ? "true" : "false",
                        selectedToken,
                        keyNickName);

        } else {

            auditMessage = CMS.getLogMessage(
                         LOGGING_SIGNED_AUDIT_COMPUTE_SESSION_KEY_REQUEST_PROCESSED_FAILURE,
                        rCUID,
                        ILogger.FAILURE,
                        status,
                        agentId,
                        isCryptoValidate ? "true" : "false",
                        serversideKeygen ? "true" : "false",
                        selectedToken,
                        keyNickName,
                        errorMsg);
        }

        audit(auditMessage);
    }

    // This method will return the shared secret name.  In new 10.1 subsystems, this
    // name will be stored in tps.X.nickname.
    //
    // Until multiple TKS/TPS connections is fully supported, this method will just
    // return the first shared secret nickname found, on the assumption that only
    // one nickname will be configured.  This will have to be changed to return the correct
    // key based on some parameter in the request in future.
    //
    // On legacy systems, this method just returns what was previously returned.
    private String getSharedSecretName(IConfigStore cs) throws EBaseException {
        boolean useNewNames = cs.getBoolean("tks.useNewSharedSecretNames", false);

        if (useNewNames) {
            String tpsList = cs.getString("tps.list", "");
            if (!tpsList.isEmpty()) {
                for (String tpsID : tpsList.split(",")) {
                    String sharedSecretName = cs.getString("tps." + tpsID + ".nickname", "");
                    if (!sharedSecretName.isEmpty()) {
                        return sharedSecretName;
                    }
                }
            }
            CMS.debug("getSharedSecretName: no shared secret has been configured");
            throw new EBaseException("No shared secret has been configured");
        }

        // legacy system - return as before
        return cs.getString("tks.tksSharedSymKeyName", TRANSPORT_KEY_NAME);
    }

    private void processDiversifyKey(HttpServletRequest req,
            HttpServletResponse resp) throws EBaseException {
        byte[] KeySetData, CUID, xCUID;
        byte[] xkeyInfo, xnewkeyInfo;
        boolean missingParam = false;
        String errorMsg = "";
        String badParams = "";

        IConfigStore sconfig = CMS.getConfigStore();
        String rnewKeyInfo = req.getParameter("newKeyInfo");
        String newMasterKeyName = req.getParameter("newKeyInfo");
        String oldMasterKeyName = req.getParameter("KeyInfo");
        String rCUID = req.getParameter("CUID");
        String auditMessage = "";

        String keySet = req.getParameter("keySet");
        if (keySet == null || keySet.equals("")) {
            keySet = "defKeySet";
        }
        CMS.debug("keySet selected: " + keySet);

        SessionContext sContext = SessionContext.getContext();

        String agentId = "";
        if (sContext != null) {
            agentId =
                    (String) sContext.get(SessionContext.USER_ID);
        }

        auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_DIVERSIFY_KEY_REQUEST,
                        rCUID,
                        ILogger.SUCCESS,
                        agentId,
                        oldMasterKeyName,
                        newMasterKeyName);

        audit(auditMessage);

        if ((rCUID == null) || (rCUID.equals(""))) {
            badParams += " CUID,";
            CMS.debug("TokenServlet: processDiversifyKey(): missing request parameter: CUID");
            missingParam = true;
        }
        if ((rnewKeyInfo == null) || (rnewKeyInfo.equals(""))) {
            badParams += " newKeyInfo,";
            CMS.debug("TokenServlet: processDiversifyKey(): missing request parameter: newKeyInfo");
            missingParam = true;
        }
        if ((oldMasterKeyName == null) || (oldMasterKeyName.equals(""))) {
            badParams += " KeyInfo,";
            CMS.debug("TokenServlet: processDiversifyKey(): missing request parameter: KeyInfo");
            missingParam = true;
        }

        if (!missingParam) {
            xkeyInfo = com.netscape.cmsutil.util.Utils.SpecialDecode(oldMasterKeyName);
            if (xkeyInfo == null || xkeyInfo.length != 2) {
                badParams += " KeyInfo length,";
                CMS.debug("TokenServlet: Invalid key info length");
                missingParam = true;
            }
            xnewkeyInfo = com.netscape.cmsutil.util.Utils.SpecialDecode(newMasterKeyName);
            if (xnewkeyInfo == null || xnewkeyInfo.length != 2) {
                badParams += " NewKeyInfo length,";
                CMS.debug("TokenServlet: Invalid new key info length");
                missingParam = true;
            }
        }
        String useSoftToken_s = CMS.getConfigStore().getString("tks.useSoftToken", "true");
        if (!useSoftToken_s.equalsIgnoreCase("true"))
            useSoftToken_s = "false";

        KeySetData = null;
        if (!missingParam) {
            xCUID = com.netscape.cmsutil.util.Utils.SpecialDecode(rCUID);
            if (xCUID == null || xCUID.length != 10) {
                badParams += " CUID length,";
                CMS.debug("TokenServlet: Invalid CUID length");
                missingParam = true;
            }
        }
        if (!missingParam) {
            CUID = com.netscape.cmsutil.util.Utils.SpecialDecode(rCUID);

            if (mKeyNickName != null)
                oldMasterKeyName = mKeyNickName;
            if (mNewKeyNickName != null)
                newMasterKeyName = mNewKeyNickName;

            String oldKeyInfoMap = "tks." + keySet + ".mk_mappings." + req.getParameter("KeyInfo"); //#xx#xx
            String oldMappingValue = CMS.getConfigStore().getString(oldKeyInfoMap, null);
            String oldSelectedToken = null;
            String oldKeyNickName = null;
            if (oldMappingValue == null) {
                oldSelectedToken = CMS.getConfigStore().getString("tks.defaultSlot", "internal");
                oldKeyNickName = req.getParameter("KeyInfo");
            } else {
                StringTokenizer st = new StringTokenizer(oldMappingValue, ":");
                oldSelectedToken = st.nextToken();
                oldKeyNickName = st.nextToken();
            }

            String newKeyInfoMap = "tks.mk_mappings." + rnewKeyInfo; //#xx#xx
            String newMappingValue = CMS.getConfigStore().getString(newKeyInfoMap, null);
            String newSelectedToken = null;
            String newKeyNickName = null;
            if (newMappingValue == null) {
                newSelectedToken = CMS.getConfigStore().getString("tks.defaultSlot", "internal");
                newKeyNickName = rnewKeyInfo;
            } else {
                StringTokenizer st = new StringTokenizer(newMappingValue, ":");
                newSelectedToken = st.nextToken();
                newKeyNickName = st.nextToken();
            }

            CMS.debug("process DiversifyKey for oldSelectedToke=" +
                    oldSelectedToken + " newSelectedToken=" + newSelectedToken +
                    " oldKeyNickName=" + oldKeyNickName + " newKeyNickName=" +
                    newKeyNickName);

            byte kekKeyArray[] =
                    com.netscape.cmsutil.util.Utils.SpecialDecode(sconfig.getString("tks." + keySet + ".kek_key"));
            KeySetData = SessionKey.DiversifyKey(oldSelectedToken,
                     newSelectedToken, oldKeyNickName,
                    newKeyNickName, rnewKeyInfo, CUID, kekKeyArray, useSoftToken_s, keySet);

            if (KeySetData == null || KeySetData.length <= 1) {
                CMS.getLogger().log(ILogger.EV_AUDIT,
                        ILogger.S_TKS,
                        ILogger.LL_INFO, "process DiversifyKey: Missing MasterKey in Slot");
            }

            CMS.getLogger().log(ILogger.EV_AUDIT,
                    ILogger.S_TKS,
                    ILogger.LL_INFO, "process DiversifyKey for CUID =" + trim(pp.toHexString(CUID))
                            + ";from oldMasterKeyName=" + oldSelectedToken + ":" + oldKeyNickName
                            + ";to newMasterKeyName=" + newSelectedToken + ":" + newKeyNickName);

            resp.setContentType("text/html");
        } // ! missingParam

        //CMS.debug("TokenServlet:processDiversifyKey " +outputString);
        //String value="keySetData=%00" if the KeySetData=byte[0]=0;

        String value = "";
        String status = "0";

        if (KeySetData != null && KeySetData.length > 1) {
            value = "status=0&" + "keySetData=" +
                     com.netscape.cmsutil.util.Utils.SpecialEncode(KeySetData);
            CMS.debug("TokenServlet:process DiversifyKey.encode " + value);
        } else if (missingParam) {
            status = "3";
            if (badParams.endsWith(",")) {
                badParams = badParams.substring(0, badParams.length() - 1);
            }
            errorMsg = "Missing input parameters: " + badParams;
            value = "status=" + status;
        } else {
            errorMsg = "Problem diversifying key data.";
            status = "1";
            value = "status=" + status;
        }

        resp.setContentLength(value.length());
        CMS.debug("TokenServlet:outputString.length " + value.length());

        try {
            OutputStream ooss = resp.getOutputStream();
            ooss.write(value.getBytes());
            ooss.flush();
            mRenderResult = false;
        } catch (Exception e) {
            CMS.debug("TokenServlet:process DiversifyKey: " + e.toString());
        }

        if (status.equals("0")) {

            auditMessage = CMS.getLogMessage(
                         LOGGING_SIGNED_AUDIT_DIVERSIFY_KEY_REQUEST_PROCESSED_SUCCESS,
                        rCUID,
                        ILogger.SUCCESS,
                        status,
                        agentId,
                        oldMasterKeyName,
                        newMasterKeyName);

        } else {

            auditMessage = CMS.getLogMessage(
                         LOGGING_SIGNED_AUDIT_DIVERSIFY_KEY_REQUEST_PROCESSED_FAILURE,
                        rCUID,
                        ILogger.FAILURE,
                        status,
                        agentId,
                        oldMasterKeyName,
                        newMasterKeyName,
                        errorMsg);
        }

        audit(auditMessage);
    }

    private void processEncryptData(HttpServletRequest req,
            HttpServletResponse resp) throws EBaseException {
        byte[] keyInfo, CUID, xCUID, encryptedData, xkeyInfo;
        boolean missingParam = false;
        byte[] data = null;
        boolean isRandom = true; // randomly generate the data to be encrypted

        String errorMsg = "";
        String badParams = "";
        IConfigStore sconfig = CMS.getConfigStore();
        encryptedData = null;
        String rdata = req.getParameter("data");
        String rKeyInfo = req.getParameter("KeyInfo");
        String rCUID = req.getParameter("CUID");
        String keySet = req.getParameter("keySet");
        if (keySet == null || keySet.equals("")) {
            keySet = "defKeySet";
        }

        SessionContext sContext = SessionContext.getContext();

        String agentId = "";
        if (sContext != null) {
            agentId =
                    (String) sContext.get(SessionContext.USER_ID);
        }

        CMS.debug("keySet selected: " + keySet);

        String s_isRandom = sconfig.getString("tks.EncryptData.isRandom", "true");
        if (s_isRandom.equalsIgnoreCase("false")) {
            CMS.debug("TokenServlet: processEncryptData(): Random number not to be generated");
            isRandom = false;
        } else {
            CMS.debug("TokenServlet: processEncryptData(): Random number generation required");
            isRandom = true;
        }

        String auditMessage = CMS.getLogMessage(
                       LOGGING_SIGNED_AUDIT_ENCRYPT_DATA_REQUEST,
                       rCUID,
                       ILogger.SUCCESS,
                       agentId,
                       s_isRandom);

        audit(auditMessage);

        if (isRandom) {
            if ((rdata == null) || (rdata.equals(""))) {
                CMS.debug("TokenServlet: processEncryptData(): no data in request.  Generating random number as data");
            } else {
                CMS.debug("TokenServlet: processEncryptData(): contain data in request, however, random generation on TKS is required. Generating...");
            }
            try {
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                data = new byte[16];
                random.nextBytes(data);
            } catch (Exception e) {
                CMS.debug("TokenServlet: processEncryptData():" + e.toString());
                badParams += " Random Number,";
                missingParam = true;
            }
        } else if ((!isRandom) && (((rdata == null) || (rdata.equals(""))))) {
            CMS.debug("TokenServlet: processEncryptData(): missing request parameter: data.");
            badParams += " data,";
            missingParam = true;
        }

        if ((rCUID == null) || (rCUID.equals(""))) {
            badParams += " CUID,";
            CMS.debug("TokenServlet: processEncryptData(): missing request parameter: CUID");
            missingParam = true;
        }

        if ((rKeyInfo == null) || (rKeyInfo.equals(""))) {
            badParams += " KeyInfo,";
            CMS.debug("TokenServlet: processEncryptData(): missing request parameter: key info");
            missingParam = true;
        }

        if (!missingParam) {
            xCUID = com.netscape.cmsutil.util.Utils.SpecialDecode(rCUID);
            if (xCUID == null || xCUID.length != 10) {
                badParams += " CUID length,";
                CMS.debug("TokenServlet: Invalid CUID length");
                missingParam = true;
            }
            xkeyInfo = com.netscape.cmsutil.util.Utils.SpecialDecode(rKeyInfo);
            if (xkeyInfo == null || xkeyInfo.length != 2) {
                badParams += " KeyInfo length,";
                CMS.debug("TokenServlet: Invalid key info length");
                missingParam = true;
            }
        }

        String useSoftToken_s = CMS.getConfigStore().getString("tks.useSoftToken", "true");
        if (!useSoftToken_s.equalsIgnoreCase("true"))
            useSoftToken_s = "false";

        String selectedToken = null;
        String keyNickName = null;
        if (!missingParam) {
            if (!isRandom)
                data = com.netscape.cmsutil.util.Utils.SpecialDecode(rdata);
            keyInfo = com.netscape.cmsutil.util.Utils.SpecialDecode(rKeyInfo);
            CUID = com.netscape.cmsutil.util.Utils.SpecialDecode(rCUID);

            String keyInfoMap = "tks." + keySet + ".mk_mappings." + rKeyInfo;
            String mappingValue = CMS.getConfigStore().getString(keyInfoMap, null);
            if (mappingValue == null) {
                selectedToken = CMS.getConfigStore().getString("tks.defaultSlot", "internal");
                keyNickName = rKeyInfo;
            } else {
                StringTokenizer st = new StringTokenizer(mappingValue, ":");
                selectedToken = st.nextToken();
                keyNickName = st.nextToken();
            }

            byte kekKeyArray[] =
                    com.netscape.cmsutil.util.Utils.SpecialDecode(sconfig.getString("tks." + keySet + ".kek_key"));
            encryptedData = SessionKey.EncryptData(
                       selectedToken, keyNickName, data, keyInfo, CUID, kekKeyArray, useSoftToken_s, keySet);

            CMS.getLogger().log(ILogger.EV_AUDIT,
                     ILogger.S_TKS,
                     ILogger.LL_INFO, "process EncryptData for CUID =" + trim(pp.toHexString(CUID)));
        } // !missingParam

        resp.setContentType("text/html");

        String value = "";
        String status = "0";
        if (encryptedData != null && encryptedData.length > 0) {
            // sending both the pre-encrypted and encrypted data back
            value = "status=0&" + "data=" +
                         com.netscape.cmsutil.util.Utils.SpecialEncode(data) +
                         "&encryptedData=" +
                         com.netscape.cmsutil.util.Utils.SpecialEncode(encryptedData);
        } else if (missingParam) {
            if (badParams.endsWith(",")) {
                badParams = badParams.substring(0, badParams.length() - 1);
            }
            errorMsg = "Missing input parameters: " + badParams;
            status = "3";
            value = "status=" + status;
        } else {
            errorMsg = "Problem encrypting data.";
            status = "1";
            value = "status=" + status;
        }

        CMS.debug("TokenServlet:process EncryptData.encode " + value);

        try {
            resp.setContentLength(value.length());
            CMS.debug("TokenServlet:outputString.lenght " + value.length());

            OutputStream ooss = resp.getOutputStream();
            ooss.write(value.getBytes());
            ooss.flush();
            mRenderResult = false;
        } catch (Exception e) {
            CMS.debug("TokenServlet: " + e.toString());
        }

        if (status.equals("0")) {

            auditMessage = CMS.getLogMessage(
                         LOGGING_SIGNED_AUDIT_ENCRYPT_DATA_REQUEST_PROCESSED_SUCCESS,
                        rCUID,
                        ILogger.SUCCESS,
                        status,
                        agentId,
                        s_isRandom,
                        selectedToken,
                        keyNickName);

        } else {

            auditMessage = CMS.getLogMessage(
                         LOGGING_SIGNED_AUDIT_ENCRYPT_DATA_REQUEST_PROCESSED_FAILURE,
                        rCUID,
                        ILogger.FAILURE,
                        status,
                        agentId,
                        s_isRandom,
                        selectedToken,
                        keyNickName,
                        errorMsg);
        }

        audit(auditMessage);
    }

    /*
     *   For EncryptData:
     *   data=value1
     *   CUID=value2 // missing from RA
     *   versionID=value3  // missing from RA
     *
     *   For ComputeSession:
     *   card_challenge=value1
     *   host_challenge=value2

     *   For DiversifyKey:
     *   new_master_key_index
     *   master_key_index
     */

    private void processComputeRandomData(HttpServletRequest req,
            HttpServletResponse resp) throws EBaseException {

        byte[] randomData = null;
        String status = "0";
        String errorMsg = "";
        String badParams = "";
        boolean missingParam = false;
        int dataSize = 0;

        CMS.debug("TokenServlet::processComputeRandomData");

        SessionContext sContext = SessionContext.getContext();

        String agentId = "";
        if (sContext != null) {
            agentId =
                    (String) sContext.get(SessionContext.USER_ID);
        }

        String sDataSize = req.getParameter("dataNumBytes");

        if (sDataSize == null || sDataSize.equals("")) {
            CMS.debug("TokenServlet::processComputeRandomData missing param dataNumBytes");
            badParams += " Random Data size, ";
            missingParam = true;
            status = "1";
        } else {
            try {
                dataSize = Integer.parseInt(sDataSize.trim());
            } catch (NumberFormatException nfe) {
                CMS.debug("TokenServlet::processComputeRandomData invalid data size input!");
                badParams += " Random Data size, ";
                missingParam = true;
                status = "1";
            }

        }

        CMS.debug("TokenServlet::processComputeRandomData data size requested: " + dataSize);

        String auditMessage = CMS.getLogMessage(
                       LOGGING_SIGNED_AUDIT_COMPUTE_RANDOM_DATA_REQUEST,
                       ILogger.SUCCESS,
                       agentId);

        audit(auditMessage);

        if (!missingParam) {
            try {
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                randomData = new byte[dataSize];
                random.nextBytes(randomData);
            } catch (Exception e) {
                CMS.debug("TokenServlet::processComputeRandomData:" + e.toString());
                errorMsg = "Can't generate random data!";
                status = "2";
            }
        }

        String randomDataOut = "";
        if (status.equals("0")) {
            if (randomData != null && randomData.length == dataSize) {
                randomDataOut =
                        com.netscape.cmsutil.util.Utils.SpecialEncode(randomData);
            } else {
                status = "2";
                errorMsg = "Can't convert random data!";
            }
        }

        if (status.equals("1") && missingParam) {

            if (badParams.endsWith(",")) {
                badParams = badParams.substring(0, badParams.length() - 1);
            }
            errorMsg = "Missing input parameters :" + badParams;
        }

        resp.setContentType("text/html");
        String value = "";

        value = "status=" + status;
        if (status.equals("0")) {
            value = value + "&DATA=" + randomDataOut;
        }

        try {
            resp.setContentLength(value.length());
            CMS.debug("TokenServler::processComputeRandomData :outputString.length " + value.length());

            OutputStream ooss = resp.getOutputStream();
            ooss.write(value.getBytes());
            ooss.flush();
            mRenderResult = false;
        } catch (Exception e) {
            CMS.debug("TokenServlet::processComputeRandomData " + e.toString());
        }

        if (status.equals("0")) {
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_COMPUTE_RANDOM_DATA_REQUEST_PROCESSED_SUCCESS,
                        ILogger.SUCCESS,
                        status,
                        agentId);
        } else {
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_COMPUTE_RANDOM_DATA_REQUEST_PROCESSED_FAILURE,
                        ILogger.FAILURE,
                        status,
                        agentId,
                        errorMsg);
        }

        audit(auditMessage);
    }

    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);
        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "execute");
        } catch (Exception e) {
        }

        if (authzToken == null) {

            try {
                resp.setContentType("text/html");
                String value = "unauthorized=";
                CMS.debug("TokenServlet: Unauthorized");

                resp.setContentLength(value.length());
                OutputStream ooss = resp.getOutputStream();
                ooss.write(value.getBytes());
                ooss.flush();
                mRenderResult = false;
            } catch (Exception e) {
                CMS.debug("TokenServlet: " + e.toString());
            }

            //       cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        String temp = req.getParameter("card_challenge");
        setDefaultSlotAndKeyName(req);
        if (temp != null) {
            processComputeSessionKey(req, resp);
        } else if (req.getParameter("data") != null) {
            processEncryptData(req, resp);
        } else if (req.getParameter("newKeyInfo") != null) {
            processDiversifyKey(req, resp);
        } else if (req.getParameter("dataNumBytes") != null) {
            processComputeRandomData(req, resp);
        }
    }

    /**
     * Serves HTTP admin request.
     *
     * @param req HTTP request
     * @param resp HTTP response
     */
    public void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.service(req, resp);
    }
}
