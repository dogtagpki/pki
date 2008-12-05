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

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.*;
import org.mozilla.jss.pkcs11.*;

import sun.misc.*;
import java.io.*;
import java.util.*;
import java.net.*;
import java.util.*;
import java.text.*;
import java.math.*;
import java.security.*;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.security.x509.*;
import java.net.URLEncoder;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.password.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.security.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.certsrv.apps.CMS;
import com.netscape.cms.servlet.base.*;
import com.netscape.cms.servlet.common.*;
import com.netscape.cmsutil.util.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.authorization.*;
import com.netscape.certsrv.tks.*;
import com.netscape.symkey.*;



/**
 * A class representings an administration servlet for Token Key
 * Service Authority. This servlet is responsible to serve 
 * tks administrative operation such as configuration 
 * parameter updates.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class TokenServlet extends CMSServlet {
    protected static final String PROP_ENABLED = "enabled";

    private final static String INFO = "TokenServlet";
    public static int ERROR = 1;
    private ITKSAuthority mTKS = null;
    private String mSelectedToken = null;
    private String mNewSelectedToken = null;
    String mKeyNickName = null;
    String mNewKeyNickName = null; 
    private final static String LOGGING_SIGNED_AUDIT_CONFIG_DRM =
        "LOGGING_SIGNED_AUDIT_CONFIG_DRM_3";
    IPrettyPrintFormat pp = CMS.getPrettyPrintFormat(":");

    /**
     * Constructs tks servlet.
     */
    public TokenServlet() {
        super();

    }

    public static String trim(String a) 
    {
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
            int c = (int) s.charAt(i);

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

    private void setDefaultSlotAndKeyName(HttpServletRequest req)
    {
         try {

        String keySet = req.getParameter("keySet");
        if (keySet == null || keySet.equals("")) {
          keySet = "defKeySet";
        }
        CMS.debug("keySet selected: " + keySet);

        mNewSelectedToken = null;
        
        mSelectedToken = CMS.getConfigStore().getString("tks.defaultSlot");
        String masterKeyPrefix = CMS.getConfigStore().getString("tks.master_key_prefix", null);
        String temp = req.getParameter("KeyInfo"); //#xx#xx
        String keyInfoMap = "tks." + keySet + ".mk_mappings." + temp;
        String mappingValue = CMS.getConfigStore().getString(keyInfoMap, null);
        if(mappingValue!=null)
            {        
            StringTokenizer st = new StringTokenizer(mappingValue, ":");
            int tokenNumber=0;
            while (st.hasMoreTokens()) {

                        String currentToken= st.nextToken();
                        if(tokenNumber==0)
                            mSelectedToken = currentToken;
                            else if(tokenNumber==1)
                                mKeyNickName = currentToken;
                        tokenNumber++;
                    
                    }
            }
        if(req.getParameter("newKeyInfo")!=null) // for diversification
            {
            temp = req.getParameter("newKeyInfo"); //#xx#xx
            String newKeyInfoMap = "tks." + keySet + ".mk_mappings." + temp;
            String newMappingValue = CMS.getConfigStore().getString(newKeyInfoMap, null);
            if(newMappingValue!=null)
                {
                StringTokenizer st = new StringTokenizer(newMappingValue, ":");
                int tokenNumber=0;
                while (st.hasMoreTokens()) {
                            String currentToken= st.nextToken();
                            if(tokenNumber==0)
                                mNewSelectedToken = currentToken;
                                else if(tokenNumber==1)
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
      HttpServletResponse resp) throws EBaseException
    {
        byte[] card_challenge ,host_challenge,keyInfo, xCUID, CUID, session_key;
        byte[] card_crypto, host_cryptogram, input_card_crypto;
        byte[] xcard_challenge, xhost_challenge;
        byte[] enc_session_key, xkeyInfo;
    
        String keySet = req.getParameter("keySet");
        if (keySet == null || keySet.equals("")) {
          keySet = "defKeySet";
        }
        CMS.debug("keySet selected: " + keySet);

        boolean serversideKeygen = false;
        byte[] drm_trans_wrapped_desKey = null;
	SymmetricKey desKey = null;
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

        String kek_wrapped_desKeyString = null;
	String keycheck_s = null;

        CMS.debug("processComputeSessionKey:");
        String useSoftToken_s = CMS.getConfigStore().getString("tks.useSoftToken", "true");
	if (!useSoftToken_s.equalsIgnoreCase("true"))
	    useSoftToken_s = "false";

	String rServersideKeygen = (String) req.getParameter("serversideKeygen");
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

        String rcard_challenge = req.getParameter("card_challenge");
        String rhost_challenge = req.getParameter("host_challenge");
        String rKeyInfo = req.getParameter("KeyInfo");
        String rCUID = req.getParameter("CUID");
        String rcard_cryptogram = req.getParameter("card_cryptogram");
        if ((rCUID == null) || (rCUID.equals(""))) {
            CMS.debug("TokenServlet: ComputeSessionKey(): missing request parameter: CUID");
            missingParam = true;
        }

        if ((rcard_challenge == null) || (rcard_challenge.equals(""))) {
            CMS.debug("TokenServlet: ComputeSessionKey(): missing request parameter: card challenge");
            missingParam = true;
        }

        if ((rhost_challenge == null) || (rhost_challenge.equals(""))) {
            CMS.debug("TokenServlet: ComputeSessionKey(): missing request parameter: host challenge");
            missingParam = true;
        }

        if ((rKeyInfo == null) || (rKeyInfo.equals(""))) {
            CMS.debug("TokenServlet: ComputeSessionKey(): missing request parameter: key info");
            missingParam = true;
        }

        
        String selectedToken = null;
        String keyNickName = null;
        boolean sameCardCrypto = true;

        if (!missingParam) {
            xCUID =com.netscape.cmsutil.util.Utils.SpecialDecode(rCUID);
            if (xCUID == null || xCUID.length != 10) {
                        CMS.debug("TokenServlet: Invalid CUID length");
                        missingParam = true;
            }
            xkeyInfo = com.netscape.cmsutil.util.Utils.SpecialDecode(rKeyInfo);
            if (xkeyInfo == null || xkeyInfo.length != 2) {
                        CMS.debug("TokenServlet: Invalid key info length");
                        missingParam = true;
            }
            xcard_challenge = 
                com.netscape.cmsutil.util.Utils.SpecialDecode(rcard_challenge);
            if (xcard_challenge == null || xcard_challenge.length != 8) {
                        CMS.debug("TokenServlet: Invalid card challenge length");
                        missingParam = true;
            }
        
            xhost_challenge = com.netscape.cmsutil.util.Utils.SpecialDecode(rhost_challenge);
            if (xhost_challenge == null || xhost_challenge.length != 8) {
                        CMS.debug("TokenServlet: Invalid host challenge length");
                        missingParam = true;
            }
        }

        if (!missingParam) {
            card_challenge = 
                com.netscape.cmsutil.util.Utils.SpecialDecode(rcard_challenge);
        
            host_challenge = com.netscape.cmsutil.util.Utils.SpecialDecode(rhost_challenge);
            keyInfo = com.netscape.cmsutil.util.Utils.SpecialDecode(rKeyInfo);

            CUID =com.netscape.cmsutil.util.Utils.SpecialDecode(rCUID);

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

                    byte macKeyArray[] = com.netscape.cmsutil.util.Utils.SpecialDecode(sconfig.getString("tks." + keySet + ".mac_key"));
                    CMS.debug("TokenServlet about to try ComputeSessionKey selectedToken=" + selectedToken + " keyNickName=" + keyNickName);
                        session_key = SessionKey.ComputeSessionKey(
			     selectedToken,keyNickName,card_challenge,
			     host_challenge,keyInfo,CUID, macKeyArray, useSoftToken_s);

                    if(session_key == null)
                    {
                        CMS.debug("TokenServlet:Tried ComputeSessionKey, got NULL ");
                        throw  new Exception("Can't compute session key!");

                    }     

                    byte encKeyArray[] = com.netscape.cmsutil.util.Utils.SpecialDecode(sconfig.getString("tks." + keySet + ".auth_key"));
                    enc_session_key = SessionKey.ComputeEncSessionKey(
                      selectedToken,keyNickName,card_challenge,
		      host_challenge,keyInfo,CUID, encKeyArray, useSoftToken_s);

                    if(enc_session_key == null)
                    {
                        CMS.debug("TokenServlet:Tried ComputeEncSessionKey, got NULL ");
                        throw  new Exception("Can't compute enc session key!");
    
                    }

                    if (serversideKeygen == true) {

                        /**
			 * 0. generate des key
                         * 1. encrypt des key with kek key
                         * 2. encrypt des key with DRM transport key
                         * These two wrapped items are to be sent back to
                         * TPS.  2nd item is to DRM
                         **/
                        CMS.debug("TokenServlet: calling ComputeKekKey");

                    byte kekKeyArray[] = com.netscape.cmsutil.util.Utils.SpecialDecode(sconfig.getString("tks." + keySet + ".kek_key"));
                        kek_key = SessionKey.ComputeKekKey(
			     selectedToken,keyNickName,card_challenge,
			     host_challenge,keyInfo,CUID, kekKeyArray, useSoftToken_s);
                        CMS.debug("TokenServlet: called ComputeKekKey");

                        if(kek_key == null)
                        {
                            CMS.debug("TokenServlet:Tried ComputeKekKey, got NULL ");
                            throw  new Exception("Can't compute kek key!");
    
                        }
                        // now use kek key to wrap kek session key..
			CMS.debug("computeSessionKey:kek key len ="+
				  kek_key.getLength());

			// (1) generate DES key
			/* applet does not support DES3
			org.mozilla.jss.crypto.KeyGenerator kg = 
			    internalToken.getKeyGenerator(KeyGenAlgorithm.DES3);
			    desKey = kg.generate();*/

			/*
			 * XXX GenerateSymkey firt generates a 16 byte DES2 key.
			 * It then pads it into a 24 byte key with last
			 * 8 bytes copied from the 1st 8 bytes.  Effectively
			 * making it a 24 byte DES2 key.  We need this for
			 * wrapping private keys on DRM.
			 */
			/*generate it on whichever token the master key is at*/
			if (useSoftToken_s.equals("true")) {
			   CMS.debug("TokenServlet: key encryption key generated on internal");
			  desKey = SessionKey.GenerateSymkey("internal");
            } else {
			   CMS.debug("TokenServlet: key encryption key generated on " + selectedToken);
			  desKey = SessionKey.GenerateSymkey(selectedToken);
            }
			if (desKey != null)
			    CMS.debug("TokenServlet: key encryption key generated for "+rCUID);
			else {
			    CMS.debug("TokenServlet: key encryption key generation failed for "+rCUID);
			    throw new Exception ("can't generate key encryption key");
			}

			/*
			 * XXX ECBencrypt actually takes the 24 byte DES2 key
			 * and discard the last 8 bytes before it encrypts.
			 * This is done so that the applet can digest it
			 */
			byte[] encDesKey =
			    SessionKey.ECBencrypt( kek_key,
						    desKey.getKeyData());
			/*
			CMS.debug("computeSessionKey:encrypted desKey size = "+encDesKey.length);
			CMS.debug(encDesKey);
			*/

                        kek_wrapped_desKeyString =
                            com.netscape.cmsutil.util.Utils.SpecialEncode(encDesKey);

			// get keycheck
			byte[] keycheck = 
			    SessionKey.ComputeKeyCheck(desKey.getKeyData());
			/*
			CMS.debug("computeSessionKey:keycheck size = "+keycheck.length);
			CMS.debug(keycheck);
			*/
			keycheck_s =
			    com.netscape.cmsutil.util.Utils.SpecialEncode(keycheck);

                        //XXX use DRM transport cert to wrap desKey
                        String drmTransNickname =  CMS.getConfigStore().getString("tks.drm_transport_cert_nickname", "");

			if ((drmTransNickname == null) || (drmTransNickname == "")) {
			    CMS.debug("TokenServlet:did not find DRM transport certificate nickname");
			    throw new Exception("can't find DRM transport certificate nickname");
			} else {
			    CMS.debug("TokenServlet:drmtransport_cert_nickname="+drmTransNickname);
			}

                        X509Certificate drmTransCert = null;
                        drmTransCert = CryptoManager.getInstance().findCertByNickname(drmTransNickname);
                        // wrap kek session key with DRM transport public key
			CryptoToken token = null;
			   if (useSoftToken_s.equals("true")) {
                     token = CryptoManager.getInstance().getTokenByName("Internal Key Storage Token");
               } else {
                     token = CryptoManager.getInstance().getTokenByName(selectedToken);
               }
                        PublicKey pubKey = drmTransCert.getPublicKey();
                        String pubKeyAlgo = pubKey.getAlgorithm();
                        CMS.debug("Transport Cert Key Algorithm: " + pubKeyAlgo);
                        KeyWrapper rsaWrap = null;
                        if (pubKeyAlgo.equals("EC")) {
                            byte iv[] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1};
                            IVParameterSpec IV = new IVParameterSpec(iv);
                            rsaWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
                            rsaWrap.initWrap(pubKey, IV);
                        } else {
                            rsaWrap = token.getKeyWrapper(KeyWrapAlgorithm.RSA);
                            rsaWrap.initWrap(pubKey, null);
                        }
                        drm_trans_wrapped_desKey = rsaWrap.wrap(desKey);
			CMS.debug("computeSessionKey:desKey wrapped with drm transportation key.");

                    } // if (serversideKeygen == true)

                    byte authKeyArray[] = com.netscape.cmsutil.util.Utils.SpecialDecode(sconfig.getString("tks." + keySet + ".auth_key"));
                    host_cryptogram = SessionKey.ComputeCryptogram(
                      selectedToken,keyNickName,card_challenge,
		      host_challenge,keyInfo,CUID,0, authKeyArray, useSoftToken_s);

                    if(host_cryptogram == null)
                    {
                        CMS.debug("TokenServlet:Tried ComputeCryptogram, got NULL ");
                        throw  new Exception("Can't compute host cryptogram!");

                    }
                    card_crypto = SessionKey.ComputeCryptogram(
                      selectedToken,keyNickName,card_challenge,
		      host_challenge,keyInfo,CUID,1, authKeyArray, useSoftToken_s);

                    if(card_crypto == null)
                    {
                        CMS.debug("TokenServlet:Tried ComputeCryptogram, got NULL ");
                        throw  new Exception("Can't compute card cryptogram!");

                    }

                    if (isCryptoValidate) {
                        if (rcard_cryptogram == null) {
                            CMS.debug("TokenServlet: ComputeCryptogram(): missing card cryptogram");
                            throw new Exception("Missing card cryptogram");
                        }
                        input_card_crypto =
                               com.netscape.cmsutil.util.Utils.SpecialDecode(rcard_cryptogram);
                        if (card_crypto.length == input_card_crypto.length) {
                            for (int i=0; i<card_crypto.length; i++) {
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
                            ILogger.LL_INFO,"processComputeSessionKey for CUID=" + 
                            trim(pp.toHexString(CUID)));
                }    catch (Exception e) {
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
        } else 
            status = "1";

        if (enc_session_key != null && enc_session_key.length > 0) {
            encSessionKeyString = 
                com.netscape.cmsutil.util.Utils.SpecialEncode(enc_session_key);
        } else 
            status = "1";

        if (serversideKeygen == true) {
	    if ( drm_trans_wrapped_desKey != null && drm_trans_wrapped_desKey.length > 0)
		drm_trans_wrapped_desKeyString  = 
		    com.netscape.cmsutil.util.Utils.SpecialEncode(drm_trans_wrapped_desKey);
	    else 
		status = "1";
	}

        if (host_cryptogram != null && host_cryptogram.length > 0) {
            cryptogram = 
                com.netscape.cmsutil.util.Utils.SpecialEncode(host_cryptogram);
        } else
            status = "2";

        if (selectedToken == null || keyNickName == null)
            status = "4";

        if (!sameCardCrypto)
            status = "3";

        if (missingParam)
            status = "3";
                
        if (!status.equals("0")) 
            value = "status="+status;
        else {

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
        CMS.debug("TokenServlet:outputString.encode " +value);

        try{
            resp.setContentLength(value.length());
            CMS.debug("TokenServlet:outputString.length " +value.length());
            OutputStream ooss = resp.getOutputStream();
            ooss.write(value.getBytes());
            ooss.flush();
            mRenderResult = false;
        } catch (IOException e) {
            CMS.debug("TokenServlet: " + e.toString());
        }
    }

    private void processDiversifyKey(HttpServletRequest req,
      HttpServletResponse resp) throws EBaseException {
        byte[] KeySetData,KeysValues,CUID,xCUID;
        byte[] xkeyInfo,xnewkeyInfo;
        boolean missingParam = false;

        IConfigStore sconfig = CMS.getConfigStore();
         String rnewKeyInfo        = req.getParameter("newKeyInfo");
        String newMasterKeyName = req.getParameter("newKeyInfo");
        String oldMasterKeyName = req.getParameter("KeyInfo");
        String rCUID =req.getParameter("CUID");

        String keySet = req.getParameter("keySet");
        if (keySet == null || keySet.equals("")) {
          keySet = "defKeySet";
        }
        CMS.debug("keySet selected: " + keySet);

        if ((rCUID == null) || (rCUID.equals(""))) {
            CMS.debug("TokenServlet: processDiversifyKey(): missing request parameter: CUID");
            missingParam = true;
        }
        if ((rnewKeyInfo == null) || (rnewKeyInfo.equals(""))) {
            CMS.debug("TokenServlet: processDiversifyKey(): missing request parameter: newKeyInfo");
            missingParam = true;
        }
        if ((oldMasterKeyName == null) || (oldMasterKeyName.equals(""))){
            CMS.debug("TokenServlet: processDiversifyKey(): missing request parameter: KeyInfo");
            missingParam = true;
        }

        if (!missingParam) {
                xkeyInfo = com.netscape.cmsutil.util.Utils.SpecialDecode(oldMasterKeyName);
                    if (xkeyInfo == null || xkeyInfo.length != 2) {
                        CMS.debug("TokenServlet: Invalid key info length");
                        missingParam = true;
                     }
                xnewkeyInfo = com.netscape.cmsutil.util.Utils.SpecialDecode(newMasterKeyName);
                    if (xnewkeyInfo == null || xnewkeyInfo.length != 2) {
                        CMS.debug("TokenServlet: Invalid new key info length");
                        missingParam = true;
                     }
                }
        String useSoftToken_s = CMS.getConfigStore().getString("tks.useSoftToken", "true");
	if (!useSoftToken_s.equalsIgnoreCase("true"))
	    useSoftToken_s = "false";

        KeySetData = null;
        String outputString = null;
        if (!missingParam) {
                   xCUID = com.netscape.cmsutil.util.Utils.SpecialDecode(rCUID);
                   if (xCUID == null || xCUID.length != 10) {
                        CMS.debug("TokenServlet: Invalid CUID length");
            missingParam = true;
                   }
                }
        if (!missingParam) {
          CUID = com.netscape.cmsutil.util.Utils.SpecialDecode(rCUID);

          if (mKeyNickName!=null)
              oldMasterKeyName =   mKeyNickName;
          if (mNewKeyNickName!=null)
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

          CMS.debug("process DiversifyKey for oldSelectedToke="+ 
                oldSelectedToken + " newSelectedToken=" + newSelectedToken + 
                " oldKeyNickName=" + oldKeyNickName + " newKeyNickName=" + 
                newKeyNickName);

          byte kekKeyArray[] = com.netscape.cmsutil.util.Utils.SpecialDecode(sconfig.getString("tks." + keySet + ".kek_key"));
          KeySetData = SessionKey.DiversifyKey(oldSelectedToken, 
                     newSelectedToken, oldKeyNickName,
		 newKeyNickName,rnewKeyInfo,CUID, kekKeyArray, useSoftToken_s);

          if (KeySetData == null || KeySetData.length<=1) {
                  CMS.getLogger().log(ILogger.EV_AUDIT,
                  ILogger.S_TKS,
                  ILogger.LL_INFO,"process DiversifyKey: Missing MasterKey in Slot");
          }

          CMS.getLogger().log(ILogger.EV_AUDIT,
                  ILogger.S_TKS,
                  ILogger.LL_INFO,"process DiversifyKey for CUID ="+ trim(pp.toHexString(CUID))
                  + ";from oldMasterKeyName="+oldSelectedToken + ":" + oldKeyNickName
                  +";to newMasterKeyName="+newSelectedToken + ":" + newKeyNickName);

          resp.setContentType("text/html");
            
          if (KeySetData != null) {
              outputString  = new String(KeySetData);
          }
        } // ! missingParam

        //CMS.debug("TokenServlet:processDiversifyKey " +outputString);
        //String value="keySetData=%00" if the KeySetData=byte[0]=0;

        String value = "";
        if (KeySetData != null && KeySetData.length > 1) {
            value = "status=0&"+"keySetData=" + 
                     com.netscape.cmsutil.util.Utils.SpecialEncode(KeySetData);
            CMS.debug("TokenServlet:process DiversifyKey.encode " +value);
        } else if (missingParam) {
            value = "status=3";
        } else 
            value = "status=1";

        resp.setContentLength(value.length());
        CMS.debug("TokenServlet:outputString.length " +value.length());

        try{
            OutputStream ooss = resp.getOutputStream();
            ooss.write(value.getBytes());
            ooss.flush();
            mRenderResult = false;
        } catch (Exception e) {
            CMS.debug("TokenServlet:process DiversifyKey: " + e.toString());
        }
    }

    private void processEncryptData(HttpServletRequest req,
      HttpServletResponse resp) throws EBaseException {
        byte[] keyInfo, CUID, xCUID, encryptedData, xkeyInfo;
        boolean missingParam = false;
        byte[] data = null;
        boolean isRandom = true; // randomly generate the data to be encrypted

        IConfigStore sconfig = CMS.getConfigStore();
        encryptedData = null;
        String rdata = req.getParameter("data");
        String rKeyInfo = req.getParameter("KeyInfo");
        String rCUID = req.getParameter("CUID");
        String keySet = req.getParameter("keySet");
        if (keySet == null || keySet.equals("")) {
            keySet = "defKeySet";
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
              CMS.debug("TokenServlet: processEncryptData():"+ e.toString());
              throw new EBaseException("processEncryptData:"+ e.toString());
            }
        } else if ((!isRandom) && (((rdata == null) || (rdata.equals(""))))){
            CMS.debug("TokenServlet: processEncryptData(): missing request parameter: data.");
            missingParam = true;
        }

        if ((rCUID == null) || (rCUID.equals(""))) {

            CMS.debug("TokenServlet: processEncryptData(): missing request parameter: CUID");
            missingParam = true;
        }
        if ((rKeyInfo == null) || (rKeyInfo.equals(""))) {
            CMS.debug("TokenServlet: processEncryptData(): missing request parameter: key info");
            missingParam = true;
        }

        if (!missingParam) {
             xCUID = com.netscape.cmsutil.util.Utils.SpecialDecode(rCUID);
                     if (xCUID == null || xCUID.length != 10) {
                        CMS.debug("TokenServlet: Invalid CUID length");
                        throw  new EBaseException("Invalid CUID length");
                      }
             xkeyInfo = com.netscape.cmsutil.util.Utils.SpecialDecode(rKeyInfo);
                     if (xkeyInfo == null || xkeyInfo.length != 2) {
                        CMS.debug("TokenServlet: Invalid key info length");
                        throw  new EBaseException("Invalid key info length");
                      }
        }

        String useSoftToken_s = CMS.getConfigStore().getString("tks.useSoftToken","true");
	if (!useSoftToken_s.equalsIgnoreCase("true"))
	    useSoftToken_s = "false";

        if (!missingParam) {
          if (!isRandom)
            data = com.netscape.cmsutil.util.Utils.SpecialDecode(rdata);
          keyInfo = com.netscape.cmsutil.util.Utils.SpecialDecode(rKeyInfo);
          CUID = com.netscape.cmsutil.util.Utils.SpecialDecode(rCUID);

          String keyInfoMap = "tks." + keySet + ".mk_mappings." + rKeyInfo;
          String mappingValue = CMS.getConfigStore().getString(keyInfoMap, null);
          String selectedToken = null;
          String keyNickName = null;
          if (mappingValue == null) {
              selectedToken = CMS.getConfigStore().getString("tks.defaultSlot", "internal");
              keyNickName = rKeyInfo;
          } else {
              StringTokenizer st = new StringTokenizer(mappingValue, ":");
              selectedToken = st.nextToken();
              keyNickName = st.nextToken();
          }
          
          byte kekKeyArray[] = com.netscape.cmsutil.util.Utils.SpecialDecode(sconfig.getString("tks." + keySet + ".kek_key"));
          encryptedData = SessionKey.EncryptData(
                       selectedToken,keyNickName,data,keyInfo,CUID, kekKeyArray, useSoftToken_s);
        
          CMS.getLogger().log(ILogger.EV_AUDIT,
                     ILogger.S_TKS,
                     ILogger.LL_INFO,"process EncryptData for CUID ="+ trim(pp.toHexString(CUID)));
        } // !missingParam

        resp.setContentType("text/html");
            
        String value = "";
        if (encryptedData != null && encryptedData.length > 0) { 
            String outputString  = new String(encryptedData);
            // sending both the pre-encrypted and encrypted data back
            value = "status=0&"+"data="+
                         com.netscape.cmsutil.util.Utils.SpecialEncode(data)+
                         "&encryptedData=" + 
                         com.netscape.cmsutil.util.Utils.SpecialEncode(encryptedData);
        } else if (missingParam) {
            value = "status=3";
        } else
            value = "status=1";

        CMS.debug("TokenServlet:process EncryptData.encode " +value);

        try {
            resp.setContentLength(value.length());
            CMS.debug("TokenServlet:outputString.lenght " +value.length());
            
            OutputStream ooss = resp.getOutputStream();
            ooss.write(value.getBytes());
            ooss.flush();
            mRenderResult = false;
        } catch (Exception e) {
            CMS.debug("TokenServlet: " + e.toString());
        }
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

    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);
        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "read");
        } catch (Exception e) {
        }

        if (authzToken == null) {

            try{
                resp.setContentType("text/html");
                String value = "unauthorized=";
                CMS.debug("TokenServlet: Unauthorized");

                resp.setContentLength(value.length());
                OutputStream ooss = resp.getOutputStream();
                ooss.write(value.getBytes());
                ooss.flush();
                mRenderResult = false;
            }catch (Exception e) {
                CMS.debug("TokenServlet: " + e.toString());
            }

            //       cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        String temp = req.getParameter("card_challenge");
        mSelectedToken = CMS.getConfigStore().getString("tks.defaultSlot");
        setDefaultSlotAndKeyName(req);
        if(temp!=null)
        {
            processComputeSessionKey(req,resp);
        }else if(req.getParameter("data")!=null){
            processEncryptData(req,resp);
        }else if(req.getParameter("newKeyInfo")!=null){
            processDiversifyKey(req,resp);
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
        String scope = req.getParameter(Constants.OP_SCOPE);
        String op = req.getParameter(Constants.OP_TYPE);

        super.service(req, resp);
    }

    /**
     * Parses uid0=pwd0,uid1=pwd1,... into AgentCredential.
     *
     * @param s credential string
     * @return a list of credentials
     */
    private Credential[] parseCredentialStr(String s) {
        StringTokenizer st = new StringTokenizer(s, ",");
        Vector v = new Vector();

        while (st.hasMoreTokens()) {
            String a = st.nextToken();
            StringTokenizer st0 = new StringTokenizer(a, "=");

            v.addElement(new Credential(st0.nextToken(),
                    st0.nextToken()));
        }
        Credential ac[] = new Credential[v.size()];

        v.copyInto(ac);
        return ac;
    }
}
