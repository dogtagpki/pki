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
package com.netscape.cms.servlet.connector;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IPrettyPrintFormat;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;

import org.dogtagpki.server.connector.IRemoteRequest;

/**
 * TokenKeyRecoveryServlet
 * handles "key recovery service" requests from the
 * netkey TPS
 *
 * @author Christina Fu (cfu)
 * @version $Revision$, $Date$
 */
//XXX add auditing later
public class TokenKeyRecoveryServlet extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -2322410659376501336L;
    private final static String INFO = "TokenKeyRecoveryServlet";
    public final static String PROP_AUTHORITY = "authority";
    protected ServletConfig mConfig = null;
    protected IAuthority mAuthority = null;
    public static int ERROR = 1;
    IPrettyPrintFormat pp = CMS.getPrettyPrintFormat(":");
    protected IAuthSubsystem mAuthSubsystem = null;

    /**
     * Constructs TokenKeyRecovery servlet.
     *
     */
    public TokenKeyRecoveryServlet() {
        super();
    }

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        mConfig = config;
        String authority = config.getInitParameter(PROP_AUTHORITY);

        if (authority != null)
            mAuthority = (IAuthority)
                    CMS.getSubsystem(authority);

        mAuthSubsystem = (IAuthSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
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
     * @param s The URL to decode
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

    /*
     * processTokenKeyRecovery
     *   handles netkey key recovery requests
     * input params are:
     *  CUID - the CUID of the old token where the keys/certs were initially for
     *  userid - the userid that belongs to both the old token and the new token
     *  keyid - the keyid in DRM for recovery using keyid
     *  drm_trans_desKey - the des key generated for the NEW token
     *                            wrapped with DRM transport key
     *  cert - the user cert corresponding to the key to be recovered
     *
     * operations:
     *  1. unwrap des key with transport key, then url decode it
     *  2. retrieve user private key
     *  3. wrap user priv key with des key
     *  4. send the following to RA:
     *      * des key wrapped(user priv key)
     *     (note: RA should have kek-wrapped des key from TKS)
     *      * recovery blob (used for recovery)
     *
     * output params are:
     *   status=value0
     *   publicKey=value1
     *   desKey-wrapped-userPrivateKey=value2
     */
    private void processTokenKeyRecovery(HttpServletRequest req,
            HttpServletResponse resp) throws EBaseException {
        IRequestQueue queue = mAuthority.getRequestQueue();
        IRequest thisreq = null;

        //        IConfigStore sconfig = CMS.getConfigStore();
        boolean missingParam = false;
        boolean missingTransAes = false;
        boolean missingTransDes = false;
        boolean missingAesKeyWrapAlg = false;
        String status = "0";

        CMS.debug("processTokenKeyRecovery begins:");

        String rCUID = req.getParameter(IRemoteRequest.TOKEN_CUID);
        String rUserid = req.getParameter(IRemoteRequest.KRA_UserId);
        String rKeyid = req.getParameter(IRemoteRequest.KRA_RECOVERY_KEYID);
        String rdesKeyString = req.getParameter(IRemoteRequest.KRA_Trans_DesKey);
        String rCert = req.getParameter(IRemoteRequest.KRA_RECOVERY_CERT);
        //RedHat : make sure the key wrap alg is being processed correctly
        String aesKeyWrapAlg = req.getParameter(IRemoteRequest.KRA_Aes_Wrap_Alg);

        String raesKeyString = req.getParameter(IRemoteRequest.KRA_Trans_AesKey);

        //RedHat : make sure the key wrap alg is being processed correctly
        if ((aesKeyWrapAlg == null) || (aesKeyWrapAlg.equals(""))) {
            CMS.debug("TokenKeyRecoveryServlet: processTokenKeyRecovery(): missing request parameter: AES-KeyWrap-alg");
            missingAesKeyWrapAlg = true;
        }


        if ((rCUID == null) || (rCUID.equals(""))) {
            CMS.debug("TokenKeyRecoveryServlet: processTokenKeyRecovery(): missing request parameter: CUID");
            missingParam = true;
        }

        if ((rUserid == null) || (rUserid.equals(""))) {
            CMS.debug("TokenKeyRecoveryServlet: processTokenKeyRecovery(): missing request parameter: userid");
            missingParam = true;
        }
        if ((raesKeyString == null) || (raesKeyString.equals(""))) {
            CMS.debug("TokenKeyRecoveryServlet: processTokenKeyRecovery(): missing request parameter: DRM-transportKey-wrapped aes key");
	    missingTransAes = true;
        }

        if ((rdesKeyString == null) ||
                (rdesKeyString.equals(""))) {
            CMS.debug("TokenKeyRecoveryServlet: processTokenKeyRecovery(): missing request parameter: DRM-transportKey-wrapped des key");
            //   We expect either a trans wrapped aes or des key.
            if(missingTransAes == true && missingTransDes == true) {
                missingParam = true;
            }
        }

        if (((rCert == null) || (rCert.equals(""))) &&
            ((rKeyid == null) || (rKeyid.equals("")))) {
            CMS.debug("TokenKeyRecoveryServlet: processTokenKeyRecovery(): missing request parameter: cert or keyid");
            missingParam = true;
        }

        if (!missingParam) {
            thisreq = queue.newRequest(IRequest.NETKEY_KEYRECOVERY_REQUEST);

            thisreq.setExtData(IRequest.REQUESTOR_TYPE, IRequest.REQUESTOR_NETKEY_RA);
            thisreq.setExtData(IRequest.NETKEY_ATTR_CUID, rCUID);
            thisreq.setExtData(IRequest.NETKEY_ATTR_USERID, rUserid);

	    if(!missingTransDes) {
                thisreq.setExtData(IRequest.NETKEY_ATTR_DRMTRANS_DES_KEY, rdesKeyString);
            }
            if(!missingTransAes) {
                thisreq.setExtData(IRequest.NETKEY_ATTR_DRMTRANS_AES_KEY, raesKeyString);
            }

            //RedHat : make sure the key wrap alg is being processed correctly
            if(!missingAesKeyWrapAlg) {
                CMS.debug("TokenKeyRecoveryServlet: processTokenKeyRecovery(): aesKeyWrapAlg: " + aesKeyWrapAlg);
                thisreq.setExtData(IRequest.NETKEY_ATTR_SSKEYGEN_AES_KEY_WRAP_ALG,aesKeyWrapAlg);
            }

            if ((rCert != null) && (!rCert.equals(""))) {
                thisreq.setExtData(IRequest.NETKEY_ATTR_USER_CERT, rCert);
               CMS.debug("TokenKeyRecoveryServlet: processTokenKeyRecovery(): received request parameter: cert");
            }
            if ((rKeyid != null) && (!rKeyid.equals(""))) {
                thisreq.setExtData(IRequest.NETKEY_ATTR_KEYID, rKeyid); 
                CMS.debug("TokenKeyRecoveryServlet: processTokenKeyRecovery(): received request parameter: keyid");
            }

            //XXX auto process for netkey
            queue.processRequest(thisreq);
            //	    IService svc = (IService) new TokenKeyRecoveryService(kra);
            //	    svc.serviceRequest(thisreq);

            Integer result = thisreq.getExtDataInInteger(IRequest.RESULT);
            if (result != null) {
                // sighs!  tps thinks 0 is good, and drm thinks 1 is good
                if (result.intValue() == 1)
                    status = "0";
                else
                    status = result.toString();
            } else
                status = "7";

            CMS.debug("processTokenKeyRecovery finished");
        } // ! missingParam

        String value = "";

        resp.setContentType("application/x-www-form-urlencoded");

        String wrappedPrivKeyString = "";
        String publicKeyString = "";
        String ivString = "";
        /* if is RECOVERY_PROTOTYPE
            String recoveryBlobString = "";

            IKeyRecord kr = (IKeyRecord) thisreq.get("keyRecord");
            byte publicKey_b[] = kr.getPublicKeyData();

            BigInteger serialNo = kr.getSerialNumber();

            String serialNumberString =
                com.netscape.cmsutil.util.Utils.SpecialEncode(serialNo.toByteArray());

            recoveryBlobString = (String)
                thisreq.get("recoveryBlob");
        */

        if (thisreq == null) {
            CMS.debug("TokenKeyRecoveryServlet::processTokenKeyRecovery() - "
                     + "thisreq is null!");
            throw new EBaseException("thisreq is null");
        }

        publicKeyString = thisreq.getExtDataInString("public_key");
        wrappedPrivKeyString = thisreq.getExtDataInString("wrappedUserPrivate");

        ivString = thisreq.getExtDataInString("iv_s");

        /*
         * zero out fields in request
         */
        thisreq.setExtData("wrappedUserPrivate", "");
        thisreq.setExtData("public_key", "");
        thisreq.setExtData("iv_s", "");
        thisreq.setExtData(IRequest.NETKEY_ATTR_DRMTRANS_DES_KEY, "");

        /* delete the fields */
        thisreq.deleteExtData("wrappedUserPrivate");
        thisreq.deleteExtData("public_key");
        thisreq.deleteExtData("iv_s");
        thisreq.deleteExtData(IRequest.NETKEY_ATTR_DRMTRANS_DES_KEY);

        // now that fields are cleared, we can really write to ldap
        thisreq.setExtData("delayLDAPCommit", "false");
        queue.updateRequest(thisreq);

        /*
          if (selectedToken == null)
          status = "4";
        */
        if (!status.equals("0"))
            value = "status=" + status;
        else {
            StringBuffer sb = new StringBuffer();
            sb.append(IRemoteRequest.RESPONSE_STATUS +"=0&");
            sb.append(IRemoteRequest.KRA_RESPONSE_Wrapped_PrivKey +"=");
            sb.append(wrappedPrivKeyString);
            sb.append("&"+ IRemoteRequest.KRA_RESPONSE_PublicKey +"=");
            sb.append(publicKeyString);
            sb.append("&"+ IRemoteRequest.KRA_RESPONSE_IV_Param +"=");
            sb.append(ivString);
            value = sb.toString();

        }
        //CMS.debug("ProcessTokenKeyRecovery:outputString.encode " + value);

        try {
            resp.setContentLength(value.length());
            CMS.debug("TokenKeyRecoveryServlet:outputString.length " + value.length());
            OutputStream ooss = resp.getOutputStream();
            ooss.write(value.getBytes());
            ooss.flush();
            mRenderResult = false;
        } catch (IOException e) {
            CMS.debug("TokenKeyRecoveryServlet: " + e.toString());
        }
    }

    /*
     *   For TokenKeyRecovery
     *
     *   input:
     *   CUID=value0
     *   trans-wrapped-desKey=value1
     *
     *   output:
     *   status=value0
     *   publicKey=value1
     *   desKey-wrapped-userPrivateKey=value2
     *   proofOfArchival=value3
     */

    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);
        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "submit");
        } catch (Exception e) {
        }

        if (authzToken == null) {

            try {
                resp.setContentType("application/x-www-form-urlencoded");
                String value = "unauthorized=";
                CMS.debug("TokenKeyRecoveryServlet: Unauthorized");

                resp.setContentLength(value.length());
                OutputStream ooss = resp.getOutputStream();
                ooss.write(value.getBytes());
                ooss.flush();
                mRenderResult = false;
            } catch (Exception e) {
                CMS.debug("TokenKeyRecoveryServlet: " + e.toString());
            }

            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        // begin Netkey serverSideKeyGen and archival
        CMS.debug("TokenKeyRecoveryServlet: processTokenKeyRecovery would be called");
        processTokenKeyRecovery(req, resp);
        return;
        // end Netkey functions

    }
}
