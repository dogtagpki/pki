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

import java.io.IOException;
import java.io.OutputStream;
import java.util.Hashtable;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.connector.IRemoteRequest;
import org.dogtagpki.server.kra.KRAEngine;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.cert.PrettyPrintFormat;
import com.netscape.cmscore.request.KeyRequestRepository;
import com.netscape.cmscore.request.RequestQueue;

/**
 * GenerateKeyPairServlet
 * handles "server-side key pair generation" requests from the
 * netkey RA.
 *
 * @author Christina Fu (cfu)
 * @version $Revision$, $Date$
 */
//XXX add auditing later
public class GenerateKeyPairServlet extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GenerateKeyPairServlet.class);

    private static final long serialVersionUID = 4308385291961910458L;
    private final static String INFO = "GenerateKeyPairServlet";
    public final static String PROP_AUTHORITY = "authority";
    protected ServletConfig mConfig = null;
    protected IAuthority mAuthority = null;
    public static int ERROR = 1;
    PrettyPrintFormat pp = new PrettyPrintFormat(":");
    protected AuthSubsystem mAuthSubsystem;
    private Hashtable<String, String> supportedECCurves_ht = null;

    /**
     * Constructs GenerateKeyPair servlet.
     *
     */
    public GenerateKeyPairServlet() {
        super();
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        mConfig = config;

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig sconfig = engine.getConfig();

        String authority = config.getInitParameter(PROP_AUTHORITY);

        if (authority != null)
            mAuthority = (IAuthority) engine.getSubsystem(authority);

        mAuthSubsystem = engine.getAuthSubsystem();
        // supported EC cuves by the smart cards
        String curveList = null;
        try {
            curveList = sconfig.getString("kra.keygen.curvelist",
                              "nistp256,nistp384,nistp521");
        } catch (EBaseException e) {
            curveList = "nistp256,nistp384,nistp521";
        }

        supportedECCurves_ht = new Hashtable<>();
        String[] supportedECCurves = curveList.split(",");
        for ( int i = 0; i < supportedECCurves.length; i++) {
            supportedECCurves_ht.put(supportedECCurves[i], supportedECCurves[i]);
        }

    }

    /**
     * Returns serlvet information.
     *
     * @return name of this servlet
     */
    @Override
    public String getServletInfo() {
        return INFO;
    }

    /*
     * processServerSideKeyGen -
     *   handles netkey DRM serverside keygen.
     * netkey operations:
     *  1. generate keypair (archive user priv key)
     *  2. unwrap des key with transport key, then url decode it
     *  3. wrap user priv key with des key
     *  4. send the following to RA:
     *      * des key wrapped(user priv key)
     *      * user public key
     *     (note: RA should have kek-wrapped des key from TKS)
     *      * recovery blob (used for recovery)
     */
    private void processServerSideKeyGen(HttpServletRequest req,
            HttpServletResponse resp) throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        KeyRequestRepository requestRepository = engine.getKeyRequestRepository();
        RequestQueue queue = engine.getRequestQueue();
        IRequest thisreq = null;

        boolean missingParam = false;
        String status = "0";

        logger.debug("processServerSideKeyGen begins:");

        String rCUID = req.getParameter(IRemoteRequest.TOKEN_CUID);
        String rUserid = req.getParameter(IRemoteRequest.KRA_UserId);
        String rdesKeyString = req.getParameter(IRemoteRequest.KRA_Trans_DesKey);
        String rArchive = req.getParameter(IRemoteRequest.KRA_KEYGEN_Archive);
        String rKeysize = req.getParameter(IRemoteRequest.KRA_KEYGEN_KeySize);
        String rKeytype = req.getParameter(IRemoteRequest.KRA_KEYGEN_KeyType);
        String rKeycurve = req.getParameter(IRemoteRequest.KRA_KEYGEN_EC_KeyCurve);

        if ((rCUID == null) || (rCUID.equals(""))) {
            logger.warn("GenerateKeyPairServlet: processServerSideKeygen(): missing request parameter: CUID");
            missingParam = true;
        }

        if ((rUserid == null) || (rUserid.equals(""))) {
            logger.warn("GenerateKeyPairServlet: processServerSideKeygen(): missing request parameter: userid");
            missingParam = true;
        }

        // if not specified, default to RSA
        if ((rKeytype == null) || (rKeytype.equals(""))) {
            rKeytype = "RSA";
        }

        // keysize is for non-EC (EC uses keycurve)
        if (!rKeytype.equals("EC") && ((rKeysize == null) || (rKeysize.equals("")))) {
            rKeysize = "1024"; // default to 1024
        }

        if (rKeytype.equals("EC")) {
            if ((rKeycurve == null) || (rKeycurve.equals(""))) {
                rKeycurve = "nistp256";
            }
            // is the specified curve supported?
            boolean isSupportedCurve = supportedECCurves_ht.containsKey(rKeycurve);
            if (isSupportedCurve == false) {
                logger.warn("GenerateKeyPairServlet: processServerSideKeygen(): unsupported curve:"+ rKeycurve);
                missingParam = true;
            } else {
                logger.debug("GenerateKeyPairServlet: processServerSideKeygen(): curve to be generated:"+ rKeycurve);
            }
        }

        if ((rdesKeyString == null) ||
                (rdesKeyString.equals(""))) {
            logger.warn("GenerateKeyPairServlet: processServerSideKeygen(): missing request parameter: DRM-transportKey-wrapped DES key");
            missingParam = true;
        }

        if ((rArchive == null) || (rArchive.equals(""))) {
            logger.debug("GenerateKeyPairServlet: processServerSideKeygen(): missing key archival flag 'archive' ,default to true");
            rArchive = "true";
        }

        if (!missingParam) {
            thisreq = requestRepository.createRequest(IRequest.NETKEY_KEYGEN_REQUEST);

            thisreq.setExtData(IRequest.REQUESTOR_TYPE, IRequest.REQUESTOR_NETKEY_RA);
            thisreq.setExtData(IRequest.NETKEY_ATTR_CUID, rCUID);
            thisreq.setExtData(IRequest.NETKEY_ATTR_USERID, rUserid);
            thisreq.setExtData(IRequest.NETKEY_ATTR_DRMTRANS_DES_KEY, rdesKeyString);
            thisreq.setExtData(IRequest.NETKEY_ATTR_ARCHIVE_FLAG, rArchive);
            thisreq.setExtData(IRequest.NETKEY_ATTR_KEY_SIZE, rKeysize);
            thisreq.setExtData(IRequest.NETKEY_ATTR_KEY_TYPE, rKeytype);
            thisreq.setExtData(IRequest.NETKEY_ATTR_KEY_EC_CURVE, rKeycurve);

            queue.processRequest(thisreq);
            Integer result = thisreq.getExtDataInInteger(IRequest.RESULT);
            if (result != null) {
                // sighs!  tps thinks 0 is good, and DRM thinks 1 is good
                if (result.intValue() == 1)
                    status = "0";
                else
                    status = result.toString();
            } else
                status = "7";

            logger.debug("processServerSideKeygen finished");
        } // ! missingParam

        String value = "";

        resp.setContentType("application/x-www-form-urlencoded");

        String wrappedPrivKeyString = "";
        String publicKeyString = "";

        if (thisreq == null) {
            logger.error("GenerateKeyPairServlet::processServerSideKeyGen() - "
                     + "thisreq is null!");
            throw new EBaseException("thisreq is null");
        }

        publicKeyString = thisreq.getExtDataInString("public_key");
        wrappedPrivKeyString = thisreq.getExtDataInString("wrappedUserPrivate");

        String ivString = thisreq.getExtDataInString("iv_s");

        /*
         * zero out the fields in request
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
            value = IRemoteRequest.RESPONSE_STATUS +"=" + status;
        else {
            StringBuffer sb = new StringBuffer();
            sb.append(IRemoteRequest.RESPONSE_STATUS +"=0&");
            sb.append(IRemoteRequest.KRA_RESPONSE_Wrapped_PrivKey+ "=");
            sb.append(wrappedPrivKeyString);
            sb.append("&"+ IRemoteRequest.KRA_RESPONSE_IV_Param+ "=");
            sb.append(ivString);
            sb.append("&"+ IRemoteRequest.KRA_RESPONSE_PublicKey+ "=");
            sb.append(publicKeyString);
            value = sb.toString();

        }
        //logger.debug("processServerSideKeyGen:outputString.encode " + value);

        try {
            resp.setContentLength(value.length());
            logger.debug("GenerateKeyPairServlet:outputString.length " + value.length());
            OutputStream ooss = resp.getOutputStream();
            ooss.write(value.getBytes());
            ooss.flush();
            mRenderResult = false;
        } catch (IOException e) {
            logger.warn("GenerateKeyPairServlet: " + e.getMessage(), e);
        }
    }

    /*

     *   For GenerateKeyPair:
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

    @Override
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
                resp.setContentType("application/x-www-form-urlencoded");
                String value = "unauthorized=";
                logger.warn("GenerateKeyPairServlet: Unauthorized");

                resp.setContentLength(value.length());
                OutputStream ooss = resp.getOutputStream();
                ooss.write(value.getBytes());
                ooss.flush();
                mRenderResult = false;
            } catch (Exception e) {
                logger.warn("GenerateKeyPairServlet: " + e.getMessage(), e);
            }

            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        // begin Netkey serverSideKeyGen and archival
        logger.debug("GenerateKeyPairServlet: processServerSideKeyGen would be called");
        processServerSideKeyGen(req, resp);
        return;
        // end Netkey functions

    }

    /**
     * XXX remember tocheck peer SSL cert and get RA id later
     *
     * Serves HTTP admin request.
     *
     * @param req HTTP request
     * @param resp HTTP response
     */
    @Override
    public void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.service(req, resp);

    }

}
