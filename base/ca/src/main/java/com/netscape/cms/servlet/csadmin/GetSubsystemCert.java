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
package com.netscape.cms.servlet.csadmin;

import java.io.IOException;
import java.util.Locale;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.X509Certificate;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.json.JSONObject;

@WebServlet(
        name = "caGetSubsystemCert",
        urlPatterns = "/admin/ca/getSubsystemCert",
        initParams = {
                @WebInitParam(name="GetClientCert", value="false"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="authority",     value="ca"),
                @WebInitParam(name="ID",            value="caGetSubsystemCert"),
                @WebInitParam(name="resourceID",    value="certServer.ee.certificate"),
                @WebInitParam(name="interface",     value="ee")
        }
)
public class GetSubsystemCert extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GetSubsystemCert.class);

    private static final long serialVersionUID = -5720342238234153488L;
    private final static String SUCCESS = "0";

    public GetSubsystemCert() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
    }

    /**
     * Process the HTTP request.
     */
    @Override
    protected void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();

        String nickname = "";
        try {
            nickname = cs.getString("ca.subsystem.nickname", "");
            String tokenname = cs.getString("ca.subsystem.tokenname", "");
            if (!CryptoUtil.isInternalToken(tokenname))
                nickname = tokenname + ":" + nickname;
        } catch (Exception e) {
        }

        logger.debug("GetSubsystemCert process: nickname=" + nickname);
        String s = "";
        try {
            CryptoManager cm = CryptoManager.getInstance();
            X509Certificate cert = cm.findCertByNickname(nickname);

            if (cert == null) {
                logger.warn("GetSubsystemCert process: subsystem cert is null");
                outputError(httpResp, "Error: Failed to get subsystem certificate.");
                return;
            }

            byte[] bytes = cert.getEncoded();
            s = CryptoUtil.normalizeCertStr(CryptoUtil.base64Encode(bytes));
        } catch (Exception e) {
            logger.warn("GetSubsystemCert process: exception: " + e.getMessage(), e);
        }

        try {
            JSONObject jsonObj = new JSONObject();

            ObjectNode responseNode = jsonObj.getMapper().createObjectNode();
            responseNode.put("Status", SUCCESS);
            responseNode.put("Cert", s);

            jsonObj.getRootNode().set("Response", responseNode);

            outputResult(httpResp, "application/json", jsonObj.toByteArray());
        } catch (Exception e) {
            logger.warn("Failed to send the output: " + e.getMessage(), e);
        }
    }

    @Override
    protected void renderResult(CMSRequest cmsReq) throws IOException {// do nothing, ie, it will not return the default javascript.
    }

    /**
     * Retrieves locale based on the request.
     */
    @Override
    protected Locale getLocale(HttpServletRequest req) {
        Locale locale = null;
        String lang = req.getHeader("accept-language");

        if (lang == null) {
            // use server locale
            locale = Locale.getDefault();
        } else {
            locale = new Locale(UserInfo.getUserLanguage(lang),
                    UserInfo.getUserCountry(lang));
        }
        return locale;
    }
}
