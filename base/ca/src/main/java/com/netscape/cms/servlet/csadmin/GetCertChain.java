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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Locale;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertificateChain;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmsutil.json.JSONObject;

@WebServlet(
        name = "caGetCertChain",
        urlPatterns = "/ee/ca/getCertChain",
        initParams = {
                @WebInitParam(name="GetClientCert", value="false"),
                @WebInitParam(name="authority",     value="ca"),
                @WebInitParam(name="ID",            value="caGetCertChain")
        }
)
public class GetCertChain extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GetCertChain.class);

    private static final long serialVersionUID = -356806997334418285L;
    private final static String SUCCESS = "0";

    public GetCertChain() {
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
     * <ul>
     * <li>http.param op 'downloadBIN' - return the binary certificate chain
     * <li>http.param op 'displayIND' - display pretty-print of certificate chain components
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    protected void process(CMSRequest cmsReq) throws EBaseException {

        HttpServletResponse httpResp = cmsReq.getHttpResp();

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        CertificateChain certChain = ca.getCACertChain();

        if (certChain == null) {
            logger.warn("GetCertChain: cannot get the certificate chain.");
            outputError(httpResp, "Error: Failed to get certificate chain.");
            return;
        }

        X509Certificate[] certs = certChain.getChain();

        if (certs == null) {
            logger.warn("GetCertChain: no certificate chain");

        } else {
            logger.debug("GetCertChain: certificate chain:");
            for (X509Certificate cert : certs) {
                logger.debug("GetCertChain: - " + cert.getSubjectDN());
            }
        }

        byte[] bytes = null;

        try {
            ByteArrayOutputStream encoded = new ByteArrayOutputStream();

            certChain.encode(encoded);
            bytes = encoded.toByteArray();
        } catch (IOException e) {
            logger.warn(CMS.getLogMessage("CMSGW_ERROR_ENCODING_CA_CHAIN_1", e.toString()), e);
            outputError(httpResp, "Error: Failed to encode the certificate chain");
        }

        String chainBase64 = Utils.base64encode(bytes, true);

        chainBase64 = normalizeCertStr(chainBase64);

        try {
            JSONObject jsonObj = new JSONObject();

            ObjectNode responseNode = jsonObj.getMapper().createObjectNode();
            responseNode.put("Status", SUCCESS);
            responseNode.put("ChainBase64", chainBase64);

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

    private String normalizeCertStr(String s) {
        StringBuffer val = new StringBuffer();

        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                continue;
            } else if (s.charAt(i) == '\r') {
                continue;
            } else if (s.charAt(i) == '"') {
                continue;
            } else if (s.charAt(i) == ' ') {
                continue;
            }
            val.append(s.charAt(i));
        }
        return val.toString();
    }
}
