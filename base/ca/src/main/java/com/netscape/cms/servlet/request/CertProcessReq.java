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
package com.netscape.cms.servlet.request;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ArgBlock;

/**
 * Display certificate request detail to the user.
 */
@WebServlet(
        name = "caProcessReq",
        urlPatterns = "/agent/ca/processReq",
        initParams = {
                @WebInitParam(name="GetClientCert", value="true"),
                @WebInitParam(name="parser",        value="CertReqParser.DETAIL_PARSER"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="authority",     value="ca"),
                @WebInitParam(name="interface",     value="agent"),
                @WebInitParam(name="ID",            value="caProcessReq"),
                @WebInitParam(name="templatePath",  value="/agent/ca/processReq.template"),
                @WebInitParam(name="resourceID",    value="certServer.ca.request.enrollment"),
                @WebInitParam(name="AuthMgr",       value="certUserDBAuthMgr")
        }
)
public class CertProcessReq extends ProcessReq {

    public CertProcessReq() {
    }

    /**
     * Initialize the servlet. This servlet uses the template file
     * "processReq.template" to process the response.
     * The initialization parameter 'parser' is read from the
     * servlet configuration, and is used to set the type of request.
     * The value of this parameter can be:
     * <UL>
     * <LI><B>CertReqParser.NODETAIL_PARSER</B> - Show certificate Summary
     * <LI><B>CertReqParser.DETAIL_PARSER</B> - Show certificate detail
     * </UL>
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {

        super.init(sc);

        String tmp = sc.getInitParameter(PROP_PARSER);

        if (tmp != null) {
            if (tmp.trim().equals("CertReqParser.NODETAIL_PARSER")) {
                mParser = CertReqParser.NODETAIL_PARSER;

            } else if (tmp.trim().equals("CertReqParser.DETAIL_PARSER")) {
                mParser = CertReqParser.DETAIL_PARSER;
            }
        }
    }

    @Override
    public void addAuthorityName(ArgBlock header) throws EBaseException {
        header.addStringValue("localca", "yes");
    }

    @Override
    public void addSigningAlgorithm(ArgBlock header) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        String[] allAlgorithms = ca.getCASigningAlgorithms();
        if (allAlgorithms == null) {
            logger.debug("CertProcessReq: Signing algorithms set to All algorithms");
            allAlgorithms = AlgorithmId.ALL_SIGNING_ALGORITHMS;
        } else {
            logger.debug("CertProcessReq: First signing algorithms is " + allAlgorithms[0]);
        }

        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < allAlgorithms.length; i++) {
            if (i > 0) {
                sb.append("+");
                sb.append(allAlgorithms[i]);
            } else {
                sb.append(allAlgorithms[i]);
            }
        }

        String validAlgorithms = sb.toString();
        header.addStringValue("validAlgorithms", validAlgorithms);

        String signingAlgorithm = ca.getDefaultAlgorithm();
        if (signingAlgorithm != null) {
            header.addStringValue("caSigningAlgorithm", signingAlgorithm);
        }

        header.addLongValue("defaultValidityLength", engine.getDefaultCertValidity() / 1000);

        X509CertImpl caCert = ca.getCACert();
        if (caCert != null) {
            int caPathLen = caCert.getBasicConstraints();
            header.addIntegerValue("caPathLen", caPathLen);
        }
    }
}
