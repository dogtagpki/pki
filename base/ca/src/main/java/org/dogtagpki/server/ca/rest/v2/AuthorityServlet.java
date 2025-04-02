//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.v2;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.server.ca.rest.base.AuthorityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.base.MediaType;
import com.netscape.certsrv.base.RequestNotAcceptable;
import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "caAuthority",
        urlPatterns = "/v2/authorities/*")
public class AuthorityServlet extends CAServlet {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(AuthorityServlet.class);

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void findCAs(HttpServletRequest request, HttpServletResponse response) throws Exception {

        HttpSession session = request.getSession();
        String id = request.getParameter("id");
        String parentID = request.getParameter("parentID");
        String dn = request.getParameter("dn");
        String issuerDN = request.getParameter("issuerDN");

        logger.info("AuthorityServlet: Finding CAs");
        logger.debug("AuthorityServlet: - session: {}", session.getId());

        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        List<AuthorityData> authorities = authorityRepository.findCAs(id, parentID, dn, issuerDN);

        PrintWriter out = response.getWriter();
        ObjectMapper mapper = new ObjectMapper();
        out.println(mapper.writeValueAsString(authorities));
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void getCA(HttpServletRequest request, HttpServletResponse response) throws Exception {

        HttpSession session = request.getSession();

        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String aid = pathElement[0];

        logger.info("AuthorityServlet: Getting CA {}", aid);
        logger.debug("AuthorityServlet: - session: {}", session.getId());

        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        AuthorityData ca = authorityRepository.getCA(aid);

        PrintWriter out = response.getWriter();
        out.println(ca.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}/cert"})
    public void getCert(HttpServletRequest request, HttpServletResponse response) throws Exception {

        HttpSession session = request.getSession();
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String aid = pathElement[0];
        String accept = request.getHeader("Accept");
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();

        logger.info("AuthorityServlet: Getting cert for CA {}", aid);
        logger.debug("AuthorityServlet: - session: {}", session.getId());

        if (accept == null)
            accept = MediaType.ANYTYPE;

        if (accept.contains(MediaType.APPLICATION_X_PEM_FILE)) {
            response.setContentType(MediaType.APPLICATION_X_PEM_FILE);
            String cert = authorityRepository.getPemCert(aid);
            PrintWriter out = response.getWriter();
            out.println(cert);
            return;
        }

        if (accept.equals(MediaType.ANYTYPE) || accept.contains(MediaType.APPLICATION_PKIX_CERT)) {
            response.setContentType(MediaType.APPLICATION_PKIX_CERT);
            byte[] cert = authorityRepository.getBinaryCert(aid);
            OutputStream out = response.getOutputStream();
            out.write(cert);
            return;
        }

        throw new RequestNotAcceptable("Certificate format not supported: " + accept);
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}/chain"})
    public void getChain(HttpServletRequest request, HttpServletResponse response) throws Exception {

        HttpSession session = request.getSession();
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String aid = pathElement[0];
        String accept = request.getHeader("Accept");

        logger.info("AuthorityServlet: Getting cert chain for CA {}", aid);
        logger.debug("AuthorityServlet: - session: {}", session.getId());

        if (accept == null)
            accept = MediaType.ANYTYPE;

        AuthorityRepository authorityRepository = engine.getAuthorityRepository();

        if (accept.contains(MediaType.APPLICATION_X_PEM_FILE)) {
            response.setContentType(MediaType.APPLICATION_X_PEM_FILE);
            String cert = authorityRepository.getPemChain(aid);
            PrintWriter out = response.getWriter();
            out.println(cert);
            return;
        }

        if (accept.equals(MediaType.ANYTYPE) || accept.contains(MediaType.APPLICATION_PKCS7)) {
            response.setContentType(MediaType.APPLICATION_PKCS7);
            byte[] cert = authorityRepository.getBinaryChain(aid);
            OutputStream out = response.getOutputStream();
            out.write(cert);
            return;
        }

        throw new RequestNotAcceptable("Certificate format not supported: " + accept);
    }

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void createCA(HttpServletRequest request, HttpServletResponse response) throws Exception {

        HttpSession session = request.getSession();

        logger.info("AuthorityServlet: Creating CA");
        logger.debug("AuthorityServlet: - session: {}", session.getId());

        String requestData = request.getReader().lines().collect(Collectors.joining());
        AuthorityData reqAuthority = JSONSerializer.fromJSON(requestData, AuthorityData.class);
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        AuthorityData newAuthhority = authorityRepository.createCA(reqAuthority);
        logger.debug("AuthorityServlet: - ID: {}", newAuthhority.getID());

        String encodedGroupID = URLEncoder.encode(newAuthhority.getID(), "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedGroupID);

        response.setStatus(HttpServletResponse.SC_CREATED);
        response.setHeader("Location", uri.toString());

        PrintWriter out = response.getWriter();
        out.println(newAuthhority.toJSON());
    }

    @WebAction(method = HttpMethod.PUT, paths = {"{}"})
    public void modifyCA(HttpServletRequest request, HttpServletResponse response) throws Exception {

        HttpSession session = request.getSession();
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String aid = pathElement[0];

        logger.info("AuthorityServlet: Modifying CA {}", aid);
        logger.debug("AuthorityServlet: - session: {}", session.getId());

        String requestData = request.getReader().lines().collect(Collectors.joining());
        AuthorityData reqAuthority = JSONSerializer.fromJSON(requestData, AuthorityData.class);
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        AuthorityData newAuthhority = authorityRepository.modifyCA(aid, reqAuthority);

        PrintWriter out = response.getWriter();
        out.println(newAuthhority.toJSON());
    }

    @WebAction(method = HttpMethod.DELETE, paths = {"{}"})
    public void deleteCA(HttpServletRequest request, HttpServletResponse response) throws Exception {

        HttpSession session = request.getSession();
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String aid = pathElement[0];

        logger.info("AuthorityServlet: Deleting CA {}", aid);
        logger.debug("AuthorityServlet: - session: {}", session.getId());

        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        authorityRepository.deleteCA(aid, request);

        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}/enable"})
    public void enableCA(HttpServletRequest request, HttpServletResponse response) throws Exception {

        HttpSession session = request.getSession();
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String aid = pathElement[0];

        logger.info("AuthorityServlet: Enabling CA {}", aid);
        logger.debug("AuthorityServlet: - session: {}", session.getId());

        AuthorityData reqAuthority = new AuthorityData(null, null, null, null, null, null, true, null, null);
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        AuthorityData newAuthhority = authorityRepository.modifyCA(aid, reqAuthority);

        PrintWriter out = response.getWriter();
        out.println(newAuthhority.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}/disable"})
    public void disableCA(HttpServletRequest request, HttpServletResponse response) throws Exception {

        HttpSession session = request.getSession();
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String aid = pathElement[0];

        logger.info("AuthorityServlet: Disabling CA {}", aid);
        logger.debug("AuthorityServlet: - session: {}", session.getId());

        AuthorityData reqAuthority = new AuthorityData(null, null, null, null, null, null, false, null, null);
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        AuthorityData newAuthhority = authorityRepository.modifyCA(aid, reqAuthority);

        PrintWriter out = response.getWriter();
        out.println(newAuthhority.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}/renew"})
    public void renewCA(HttpServletRequest request, HttpServletResponse response) throws Exception {

        HttpSession session = request.getSession();
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String aid = pathElement[0];

        logger.info("AuthorityServlet: Renewing CA {}", aid);
        logger.debug("AuthorityServlet: - session: {}", session.getId());

        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        authorityRepository.renewCA(aid, request);

        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
