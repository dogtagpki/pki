package org.dogtagpki.server.ca.v2;

import java.io.PrintWriter;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.common.CAInfo;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAServlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@WebServlet("/v2/info")
public class CAInfoServlet extends CAServlet {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(CAInfoServlet.class);

    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("CAInfoServlet.get(): session: " + session.getId());

        CAEngine engine = getCAEngine();
        CAInfo info = engine.getInfo(request.getLocale());

        response.setContentType("application/json");

        PrintWriter out = response.getWriter();
        out.println(info.toJSON());
    }
}
