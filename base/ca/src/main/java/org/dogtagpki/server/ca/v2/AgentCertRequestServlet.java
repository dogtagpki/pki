//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.v2;

import java.io.PrintWriter;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.ca.CAServlet;

import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.request.RequestId;

@WebServlet(
        name = "caCertRequest-agent",
        urlPatterns = "/v2/agent/certrequests")
public class AgentCertRequestServlet extends CAServlet {

    @Override
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.setContentType("application/json");
        PrintWriter out = response.getWriter();
        out.print("...");
    }

    public CertRequestInfos listRequests(String requestState, String requestType,
            RequestId start, Integer pageSize, Integer maxResults, Integer maxTime) {
        return null;
    }

}
