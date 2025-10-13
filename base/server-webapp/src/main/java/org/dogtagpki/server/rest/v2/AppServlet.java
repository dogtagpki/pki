//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import jakarta.servlet.ServletContext;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.common.AppInfo;
import org.dogtagpki.server.PKIServlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.base.MimeType;
import com.netscape.cmscore.apps.CMS;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author Endi S. Dewata
 */
@WebServlet("/v2/apps")
public class AppServlet extends PKIServlet {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(AppServlet.class);

    @Override
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {

        logger.info("PKI applications:");
        Collection<AppInfo> apps = new ArrayList<>();

        // get <instance>/conf folder
        File instanceDir = new File(CMS.getInstanceDir());
        File confDir = new File(instanceDir, "conf");

        // get all folders under <instance>/conf
        File[] appConfDirs = confDir.listFiles(File::isDirectory);
        Arrays.sort(appConfDirs);

        for (File appConfDir : appConfDirs) {
            String id = appConfDir.getName();

            // get app info if the app is deployed
            AppInfo info = getAppInfo(request.getServletContext(), id);
            if (info == null) continue;

            logger.info("- ID: {}", info.getID());
            logger.info("  Name: {}", info.getName());
            logger.info("  Path: {}", info.getPath());

            apps.add(info);
        }

        response.setContentType(MimeType.APPLICATION_JSON);

        PrintWriter out = response.getWriter();
        ObjectMapper mapper = new ObjectMapper();
        out.println(mapper.writeValueAsString(apps));
    }

    public AppInfo getAppInfo(ServletContext context, String id) {

        // get path of the application
        String path = "/" + id;

        // find context of the path
        ServletContext ctx = context.getContext(path);

        if (ctx == null) {
            // context not available
            return null;
        }

        if (!path.equals(ctx.getContextPath())) {
            // path belongs to a different context,
            // so the application is not deployed
            return null;
        }

        // get display name from web.xml
        String displayName = ctx.getServletContextName();

        AppInfo info = new AppInfo();
        info.setID(id);
        info.setName(displayName);
        info.setPath(path);

        return info;
    }
}
