//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import javax.servlet.ServletContext;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.dogtagpki.common.AppInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Endi S. Dewata
 */
@Path("apps")
public class AppService {

    private static Logger logger = LoggerFactory.getLogger(AppService.class);

    @Context
    ServletContext context;

    public AppInfo getAppInfo(String id) {

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

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getApplications() throws Exception {

        logger.info("PKI applications:");
        Collection<AppInfo> apps = new ArrayList<>();

        // get <instance>/conf folder
        File instanceDir = new File(System.getProperty("catalina.base"));
        File confDir = new File(instanceDir, "conf");

        // get all folders under <instance>/conf
        File[] appConfDirs = confDir.listFiles(File::isDirectory);
        Arrays.sort(appConfDirs);

        for (File appConfDir : appConfDirs) {
            String id = appConfDir.getName();

            // get app info if the app is deployed
            AppInfo info = getAppInfo(id);
            if (info == null) continue;

            logger.info("- ID: " + info.getID());
            logger.info("  Name: " + info.getName());
            logger.info("  Path: " + info.getPath());

            apps.add(info);
        }

        ResponseBuilder builder = Response.ok();
        builder.entity(apps);

        return builder.build();
    }
}
