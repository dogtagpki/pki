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
// (C) 2015 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server;

import javax.servlet.ServletException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.Constants;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

public class PKIServer {

    public static Logger logger = LoggerFactory.getLogger(PKIServer.class);

    public static void main(String[] args) throws Exception {

        String path = CMS.CONFIG_FILE;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];

            if (arg.equals("-f")) {
                path = args[++i];
            } else {
                throw new Exception("Unknown option: " + arg);
            }
        }

        String classname = "com.netscape.cmscore.apps.CMSEngine";
        CMSEngine engine = null;

        try {
            engine = (CMSEngine) Class.forName(classname).newInstance();
            CMS.setCMSEngine(engine);

            IConfigStore mainConfig = engine.createFileConfigStore(path);
            engine.init(null, mainConfig);

            engine.startup();

        } catch (Exception e) {
            logger.error("Unable to start server: " + e.getMessage(), e);
            logger.info(Constants.SERVER_SHUTDOWN_MESSAGE);

            if (engine != null) {
                engine.shutdown();
            }
            throw new ServletException(e);
        }

        final CMSEngine finalEngine = engine;

        // Use shutdown hook in stand-alone application
        // to catch SIGINT, SIGTERM, or SIGHUP.
        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {

                logger.info("Received shutdown signal");
                logger.info(Constants.SERVER_SHUTDOWN_MESSAGE);

                finalEngine.shutdown();
            };
        });
    }

}
