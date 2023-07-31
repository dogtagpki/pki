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

package com.netscape.cms.tomcat;

import java.io.File;

import org.apache.catalina.Context;
import org.apache.catalina.Engine;
import org.apache.catalina.Host;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.Server;
import org.apache.catalina.Service;
import org.dogtagpki.jss.tomcat.JSSListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PKIListener extends JSSListener {

    final static Logger logger = LoggerFactory.getLogger(PKIListener.class);

    @Override
    public void lifecycleEvent(LifecycleEvent event) {

        super.lifecycleEvent(event);

        String type = event.getType();

        if (type.equals(Lifecycle.AFTER_START_EVENT)) {

            verifySubsystems((Server) event.getLifecycle());
        }
    }

    public void verifySubsystems(Server server) {

        Service service = server.findService("Catalina");
        Engine engine = service.getContainer();
        String defaultHost = engine.getDefaultHost();
        Host host = (Host) engine.findChild(defaultHost);

        File instanceDir = new File(System.getProperty("catalina.base"));
        String instanceName = instanceDir.getName();

        for (File file : instanceDir.listFiles()) {

            if (!file.isDirectory())
                continue;

            File csCfg = new File(file, "conf" + File.separator + "CS.cfg");
            if (!csCfg.exists())
                continue;

            String subsystemName = file.getName();

            File contextXml = new File(
                    instanceDir,
                    "conf" + File.separator + "Catalina" + File.separator +
                            defaultHost + File.separator + subsystemName + ".xml");

            if (!contextXml.exists()) {

                logger.warn("PKIListener: Subsystem " + subsystemName.toUpperCase() + " is disabled.");

                String selftestsLog = "/var/log/pki/" + instanceName + "/" + subsystemName + "/selftests.log";
                logger.warn("PKIListener: Check " + selftestsLog + " for possible errors.");

                logger.warn("PKIListener: To enable the subsystem:");
                logger.warn("PKIListener:   pki-server subsystem-enable -i " + instanceName + " " + subsystemName);

                continue;
            }

            Context context = (Context) host.findChild("/" + subsystemName);

            if (context == null) {

                logger.warn("PKIListener: " + "Subsystem " + subsystemName.toUpperCase() + " is not deployed.");

                String catalinaLog = "/var/log/pki/" + instanceName + "/catalina.*.log";
                logger.warn("PKIListener: Check " + catalinaLog);
                logger.warn("PKIListener: and Tomcat's standard output and error for possible errors:");
                logger.warn("PKIListener:   journalctl -u pki-tomcatd@" + instanceName + ".service");

                continue;
            }

            logger.info("PKIListener: Subsystem " + subsystemName.toUpperCase() + " is running.");
        }
    }
}
