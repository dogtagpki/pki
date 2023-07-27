//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.systemd;

import java.util.ArrayList;
import java.util.List;

import com.netscape.cmscore.apps.SubsystemListener;

/**
 * Notify of startup when systemd notification socket is available.
 *
 * This class invokes systemd-notify(1) to notify systemd when the system
 * has been initialised.  To configure systemd notifcation, use drop-in
 * unit configuration, e.g. put into the file:
 *
 *   /etc/systemd/system/pki-tomcatd@pki-tomcat.service.d/notify.conf
 *
 * the contents:
 *
 *   [Service]
 *   Type=notify
 *   NotifyAccess=all
 */
public class SystemdNotifier extends SubsystemListener {

    @Override
    public void subsystemStarted() throws Exception {

        List<String> command = new ArrayList<>();
        command.add("systemd-notify");
        command.add("--ready");

        logger.debug("SystemdNotifier: Command: " + String.join(" ", command));

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.inheritIO();

        Process p = pb.start();
        int rc = p.waitFor();

        if (rc != 0) {
            throw new Exception("Command failed: rc=" + rc);
        }
    }
}
