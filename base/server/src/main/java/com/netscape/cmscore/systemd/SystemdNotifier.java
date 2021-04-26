//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.systemd;

import java.util.ArrayList;
import java.util.List;

import com.netscape.cmscore.apps.SubsystemListener;

public class SystemdNotifier extends SubsystemListener {

    @Override
    public void subsystemStarted() throws Exception {

        List<String> command = new ArrayList<>();
        command.add("systemd-notify");
        command.add("--ready");

        logger.info("SystemdNotifier: Command: " + String.join(" ", command));

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.inheritIO();

        Process p = pb.start();
        int rc = p.waitFor();

        if (rc != 0) {
            throw new Exception("Command failed: rc=" + rc);
        }
    }
}
