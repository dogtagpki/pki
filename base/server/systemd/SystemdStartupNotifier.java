//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.systemd;

import com.netscape.cmscore.apps.StartupNotifier;

public class SystemdStartupNotifier implements StartupNotifier {
    public void notifyReady() {
        System.out.println("Notifying systemd... not!");
    }
}
