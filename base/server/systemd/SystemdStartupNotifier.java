//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.systemd;

import com.sun.jna.Library;
import com.sun.jna.Native;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cmscore.apps.StartupNotifier;

public class SystemdStartupNotifier implements StartupNotifier {
    interface Systemd extends Library {
        public int sd_booted();
        public int sd_notify(int unset_environment, String state);
    }

    /* We load the library in init() */
    Systemd systemd = null;
    boolean systemdBooted = false;

    static boolean hasNotifySocket() {
        return System.getenv("NOTIFY_SOCKET") != null;
    }

    void notify(String status) {
        if (systemd == null) {
            System.err.println("Failed to load libsystemd");
        } else if (!systemdBooted) {
            System.err.println("Not running under systemd");
        } else if (!hasNotifySocket()) {
            System.err.println("No systemd notify socket");
        } else {
            systemd.sd_notify(0 /* unset_environment */, status);
        }
    }

    public void init(IConfigStore cs) {
        /* loadLibrary is deprecated in jna >= 5; replaced with load()
         * which avoids the cast.  But RHEL 8 has jna 4.5 so we must put
         * up with deprecation warnings on Fedora. */
        try {
            systemd = Native.loadLibrary("systemd", Systemd.class);
            systemdBooted = systemd.sd_booted() > 0;
        } catch (Throwable e) {
            systemd = null;
            systemdBooted = false;
        }
    }

    public void notifyReady() {
        notify("READY=1");
    }
}
