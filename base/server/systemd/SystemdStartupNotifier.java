//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.systemd;

import com.sun.jna.Library;
import com.sun.jna.Native;

import com.netscape.cmscore.apps.StartupNotifier;

public class SystemdStartupNotifier implements StartupNotifier {
    interface Systemd extends Library {
        public int sd_booted();
        public int sd_notify(int unset_environment, String state);
    }

    /* loadLibrary is deprecated in jna >= 5; replaced with load()
     * which avoids the cast.  But RHEL 8 has jna 4.5 so we must put
     * up with deprecation warnings on Fedora. */
    static Systemd systemd = (Systemd) Native.loadLibrary("systemd", Systemd.class);

    static boolean isNotifyService = hasNotifySocket() && systemdBooted();

    private static boolean systemdBooted() {
        return systemd.sd_booted() > 0;
    }

    private static boolean hasNotifySocket() {
        return System.getenv("NOTIFY_SOCKET") != null;
    }

    private static void notify(String status) {
        if (isNotifyService) {
            System.out.println("Notifying systemd:\n" + status);
            systemd.sd_notify(0 /* unset_environment */, status);
        } else {
            System.err.println("Failed to notify systemd (isNotifyService = false)");
        }
    }

    public void notifyReady() {
        notify("READY=1");
    }
}
