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
import com.netscape.cmscore.apps.StartupNotifier.NotifyResult;

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

    NotifyResult notify(String status) {
        if (systemd == null) {
            return new NotifyResult(NotifyResultStatus.Failure, "Failed to load libsystemd");
        } else if (!systemdBooted) {
            return new NotifyResult(NotifyResultStatus.Failure, "Not running under systemd");
        } else if (!hasNotifySocket()) {
            return new NotifyResult(NotifyResultStatus.Failure, "No systemd notify socket");
        } else {
            int r = systemd.sd_notify(0 /* unset_environment */, status);
            if (r < 1) {
                return new NotifyResult(NotifyResultStatus.Failure, "sd_notify returned " + r);
            } else {
                return new NotifyResult(NotifyResultStatus.Success, "sd_notify returned " + r);
            }
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

    public NotifyResult notifyReady() {
        return notify("READY=1");
    }
}
