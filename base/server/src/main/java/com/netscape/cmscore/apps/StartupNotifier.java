//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

package com.netscape.cmscore.apps;

import com.netscape.certsrv.base.IConfigStore;

public interface StartupNotifier {
    void init(IConfigStore cs);
    NotifyResult notifyReady();

    class NotifyResult {
        NotifyResultStatus status;
        String message;

        public NotifyResult(NotifyResultStatus status, String message) {
            this.status = status;
            this.message = message;
        }

        public NotifyResultStatus getStatus() {
            return status;
        }

        public String getMessage() {
            return message;
        }
    }

    enum NotifyResultStatus { Failure, Success };
}
