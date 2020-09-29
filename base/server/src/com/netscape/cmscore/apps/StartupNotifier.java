//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

package com.netscape.cmscore.apps;

import com.netscape.certsrv.base.IConfigStore;

public interface StartupNotifier {
    default void init(IConfigStore cs) {
        // default implementation ignores value
    };

    void notifyReady() throws RuntimeException;
}
