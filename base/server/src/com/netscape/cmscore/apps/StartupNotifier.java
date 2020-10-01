//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

package com.netscape.cmscore.apps;

import com.netscape.certsrv.base.IConfigStore;

public interface StartupNotifier {
    void init(IConfigStore cs);
    void notifyReady() throws RuntimeException;
}
