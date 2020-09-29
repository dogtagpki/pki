//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

package com.netscape.cmscore.apps;

public interface StartupNotifier {
    void notifyReady() throws RuntimeException;
}
