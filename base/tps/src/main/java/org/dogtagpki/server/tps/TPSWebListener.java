//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps;

import jakarta.servlet.annotation.WebListener;

import com.netscape.cmscore.apps.CMSWebListener;

@WebListener
public class TPSWebListener extends CMSWebListener {

    public TPSEngine createEngine() {
        return new TPSEngine();
    }
}
