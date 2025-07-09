//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks;

import jakarta.servlet.annotation.WebListener;

import com.netscape.cmscore.apps.CMSWebListener;

@WebListener
public class TKSWebListener extends CMSWebListener {

    public TKSEngine createEngine() {
        return new TKSEngine();
    }
}
