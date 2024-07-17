//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra;

import jakarta.servlet.annotation.WebListener;

import com.netscape.cmscore.apps.CMSWebListener;

@WebListener
public class KRAWebListener extends CMSWebListener {

    public KRAEngine createEngine() {
        return new KRAEngine();
    }
}
