//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps;

import javax.servlet.annotation.WebListener;

import com.netscape.cmscore.apps.PKIWebListener;

@WebListener
public class TPSWebListener extends PKIWebListener {

    public TPSEngine createEngine() {
        return new TPSEngine();
    }
}
