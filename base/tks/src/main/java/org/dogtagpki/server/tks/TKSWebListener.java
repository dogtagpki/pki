//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks;

import javax.servlet.annotation.WebListener;

import com.netscape.cmscore.apps.PKIWebListener;

@WebListener
public class TKSWebListener extends PKIWebListener {

    public TKSEngine createEngine() {
        return new TKSEngine();
    }
}
