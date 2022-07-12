//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra;

import javax.servlet.annotation.WebListener;

import com.netscape.cmscore.apps.PKIWebListener;

@WebListener
public class KRAWebListener extends PKIWebListener {

    public KRAEngine createEngine() {
        return new KRAEngine();
    }
}
