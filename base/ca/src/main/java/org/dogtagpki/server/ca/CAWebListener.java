//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca;

import javax.servlet.annotation.WebListener;

import com.netscape.cmscore.apps.PKIWebListener;

@WebListener
public class CAWebListener extends PKIWebListener {

    public CAEngine createEngine() {
        return new CAEngine();
    }
}
