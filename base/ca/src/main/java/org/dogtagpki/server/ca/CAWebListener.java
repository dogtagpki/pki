//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca;

import jakarta.servlet.annotation.WebListener;

import com.netscape.cmscore.apps.CMSWebListener;

@WebListener
public class CAWebListener extends CMSWebListener {

    public CAEngine createEngine() {
        return new CAEngine();
    }
}
