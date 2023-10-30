//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp;

import javax.servlet.annotation.WebListener;

import com.netscape.cmscore.apps.CMSWebListener;

@WebListener
public class OCSPWebListener extends CMSWebListener {

    public OCSPEngine createEngine() {
        return new OCSPEngine();
    }
}
