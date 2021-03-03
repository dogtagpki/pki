//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.ca;

import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.cmscore.ldap.PublisherProcessor;
import com.netscape.cmscore.request.RequestNotifier;

public class CANotify extends RequestNotifier {

    CertificateAuthority ca;

    public CANotify(CertificateAuthority ca) {
        this.ca = ca;
    }

    public IRequestQueue getRequestQueue() {
        return ca.getRequestQueue();
    }

    public PublisherProcessor getPublisherProcessor() {
        return ca.getPublisherProcessor();
    }
}
