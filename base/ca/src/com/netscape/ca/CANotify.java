//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.ca;

import org.dogtagpki.server.ca.CAEngine;

import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.ldap.ILdapConnModule;
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

    public boolean checkAvailablePublishingConnections() {

        CAEngine engine = CAEngine.getInstance();
        PublisherProcessor pp = engine.getPublisherProcessor();

        if (pp == null) {
            logger.warn("CANotify: Publisher processor is not accessible");
            return false;
        }

        if (!pp.isCertPublishingEnabled() && !pp.isCRLPublishingEnabled()) {
            logger.warn("CANotify: Publisher processor is not enabled");
            return false;
        }

        ILdapConnModule ldapConnModule = pp.getLdapConnModule();
        if (ldapConnModule == null) {
            logger.warn("CANotify: LDAP connection module is not accessible");
            return false;
        }

        ILdapConnFactory ldapConnFactory = ldapConnModule.getLdapConnFactory();
        if (ldapConnFactory == null) {
            logger.warn("CANotify: LDAP connection factory is not accessible");
            return false;
        }

        int maxConnection = ldapConnFactory.maxConn();
        logger.debug("CANotify: max connection: " + maxConnection);

        int totalConnection = ldapConnFactory.totalConn();
        logger.debug("CANotify: total connection: " + totalConnection);

        return maxConnection > totalConnection;
    }
}
