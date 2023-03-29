//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.ca;

import org.dogtagpki.server.ca.CAEngine;

import com.netscape.certsrv.ldap.LdapConnFactory;
import com.netscape.certsrv.ldap.ILdapConnModule;
import com.netscape.cmscore.ldap.CAPublisherProcessor;
import com.netscape.cmscore.request.RequestNotifier;

public class CANotify extends RequestNotifier {

    public CANotify() {
    }

    @Override
    public boolean checkAvailablePublishingConnections() {

        CAEngine engine = CAEngine.getInstance();
        CAPublisherProcessor pp = engine.getPublisherProcessor();

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

        LdapConnFactory ldapConnFactory = ldapConnModule.getLdapConnFactory();
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
