//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.base;

import java.security.Principal;
import java.util.Arrays;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.account.Account;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.usrgrp.User;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class AccountServletBase {
    public static final Logger logger = LoggerFactory.getLogger(AccountServletBase.class);

    public static Account createAccount(Principal principal) {
        logger.info("Principal:");

        Account account = new Account();
        String name = principal.getName();
        logger.info("- ID: {}", name);
        account.setID(name);

        if (principal instanceof PKIPrincipal pkiPrincipal) {
            User user = pkiPrincipal.getUser();

            String fullName = user.getFullName();
            logger.info("- Full Name: {}", fullName);
            if (!StringUtils.isEmpty(fullName)) account.setFullName(fullName);

            String email = user.getEmail();
            logger.info("- Email: {}", email);
            if (!StringUtils.isEmpty(email)) account.setEmail(email);
        }

        if (principal instanceof GenericPrincipal genericPrincipal) {
            String[] roles = genericPrincipal.getRoles();
            logger.info("Roles:");
            for (String role : roles) {
                logger.info("- {}", role);
            }
            account.setRoles(Arrays.asList(roles));
        }

        return account;
    }
}
