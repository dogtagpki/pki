//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.realm;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import org.apache.catalina.LifecycleException;

import com.netscape.cmscore.usrgrp.User;

/**
 * @author Endi S. Dewata
 */
public class PKIInMemoryRealm extends RealmCommon {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIInMemoryRealm.class);

    String username;
    String password;

    User user;
    List<String> roles;

    @Override
    public void initInternal () throws LifecycleException {

        username = config.getParameter("username");
        password = config.getParameter("password");

        user = new User();
        user.setUserID(username);
        user.setFullName("Administrator");

        roles = new ArrayList<>();
        roles.add("Administrators");
    }

    @Override
    public Principal authenticate(String username, String password) {

        logger.info("Authenticating user " + username + " with password");

        if (!this.username.equals(username)) {
            logger.warn("Unable to authenticate user " + username + ": User not found");
            return null;
        }

        if (!this.password.equals(password)) {
            logger.warn("Unable to authenticate user " + username + ": Invalid password");
            return null;
        }

        logger.info("User " + username + " authenticated");

        return new PKIPrincipal(user, null, roles);
    }


}
