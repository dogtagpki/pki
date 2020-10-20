//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.realm;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.usrgrp.User;

/**
 * @author Endi S. Dewata
 */
public class InMemoryRealm extends ACMERealm {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(InMemoryRealm.class);

    String username;
    String password;

    User user;
    List<String> roles;

    @Override
    public void init() throws Exception {

        username = config.getParameter("username");
        password = config.getParameter("password");

        user = new User();
        user.setUserID(username);
        user.setFullName("Administrator");

        roles = new ArrayList<>();
        roles.add("Administrators");
    }

    public Principal authenticate(String username, String password) throws Exception {

        logger.info("Authenticating user " + username + " with password");

        if (!this.username.equals(username)) {
            return null;
        }

        if (!this.password.equals(password)) {
            return null;
        }

        return new PKIPrincipal(user, null, roles);
    }
}
