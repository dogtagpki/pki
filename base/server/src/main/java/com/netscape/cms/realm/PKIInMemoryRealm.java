//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.realm;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.catalina.LifecycleException;

import com.netscape.cmscore.usrgrp.User;

/**
 * @author Endi S. Dewata
 */
public class PKIInMemoryRealm extends RealmCommon {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIInMemoryRealm.class);

    String username;
    String password;

    User user;
    List<String> roles;

    @Override
    public void initInternal() throws LifecycleException {

        username = config.getParameter("username");
        password = config.getParameter("password");
        String roleList = config.getParameter("roles");

        user = new User();
        user.setUserID(username);
        user.setFullName("Administrator");

        if (roleList == null) {
            roles = new ArrayList<>();
            roles.add("Administrators");
        }
        else {
            roles = Stream.of(roleList.split(",")).map(String::trim).collect(Collectors.toList());
        }
    }

    @Override
    public Principal authenticate(String username, String password) {

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
