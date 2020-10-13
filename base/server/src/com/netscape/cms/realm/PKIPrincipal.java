package com.netscape.cms.realm;

import java.util.List;

import org.apache.catalina.realm.GenericPrincipal;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.cmscore.usrgrp.User;

/**
 * @author Endi S. Dewata
 */

public class PKIPrincipal extends GenericPrincipal {

    User user;
    IAuthToken authToken;

    public PKIPrincipal(User user, String password, List<String> roles, IAuthToken authToken) {
        super(user.getUserID(), password, roles);
        this.user = user;
        this.authToken = authToken;
    }

    public User getUser() {
        return user;
    }

    public IAuthToken getAuthToken() {
        return authToken;
    }
}
