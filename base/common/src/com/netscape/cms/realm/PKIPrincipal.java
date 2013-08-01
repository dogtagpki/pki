package com.netscape.cms.realm;

import java.util.List;

import org.apache.catalina.realm.GenericPrincipal;

import com.netscape.certsrv.authentication.IAuthToken;

/**
 * @author Endi S. Dewata
 */

public class PKIPrincipal extends GenericPrincipal {

    IAuthToken authToken;

    public PKIPrincipal(String name, String password, List<String> roles, IAuthToken authToken) {
        super(name, password, roles);
        this.authToken = authToken;
    }

    public PKIPrincipal(String name, String password, List<String> roles) {
        this(name, password, roles, null);
    }

    public IAuthToken getAuthToken() {
        return authToken;
    }
}
