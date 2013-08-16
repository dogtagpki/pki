package com.netscape.kra;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

import com.netscape.certsrv.base.PKIException;
import com.netscape.cms.authorization.ACLInterceptor;
import com.netscape.cms.authorization.AuthMethodInterceptor;
import com.netscape.cms.servlet.account.AccountService;
import com.netscape.cms.servlet.admin.GroupMemberService;
import com.netscape.cms.servlet.admin.GroupService;
import com.netscape.cms.servlet.admin.SystemCertService;
import com.netscape.cms.servlet.admin.UserCertService;
import com.netscape.cms.servlet.admin.UserMembershipService;
import com.netscape.cms.servlet.admin.UserService;
import com.netscape.cms.servlet.csadmin.SystemConfigService;
import com.netscape.cms.servlet.key.KeyService;
import com.netscape.cms.servlet.request.KeyRequestService;

public class KeyRecoveryAuthorityApplication extends Application {

    private Set<Object> singletons = new HashSet<Object>();
    private Set<Class<?>> classes = new HashSet<Class<?>>();

    public KeyRecoveryAuthorityApplication() {

        // account
        classes.add(AccountService.class);

        // installer
        classes.add(SystemConfigService.class);

        // keys and keyrequests
        classes.add(KeyService.class);
        classes.add(KeyRequestService.class);

        // user and group management
        classes.add(GroupMemberService.class);
        classes.add(GroupService.class);
        classes.add(UserCertService.class);
        classes.add(UserMembershipService.class);
        classes.add(UserService.class);

        // system certs
        classes.add(SystemCertService.class);

        // exception mapper
        classes.add(PKIException.Mapper.class);

        // interceptors
        singletons.add(new AuthMethodInterceptor());
        singletons.add(new ACLInterceptor());
    }

    public Set<Class<?>> getClasses() {
        return classes;
    }

    public Set<Object> getSingletons() {
        return singletons;
    }

}
