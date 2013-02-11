package com.netscape.tks;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

import com.netscape.certsrv.acls.ACLInterceptor;
import com.netscape.certsrv.base.PKIException;
import com.netscape.cms.servlet.account.AccountService;
import com.netscape.cms.servlet.admin.GroupMemberService;
import com.netscape.cms.servlet.admin.GroupService;
import com.netscape.cms.servlet.admin.SystemCertService;
import com.netscape.cms.servlet.admin.UserCertService;
import com.netscape.cms.servlet.admin.UserMembershipService;
import com.netscape.cms.servlet.admin.UserService;
import com.netscape.cms.servlet.csadmin.SystemConfigService;

public class TKSApplication extends Application {

    private Set<Object> singletons = new HashSet<Object>();
    private Set<Class<?>> classes = new HashSet<Class<?>>();

    public TKSApplication() {

        // account
        classes.add(AccountService.class);

        // installer
        classes.add(SystemConfigService.class);

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

        // ACL interceptor
        singletons.add(new ACLInterceptor());
    }

    public Set<Class<?>> getClasses() {
        return classes;
    }

    public Set<Object> getSingletons() {
        return singletons;
    }

}

