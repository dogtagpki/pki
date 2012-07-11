package com.netscape.ocsp;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

import com.netscape.cms.servlet.admin.GroupMemberResourceService;
import com.netscape.cms.servlet.admin.GroupResourceService;
import com.netscape.cms.servlet.admin.SystemCertificateResourceService;
import com.netscape.cms.servlet.admin.UserCertResourceService;
import com.netscape.cms.servlet.admin.UserResourceService;
import com.netscape.cms.servlet.base.CMSException;
import com.netscape.cms.servlet.csadmin.SystemConfigurationResourceService;

public class OCSPApplication extends Application {

    private Set<Object> singletons = new HashSet<Object>();
    private Set<Class<?>> classes = new HashSet<Class<?>>();

    public OCSPApplication() {
        // installer
        classes.add(SystemConfigurationResourceService.class);

        // user and group management
        classes.add(GroupMemberResourceService.class);
        classes.add(GroupResourceService.class);
        classes.add(UserCertResourceService.class);
        classes.add(UserResourceService.class);

        // system certs
        classes.add(SystemCertificateResourceService.class);

        // exception mapper
        classes.add(CMSException.Mapper.class);
    }

    public Set<Class<?>> getClasses() {
        return classes;
    }

    public Set<Object> getSingletons() {
        return singletons;
    }
}
