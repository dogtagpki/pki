package com.netscape.ca;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

import com.netscape.cms.servlet.admin.GroupMemberResourceService;
import com.netscape.cms.servlet.admin.GroupResourceService;
import com.netscape.cms.servlet.admin.SystemCertificateResourceService;
import com.netscape.cms.servlet.admin.UserCertResourceService;
import com.netscape.cms.servlet.admin.UserResourceService;
import com.netscape.cms.servlet.base.CMSException;
import com.netscape.cms.servlet.cert.CertResourceService;
import com.netscape.cms.servlet.csadmin.SystemConfigurationResourceService;
import com.netscape.cms.servlet.profile.ProfileResourceService;
import com.netscape.cms.servlet.request.CertRequestResourceService;

public class CertificateAuthorityApplication extends Application {
    private Set<Object> singletons = new HashSet<Object>();
    private Set<Class<?>> classes = new HashSet<Class<?>>();

    public CertificateAuthorityApplication() {
        // installer
        classes.add(SystemConfigurationResourceService.class);

        // certs and requests
        classes.add(CertResourceService.class);
        classes.add(CertRequestResourceService.class);

        // profile management
        classes.add(ProfileResourceService.class);

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
