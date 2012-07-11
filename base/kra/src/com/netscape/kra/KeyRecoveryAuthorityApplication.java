package com.netscape.kra;

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
import com.netscape.cms.servlet.key.KeyResourceService;
import com.netscape.cms.servlet.key.KeysResourceService;
import com.netscape.cms.servlet.request.KeyRequestResourceService;
import com.netscape.cms.servlet.request.KeyRequestsResourceService;

public class KeyRecoveryAuthorityApplication extends Application {

    private Set<Object> singletons = new HashSet<Object>();
    private Set<Class<?>> classes = new HashSet<Class<?>>();

    public KeyRecoveryAuthorityApplication() {
        // installer
        classes.add(SystemConfigurationResourceService.class);

        // keys and keyrequests
        classes.add(KeysResourceService.class);
        classes.add(KeyResourceService.class);
        classes.add(KeyRequestsResourceService.class);
        classes.add(KeyRequestResourceService.class);

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
