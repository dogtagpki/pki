package org.dogtagpki.server.kra.rest;

import java.util.LinkedHashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

import org.dogtagpki.server.rest.ACLInterceptor;
import org.dogtagpki.server.rest.AccountService;
import org.dogtagpki.server.rest.AuditService;
import org.dogtagpki.server.rest.AuthMethodInterceptor;
import org.dogtagpki.server.rest.GroupService;
import org.dogtagpki.server.rest.PKIExceptionMapper;
import org.dogtagpki.server.rest.MessageFormatInterceptor;
import org.dogtagpki.server.rest.SecurityDomainService;
import org.dogtagpki.server.rest.SelfTestService;
import org.dogtagpki.server.rest.SystemCertService;
import org.dogtagpki.server.rest.UserService;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

public class KRAApplication extends Application {

    private Set<Object> singletons = new LinkedHashSet<Object>();
    private Set<Class<?>> classes = new LinkedHashSet<Class<?>>();

    public KRAApplication() {

        // account
        classes.add(AccountService.class);

        // audit
        classes.add(AuditService.class);

        // installer
        classes.add(KRAInstallerService.class);

        // security domain
        IConfigStore cs = CMS.getConfigStore();
        try {
            boolean standalone = cs.getBoolean("kra.standalone", false);
            if (standalone) {
                classes.add(SecurityDomainService.class);
            }
        } catch (EBaseException e) {
            CMS.debug(e);
            throw new RuntimeException(e);
        }

        // keys and keyrequests
        classes.add(KeyService.class);
        classes.add(KeyRequestService.class);

        // selftests
        classes.add(SelfTestService.class);

        // user and group management
        classes.add(GroupService.class);
        classes.add(UserService.class);

        // system certs
        classes.add(SystemCertService.class);

        // exception mapper
        classes.add(PKIExceptionMapper.class);

        // interceptors
        singletons.add(new AuthMethodInterceptor());
        singletons.add(new ACLInterceptor());
        singletons.add(new MessageFormatInterceptor());
    }

    public Set<Class<?>> getClasses() {
        return classes;
    }

    public Set<Object> getSingletons() {
        return singletons;
    }

}
