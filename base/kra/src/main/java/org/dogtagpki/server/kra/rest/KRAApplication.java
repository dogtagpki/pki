package org.dogtagpki.server.kra.rest;

import java.util.LinkedHashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import org.dogtagpki.server.rest.ACLInterceptor;
import org.dogtagpki.server.rest.AccountService;
import org.dogtagpki.server.rest.AuditService;
import org.dogtagpki.server.rest.AuthMethodInterceptor;
import org.dogtagpki.server.rest.GroupService;
import org.dogtagpki.server.rest.JobService;
import org.dogtagpki.server.rest.KRAInfoService;
import org.dogtagpki.server.rest.MessageFormatInterceptor;
import org.dogtagpki.server.rest.PKIExceptionMapper;
import org.dogtagpki.server.rest.SecurityDomainService;
import org.dogtagpki.server.rest.SelfTestService;
import org.dogtagpki.server.rest.SessionContextInterceptor;
import org.dogtagpki.server.rest.UserService;

@ApplicationPath("/v1")
public class KRAApplication extends Application {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAApplication.class);

    private Set<Object> singletons = new LinkedHashSet<>();
    private Set<Class<?>> classes = new LinkedHashSet<>();

    public KRAApplication() {

        // account
        classes.add(AccountService.class);

        // audit
        classes.add(AuditService.class);

        // security domain
        classes.add(SecurityDomainService.class);

        // keys and keyrequests
        classes.add(KeyService.class);
        classes.add(KeyRequestService.class);

        // job management
        classes.add(JobService.class);

        // selftests
        classes.add(SelfTestService.class);

        // user and group management
        classes.add(GroupService.class);
        classes.add(UserService.class);

        // system certs
        classes.add(KRASystemCertService.class);

        // exception mapper
        classes.add(PKIExceptionMapper.class);

        // info service
        classes.add(KRAInfoService.class);

        // interceptors
        singletons.add(new SessionContextInterceptor());
        singletons.add(new AuthMethodInterceptor());
        singletons.add(new ACLInterceptor());
        singletons.add(new MessageFormatInterceptor());
    }

    @Override
    public Set<Class<?>> getClasses() {
        return classes;
    }

    @Override
    public Set<Object> getSingletons() {
        return singletons;
    }

}
