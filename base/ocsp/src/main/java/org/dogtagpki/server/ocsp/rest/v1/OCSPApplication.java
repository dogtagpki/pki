package org.dogtagpki.server.ocsp.rest.v1;

import java.util.LinkedHashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import org.dogtagpki.server.rest.v1.ACLInterceptor;
import org.dogtagpki.server.rest.v1.AccountService;
import org.dogtagpki.server.rest.v1.AuditService;
import org.dogtagpki.server.rest.v1.AuthMethodInterceptor;
import org.dogtagpki.server.rest.v1.GroupService;
import org.dogtagpki.server.rest.v1.JobService;
import org.dogtagpki.server.rest.v1.MessageFormatInterceptor;
import org.dogtagpki.server.rest.v1.PKIExceptionMapper;
import org.dogtagpki.server.rest.v1.SecurityDomainService;
import org.dogtagpki.server.rest.v1.SelfTestService;
import org.dogtagpki.server.rest.v1.SessionContextInterceptor;
import org.dogtagpki.server.rest.v1.UserService;

@ApplicationPath("/v1")
public class OCSPApplication extends Application {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(OCSPApplication.class);

    private Set<Object> singletons = new LinkedHashSet<>();
    private Set<Class<?>> classes = new LinkedHashSet<>();

    public OCSPApplication() {

        // account
        classes.add(AccountService.class);

        // audit
        classes.add(AuditService.class);

        // security domain
        classes.add(SecurityDomainService.class);

        // job management
        classes.add(JobService.class);

        // selftests
        classes.add(SelfTestService.class);

        // user and group management
        classes.add(GroupService.class);
        classes.add(UserService.class);

        // exception mapper
        classes.add(PKIExceptionMapper.class);

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
