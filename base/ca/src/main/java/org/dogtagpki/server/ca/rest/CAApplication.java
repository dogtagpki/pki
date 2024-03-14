package org.dogtagpki.server.ca.rest;

import java.util.LinkedHashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import org.dogtagpki.server.rest.ACLInterceptor;
import org.dogtagpki.server.rest.AccountService;
import org.dogtagpki.server.rest.AuditService;
import org.dogtagpki.server.rest.AuthMethodInterceptor;
import org.dogtagpki.server.rest.CAInfoService;
import org.dogtagpki.server.rest.FeatureService;
import org.dogtagpki.server.rest.GroupService;
import org.dogtagpki.server.rest.JobService;
import org.dogtagpki.server.rest.MessageFormatInterceptor;
import org.dogtagpki.server.rest.PKIExceptionMapper;
import org.dogtagpki.server.rest.SecurityDomainService;
import org.dogtagpki.server.rest.SelfTestService;
import org.dogtagpki.server.rest.SessionContextInterceptor;
import org.dogtagpki.server.rest.UserService;

@ApplicationPath("/rest")
public class CAApplication extends Application {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAApplication.class);

    private Set<Object> singletons = new LinkedHashSet<>();
    private Set<Class<?>> classes = new LinkedHashSet<>();

    public CAApplication() {

        // account
        classes.add(AccountService.class);

        // audit
        classes.add(AuditService.class);

        // installer
        classes.add(CAInstallerService.class);

        // sub-ca management
        classes.add(AuthorityService.class);

        // certs and requests
        classes.add(CertService.class);
        classes.add(CertRequestService.class);
        classes.add(AgentCertService.class);
        classes.add(AgentCertRequestService.class);

        // profile management
        classes.add(ProfileService.class);

        // job management
        classes.add(JobService.class);

        // selftests
        classes.add(SelfTestService.class);

        // user and group management
        classes.add(GroupService.class);
        classes.add(UserService.class);

        // system certs
        classes.add(CASystemCertService.class);

        // kra connector
        classes.add(KRAConnectorService.class);

        // features
        classes.add(FeatureService.class);

        // info service
        classes.add(CAInfoService.class);

        // security domain
        classes.add(SecurityDomainService.class);

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
