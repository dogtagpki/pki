package org.dogtagpki.server.ca.rest;

import java.util.LinkedHashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.rest.ACLInterceptor;
import org.dogtagpki.server.rest.AccountService;
import org.dogtagpki.server.rest.AuditService;
import org.dogtagpki.server.rest.AuthMethodInterceptor;
import org.dogtagpki.server.rest.CAInfoService;
import org.dogtagpki.server.rest.FeatureService;
import org.dogtagpki.server.rest.GroupService;
import org.dogtagpki.server.rest.MessageFormatInterceptor;
import org.dogtagpki.server.rest.PKIExceptionMapper;
import org.dogtagpki.server.rest.SecurityDomainHostService;
import org.dogtagpki.server.rest.SecurityDomainService;
import org.dogtagpki.server.rest.SelfTestService;
import org.dogtagpki.server.rest.SessionContextInterceptor;
import org.dogtagpki.server.rest.UserService;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.EngineConfig;

public class CAApplication extends Application {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAApplication.class);

    private Set<Object> singletons = new LinkedHashSet<Object>();
    private Set<Class<?>> classes = new LinkedHashSet<Class<?>>();

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

        // profile management
        classes.add(ProfileService.class);

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
        CAEngine engine = CAEngine.getInstance();
        EngineConfig cs = engine.getConfig();

        // check server state
        int state;
        try {
            state = cs.getState();
        } catch (EBaseException e) {
            logger.error("CAApplication: " + e.getMessage(), e);
            throw new RuntimeException(e);
        }

        // if server is configured, check security domain selection
        if (state == 1) {
            String select;
            try {
                select = cs.getString("securitydomain.select");
            } catch (EBaseException e) {
                logger.error("CAApplication: " + e.getMessage(), e);
                throw new RuntimeException(e);
            }

            // if it's a new security domain, register the service
            if ("new".equals(select)) {
                classes.add(SecurityDomainService.class);
                classes.add(SecurityDomainHostService.class);
            }
        }

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
