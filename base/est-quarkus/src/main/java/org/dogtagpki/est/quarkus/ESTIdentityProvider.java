package org.dogtagpki.est.quarkus;

import java.security.cert.X509Certificate;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.realm.PKIPrincipalCore;

import org.dogtagpki.server.quarkus.PKIIdentityProvider;

/**
 * EST Identity Provider for Quarkus.
 *
 * Extends the shared PKIIdentityProvider to provide EST-specific
 * certificate authentication. In the current implementation, this
 * performs basic certificate validation and assigns the "est-client"
 * role. When a realm configuration is present, this can integrate
 * with LDAP/database for user lookup and role assignment.
 *
 * @author Fraser Tweedale (original)
 */
@ApplicationScoped
public class ESTIdentityProvider extends PKIIdentityProvider {

    private static final Logger logger = LoggerFactory.getLogger(ESTIdentityProvider.class);

    @Inject
    ESTEngineQuarkus engine;

    @Override
    protected PKIPrincipalCore authenticateCertificate(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();
        String cn = extractCN(dn);
        String principalName = cn != null ? cn : dn;

        logger.info("EST: Authenticated certificate for: {}", principalName);

        // If a realm is configured, use it to look up user roles.
        // For now, assign default EST client role.
        ESTRealmQuarkus realm = engine.getRealm();
        if (realm != null) {
            logger.debug("EST: Realm class: {}", realm.getClassName());
        }

        return new PKIPrincipalCore(principalName, null, java.util.List.of("est-client"));
    }
}
