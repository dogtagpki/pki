package com.netscape.cms.tomcat;

import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;
import javax.ws.rs.ServiceUnavailableException;

import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.CredentialHandler;
import org.apache.catalina.Realm;
import org.apache.catalina.Wrapper;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.realm.RealmBase;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.ietf.jgss.GSSContext;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.dbs.certdb.CertId;

/**
 * @author Endi S. Dewata
 */
public class ProxyRealm implements Realm {

    private static Logger logger = LoggerFactory.getLogger(ProxyRealm.class);

    public static Map<String, ProxyRealm> proxies = new HashMap<>();

    public Container container;
    public String name;
    public Realm realm;

    public ProxyRealm() {
    }

    @Override
    public Container getContainer() {
        return container;
    }

    @Override
    public void setContainer(Container container) {
        this.container = container;
        if (container instanceof Context) {
            Context context = (Context)container;
            String contextName = context.getBaseName();
            name = contextName.toUpperCase();
            proxies.put(contextName, this);
        }
    }

    public Realm getRealm() {
        return realm;
    }

    public void setRealm(Realm realm) {
        this.realm = realm;
        realm.setContainer(container);
    }

    public static void registerRealm(String contextName, Realm realm) {
        ProxyRealm proxy = proxies.get(contextName);
        if (proxy == null) return;

        if (realm instanceof RealmBase) {
            // RealmBase instances from Tomcat require Container to be set.
            // Propagate it from the ProxyRealm to the RealmBase instance.
            ((RealmBase) realm).setContainer(proxy.getContainer());
        }

        proxy.setRealm(realm);
    }

    public void validateRealm() {
        if (realm != null) return;

        String message = String.format(
                "%s subsystem unavailable. Check %s debug log.",
                name,
                name);

        logger.error("ProxyRealm: " + message);
        throw new ServiceUnavailableException(message);
    }
    @Override
    public Principal authenticate(String username) {
        validateRealm();
        logger.info("ProxyRealm: Authenticating user " + username);
        try {
            Principal principal = realm.authenticate(username);
            logger.info("ProxyRealm: Principal: " + principal);
            return principal;
        } catch (Exception e) {
            logger.error("ProxyRealm: Unable to authenticate " + username + ": " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public Principal authenticate(String username, String password) {
        validateRealm();
        logger.info("ProxyRealm: Authenticating user " + username + " with password");
        try {
            Principal principal = realm.authenticate(username, password);
            logger.info("ProxyRealm: Principal: " + principal);
            return principal;
        } catch (Exception e) {
            logger.error("ProxyRealm: Unable to authenticate " + username + " with password: " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public Principal authenticate(X509Certificate[] certs) {
        validateRealm();

        logger.info("ProxyRealm: Authenticating certificate chain:");
        for (X509Certificate cert : certs) {
            logger.info("ProxyRealm: - Serial Number: " + new CertId(cert.getSerialNumber()).toHexString());
            logger.info("ProxyRealm:   Subject DN: " + cert.getSubjectX500Principal());
        }

        X500Principal subjectDN;

        try {
            CertificateChain chain = new CertificateChain(certs);
            chain.sort();

            List<X509Certificate> sortedCerts = chain.getCertificates();
            int size = sortedCerts.size();

            X509Certificate userCert = sortedCerts.get(size - 1);
            subjectDN = userCert.getSubjectX500Principal();
            logger.info("ProxyRealm: Authenticating cert " + subjectDN);

        } catch (Exception e) {
            logger.error("ProxyRealm: Unable to sort certificates: " + e.getMessage(), e);
            throw new RuntimeException("Unable to sort certificates: " + e.getMessage(), e);
        }

        try {
            Principal principal = realm.authenticate(certs);
            logger.info("ProxyRealm: Principal: " + principal);
            return principal;
        } catch (Exception e) {
            logger.error("ProxyRealm: Unable to authenticate " + subjectDN + ": " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public Principal authenticate(
            String username,
            String digest,
            String nonce,
            String nc,
            String cnonce,
            String qop,
            String realmName,
            String md5a2
    ) {
        validateRealm();
        logger.info("ProxyRealm: Authenticating user " + username + " for realm "+ realmName);
        try {
            Principal principal = realm.authenticate(username, digest, nonce, nc, cnonce, qop, realmName, md5a2);
            logger.info("ProxyRealm: Principal: " + principal);
            return principal;
        } catch (Exception e) {
            logger.error("ProxyRealm: Unable to authenticate " + username + " for realm " + realmName + ": " + e.getMessage(), e);
            throw e;
        }
}

    @Override
    public Principal authenticate(GSSContext gssContext, boolean storeCreds) {
        validateRealm();
        logger.info("ProxyRealm: Authenticating GSS context " + gssContext);
        try {
            Principal principal = realm.authenticate(gssContext, storeCreds);
            logger.info("ProxyRealm: Principal: " + principal);
            return principal;
        } catch (Exception e) {
            logger.error("ProxyRealm: Unable to authenticate " + gssContext + ": " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public boolean hasResourcePermission(
            Request request,
            Response response,
            SecurityConstraint[] constraints,
            Context context
    ) throws IOException {
        validateRealm();
        return realm.hasResourcePermission(request, response, constraints, context);
    }

    @Override
    public void backgroundProcess() {
        validateRealm();
        realm.backgroundProcess();
    }

    @Override
    public SecurityConstraint[] findSecurityConstraints(Request request, Context context) {
        validateRealm();
        return realm.findSecurityConstraints(request, context);
    }

    @Override
    public boolean hasRole(Wrapper wrapper, Principal principal, String role) {
        validateRealm();
        return realm.hasRole(wrapper, principal, role);
    }

    @Override
    public boolean hasUserDataPermission(
            Request request,
            Response response,
            SecurityConstraint[] constraint
    ) throws IOException {
        validateRealm();
        return realm.hasUserDataPermission(request,  response, constraint);
    }

    @Override
    public void addPropertyChangeListener(PropertyChangeListener listener) {
        validateRealm();
        realm.addPropertyChangeListener(listener);
    }

    @Override
    public void removePropertyChangeListener(PropertyChangeListener listener) {
        validateRealm();
        realm.removePropertyChangeListener(listener);
    }

    @Override
    public CredentialHandler getCredentialHandler() {
        validateRealm();
        return realm.getCredentialHandler();
    }

    @Override
    public void setCredentialHandler(CredentialHandler handler) {
        validateRealm();
        realm.setCredentialHandler(handler);
    }

    @Override
    public String[] getRoles(Principal principal) {
        validateRealm();
        return realm.getRoles(principal);
    }

    @Override
    public boolean isAvailable() {
        validateRealm();
        return realm.isAvailable();
    }
}
