package com.netscape.cms.tomcat;

import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.Realm;
import org.apache.catalina.Wrapper;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.SecurityConstraint;
import org.ietf.jgss.GSSContext;

/**
 * @author Endi S. Dewata
 */
public class ProxyRealm implements Realm {

    public static Map<String, ProxyRealm> proxies = new HashMap<String, ProxyRealm>();

    public Container container;
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
            proxies.put(context.getBaseName(), this);
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

        proxy.setRealm(realm);
    }

    @Override
    public Principal authenticate(String username, String password) {
        return realm.authenticate(username, password);
    }

    @Override
    public Principal authenticate(X509Certificate certs[]) {
        return realm.authenticate(certs);
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
        return realm.authenticate(username, digest, nonce, nc, cnonce, qop, realmName, md5a2);
    }

    @Override
    public Principal authenticate(GSSContext gssContext, boolean storeCreds) {
        return realm.authenticate(gssContext, storeCreds);
    }

    @Override
    public boolean hasResourcePermission(
            Request request,
            Response response,
            SecurityConstraint[] constraints,
            Context context
    ) throws IOException {
        return realm.hasResourcePermission(request, response, constraints, context);
    }

    @Override
    public String getInfo() {
        return realm.getInfo();
    }

    @Override
    public void backgroundProcess() {
        realm.backgroundProcess();
    }

    @Override
    public SecurityConstraint[] findSecurityConstraints(Request request, Context context) {
        return realm.findSecurityConstraints(request, context);
    }

    @Override
    public boolean hasRole(Wrapper wrapper, Principal principal, String role) {
        return realm.hasRole(wrapper, principal, role);
    }

    @Override
    public boolean hasUserDataPermission(
            Request request,
            Response response,
            SecurityConstraint[] constraint
    ) throws IOException {
        return realm.hasUserDataPermission(request,  response, constraint);
    }

    @Override
    public void addPropertyChangeListener(PropertyChangeListener listener) {
        realm.addPropertyChangeListener(listener);
    }

    @Override
    public void removePropertyChangeListener(PropertyChangeListener listener) {
        realm.removePropertyChangeListener(listener);
    }
}
