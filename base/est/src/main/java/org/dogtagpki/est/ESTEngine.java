package org.dogtagpki.est;

import java.io.File;
import java.io.FileReader;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

import org.apache.catalina.Realm;
import org.apache.catalina.realm.RealmBase;
import org.apache.catalina.util.LifecycleBase;
import org.apache.tomcat.util.IntrospectionUtils;

import com.netscape.cms.realm.RealmCommon;
import com.netscape.cms.realm.RealmConfig;
import com.netscape.cms.tomcat.ProxyRealm;
import com.netscape.cmscore.apps.CMS;


/**
 * Engine that manages the EST backend(s) according to configuration.
 *
 * @author Fraser Tweedale
 */
public class ESTEngine {

    private static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ESTEngine.class);

    private static ESTEngine INSTANCE;

    private String id;

    private Realm realm;

    private ESTBackend backend;
    private ESTRequestAuthorizer requestAuthorizer;

    public static ESTEngine getInstance() {
        return INSTANCE;
    }

    public ESTEngine() {
        INSTANCE = this;
    }

    public ESTBackend getBackend() {
        return backend;
    }

    public ESTRequestAuthorizer getRequestAuthorizer() {
        return requestAuthorizer;
    }

    public void start(String contextPath) throws Throwable {
        logger.info("Starting EST engine");

        String contextPathDirName = "".equals(contextPath) ? "ROOT" : contextPath.substring(1);
        String instanceDir = CMS.getInstanceDir();
        String serverConfDir = instanceDir + File.separator + "conf";
        String estConfDir = serverConfDir + File.separator + contextPathDirName;

        logger.info("EST configuration directory: " + estConfDir);

        loadLoggingProperties(estConfDir + File.separator + "logging.properties");
        initBackend(estConfDir + File.separator + "backend.conf");
        initRequestAuthorizer(estConfDir + File.separator + "authorizer.conf");
        initRealm(estConfDir + File.separator + "realm.conf");

        logger.info("EST engine started");
    }

    public void stop() throws Throwable {
        logger.info("Stopping EST engine");

        if (backend != null) {
            backend.stop();
        }
        if (requestAuthorizer != null) {
            requestAuthorizer.stop();
        }

        if (realm != null) {
            if (realm instanceof RealmCommon) {
                ((RealmCommon) realm).stop();
            } else if (realm instanceof LifecycleBase) {
                ((LifecycleBase) realm).stop();
            }
        }
        logger.info("EST engine stopped");
    }

    public void loadLoggingProperties(String loggingProperties) throws Exception {

        File file = new File(loggingProperties);
        if (!file.exists()) return;

        logger.info("Loading " + loggingProperties);
        Properties properties = new Properties();
        properties.load(new FileReader(file));

        for (String key : properties.stringPropertyNames()) {
            String value = properties.getProperty(key);

            logger.info("- " + key + ": " + value);
            if (!key.endsWith(".level")) continue;

            String loggerName = key.substring(0, key.length() - 6);
            java.util.logging.Level level = java.util.logging.Level.parse(value);

            Logger.getLogger(loggerName).setLevel(level);
        }
    }

    private void initBackend(String filename) throws Throwable {
        File file = new File(filename);
        if (!file.exists()) {
            throw new RuntimeException("Missing backend configuration file " + filename);
        }

        logger.info("Loading EST backend config from " + filename);
        Properties props = new Properties();
        try (FileReader reader = new FileReader(file)) {
            props.load(reader);
        }
        ESTBackendConfig config = ESTBackendConfig.fromProperties(props);

        logger.info("Initializing EST backend");

        String className = config.getClassName();
        Class<ESTBackend> backendClass = (Class<ESTBackend>) Class.forName(className);

        backend = backendClass.getDeclaredConstructor().newInstance();
        backend.setConfig(config);
        backend.start();
    }

    private void initRequestAuthorizer(String filename) throws Throwable {
        File file = new File(filename);
        if (!file.exists()) {
            throw new RuntimeException("Missing request authorizer configuration file " + filename);
        }

        logger.info("Loading EST request authorizer config from " + filename);
        Properties props = new Properties();
        try (FileReader reader = new FileReader(file)) {
            props.load(reader);
        }
        ESTRequestAuthorizerConfig config = ESTRequestAuthorizerConfig.fromProperties(props);

        logger.info("Initializing EST request authorizer");

        String className = config.getClassName();
        Class<ESTRequestAuthorizer> clazz = (Class<ESTRequestAuthorizer>) Class.forName(className);

        requestAuthorizer = clazz.getDeclaredConstructor().newInstance();
        requestAuthorizer.setConfig(config);
        requestAuthorizer.start();
    }

    private void initRealm(String filename) throws Throwable {
        RealmConfig realmConfig = null;
        File realmConfigFile = new File(filename);

        if (realmConfigFile.exists()) {
            logger.info("Loading EST realm config from " + realmConfigFile);
            Properties props = new Properties();
            try (FileReader reader = new FileReader(realmConfigFile)) {
                props.load(reader);
            }
            realmConfig = RealmConfig.fromProperties(props);

        } else {
            logger.info("Loading default realm config");
            realmConfig = new RealmConfig();
        }

        logger.info("Initializing EST realm");
        String className = realmConfig.getClassName();
        if (className == null) {
            throw new RuntimeException("File " + filename + " misses 'class' property");
        }
        Class<Realm> realmClass = (Class<Realm>) Class.forName(className);
        realm = realmClass.getDeclaredConstructor().newInstance();

        // registerRealm() does some required setup for RealmBase instances.
        // So we have to invoke registerRealm() /before/ start().
        ProxyRealm.registerRealm(id, realm);

        // configure realm
        if (realm instanceof RealmCommon) {
            ((RealmCommon) realm).setConfig(realmConfig);
        } else if (realm instanceof RealmBase) {
            // RealmBase subclasses are configured by setting properties
            // via introspection.
            for (Map.Entry<String, String> entry : realmConfig.getParameters().entrySet()) {
                boolean result =
                    IntrospectionUtils.setProperty(realm, entry.getKey(), entry.getValue());
                if (!result) {
                    throw new RuntimeException(
                        "Failed to set Realm property '" + entry.getKey() + "'.");
                }
            }
        }

        // start realm
        if (realm instanceof RealmCommon) {
            ((RealmCommon) realm).start();
        } else if (realm instanceof LifecycleBase) {
            ((LifecycleBase) realm).start();
        }
    }

    public void setId(String id) {
        this.id = id;
    }

}
