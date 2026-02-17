package org.dogtagpki.est.quarkus;

import java.io.File;
import java.io.FileReader;
import java.util.Properties;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;

import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.QuarkusInstanceConfig;

import org.dogtagpki.est.ESTBackend;
import org.dogtagpki.est.ESTBackendConfig;
import org.dogtagpki.est.ESTRequestAuthorizer;
import org.dogtagpki.est.ESTRequestAuthorizerConfig;

/**
 * EST Engine for Quarkus - manages the EST backend and authorizer.
 *
 * Uses CDI lifecycle and MicroProfile Config instead of Tomcat's
 * ServletContextListener. Delegates to real PKI EST backend classes
 * (ESTBackend, ESTRequestAuthorizer) from pki-est.
 *
 * @author Fraser Tweedale (original)
 */
@ApplicationScoped
public class ESTEngineQuarkus {

    private static final Logger logger = LoggerFactory.getLogger(ESTEngineQuarkus.class);

    @Inject
    ESTConfig config;

    private ESTBackend backend;
    private ESTRequestAuthorizer requestAuthorizer;
    private ESTRealmQuarkus realm;

    void onStart(@Observes StartupEvent event) {
        try {
            start();
        } catch (Throwable e) {
            logger.error("Failed to start EST engine: " + e.getMessage(), e);
            throw new RuntimeException("Failed to start EST engine", e);
        }
    }

    void onStop(@Observes ShutdownEvent event) {
        try {
            stop();
        } catch (Throwable e) {
            logger.error("Failed to stop EST engine: " + e.getMessage(), e);
        }
    }

    private void start() throws Throwable {
        logger.info("Starting EST engine (Quarkus)");
        logger.info("EST instance ID: {}", config.instanceId());
        logger.info("EST configuration directory: {}", config.configDir());

        // Configure InstanceConfig for Quarkus deployment
        String instanceDir = System.getProperty(QuarkusInstanceConfig.INSTANCE_DIR_PROPERTY);
        if (instanceDir == null) {
            // Fall back to config dir parent if pki.instance.dir not set
            logger.info("EST: pki.instance.dir not set, using config-based paths");
        } else {
            CMS.setInstanceConfig(new QuarkusInstanceConfig());
            logger.info("EST: Using Quarkus instance dir: {}", instanceDir);
        }

        initBackend(config.backend().configFile());
        initRequestAuthorizer(config.authorizer().configFile());
        initRealm(config.realm().configFile());

        logger.info("EST engine started successfully");
    }

    private void stop() throws Throwable {
        logger.info("Stopping EST engine");

        if (backend != null) {
            backend.stop();
        }
        if (requestAuthorizer != null) {
            requestAuthorizer.stop();
        }
        if (realm != null) {
            realm.stop();
        }

        logger.info("EST engine stopped");
    }

    private void initBackend(String filename) throws Throwable {
        File file = new File(filename);
        if (!file.exists()) {
            throw new RuntimeException("Missing backend configuration file: " + filename);
        }

        logger.info("Loading EST backend config from {}", filename);
        Properties props = new Properties();
        try (FileReader reader = new FileReader(file)) {
            props.load(reader);
        }
        ESTBackendConfig backendConfig = ESTBackendConfig.fromProperties(props);

        logger.info("Initializing EST backend");
        String className = backendConfig.getClassName();
        @SuppressWarnings("unchecked")
        Class<ESTBackend> backendClass = (Class<ESTBackend>) Class.forName(className);

        backend = backendClass.getDeclaredConstructor().newInstance();
        backend.setConfig(backendConfig);
        backend.start();

        logger.info("EST backend initialized: {}", className);
    }

    private void initRequestAuthorizer(String filename) throws Throwable {
        File file = new File(filename);
        if (!file.exists()) {
            throw new RuntimeException("Missing request authorizer configuration file: " + filename);
        }

        logger.info("Loading EST request authorizer config from {}", filename);
        Properties props = new Properties();
        try (FileReader reader = new FileReader(file)) {
            props.load(reader);
        }
        ESTRequestAuthorizerConfig authorizerConfig = ESTRequestAuthorizerConfig.fromProperties(props);

        logger.info("Initializing EST request authorizer");
        String className = authorizerConfig.getClassName();
        @SuppressWarnings("unchecked")
        Class<ESTRequestAuthorizer> clazz = (Class<ESTRequestAuthorizer>) Class.forName(className);

        requestAuthorizer = clazz.getDeclaredConstructor().newInstance();
        requestAuthorizer.setConfig(authorizerConfig);
        requestAuthorizer.start();

        logger.info("EST request authorizer initialized: {}", className);
    }

    private void initRealm(String filename) throws Throwable {
        File realmConfigFile = new File(filename);

        if (realmConfigFile.exists()) {
            logger.info("Loading EST realm config from {}", realmConfigFile);
            Properties props = new Properties();
            try (FileReader reader = new FileReader(realmConfigFile)) {
                props.load(reader);
            }
            realm = new ESTRealmQuarkus(props);
        } else {
            logger.info("No realm config file found, using default realm");
            realm = new ESTRealmQuarkus();
        }

        realm.start();
        logger.info("EST realm initialized");
    }

    public ESTBackend getBackend() {
        return backend;
    }

    public ESTRequestAuthorizer getRequestAuthorizer() {
        return requestAuthorizer;
    }

    public ESTRealmQuarkus getRealm() {
        return realm;
    }
}
