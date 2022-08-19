package org.dogtagpki.est;

import java.io.File;
import java.io.FileReader;
import java.util.Properties;

/**
 * Engine that manages the EST backend(s) according to configuration.
 *
 * @author Fraser Tweedale
 */
public class ESTEngine {

    private static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ESTEngine.class);

    private static ESTEngine INSTANCE;

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
        String catalinaBase = System.getProperty("catalina.base");
        String serverConfDir = catalinaBase + File.separator + "conf";
        String estConfDir = serverConfDir + File.separator + contextPathDirName;

        logger.info("EST configuration directory: " + estConfDir);

        initBackend(estConfDir + File.separator + "backend.conf");
        initRequestAuthorizer(estConfDir + File.separator + "authorizer.conf");

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

        logger.info("EST engine stopped");
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

}
