package org.dogtagpki.est;

import java.io.File;
import java.io.FileReader;
import java.util.Properties;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

/**
 * Engine that manages the EST backend(s) according to configuration.
 *
 * @author Fraser Tweedale
 */
@WebListener
public class ESTEngine implements ServletContextListener {

    private static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ESTEngine.class);

    private static ESTEngine INSTANCE;

    private ESTBackend backend;

    public static ESTEngine getInstance() {
        return INSTANCE;
    }

    public ESTEngine() {
        INSTANCE = this;
    }

    public ESTBackend getBackend() {
        return backend;
    }

    public void start(String contextPath) throws Throwable {
        logger.info("Starting EST engine");

        String contextPathDirName = "".equals(contextPath) ? "ROOT" : contextPath.substring(1);
        String catalinaBase = System.getProperty("catalina.base");
        String serverConfDir = catalinaBase + File.separator + "conf";
        String estConfDir = serverConfDir + File.separator + contextPathDirName;

        logger.info("EST configuration directory: " + estConfDir);

        initBackend(estConfDir + File.separator + "backend.conf");

        logger.info("EST engine started");
    }

    public void stop() throws Throwable {
        logger.info("Stopping EST engine");

        if (backend != null) {
            backend.stop();
        }

        logger.info("EST engine stopped");
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        try {
            start(event.getServletContext().getContextPath());
        } catch (Throwable e) {
            logger.error("Unable to start EST engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to start EST engine: " + e.getMessage(), e);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        try {
            stop();
        } catch (Throwable e) {
            logger.error("Unable to stop EST engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to stop EST engine: " + e.getMessage(), e);
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

}
