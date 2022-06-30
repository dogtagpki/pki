package org.dogtagpki.est;

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

    public void start() throws Exception {
        logger.info("Starting EST engine");

        // initialize backend
        String className = "org.dogtagpki.est.DogtagRABackend"; // TODO read from config
        Class<ESTBackend> backendClass = (Class<ESTBackend>) Class.forName(className);
        backend = backendClass.getDeclaredConstructor().newInstance();
        backend.start();

        logger.info("EST engine started");
    }

    public void stop() throws Exception {
        logger.info("Stopping EST engine");

        if (backend != null) {
            backend.stop();
        }

        logger.info("EST engine stopped");
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        String path = event.getServletContext().getContextPath();
        /* TODO
        if ("".equals(path)) {
            name = "ROOT";
        } else {
            name = path.substring(1);
        }
        */

        try {
            start();
        } catch (Exception e) {
            logger.error("Unable to start EST engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to start EST engine: " + e.getMessage(), e);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        try {
            stop();
        } catch (Exception e) {
            logger.error("Unable to stop EST engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to stop EST engine: " + e.getMessage(), e);
        }
    }

}
