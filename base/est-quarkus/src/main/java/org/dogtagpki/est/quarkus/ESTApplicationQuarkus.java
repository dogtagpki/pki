package org.dogtagpki.est.quarkus;

import java.util.LinkedHashSet;
import java.util.Set;

import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * EST JAX-RS Application for Quarkus.
 *
 * Migrated from javax.ws.rs to jakarta.ws.rs namespace.
 * Quarkus automatically discovers JAX-RS resources, but we keep
 * this Application class for explicit configuration and filters.
 *
 * @author Fraser Tweedale (original)
 * @author Claude Code (Quarkus migration)
 */
@ApplicationPath("/rest")
public class ESTApplicationQuarkus extends Application {

    private static final Logger logger = LoggerFactory.getLogger(ESTApplicationQuarkus.class);

    private Set<Class<?>> classes = new LinkedHashSet<>();
    private Set<Object> singletons = new LinkedHashSet<>();

    public ESTApplicationQuarkus() {
        logger.info("Initializing EST Application (Quarkus)");

        // Register REST resources
        classes.add(ESTFrontendQuarkus.class);

        // Register exception mapper
        classes.add(PKIExceptionMapperQuarkus.class);

        // Register filters
        singletons.add(new HandleBadAcceptHeaderRequestFilterQuarkus());
        singletons.add(new ReformatContentTypeResponseFilterQuarkus());

        logger.info("EST Application initialized with {} resources and {} filters",
                    classes.size(), singletons.size());
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
