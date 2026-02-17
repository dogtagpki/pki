package org.dogtagpki.est.quarkus;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * EST configuration using Quarkus MicroProfile Config.
 * Replaces properties file loading from ESTEngine.
 *
 * @author Claude Code (Quarkus PoC)
 */
@ConfigMapping(prefix = "est")
public interface ESTConfig {

    /**
     * EST instance ID (default: ROOT)
     */
    @WithDefault("ROOT")
    String instanceId();

    /**
     * EST configuration directory
     */
    @WithDefault("/etc/pki/pki-tomcat/est")
    String configDir();

    /**
     * Backend configuration
     */
    BackendConfig backend();

    /**
     * Request authorizer configuration
     */
    AuthorizerConfig authorizer();

    /**
     * Realm configuration
     */
    RealmConfig realm();

    interface BackendConfig {
        /**
         * Backend configuration file path
         */
        String configFile();
    }

    interface AuthorizerConfig {
        /**
         * Authorizer configuration file path
         */
        String configFile();
    }

    interface RealmConfig {
        /**
         * Realm configuration file path
         */
        String configFile();
    }
}
