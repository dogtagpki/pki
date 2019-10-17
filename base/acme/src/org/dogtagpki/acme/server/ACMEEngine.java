//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.File;
import java.nio.file.Files;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import org.dogtagpki.acme.ACMEMetadata;
import org.dogtagpki.acme.backend.ACMEBackend;
import org.dogtagpki.acme.backend.ACMEBackendConfig;
import org.dogtagpki.acme.database.ACMEDatabase;
import org.dogtagpki.acme.database.ACMEDatabaseConfig;

/**
 * @author Endi S. Dewata
 */
@WebListener
public class ACMEEngine implements ServletContextListener {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEEngine.class);

    public static ACMEEngine INSTANCE;

    private String name;

    private ACMEMetadata metadata;

    private ACMEDatabaseConfig databaseConfig;
    private ACMEDatabase database;

    private ACMEBackendConfig backendConfig;
    private ACMEBackend backend;

    public static ACMEEngine getInstance() {
        return INSTANCE;
    }

    public ACMEEngine() {
        INSTANCE = this;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public ACMEMetadata getMetadata() {
        return metadata;
    }

    public void setMetadata(ACMEMetadata metadata) {
        this.metadata = metadata;
    }

    public ACMEDatabaseConfig getDatabaseConfig() {
        return databaseConfig;
    }

    public void setDatabaseConfig(ACMEDatabaseConfig databaseConfig) {
        this.databaseConfig = databaseConfig;
    }

    public ACMEDatabase getDatabase() {
        return database;
    }

    public void setDatabase(ACMEDatabase database) {
        this.database = database;
    }

    public ACMEBackendConfig getBackendConfig() {
        return backendConfig;
    }

    public void setBackendConfig(ACMEBackendConfig backendConfig) {
        this.backendConfig = backendConfig;
    }

    public ACMEBackend getBackend() {
        return backend;
    }

    public void setBackend(ACMEBackend backend) {
        this.backend = backend;
    }

    public void loadMetadata(String filename) throws Exception {

        File metadataConfigFile = new File(filename);

        if (metadataConfigFile.exists()) {
            logger.info("Loading ACME metadata from " + metadataConfigFile);
            String content = new String(Files.readAllBytes(metadataConfigFile.toPath()));
            metadata = ACMEMetadata.fromJSON(content);

        } else {
            logger.info("Loading default ACME metadata");
            metadata = new ACMEMetadata();
        }

        logger.info("Metadata:\n" + metadata);
    }

    public void loadDatabaseConfig(String filename) throws Exception {

        File databaseConfigFile = new File(filename);

        if (databaseConfigFile.exists()) {
            logger.info("Loading ACME database config from " + databaseConfigFile);
            String content = new String(Files.readAllBytes(databaseConfigFile.toPath()));
            databaseConfig = ACMEDatabaseConfig.fromJSON(content);

        } else {
            logger.info("Loading default ACME database config");
            databaseConfig = new ACMEDatabaseConfig();
        }

        logger.info("Database:\n" + databaseConfig);
    }

    public void initDatabase() throws Exception {

        logger.info("Initializing ACME database");

        String className = databaseConfig.getClassName();
        Class<ACMEDatabase> databaseClass = (Class<ACMEDatabase>) Class.forName(className);

        database = databaseClass.newInstance();
        database.setConfig(databaseConfig);
        database.init();
    }

    public void shutdownDatabase() throws Exception {
        database.close();
    }

    public void loadBackendConfig(String filename) throws Exception {

        File backendConfigFile = new File(filename);

        if (backendConfigFile.exists()) {
            logger.info("Loading ACME backend config from " + backendConfigFile);
            String content = new String(Files.readAllBytes(backendConfigFile.toPath()));
            backendConfig = ACMEBackendConfig.fromJSON(content);

        } else {
            logger.info("Loading default ACME backend config");
            backendConfig = new ACMEBackendConfig();
        }

        logger.info("Backend:\n" + backendConfig);
    }

    public void initBackend() throws Exception {

        logger.info("Initializing ACME backend");

        String className = backendConfig.getClassName();
        Class<ACMEBackend> backendClass = (Class<ACMEBackend>) Class.forName(className);

        backend = backendClass.newInstance();
        backend.setConfig(backendConfig);
        backend.init();
    }

    public void shutdownBackend() throws Exception {
        backend.close();
    }

    public void contextInitialized(ServletContextEvent event) {

        logger.info("Initializing ACME engine");

        String path = event.getServletContext().getContextPath();
        if ("".equals(path)) {
            name = "ROOT";
        } else {
            name = path.substring(1);
        }

        String catalinaBase = System.getProperty("catalina.base");
        String serverConfDir = catalinaBase + File.separator + "conf";
        String acmeConfDir = serverConfDir + File.separator + name;

        logger.info("ACME configuration directory: " + acmeConfDir);

        try {
            loadMetadata(acmeConfDir + File.separator + "metadata.json");

            loadDatabaseConfig(acmeConfDir + File.separator + "database.json");
            initDatabase();

            loadBackendConfig(acmeConfDir + File.separator + "backend.json");
            initBackend();

        } catch (Exception e) {
            logger.error("Unable to initialize ACME engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to initialize ACME engine: " + e.getMessage(), e);
        }
    }

    public void contextDestroyed(ServletContextEvent event) {

        logger.info("Shutting down ACME engine");

        try {
            shutdownBackend();
            shutdownDatabase();

        } catch (Exception e) {
            logger.error("Unable to initialize ACME engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to shutdown ACME engine: " + e.getMessage(), e);
        }
    }
}
