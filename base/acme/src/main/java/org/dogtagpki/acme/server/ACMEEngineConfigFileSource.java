//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.Optional;
import java.util.Properties;

/**
 * Monitor the file for configuration changes.
 */
class ACMEEngineConfigFileSource
        extends ACMEEngineConfigSource
        implements Runnable {

    static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEEngine.class);

    String filename;
    boolean monitor = true;
    Thread monitorThread = null;

    // cached config values, so we only send values that actually changed
    Optional<Boolean> cacheEnabled = Optional.empty();
    Optional<Boolean> cacheWildcard = Optional.empty();

    public void init(Properties cfg) throws Exception {

        filename = cfg.getProperty("engine.filename");
        if (null == filename) {
            throw new IllegalArgumentException("'engine.filename' parameter must not be null");
        }

        // initial load
        loadFile();

        // start file monitor thread
        monitor = true;  // in case shutdown() was previously called
        monitorThread = new Thread(this, "ACMEEngineConfigFileSource");
        monitorThread.start();
    }

    void loadFile() throws IOException {
        // default values
        Boolean enabled = true;
        Boolean wildcard = true;

        // read values
        File f = new File(filename);
        if (f.exists()) {
            Properties props = new Properties();
            try (FileReader reader = new FileReader(f)) {
                props.load(reader);
            }

            String s = props.getProperty("enabled");
            if (s != null) {
                enabled = !("0".equals(s) || "false".equalsIgnoreCase(s));
            }

            s = props.getProperty("wildcard");
            if (s != null) {
                wildcard = !("0".equals(s) || "false".equalsIgnoreCase(s));
            }
        }

        // send changed values and update cache
        Optional<Boolean> v = Optional.of(enabled);
        if (!cacheEnabled.equals(v)) {
            enabledConsumer.accept(enabled);
            cacheEnabled = v;
        }

        v = Optional.of(wildcard);
        if (!cacheWildcard.equals(v)) {
            wildcardConsumer.accept(wildcard);
            cacheWildcard = v;
        }
    }

    public void run() {

        final Path path = FileSystems.getDefault().getPath(filename);

        // how long to sleep before retrying
        int delay_ms = 0;

        while (monitor) {

            if (delay_ms > 0) {
                try {
                    logger.info("ACMEEngineConfigSource: sleeping for " + delay_ms + "ms");
                    Thread.sleep(delay_ms);
                } catch (InterruptedException e) {
                    // no big deal
                }

                // We looped due to an exception.  It is possible that the file
                // changed, and that we were unable to read it, but after the sleep
                // it might be OK.  So let's try and read it, but ignore failures.
                try {
                    loadFile();
                } catch (Throwable e) {
                    // log warning then move on
                    logger.warn(
                        "ACMEEngineConfigSource: Unable to load " + filename
                        + ": " + e.getMessage());
                }

            }

            try (WatchService watchService = FileSystems.getDefault().newWatchService()) {
                // You can only watch a directory, not a file.  So we must
                // watch the parent dir and check the event is for the file.
                path.getParent().register(
                    watchService,
                    StandardWatchEventKinds.ENTRY_MODIFY,   // ordinary writes
                    StandardWatchEventKinds.ENTRY_CREATE    // rename to target file
                );

                // so far so good; reset the delay
                logger.info("ACMEEngineConfigSource: watching " + filename);
                delay_ms = 0;  // reset the delay

                while (true) {
                    logger.debug("ACMEEngineConfigSource: something happened");
                    WatchKey wk = watchService.take();
                    for (WatchEvent<?> event : wk.pollEvents()) {

                        if (
                            (
                                event.kind() == StandardWatchEventKinds.ENTRY_MODIFY
                                || event.kind() == StandardWatchEventKinds.ENTRY_CREATE
                            )
                            && event.context() instanceof Path
                            && ((Path) event.context()).endsWith(path.getFileName())
                        ) {
                            logger.debug("ACMEEngineConfigSource: file modified");
                            // sleep for a moment before reading file; this seems
                            // to avoid a race situation observed with vi/vim.
                            Thread.sleep(1000);
                            loadFile();
                        }
                    }

                    if (!wk.reset()) {
                        // watch key could not be reset; break inner loop
                        logger.warn("ACMEEngineConfigSource: watch key could not be reset");
                        break;
                    }
                }
            } catch (InterruptedException e) {
                // probably due to shutdown(), in which case monitor == false
                // and the outer while loop will terminate
                logger.info("ACMEEngineConfigSource: file monitoring interrupted");
            } catch (Throwable e) {
                logger.error(
                    "ACMEEngineConfigFileSource: caught exception while monitoring file",
                    e
                );
            }

            // Something went wrong, or we were interrupted by shutdown().
            // Set or increase the delay, then loop back and either try
            // again, or in case of shutdown() the loop condition fails.
            if (delay_ms == 0) {
                delay_ms = 1000;
            } else {
                // double; clamp at 5 mins
                delay_ms = Math.min(delay_ms * 2, 5 * 60 * 1000);
            }

        }

        logger.info("ACMEConfigFileSource: watch thread exiting");
        monitorThread = null;

    }

    @Override
    public void shutdown() {
        monitor = false;

        if (monitorThread != null) {
            logger.info("ACMEEngineConfigSource.shutdown(): interrupting monitor thread");
            monitorThread.interrupt();
            monitorThread = null;
        }
    }
}
