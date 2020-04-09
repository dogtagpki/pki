//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Monitor the file for configuration changes.
 */
class ACMEEngineConfigFileSource
        extends ACMEEngineConfigSource
        implements Runnable {

    static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEEngine.class);

    String filename;
    Thread monitorThread = null;

    // cached config values, so we only send values that actually changed
    Optional<Boolean> cacheEnabled = Optional.empty();

    public void init(
            Properties cfg,
            Consumer<Boolean> setEnabled)
            throws Exception {
        init(setEnabled);

        filename = cfg.getProperty("engine.filename");
        if (null == filename) {
            throw new IllegalArgumentException("'engine.filename' parameter must not be null");
        }

        // initial load
        loadFile();

        // start file monitor thread
        monitorThread = new Thread(this, "ACMEEngineConfigFileSource");
        monitorThread.start();
    }

    void loadFile() throws IOException {
        // default values
        Boolean enabled = true;

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
        }

        // send changed values and update cache
        Optional<Boolean> v = Optional.of(enabled);
        if (!cacheEnabled.equals(v)) {
            setEnabled.accept(enabled);
            cacheEnabled = v;
        }
    }

    public void run() {

        final Path path = FileSystems.getDefault().getPath(filename);

        try (WatchService watchService = FileSystems.getDefault().newWatchService()) {
            // You can only watch a directory, not a file.  So we must
            // watch the parent dir and check the event is for the file.
            path.getParent().register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);
            while (true) {
                WatchKey wk = watchService.take();
                for (WatchEvent<?> event : wk.pollEvents()) {
                    if (event.kind() == StandardWatchEventKinds.ENTRY_MODIFY) {
                        if (((Path) event.context()).endsWith(path.getFileName())) {
                            loadFile();
                        }
                    }
                }

                if (!wk.reset()) {
                    // watch key could not be reset; break loop
                    break;
                }
            }
        } catch (InterruptedException e) {
            // probably due to shutdown()
            logger.info("ACMEEngineConfigSource: file monitoring interrupted");
        } catch (Throwable e) {
            logger.error(
                "ACMEEngineConfigFileSource: caught exception while monitoring file",
                e
            );
        }
        logger.info("ACMEConfigFileSource: watch thread exiting");
        monitorThread = null;

    }

    @Override
    public void shutdown() {
        if (monitorThread != null) {
            logger.info("ACMEEngineConfigSource.shutdown(): interrupting monitor thread");
            monitorThread.interrupt();
            monitorThread = null;
        }
    }
}
