//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.scheduler;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * @author Endi S. Dewata
 */
public class ACMEScheduler {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEScheduler.class);

    private ACMESchedulerConfig config;

    private ScheduledExecutorService executorService;

    public ACMESchedulerConfig getConfig() {
        return config;
    }

    public void setConfig(ACMESchedulerConfig config) {
        this.config = config;
    }

    public void init() throws Exception {

        logger.info("Initializing ACME scheduler");

        Integer threads = config.getThreads();
        if (threads == null) threads = 1;
        logger.info("- threads: " + threads);

        // https://docs.oracle.com/javase/8/docs/api/java/util/concurrent/ScheduledExecutorService.html
        executorService = Executors.newScheduledThreadPool(threads);

        for (String name : config.getTaskNames()) {

            logger.info("Initializing " + name + " task");

            ACMETaskConfig taskConfig = config.getTask(name);

            String className = taskConfig.getClassName();
            Class<ACMETask> taskClass = (Class<ACMETask>) Class.forName(className);

            ACMETask task = taskClass.newInstance();
            task.setConfig(taskConfig);
            task.init();

            Runnable runnable = new Runnable() {
                @Override
                public void run() {
                    try {
                        task.run();
                    } catch (Exception e) {
                        logger.error("Unable to run " + name + " task");
                        throw new RuntimeException(e);
                    }
                }
            };

            Integer initialDelay = taskConfig.getInitialDelay();
            if (initialDelay == null) initialDelay = 0;
            logger.info("- initial delay: " + initialDelay);

            Integer delay = taskConfig.getDelay();
            logger.info("- delay: " + delay);

            Integer interval = taskConfig.getInterval();
            logger.info("- interval: " + interval);

            TimeUnit unit = taskConfig.getUnit();
            if (unit == null) unit = TimeUnit.MINUTES;
            logger.info("- unit: " + unit);

            if (delay != null) { // recurring task with fixed delay
                executorService.scheduleWithFixedDelay(runnable, initialDelay, delay, unit);

            } else if (interval != null) { // recurring task with fixed rate
                executorService.scheduleAtFixedRate(runnable, initialDelay, interval, unit);

            } else { // one-off task
                executorService.schedule(runnable, initialDelay, unit);
            }
        }
    }

    public void shutdown() throws Exception {
        executorService.shutdown();
    }
}
