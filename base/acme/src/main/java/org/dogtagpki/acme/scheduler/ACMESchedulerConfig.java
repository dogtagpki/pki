//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.scheduler;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ACMESchedulerConfig {

    private Integer threads;
    private Map<String, ACMETaskConfig> tasks = new HashMap<>();

    public Integer getThreads() {
        return threads;
    }

    public void setThreads(Integer threads) {
        this.threads = threads;
    }

    public ACMETaskConfig getTask(String name) {
        return tasks.get(name);
    }

    public void addTask(String name, ACMETaskConfig taskConfig) {
        tasks.put(name, taskConfig);
    }

    @JsonIgnore
    public Collection<String> getTaskNames() {
        return tasks.keySet();
    }

    public Map<String, ACMETaskConfig> getTasks() {
        return tasks;
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static ACMESchedulerConfig fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, ACMESchedulerConfig.class);
    }

    public static ACMESchedulerConfig fromProperties(Properties props) throws Exception {

        ACMESchedulerConfig schedulerConfig = new ACMESchedulerConfig();

        for (Entry<Object, Object> entry : props.entrySet()) {

            String key = entry.getKey().toString();
            String value = entry.getValue().toString();

            if (key.equals("threads")) {
                schedulerConfig.setThreads(new Integer(value));
                continue;
            }

            // split key by dots
            String[] parts = key.split("\\.");
            String name = parts[0];
            String param = parts[1];

            ACMETaskConfig taskConfig = schedulerConfig.getTask(name);

            if (taskConfig == null) {
                taskConfig = new ACMETaskConfig();
                schedulerConfig.addTask(name, taskConfig);
            }

            if (param.equals("class")) {
                taskConfig.setClassName(value);

            } else if (param.equals("initialDelay")) {
                taskConfig.setInitialDelay(new Integer(value));

            } else if (param.equals("delay")) {
                taskConfig.setDelay(new Integer(value));

            } else if (param.equals("interval")) {
                taskConfig.setInterval(new Integer(value));

            } else if (param.equals("unit")) {
                taskConfig.setUnit(TimeUnit.valueOf(value));

            } else {
                taskConfig.setParameter(param, value);
            }
        }

        return schedulerConfig;
    }

    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {

        ACMESchedulerConfig schedulerConfig = new ACMESchedulerConfig();
        schedulerConfig.setThreads(1);

        ACMETaskConfig taskConfig = new ACMETaskConfig();
        taskConfig.setClassName(ACMETask.class.getName());
        taskConfig.setInitialDelay(5);
        taskConfig.setDelay(5);
        taskConfig.setUnit(TimeUnit.MINUTES);

        schedulerConfig.addTask("task", taskConfig);

        System.out.println(schedulerConfig);
    }
}
