//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.est;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.stream.Collectors;

public class ESTRequestAuthorizerConfig {

    private String className = null;

    private Map<String, String> parameters = new LinkedHashMap<>();

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters.clear();
        this.parameters.putAll(parameters);
    }

    public Collection<String> getParameterNames() {
        return parameters.keySet();
    }

    public Collection<String> getParameterNames(String parent) {

        String prefix = parent + ".";
        int length = prefix.length();

        return parameters.keySet().stream()
            .filter(name -> name.startsWith(prefix))
            .map(name -> name.substring(length))
            .collect(Collectors.toSet());
    }

    public String getParameter(String name) {
        return parameters.get(name);
    }

    public void setParameter(String name, String value) {
        parameters.put(name, value);
    }

    public String removeParameter(String name) {
        return parameters.remove(name);
    }

    public static ESTRequestAuthorizerConfig fromProperties(Properties props) throws Exception {

        ESTRequestAuthorizerConfig config = new ESTRequestAuthorizerConfig();

        for (Entry<Object, Object> entry : props.entrySet()) {

            String key = entry.getKey().toString();
            String value = entry.getValue().toString();

            if (key.equals("class")) {
                config.setClassName(value);
            } else {
                config.setParameter(key, value);
            }
        }

        if (config.getClassName() == null) {
            throw new RuntimeException("ESTRequestAuthorizerConfig: missing 'class' property");
        }

        return config;
    }

}
