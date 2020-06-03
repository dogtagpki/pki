//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.issuer;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ACMEIssuerConfig {

    @JsonProperty("class")
    private String className;

    private Map<String, String> parameters = new LinkedHashMap<String, String>();

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

    @JsonIgnore
    public Collection<String> getParameterNames() {
        return parameters.keySet();
    }

    @JsonIgnore
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

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static ACMEIssuerConfig fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, ACMEIssuerConfig.class);
    }

    public static ACMEIssuerConfig fromProperties(Properties props) throws Exception {

        ACMEIssuerConfig config = new ACMEIssuerConfig();

        for (Entry<Object, Object> entry : props.entrySet()) {

            String key = entry.getKey().toString();
            String value = entry.getValue().toString();

            if (key.equals("class")) {
                config.setClassName(value);

            } else {
                config.setParameter(key, value);
            }
        }

        return config;
    }

    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
