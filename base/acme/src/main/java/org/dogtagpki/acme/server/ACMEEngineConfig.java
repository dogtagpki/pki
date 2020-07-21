//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.util.Map.Entry;
import java.util.Properties;

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
public class ACMEEngineConfig {

    private Boolean enabled = true;

    @JsonProperty("policy")
    private ACMEPolicyConfig policyConfig = new ACMEPolicyConfig();

    public Boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public ACMEPolicyConfig getPolicyConfig() {
        return policyConfig;
    }

    public void setPolicyConfig(ACMEPolicyConfig wildcard) {
        this.policyConfig = wildcard;
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static ACMEEngineConfig fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, ACMEEngineConfig.class);
    }

    public static ACMEEngineConfig fromProperties(Properties props) throws Exception {

        ACMEEngineConfig config = new ACMEEngineConfig();

        for (Entry<Object, Object> entry : props.entrySet()) {

            String key = entry.getKey().toString();
            String value = entry.getValue().toString();

            if (key.equals("enabled")) {
                config.setEnabled(new Boolean(value));

            } else if (key.startsWith("policy.")) {

                String policyKey = key.substring(7);

                ACMEPolicyConfig policyConfig = config.getPolicyConfig();
                policyConfig.setProperty(policyKey, value);
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

    public static void main(String[] args) {
        ACMEEngineConfig engineConfig = new ACMEEngineConfig();
        System.out.println(engineConfig);
    }
}
