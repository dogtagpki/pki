//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.validator;

import java.util.HashMap;
import java.util.Properties;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ACMEValidatorsConfig extends HashMap<String, ACMEValidatorConfig> {

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static ACMEValidatorsConfig fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, ACMEValidatorsConfig.class);
    }

    public static ACMEValidatorsConfig fromProperties(Properties props) throws Exception {

        ACMEValidatorsConfig validatorsConfig = new ACMEValidatorsConfig();

        for (Entry<Object, Object> entry : props.entrySet()) {

            String key = entry.getKey().toString();
            String value = entry.getValue().toString();

            // split key by dots
            String[] parts = key.split("\\.");
            String name = parts[0];
            String param = parts[1];

            ACMEValidatorConfig validatorConfig = validatorsConfig.get(name);

            if (validatorConfig == null) {
                validatorConfig = new ACMEValidatorConfig();
                validatorsConfig.put(name, validatorConfig);
            }

            if (param.equals("class")) {
                validatorConfig.setClassName(value);

            } else {
                validatorConfig.setParameter(param, value);
            }
        }

        return validatorsConfig;
    }

    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
