//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.validator;

import java.util.HashMap;
import java.util.Properties;

import org.dogtagpki.server.rest.JSONSerializer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ACMEValidatorsConfig extends HashMap<String, ACMEValidatorConfig> implements JSONSerializer {

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

    @Override
    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
