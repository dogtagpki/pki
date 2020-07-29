//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.lang.reflect.Field;
import java.time.temporal.ChronoUnit;
import java.util.Map.Entry;
import java.util.Properties;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ACMERetentionConfig {

    private ACMERetention nonces = new ACMERetention(30, ChronoUnit.MINUTES);
    private ACMERetention validAuthorizations = new ACMERetention(30, ChronoUnit.MINUTES);
    private ACMERetention pendingOrders = new ACMERetention(30, ChronoUnit.MINUTES);
    private ACMERetention validOrders = new ACMERetention(30, ChronoUnit.MINUTES);

    public ACMERetentionConfig() {}

    public ACMERetention getNonces() {
        return nonces;
    }

    public void setNonces(ACMERetention nonces) {
        this.nonces = nonces;
    }

    public ACMERetention getValidAuthorizations() {
        return validAuthorizations;
    }

    public void setValidAuthorizations(ACMERetention validAuthorizations) {
        this.validAuthorizations = validAuthorizations;
    }

    public ACMERetention getPendingOrders() {
        return pendingOrders;
    }

    public void setPendingOrders(ACMERetention pendingOrders) {
        this.pendingOrders = pendingOrders;
    }

    public ACMERetention getValidOrders() {
        return validOrders;
    }

    public void setValidOrders(ACMERetention validOrders) {
        this.validOrders = validOrders;
    }

    public void setProperty(String key, String value) throws Exception {

        // split key by dots
        String[] parts = key.split("\\.");
        String name = parts[0];
        String param = parts[1];

        Field field = ACMERetentionConfig.class.getDeclaredField(name);
        field.setAccessible(true);

        ACMERetention retention = (ACMERetention) field.get(this);
        if (retention == null) {
            retention = new ACMERetention();
            field.set(this, retention);
        }

        retention.setProperty(param, value);
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static ACMERetentionConfig fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, ACMERetentionConfig.class);
    }

    public static ACMERetentionConfig fromProperties(Properties props) throws Exception {

        ACMERetentionConfig config = new ACMERetentionConfig();

        for (Entry<Object, Object> entry : props.entrySet()) {
            String key = entry.getKey().toString();
            String value = entry.getValue().toString();
            config.setProperty(key, value);
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
        ACMERetentionConfig config = new ACMERetentionConfig();
        System.out.println(config);
    }
}
