//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.apache.commons.lang.StringUtils;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ACMERetention {

    private Long length;
    private ChronoUnit unit;

    public ACMERetention() {
    }

    public ACMERetention(Long length, ChronoUnit unit) {
        this.length = length;
        this.unit = unit;
    }

    public ACMERetention(Integer length, ChronoUnit unit) {
        this.length = Long.valueOf(length);
        this.unit = unit;
    }

    public Long getLength() {
        return length;
    }

    public void setLength(Long length) {
        this.length = length;
    }

    public ChronoUnit getUnit() {
        return unit;
    }

    public void setUnit(ChronoUnit unit) {
        this.unit = unit;
    }

    public Date getExpirationTime(Date currentTime) {

        if (length == null || unit == null) return null;

        Instant now = currentTime.toInstant();
        Instant expirationTime = now.plus(length, unit);
        return Date.from(expirationTime);
    }

    public void setProperty(String key, String value) throws Exception {
        if (key.equals("length")) {
            if (StringUtils.isEmpty(value)) {
                length = null;
            } else {
                length = new Long(value);
            }

        } else if (key.equals("unit")) {
            if (StringUtils.isEmpty(value)) {
                unit = null;
            } else {
                unit = ChronoUnit.valueOf(value);
            }
        }
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static ACMERetention fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, ACMERetention.class);
    }

    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        ACMERetention retention = new ACMERetention(30, ChronoUnit.MINUTES);
        System.out.println(retention);
    }
}
