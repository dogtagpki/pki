//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

package org.dogtagpki.ct;

import java.util.ArrayList;
import java.util.List;

import org.dogtagpki.server.rest.JSONSerializer;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonSetter;

/**
 * @author Dinesh Prasanth M K
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CTRequest implements JSONSerializer {

    private List<String> certs = new ArrayList<>();

    public CTRequest() {
    }

    @JsonGetter("chain")
    public List<String> getCerts() {
        return certs;
    }

    @JsonSetter("chain")
    public void setCerts(List<String> certs) {
        this.certs = certs;
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
