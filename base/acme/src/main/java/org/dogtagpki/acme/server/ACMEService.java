//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import org.dogtagpki.acme.ACMEError;

/**
 * Base class providing common ACME web service behaviour.
 */
public class ACMEService {

    public void throwError(Response.Status status, ACMEError error) {
        throw new WebApplicationException(
            Response
                .status(status)
                .type("application/problem+json")
                .entity(error)
                .build()
        );
    }

}
