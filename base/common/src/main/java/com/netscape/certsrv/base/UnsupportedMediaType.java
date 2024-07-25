//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.base;

import javax.ws.rs.core.Response;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class UnsupportedMediaType extends PKIException {

    private static final long serialVersionUID = 1L;

    public UnsupportedMediaType(String message) {
        super(Response.Status.UNSUPPORTED_MEDIA_TYPE, message);
    }

    public UnsupportedMediaType(String message, Throwable cause) {
        super(Response.Status.UNSUPPORTED_MEDIA_TYPE, message, cause);
    }

    public UnsupportedMediaType(Data data) {
        super(data);
    }

}
