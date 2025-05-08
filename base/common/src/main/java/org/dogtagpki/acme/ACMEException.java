//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.netscape.certsrv.base.PKIException;
/**
 * ACME exception.
 *
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class ACMEException extends PKIException {

    private static final long serialVersionUID = 1L;
    private ACMEError error;

    public ACMEException(int code, ACMEError error) {
        super(code, error.getDetail());
        this.error = error;
    }

    @Override
    public String getSerializedFormat() {
        return "application/problem+json";
    }
    @Override
    public String getSerializedError() throws JsonProcessingException {
        return error.toString();
    }


}
