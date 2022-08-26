//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.est;

import org.mozilla.jss.netscape.security.pkcs.PKCS10;

import com.netscape.certsrv.base.PKIException;

/**
 * The EST authorization backend interface.
 *
 * @author Fraser Tweedale
 */
public abstract class ESTRequestAuthorizer {

    void start() throws Throwable { }

    void stop() throws Throwable { }

    protected ESTRequestAuthorizerConfig config;

    public void setConfig(ESTRequestAuthorizerConfig config) {
        this.config = config;
    }

    /**
     * Authorize a simpleenroll request
     *
     * @throws ForbiddenException on authorization failure
     * @throws PKIException on error
     * @return on success, an Object, which will be passed to the
     *         issuance backend (null allowed)
     */
    public abstract Object authorizeSimpleenroll(
        ESTRequestAuthorizationData data, PKCS10 csr)
            throws PKIException;

    /**
     * Authorize a simplereenroll request
     *
     * @throws ForbiddenException on authorization failure
     * @throws PKIException on error
     * @return on success, an Object, which will be passed to the
     *         issuance backend (null allowed)
     */
    public abstract Object authorizeSimplereenroll(
        ESTRequestAuthorizationData data, PKCS10 csr)
            throws PKIException;

}
