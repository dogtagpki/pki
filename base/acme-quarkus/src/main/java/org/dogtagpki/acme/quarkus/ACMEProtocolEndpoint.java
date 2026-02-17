//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.ws.rs.NameBinding;

/**
 * Name binding annotation for ACME protocol endpoints.
 *
 * Used to bind the ACMEEnableFilterQuarkus to protocol endpoints
 * (directory, new-nonce, new-account, new-order, authz, chall,
 * order, cert, revoke-cert, acct) while excluding admin endpoints
 * (enable, disable, login, logout).
 */
@NameBinding
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ACMEProtocolEndpoint {
}
