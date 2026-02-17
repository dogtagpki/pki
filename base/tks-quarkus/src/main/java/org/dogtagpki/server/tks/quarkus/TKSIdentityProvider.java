//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.dogtagpki.server.quarkus.PKIIdentityProvider;
import org.dogtagpki.server.tks.TKSEngine;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TKS-specific identity provider for Quarkus.
 * Extends PKIIdentityProvider with TKS engine integration.
 */
@ApplicationScoped
public class TKSIdentityProvider extends PKIIdentityProvider {

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }

    @Override
    protected String getDefaultRole() {
        return "TKS Agents";
    }
}
