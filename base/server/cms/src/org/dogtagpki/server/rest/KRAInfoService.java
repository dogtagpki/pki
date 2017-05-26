// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.rest;

import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;

import org.dogtagpki.common.KRAInfo;
import org.dogtagpki.common.KRAInfoResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.cms.servlet.base.PKIService;

import netscape.security.util.WrappingParams;

/**
 * @author Ade Lee
 */
public class KRAInfoService extends PKIService implements KRAInfoResource {

    private static Logger logger = LoggerFactory.getLogger(InfoService.class);
    private IKeyRecoveryAuthority kra;
    private IStorageKeyUnit storageUnit;

    public KRAInfoService() {
        kra = (IKeyRecoveryAuthority) CMS.getSubsystem("kra");
        storageUnit = kra.getStorageKeyUnit();
    }

    @Override
    public Response getInfo() throws Exception {

        HttpSession session = servletRequest.getSession();
        logger.debug("KRAInfoService.getInfo(): session: " + session.getId());

        KRAInfo info = new KRAInfo();
        info.setArchivalMechanism(getArchivalMechanism());
        info.setRecoveryMechanism(getRecoveryMechanism());
        info.setEncryptAlgorithm(getEncryptAlgorithm());
        info.setArchivalMechanism(getWrapAlgorithm());

        return createOKResponse(info);
    }

    String getArchivalMechanism() throws EBaseException {
        IConfigStore cs = CMS.getConfigStore();
        boolean encrypt_archival = cs.getBoolean("kra.allowEncDecrypt.archival", false);
        return encrypt_archival ? KRAInfoResource.ENCRYPT_MECHANISM : KRAInfoResource.KEYWRAP_MECHANISM;
    }

    String getRecoveryMechanism() throws EBaseException {
        IConfigStore cs = CMS.getConfigStore();
        boolean encrypt_recovery = cs.getBoolean("kra.allowEncDecrypt.recovery", false);
        return encrypt_recovery ? KRAInfoResource.ENCRYPT_MECHANISM : KRAInfoResource.KEYWRAP_MECHANISM;
    }

    String getWrapAlgorithm() throws EBaseException {
        IConfigStore cs = CMS.getConfigStore();
        boolean encrypt_archival = cs.getBoolean("kra.allowEncDecrypt.archival", false);
        WrappingParams params = null;
        try {
            params = storageUnit.getWrappingParams(encrypt_archival);
        } catch (Exception e) {
            // return something that should always work
            return "AES/CBC/Padding";
        }
        return params.getPayloadWrapAlgorithm().toString();
    }

    String getEncryptAlgorithm() throws EBaseException {
        IConfigStore cs = CMS.getConfigStore();
        boolean encrypt_archival = cs.getBoolean("kra.allowEncDecrypt.archival", false);
        WrappingParams params = null;
        try {
            params = storageUnit.getWrappingParams(encrypt_archival);
        } catch (Exception e) {
            // return something that should always work
            return "AES/CBC/Padding";
        }
        return params.getPayloadEncryptionAlgorithm().toString();
    }
}

