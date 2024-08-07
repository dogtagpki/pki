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

package org.dogtagpki.server.kra.rest.v1;

import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;

import org.dogtagpki.common.KRAInfo;
import org.dogtagpki.common.KRAInfoResource;
import org.dogtagpki.server.kra.KRAEngine;
import org.dogtagpki.server.kra.KRAEngineConfig;
import org.mozilla.jss.netscape.security.util.WrappingParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * @author Ade Lee
 */
public class KRAInfoService extends PKIService implements KRAInfoResource {

    private static Logger logger = LoggerFactory.getLogger(KRAInfoService.class);

    private KeyRecoveryAuthority kra;
    private IStorageKeyUnit storageUnit;

    public KRAInfoService() {
        KRAEngine engine = KRAEngine.getInstance();
        kra = (KeyRecoveryAuthority) engine.getSubsystem(KeyRecoveryAuthority.ID);
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
        info.setWrapAlgorithm(getWrapAlgorithm());
        info.setRsaPublicKeyWrapAlgorithm(getRsaPublicKeyWrapAlgorithm());
        return createOKResponse(info);
    }

    String getArchivalMechanism() throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        KRAEngineConfig cs = engine.getConfig();

        boolean encrypt_archival = cs.getBoolean("kra.allowEncDecrypt.archival", false);
        return encrypt_archival ? KRAInfoResource.ENCRYPT_MECHANISM : KRAInfoResource.KEYWRAP_MECHANISM;
    }

    String getRecoveryMechanism() throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        KRAEngineConfig cs = engine.getConfig();

        boolean encrypt_recovery = cs.getBoolean("kra.allowEncDecrypt.recovery", false);
        return encrypt_recovery ? KRAInfoResource.ENCRYPT_MECHANISM : KRAInfoResource.KEYWRAP_MECHANISM;
    }

    String getWrapAlgorithm() throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        KRAEngineConfig cs = engine.getConfig();

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

        KRAEngine engine = KRAEngine.getInstance();
        KRAEngineConfig cs = engine.getConfig();

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

    String getRsaPublicKeyWrapAlgorithm() throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        KRAEngineConfig cs = engine.getConfig();

        boolean useOAEP = cs.getUseOAEPKeyWrap();

        return useOAEP ? "RSA_OAEP" : "RSA";
    }
}

