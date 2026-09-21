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
// (C) 2026 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.constraint;

import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.profile.common.PolicyConstraintConfig;
import com.netscape.cmscore.request.Request;

/**
 * Behavioral KeyConstraint.validate() coverage for IDM-8250 (allowedKeys
 * syntax without keyType / keyParameters).
 *
 * When keyType is unset, allowedKeys must still be enforced for EC and RSA
 * enrollments.
 */
public class KeyConstraintTest {

    /** nistp256 / secp256r1 */
    private static final String OID_NISTP256 = "OID.1.2.840.10045.3.1.7";
    /** nistp384 / secp384r1 */
    private static final String OID_NISTP384 = "OID.1.3.132.0.34";

    private Fixture constraint;
    private Request request;

    /**
     * Same-package fixture: sets allowedKeys without CAEngine.init(),
     * and stubs RSA size so validate() does not need a real RSA key blob.
     */
    static class Fixture extends KeyConstraint {
        int rsaKeyLen = 2048;

        /**
         * @param entries allowedKeys leaves as {@code ALG.param=value},
         *                e.g. {@code "RSA.2048=true"}, {@code "EC.nistp256=true"}
         */
        void configureAllowedKeys(String... entries) {
            PolicyConstraintConfig store = new PolicyConstraintConfig();
            for (String entry : entries) {
                int eq = entry.indexOf('=');
                store.putString("params.allowedKeys." + entry.substring(0, eq),
                        entry.substring(eq + 1));
            }
            mConfig = store;
        }

        @Override
        public int getRSAKeyLen(X509Key key) {
            return rsaKeyLen;
        }
    }

    @BeforeEach
    public void setUp() {
        constraint = new Fixture();
        request = new Request(new RequestId("0"));
    }

    private static X509CertInfo certInfo(String algName, String ecParamsOid)
            throws Exception {
        AlgorithmId algId;
        if ("EC".equals(algName)) {
            algId = new AlgorithmId(AlgorithmId.ANSIX962_EC_Public_Key_oid);
        } else {
            algId = AlgorithmId.get(algName);
        }
        if (ecParamsOid != null) {
            algId.setParametersString(ecParamsOid);
        }
        X509Key key = new X509Key(algId, new byte[] { 0x00 });
        CertificateX509Key certKey = new CertificateX509Key(key);
        X509CertInfo info = new X509CertInfo();
        info.set(X509CertInfo.KEY, certKey);
        return info;
    }

    private void assertRejected(X509CertInfo info) throws Exception {
        try {
            constraint.validate(request, info);
            fail("expected ERejectException");
        } catch (ERejectException e) {
            // expected
        }
    }

    private void assertAccepted(X509CertInfo info) throws Exception {
        constraint.validate(request, info);
    }

    // --- Req 1: RSA-only constraint rejects EC ---

    @Test
    public void rsaOnly_rejectsEC() throws Exception {
        constraint.configureAllowedKeys("RSA.2048=true");
        assertRejected(certInfo("EC", OID_NISTP256));
    }

    // --- Req 2: EC curve-restricted rejects other curves ---

    @Test
    public void nistp256Only_rejectsNistp384() throws Exception {
        constraint.configureAllowedKeys("EC.nistp256=true");
        assertRejected(certInfo("EC", OID_NISTP384));
    }

    // --- Req 3: EC-only constraint rejects RSA ---

    @Test
    public void ecOnly_rejectsRSA() throws Exception {
        constraint.configureAllowedKeys("EC.nistp256=true");
        assertRejected(certInfo("RSA", null));
    }

    // --- Req 4: matching enrollments succeed ---

    @Test
    public void rsa2048_acceptsRSA2048() throws Exception {
        constraint.configureAllowedKeys("RSA.2048=true");
        assertAccepted(certInfo("RSA", null));
    }

    @Test
    public void nistp256Only_acceptsNistp256() throws Exception {
        constraint.configureAllowedKeys("EC.nistp256=true");
        assertAccepted(certInfo("EC", OID_NISTP256));
    }

    @Test
    public void mixedAllowedKeys_acceptsMatchingEC() throws Exception {
        constraint.configureAllowedKeys(
                "RSA.1024=true",
                "RSA.2048=true",
                "RSA.3072=true",
                "RSA.4096=true",
                "EC.nistp256=true",
                "EC.nistp384=true",
                "EC.nistp521=true");
        assertAccepted(certInfo("EC", OID_NISTP256));
    }

    @Test
    public void mixedAllowedKeys_acceptsMatchingRSA() throws Exception {
        constraint.configureAllowedKeys(
                "RSA.1024=true",
                "RSA.2048=true",
                "RSA.3072=true",
                "RSA.4096=true",
                "EC.nistp256=true",
                "EC.nistp384=true",
                "EC.nistp521=true");
        assertAccepted(certInfo("RSA", null));
    }

    // --- Req 5: family-restricted allowedKeys — no regression ---

    @Test
    public void rsaOnly_rejectsWrongSize() throws Exception {
        constraint.configureAllowedKeys("RSA.2048=true");
        constraint.rsaKeyLen = 1024;
        assertRejected(certInfo("RSA", null));
    }

    @Test
    public void ecOnly_rejectsRSA_family() throws Exception {
        constraint.configureAllowedKeys("EC.nistp256=true", "EC.nistp384=true");
        assertRejected(certInfo("RSA", null));
    }
}
