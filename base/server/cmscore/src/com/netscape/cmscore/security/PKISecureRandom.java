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
package com.netscape.cmscore.security;

import java.security.SecureRandom;

import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.RandomGenerationEvent;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;

public class PKISecureRandom extends SecureRandom {

    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    private static final long serialVersionUID = 1L;

    SecureRandom random;

    public PKISecureRandom(SecureRandom random) {
        this.random = random;
    }

    /**
     * Generates a user-specified number of random bytes.
     *
     * This method overrides the base implementation in SecureRandom
     * to call the nextBytes() of the wrapped random number generator.
     *
     * See also: http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/687fd7c7986d/src/share/classes/java/security/SecureRandom.java#l456
     */
    @Override
    public void nextBytes(byte[] bytes) {

        // find PKI code that calls the random generator

        String info = null;

        for (StackTraceElement e : Thread.currentThread().getStackTrace()) {

            String className = e.getClassName();

            if (PKISecureRandom.class.getName().equals(className)) {
                // skip this class
                continue;
            }

            if (!className.startsWith("com.netscape.") &&
                    !className.startsWith("netscape.") &&
                    !className.startsWith("org.dogtagpki.")) {
                // skip non-PKI classes
                continue;
            }

            // construct caller info

            String methodName = e.getMethodName();
            String fileName = e.getFileName();
            int lineNumber = e.getLineNumber();

            info = className + "." + methodName + "(" + fileName + ":" + lineNumber + ")";

            break;
        }

        try {
            signedAuditLogger.log(RandomGenerationEvent.createSuccessEvent(getSubjectID(), info));
            random.nextBytes(bytes);

        } catch (RuntimeException e) {
            signedAuditLogger.log(RandomGenerationEvent.createFailureEvent(getSubjectID(), info, e.getMessage()));
            throw e;
        }
    }

    protected String getSubjectID() {

        SessionContext context = SessionContext.getExistingContext();

        if (context == null) {
            return ILogger.UNIDENTIFIED;
        }

        String subjectID = (String) context.get(SessionContext.USER_ID);

        if (subjectID == null) {
            return ILogger.NONROLEUSER;
        }

        return subjectID.trim();
    }
}
