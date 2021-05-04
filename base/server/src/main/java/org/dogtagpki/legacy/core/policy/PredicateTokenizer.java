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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.legacy.core.policy;

import org.dogtagpki.legacy.policy.EPolicyException;

class PredicateTokenizer {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PredicateTokenizer.class);

    String input;
    int currentIndex;
    String nextToken;

    public PredicateTokenizer(String predString) {
        input = predString;
        currentIndex = 0;
        nextToken = null;
    }

    public boolean hasMoreTokens() {
        return (currentIndex != -1);
    }

    public String nextToken() throws EPolicyException {
        if (nextToken != null) {
            String toReturn = nextToken;

            nextToken = null;
            return toReturn;
        }

        int andIndex = input.indexOf(" AND", currentIndex);

        if (andIndex < 0)
            andIndex = input.indexOf(" and", currentIndex);
        int orIndex = input.indexOf(" OR", currentIndex);

        if (orIndex < 0)
            orIndex = input.indexOf(" or", currentIndex);
        String toReturn = null;

        if (andIndex == -1 && orIndex == -1) {
            if (currentIndex == 0) {
                currentIndex = -1;
                toReturn = input;
            } else {
                int temp = currentIndex;

                currentIndex = -1;
                toReturn = input.substring(temp);
            }
        } else if (andIndex >= 0 && (andIndex < orIndex || orIndex == -1)) {
            if (currentIndex != andIndex) {
                toReturn = input.substring(currentIndex, andIndex);
                nextToken = input.substring(andIndex + 1, andIndex + 4);
                currentIndex = andIndex + 4;
            } else {
                toReturn = "AND";
                currentIndex += 4;
            }
        } else if (orIndex >= 0 && (orIndex < andIndex || andIndex == -1)) {
            if (currentIndex != orIndex) {
                toReturn = input.substring(currentIndex, orIndex);
                nextToken = input.substring(orIndex + 1, orIndex + 3);
                currentIndex = orIndex + 3;
            } else {
                toReturn = "OR";
                currentIndex += 3;
            }
        } else {
            // Cannot happen; Assert here.
            logger.error("Malformed Predicate Expression : No Tokens");
            throw new EPolicyException("Malformed Predicate Expression : No Tokens");
        }

        String trimmed = toReturn.trim();

        if (trimmed.length() == 0)
            return nextToken();
        else
            return trimmed;

    }
}
