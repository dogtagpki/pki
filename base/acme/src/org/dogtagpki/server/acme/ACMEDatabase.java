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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.acme;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEOrder;

public class ACMEDatabase {

    public final static ACMEDatabase INSTANCE = new ACMEDatabase();

    private Map<String, ACMEOrder> orders = new HashMap<>();
    private Map<String, ACMEAuthorization> authorizations = new HashMap<>();
    private Map<String, ACMEChallenge> challenges = new HashMap<>();

    private Map<String, Collection<String>> orderToAuthzMap = new HashMap<>();

    private Map<String, Collection<String>> authzToChallengeMap = new HashMap<>();
    private Map<String, String> challengeToAuthzMap = new HashMap<>();

    public final static ACMEDatabase getInstance() {
        return INSTANCE;
    }

    public ACMEOrder getOrder(String orderID) {
        return orders.get(orderID);
    }

    public ACMEAuthorization getAuthorization(String authzID) {
        return authorizations.get(authzID);
    }

    public ACMEChallenge getChallenge(String challengeID) {
        return challenges.get(challengeID);
    }

    public void addOrder(String orderID, ACMEOrder order) {
        orders.put(orderID, order);
    }

    public void addAuthorization(String authzID, ACMEAuthorization authorization) {
        authorizations.put(authzID, authorization);

        Collection<String> challenges = new LinkedList<String>();
        authzToChallengeMap.put(authzID, challenges);
    }

    public void addChallenge(String authzID, String challengeID, ACMEChallenge challenge) {
        challenges.put(challengeID, challenge);

        Collection<String> collection = authzToChallengeMap.get(authzID);
        collection.add(challengeID);

        challengeToAuthzMap.put(challengeID, authzID);
    }

    public String getAuthorizationID(String challengeID) {
        return challengeToAuthzMap.get(challengeID);
    }

    public Collection<String> getChallenges(String authzID) {
        return authzToChallengeMap.get(authzID);
    }
}
