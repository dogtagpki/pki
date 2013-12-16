/* --- BEGIN COPYRIGHT BLOCK ---
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 *
 * @author Endi S. Dewata
 */

var TokenModel = Model.extend({
    urlRoot: "/tps/rest/tokens",
    parseResponse: function(response) {
        if (!response || !response.Token) return {};
        return {
            id: response.Token["@id"],
            tokenID: response.Token.TokenID,
            userID: response.Token.UserID,
            status: response.Token.Status,
            reason: response.Token.Reason,
            appletID: response.Token.AppletID,
            keyInfo: response.Token.KeyInfo,
            createTimestamp: response.Token.CreateTimestamp,
            modifyTimestamp: response.Token.ModifyTimestamp
        };
    },
    createRequest: function(attributes) {
        return {
            Token: {
                "@id": this.id,
                TokenID: attributes.tokenID,
                UserID: attributes.userID,
                Status: attributes.status,
                Reason: attributes.reason,
                AppletID: attributes.appletID,
                KeyInfo: attributes.keyInfo,
                CreateTimestamp: attributes.createTimestamp,
                ModifyTimestamp: attributes.modifyTimestamp
            }
        };
    }
});

var TokenCollection = Collection.extend({
    model: TokenModel,
    urlRoot: "/tps/rest/tokens",
    getEntries: function(response) {
        return response.Tokens.Token;
    },
    getLinks: function(response) {
        return response.Tokens.Link;
    },
    parseEntry: function(entry) {
        return new TokenModel({
            id: entry["@id"],
            tokenID: entry.TokenID,
            userID: entry.UserID,
            status: entry.Status,
            reason: entry.Reason,
            appletID: entry.AppletID,
            keyInfo: entry.KeyInfo,
            created: entry.CreateTimestamp,
            modified: entry.ModifyTimestamp
        });
    }
});
