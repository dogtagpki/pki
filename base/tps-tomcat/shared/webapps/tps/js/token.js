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
        return {
            id: response.id,
            tokenID: response.TokenID,
            userID: response.UserID,
            status: response.Status,
            reason: response.Reason,
            appletID: response.AppletID,
            keyInfo: response.KeyInfo,
            createTimestamp: response.CreateTimestamp,
            modifyTimestamp: response.ModifyTimestamp
        };
    },
    createRequest: function(attributes) {
        return {
            id: this.id,
            TokenID: attributes.tokenID,
            UserID: attributes.userID,
            Status: attributes.status,
            Reason: attributes.reason,
            AppletID: attributes.appletID,
            KeyInfo: attributes.keyInfo,
            CreateTimestamp: attributes.createTimestamp,
            ModifyTimestamp: attributes.modifyTimestamp
        };
    }
});

var TokenCollection = Collection.extend({
    model: TokenModel,
    urlRoot: "/tps/rest/tokens",
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        return new TokenModel({
            id: entry.id,
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

var TokenPage = Page.extend({
    load: function() {
        var self = this;

        var addDialog = new Dialog({
            el: $("#token-dialog"),
            title: "Add Token",
            readonly: ["status", "reason", "appletID", "keyInfo",
                "createTimestamp", "modifyTimestamp"],
            actions: ["cancel", "add"]
        });

        var editDialog = new Dialog({
            el: $("#token-dialog"),
            title: "Edit Token",
            readonly: ["tokenID", "status", "reason", "appletID", "keyInfo",
                "createTimestamp", "modifyTimestamp"],
            actions: ["cancel", "save"]
        });

        var table = new Table({
            el: $("table[name='tokens']"),
            collection: new TokenCollection(),
            addDialog: addDialog,
            editDialog: editDialog
        });

        table.render();
    }
});
