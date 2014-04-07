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

var TokenStatus = {
    UNINITIALIZED: "Uninitialized",
    ACTIVE: "Active",
    TEMP_LOST: "Temporarily lost",
    PERM_LOST: "Permanently lost",
    DAMAGED: "Physically damaged",
    TERMINATED: "Terminated"
};

var TokenModel = Model.extend({
    urlRoot: "/tps/rest/tokens",
    parseResponse: function(response) {
        return {
            id: response.id,
            tokenID: response.TokenID,
            userID: response.UserID,
            type: response.Type,
            status: response.Status,
            statusLabel: TokenStatus[response.Status],
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
            Type: attributes.type,
            Status: attributes.status,
            AppletID: attributes.appletID,
            KeyInfo: attributes.keyInfo,
            CreateTimestamp: attributes.createTimestamp,
            ModifyTimestamp: attributes.modifyTimestamp
        };
    },
    changeStatus: function(options) {
        var self = this;
        $.ajax({
            type: "POST",
            url: self.url() + "?status=" + options.status,
            dataType: "json"
        }).done(function(data, textStatus, jqXHR) {
            self.set(self.parseResponse(data));
            if (options.success) options.success.call(self, data, textStatus, jqXHR);
        }).fail(function(jqXHR, textStatus, errorThrown) {
            if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
        });
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
            type: entry.Type,
            status: entry.Status,
            statusLabel: TokenStatus[entry.Status],
            appletID: entry.AppletID,
            keyInfo: entry.KeyInfo,
            createTimestamp: entry.CreateTimestamp,
            modifyTimestamp: entry.ModifyTimestamp
        });
    }
});

var TokenTableItem = TableItem.extend({
    initialize: function(options) {
        var self = this;
        PropertiesTableItem.__super__.initialize.call(self, options);
    },
    open: function(td) {
        var self = this;

        var name = td.attr("name");
        if (name != "status") {
            TokenTableItem.__super__.open.call(self, td);
            return;
        }

        var dialog = new Dialog({
            el: $("#token-state-dialog"),
            title: "Change Token State",
            readonly: ["tokenID", "userID", "type",
                "appletID", "keyInfo", "createTimestamp", "modifyTimestamp"],
            actions: ["cancel", "save"]
        });

        dialog.entry = _.clone(self.entry);

        dialog.handler("save", function() {

            // save changes
            dialog.save();

            // check if the status was changed
            if (self.entry.status != dialog.entry.status) {

                var model = self.table.collection.get(self.entry.id);
                model.changeStatus({
                    status: dialog.entry.status,
                    success: function(data, textStatus, jqXHR) {
                        self.table.render();
                    },
                    error: function(jqXHR, textStatus, errorThrow) {
                        alert("ERROR: " + jqXHR.responseText);
                    }
                });
            }

            dialog.close();
        });

        dialog.open();
    }
});

var TokenPage = Page.extend({
    load: function() {
        var self = this;

        var addDialog = new Dialog({
            el: $("#token-dialog"),
            title: "Add Token",
            readonly: ["statusLabel", "createTimestamp", "modifyTimestamp"],
            actions: ["cancel", "add"]
        });

        var editDialog = new Dialog({
            el: $("#token-dialog"),
            title: "Edit Token",
            readonly: ["tokenID", "statusLabel", "createTimestamp", "modifyTimestamp"],
            actions: ["cancel", "save"]
        });

        var table = new ModelTable({
            el: $("table[name='tokens']"),
            collection: new TokenCollection(),
            addDialog: addDialog,
            editDialog: editDialog,
            tableItem: TokenTableItem
        });

        table.render();
    }
});
