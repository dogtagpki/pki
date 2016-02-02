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
    TEMP_LOST_PERM_LOST: "Temporarily lost then permanently lost",
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
            nextStates: response.NextStates,
            appletID: response.AppletID,
            keyInfo: response.KeyInfo,
            policy: response.Policy,
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
            Policy: attributes.policy,
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
            nextStates: entry.NextStates,
            appletID: entry.AppletID,
            keyInfo: entry.KeyInfo,
            policy: entry.Policy,
            createTimestamp: entry.CreateTimestamp,
            modifyTimestamp: entry.ModifyTimestamp
        });
    }
});

var TokenDialog = Dialog.extend({
    loadField: function(input) {
        var self = this;

        var name = input.attr("name");
        if (name != "status") {
            TokenDialog.__super__.loadField.call(self, input);
            return;
        }

        var select = input.empty();
        var status = self.entry["status"];

        $('<option/>', {
            text: TokenStatus[status],
            value: status,
            selected: true
        }).appendTo(select);

        var nextStates = self.entry["nextStates"];
        _.each(nextStates, function(nextState) {
            $('<option/>', {
                text: TokenStatus[nextState],
                value: nextState
            }).appendTo(select);
        });
    }
});

var TokenPage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        TokenPage.__super__.initialize.call(self, options);
    },
    setup: function() {
        var self = this;

        TokenPage.__super__.setup.call(self);

        self.changeStatusAction = $("[name='changeStatus']", self.viewMenu);

        $("a", self.changeStatusAction).click(function(e) {

            e.preventDefault();

            var dialog = new TokenDialog({
                el: $("#token-status-dialog"),
                title: "Change Token Status",
                readonly: ["tokenID"],
                actions: ["cancel", "save"]
            });

            dialog.entry = _.clone(self.model.attributes);

            dialog.handler("save", function() {

                // save changes
                dialog.save();

                // check if the status was changed
                if (dialog.entry.status != self.model.attributes.status) {

                    self.model.changeStatus({
                        status: dialog.entry.status,
                        success: function(data, textStatus, jqXHR) {
                            self.render();
                        },
                        error: function(jqXHR, textStatus, errorThrow) {
                            new ErrorDialog({
                                el: $("#error-dialog"),
                                title: "HTTP Error " + jqXHR.responseJSON.Code,
                                content: jqXHR.responseJSON.Message
                            }).open();
                        }
                    });
                }

                dialog.close();
            });

            dialog.open();
        });

        self.showCertsAction = $("[name='showCerts']", self.viewMenu);

        $("a", self.showCertsAction).click(function(e) {

            e.preventDefault();
            window.location.hash = window.location.hash + "/certs";
        });
    },
    renderContent: function() {
        var self = this;

        TokenPage.__super__.renderContent.call(self);

        if (self.mode == "add") {
            self.changeStatusAction.hide();
        } else {
            self.changeStatusAction.show();
        }
    }
});

var TokenTableItem = TableItem.extend({
    initialize: function(options) {
        var self = this;
        TokenTableItem.__super__.initialize.call(self, options);
    },
    renderColumn: function(td, templateTD) {
        var self = this;

        TokenTableItem.__super__.renderColumn.call(self, td, templateTD);

        var name = td.attr("name");
        if (name == "status") {
            $("a", td).click(function(e) {
                e.preventDefault();
                self.editStatus();
            });
        }
    },
    editStatus: function() {
        var self = this;

        var model = self.table.collection.get(self.entry.id);

        var dialog = new TokenDialog({
            el: $("#token-status-dialog"),
            title: "Change Token Status",
            readonly: ["tokenID", "userID", "type",
                "appletID", "keyInfo", "policy",
                "createTimestamp", "modifyTimestamp"],
            actions: ["cancel", "save"]
        });

        dialog.entry = _.clone(model.attributes);

        dialog.handler("save", function() {

            // save changes
            dialog.save();

            // check if the status was changed
            if (dialog.entry.status != model.attributes.status) {

                model.changeStatus({
                    status: dialog.entry.status,
                    success: function(data, textStatus, jqXHR) {
                        self.table.render();
                    },
                    error: function(jqXHR, textStatus, errorThrow) {
                        new ErrorDialog({
                            el: $("#error-dialog"),
                            title: "HTTP Error " + jqXHR.responseJSON.Code,
                            content: jqXHR.responseJSON.Message
                        }).open();
                    }
                });
            }

            dialog.close();
        });

        dialog.open();
    }
});

var TokensTable = ModelTable.extend({
    initialize: function(options) {
        var self = this;
        options.tableItem = TokenTableItem;
        TokensTable.__super__.initialize.call(self, options);
    },
    add: function() {
        var self = this;

        window.location.hash = "#new-token";
    }
});

var TokensPage = Page.extend({
    load: function() {
        var self = this;

        var table = new TokensTable({
            el: $("table[name='tokens']"),
            collection: new TokenCollection()
        });

        table.render();
    }
});
