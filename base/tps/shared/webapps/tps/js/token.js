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

// TODO: load labels from server
var TokenStatus = {
    UNFORMATTED         : "Unformatted",
    FORMATTED           : "Formatted (uninitialized)",
    ACTIVE              : "Active",
    SUSPENDED           : "Suspended (temporarily lost)",
    PERM_LOST           : "Permanently lost",
    DAMAGED             : "Physically damaged",
    TEMP_LOST_PERM_LOST : "Temporarily lost then permanently lost",
    TERMINATED          : "Terminated"
};

var TOKEN_REUSE_MESSAGE = "When reusing a token that was previously " +
    "enrolled, out of security concerns, make sure the certificate and " +
    "key objects are removed from the token.";

var TokenModel = Model.extend({
    urlRoot: "/tps/rest/tokens",
    parseResponse: function(response) {
        return {
            id: response.id,
            tokenID: response.TokenID,
            userID: response.UserID,
            type: response.Type,
            status: response.Status,
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
        var status = self.entry.status;

        $('<option/>', {
            text: status.label,
            value: status.name,
            selected: true
        }).appendTo(select);

        var nextStates = self.entry.nextStates;
        _.each(nextStates, function(nextState) {
            $('<option/>', {
                text: nextState.label,
                value: nextState.name
            }).appendTo(select);
        });
    }
});

var TokenFilterDialog = Dialog.extend({
    loadField: function(input) {
        var self = this;

        var name = input.attr("name");
        if (name != "status") {
            TokenFilterDialog.__super__.loadField.call(self, input);
            return;
        }

        var select = input.empty();
        var status = self.entry.status;

        $('<option/>', {
            text: "",
            value: ""
        }).appendTo(select);

        _.each(TokenStatus, function(value, key) {
            $('<option/>', {
                value: key,
                text: value,
                selected: key == status
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
                        success: function(data, textStatus, response) {
                            self.render();
                        },
                        error: function(response, textStatus, errorThrow) {
                            new ErrorDialog({
                                el: $("#error-dialog"),
                                response: response
                            }).open();
                        }
                    });
                }

                dialog.close();
            });

            var orig_status = dialog.entry["status"].name;
            var status_field = dialog.$("select[name=status]");
            var warning_area = dialog.$(".pki-warning");

            status_field.change(function() {
                var status = status_field.val();
                if (orig_status == "TERMINATED" && status == "UNFORMATTED") {
                    warning_area.text(TOKEN_REUSE_MESSAGE);
                } else {
                    warning_area.empty();
                }
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
            self.$("label[name='type']").hide();
            self.$("input[name='type']").hide();
            self.$("label[name='appletID']").hide();
            self.$("input[name='appletID']").hide();
            self.$("label[name='keyInfo']").hide();
            self.$("input[name='keyInfo']").hide();
            self.$("label[name='createTimestamp']").hide();
            self.$("input[name='createTimestamp']").hide();
            self.$("label[name='modifyTimestamp']").hide();
            self.$("input[name='modifyTimestamp']").hide();
            self.$("label[name='status']").hide();
            self.$("input[name='status']").hide();

        } else {
            self.changeStatusAction.show();
            self.$("label[name='type']").show();
            self.$("input[name='type']").show();
            self.$("label[name='appletID']").show();
            self.$("input[name='appletID']").show();
            self.$("label[name='keyInfo']").show();
            self.$("input[name='keyInfo']").show();
            self.$("label[name='createTimestamp']").show();
            self.$("input[name='createTimestamp']").show();
            self.$("label[name='modifyTimestamp']").show();
            self.$("input[name='modifyTimestamp']").show();
            self.$("label[name='status']").show();
            self.$("input[name='status']").show();
        }
    },
    loadField: function(input) {
        var self = this;

        var name = input.attr("name");
        if (name != "status") {
            TokenPage.__super__.loadField.call(self, input);
            return;
        }

        var value = self.entry.status;
        if (value) value = value.label;
        if (value === undefined) value = "";
        input.val(value);
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
                    success: function(data, textStatus, response) {
                        self.table.render();
                    },
                    error: function(response, textStatus, errorThrow) {
                        new ErrorDialog({
                            el: $("#error-dialog"),
                            response: response
                        }).open();
                    }
                });
            }

            dialog.close();
        });

        var orig_status = dialog.entry["status"].name;
        var status_field = dialog.$("select[name=status]");
        var warning_area = dialog.$(".pki-warning");

        status_field.change(function() {
            var status = status_field.val();
            if (orig_status == "TERMINATED" && status == "UNFORMATTED") {
                warning_area.text(TOKEN_REUSE_MESSAGE);
            } else {
                warning_area.empty();
            }
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

        self.tokensTable = self.$("table[name='tokens']");

        var table = new TokensTable({
            el: self.tokensTable,
            collection: new TokenCollection()
        });

        table.render();

        $("a[name='filter']", self.tokensTable).click(function(e) {

            e.preventDefault();

            var dialog = new TokenFilterDialog({
                el: $("#token-filter-dialog"),
                actions: ["cancel", "apply"]
            });

            dialog.entry = _.clone(table.searchAttributes);

            dialog.handler("apply", function() {

                dialog.save();

                table.searchAttributes = _.clone(dialog.entry);

                // show the first page of search results
                table.page = 1;
                table.render();

                dialog.close();
            });

            dialog.open();
        });
    }
});
