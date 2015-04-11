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

var AuditModel = Model.extend({
    url: function() {
        return "/tps/rest/audit";
    },
    parseResponse: function(response) {
        return {
            id: "audit",
            status: response.Status,
            signed: response.Signed,
            interval: response.Interval,
            bufferSize: response.BufferSize,
            events: response.Events.Event
        };
    },
    createRequest: function(entry) {
        return {
            Status: entry.status,
            Signed: entry.signed,
            Interval: entry.interval,
            BufferSize: entry.bufferSize,
            Events: {
                Event: entry.events
            }
        };
    },
    changeStatus: function(action, options) {
        var self = this;
        $.ajax({
            type: "POST",
            url: self.url() + "?action=" + action,
            dataType: "json"
        }).done(function(data, textStatus, jqXHR) {
            self.set(self.parseResponse(data));
            if (options.success) options.success.call(self, data, textStatus, jqXHR);
        }).fail(function(jqXHR, textStatus, errorThrown) {
            if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
        });
    }
});

var AuditTableItem = TableItem.extend({
    initialize: function(options) {
        var self = this;
        AuditTableItem.__super__.initialize.call(self, options);
    },
    renderColumn: function(td, templateTD) {
        var self = this;

        AuditTableItem.__super__.renderColumn.call(self, td, templateTD);

        $("a", td).click(function(e) {
            e.preventDefault();
            self.open();
        });
    },
    open: function() {
        var self = this;

        var value = self.get("value");
        var dialog;

        if (self.table.mode == "view" || value == "mandatory") {
            // In view mode all events are read-only.
            // Mandatory events are always read-only.
            dialog = new Dialog({
                el: self.table.parent.$("#event-dialog"),
                title: "Event",
                readonly: ["name", "value"],
                actions: ["close"]
            });

        } else if (self.table.mode == "edit" && value != "mandatory") {
            // Optional events are editable in edit mode.
            dialog = new Dialog({
                el: self.table.parent.$("#event-dialog"),
                title: "Edit Event",
                readonly: ["name"],
                actions: ["cancel", "save"]
            });

            dialog.handler("save", function() {

                // save changes
                dialog.save();
                _.extend(self.entry, dialog.entry);

                // redraw table
                self.table.render();
                dialog.close();
            });
        }

        dialog.entry = _.clone(self.entry);

        dialog.open();
    }
});

var AuditPage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        options.model = new AuditModel();
        options.editable = ["signed", "interval", "bufferSize"];
        AuditPage.__super__.initialize.call(self, options);
    },
    setup: function() {
        var self = this;

        AuditPage.__super__.setup.call(self);

        self.enableAction = $("[name='enable']", self.viewMenu);
        self.disableAction = $("[name='disable']", self.viewMenu);

        $("a", self.enableAction).click(function(e) {

            e.preventDefault();

            var message = "Are you sure you want to enable this entry?";
            if (!confirm(message)) return;
            self.model.changeStatus("enable", {
                success: function(data, textStatus, jqXHR) {
                    self.entry = _.clone(self.model.attributes);
                    self.render();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        title: "HTTP Error " + jqXHR.responseJSON.Code,
                        content: jqXHR.responseJSON.Message
                    }).open();
                }
            });
        });

        $("a", self.disableAction).click(function(e) {

            e.preventDefault();

            var message = "Are you sure you want to disable this entry?";
            if (!confirm(message)) return;
            self.model.changeStatus("disable", {
                success: function(data, textStatus, jqXHR) {
                    self.entry = _.clone(self.model.attributes);
                    self.render();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        title: "HTTP Error " + jqXHR.responseJSON.Code,
                        content: jqXHR.responseJSON.Message
                    }).open();
                }
            });
        });

        self.eventsTable = new Table({
            el: self.$("table[name='events']"),
            columnMappings: {
                id: "name"
            },
            pageSize: 10,
            tableItem: AuditTableItem,
            parent: self
        });
    },
    renderContent: function() {
        var self = this;

        AuditPage.__super__.renderContent.call(self);

        var status = self.entry.status;
        if (status == "Disabled") {
            self.editAction.show();
            self.enableAction.show();
            self.disableAction.hide();

        } else {
            self.editAction.hide();
            self.enableAction.hide();
            self.disableAction.show();
        }

        if (self.mode == "edit") {
            self.eventsTable.mode = "edit";

        } else { // self.mode == "view"
            self.eventsTable.mode = "view";
        }

        self.eventsTable.entries = self.entry.events;
        self.eventsTable.render();
    },
    saveFields: function() {
        var self = this;

        AuditPage.__super__.saveFields.call(self);

        self.entry.events = self.eventsTable.entries;
    }
});
