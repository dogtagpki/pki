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
    enable: function(options) {
        var self = this;
        $.ajax({
            type: "POST",
            url: self.url() + "?action=enable",
            dataType: "json"
        }).done(function(data, textStatus, jqXHR) {
            self.set(self.parseResponse(data));
            if (options.success) options.success.call(self, data, textStatus, jqXHR);
        }).fail(function(jqXHR, textStatus, errorThrown) {
            if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
        });
    },
    disable: function(options) {
        var self = this;
        $.ajax({
            type: "POST",
            url: self.url() + "?action=disable",
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
    open: function(td) {
        var self = this;

        // in view mode all events are read-only
        if (self.table.mode == "view") {
            return;
        }

        // mandatory events are read-only
        var value = self.get("value");
        if (value == "mandatory") {
            return;
        }

        // optional events are editable in edit mode
        AuditTableItem.__super__.open.call(self, td);
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

        self.enableLink = $("a[name='enable']", self.menu);
        self.disableLink = $("a[name='disable']", self.menu);

        self.enableLink.click(function(e) {
            var message = "Are you sure you want to enable this entry?";
            if (!confirm(message)) return;
            self.model.enable({
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

        self.disableLink.click(function(e) {
            var message = "Are you sure you want to disable this entry?";
            if (!confirm(message)) return;
            self.model.disable({
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

        var eventDialog = self.$("#event-dialog");

        var eventEditDialog = new Dialog({
            el: eventDialog,
            title: "Edit Event",
            readonly: ["name"],
            actions: ["cancel", "save"]
        });

        var eventViewDialog = new Dialog({
            el: eventDialog,
            title: "Event",
            readonly: ["name", "value"],
            actions: ["close"]
        });

        self.eventsTable = new Table({
            el: self.$("table[name='events']"),
            columnMappings: {
                id: "name"
            },
            editDialog: eventEditDialog,
            viewDialog: eventViewDialog,
            pageSize: 10,
            tableItem: AuditTableItem
        });
    },
    renderContent: function() {
        var self = this;

        AuditPage.__super__.renderContent.call(self);

        var status = self.entry.status;
        if (status == "Disabled") {
            self.enableLink.show();
            self.disableLink.hide();
        } else if (status == "Enabled") {
            self.enableLink.hide();
            self.disableLink.show();
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
