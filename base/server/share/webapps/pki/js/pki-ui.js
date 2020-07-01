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

var Page = Backbone.View.extend({
    initialize: function(options) {
        var self = this;
        options = options || {};
        Page.__super__.initialize.call(self, options);

        self.url = options.url;
    },
    open: function() {
        var self = this;
        // load template
        self.$el.load(self.url, function(response, status, xhr) {
            // load content
            self.load();
        });
    },
    load: function() {
    }
});

var Dialog = Backbone.View.extend({
    initialize: function(options) {
        var self = this;
        options = options || {};
        Dialog.__super__.initialize.call(self, options);

        self.body = self.$(".modal-body");

        self.title = options.title;
        self.content = options.content;
        self.entry = options.entry || {};

        // list of readonly fields
        // by default all fields are editable
        self.readonly = options.readonly || [];

        // list of active actions
        self.actions = options.actions;
        if (self.actions == undefined) {
            // by default all buttons are active
            self.actions = [];
            self.$(".modal-footer button").each(function(index) {
                var button = $(this);
                var action = button.attr("name");
                self.actions.push(action);
            });
        }

        self.handlers = {};

        // add default handlers
        self.handlers["cancel"] = function() {
            self.close();
        };
        self.handlers["close"] = function() {
            self.close();
        };

        self.$el.modal({ show: false });
    },
    render: function() {
        var self = this;

        if (self.title) {
            self.$(".modal-title").text(self.title);
        }

        if (self.content) {
            self.body.html(self.content);
        }

        // setup input fields
        // TODO: handle drop-down lists
        $("input, textarea", self.body).each(function(index) {
            var input = $(this);
            var name = input.attr("name");
            if (_.contains(self.readonly, name)) {
                input.attr("readonly", "readonly");
            } else {
                input.removeAttr("readonly");
            }
        });

        // setup buttons
        self.$(".modal-footer button").each(function(index) {
            var button = $(this);
            var action = button.attr("name");

            if (_.contains(self.actions, action)) {
                // enable buttons for specified actions
                button.show();
                button.click(function(e) {
                    var handler = self.handlers[action];
                    handler.call(self);
                    e.preventDefault();
                });

            } else {
                // hide unused buttons
                button.hide();
            }
        });

        self.load();
    },
    handler: function(name, handler) {
        var self = this;
        self.handlers[name] = handler;
    },
    open: function() {
        var self = this;
        self.render();
        self.$el.modal("show");
    },
    close: function() {
        var self = this;
        self.$el.modal("hide");

        // remove event handlers
        self.$(".modal-footer button").each(function(index) {
            var button = $(this);
            button.off("click");
        });
        self.trigger("close");
    },
    load: function() {
        var self = this;

        // load input fields
        $("input, select, textarea", self.body).each(function(index) {
            var input = $(this);
            self.loadField(input);
        });
    },
    loadField: function(input) {
        var self = this;
        var name = input.attr("name");
        var value = self.entry[name];
        if (value === undefined) value = "";
        input.val(value);
    },
    save: function() {
        var self = this;

        // save input fields
        self.$(".modal-body input").each(function(index) {
            var input = $(this);
            self.saveField(input);
        });

        // save drop-down lists
        self.$(".modal-body select").each(function(index) {
            var input = $(this);
            self.saveField(input);
        });

        // save textareas
        self.$(".modal-body textarea").each(function(index) {
            var input = $(this);
            self.saveField(input);
        });
    },
    saveField: function(input) {
        var self = this;
        var name = input.attr("name");
        var value = input.val();
        self.entry[name] = value;
    }
});

var ErrorDialog = Backbone.View.extend({
    initialize: function(options) {
        var self = this;
        options = options || {};
        ErrorDialog.__super__.initialize.call(self, options);

        var response = options.response;
        if (response && response.responseJSON !== undefined) {
            self.title = "HTTP Error " + response.responseJSON.Code;
            self.content = response.responseJSON.Message;

        } else if (response && response.responseText !== undefined) {
            self.title = "HTTP Error " + response.status;

            if (response.getResponseHeader("Content-Type") === "text/html") {
                self.htmlContent = response.responseText;
            } else {
                self.content = response.responseText;
            }

        } else {
            self.title = options.title;
            self.content = options.content;
            self.htmlContent = options.htmlContent;
        }
    },
    render: function() {
        var self = this;

        if (self.title) {
            self.$(".modal-title").text(self.title);
        }

        if (self.content) {
            self.$("span[name=content]").text(self.content);

        } else if (self.htmlContent) {
            self.$("span[name=content]").html(self.htmlContent);
        }

        self.$("button[name=close]").click(function(e) {
            self.close();
            e.preventDefault();
        });
    },
    open: function() {
        var self = this;
        self.render();
        self.$el.show();
    },
    close: function() {
        var self = this;
        self.$el.hide();
        self.trigger("close");
    }
});

var TableItem = Backbone.View.extend({
    initialize: function(options) {
        var self = this;
        options = options || {};
        TableItem.__super__.initialize.call(self, options);

        self.table = options.table;
        self.reset();
    },
    reset: function() {
        var self = this;
        $("td", self.$el).each(function(index) {
            var td = $(this);
            var name = td.attr("name");

            if (td.hasClass("pki-select-column")) {
                // uncheck checkbox and reset the value
                var checkbox = $("input[type='checkbox']", td);
                checkbox.attr("checked", false);
                checkbox.val("");

                // hide checkbox by hiding the label
                $("label", td).hide();

            } else {
                // empty the content
                td.html("&nbsp;");
            }
        });
    },
    render: function() {
        var self = this;

        var template = self.table.template;
        var templateCheckbox = $("input[type='checkbox']", template);
        var prefix = templateCheckbox.attr("id") + "-";

        var templateTDs = $("td", self.table.template);
        $("td", self.$el).each(function(index) {
            var td = $(this);
            var name = td.attr("name");
            var templateTD = $(templateTDs[index]);

            if (td.hasClass("pki-select-column")) {
                // generate a unique input ID based on entry ID
                var entryID = self.get("id")
                var inputID = prefix + entryID;

                // set the checkbox ID and value
                var checkbox = $("input[type='checkbox']", td);
                checkbox.attr("id", inputID);
                checkbox.attr("checked", false);
                checkbox.val(entryID);

                // point the label to the checkbox and make it visible
                var label = $("label", td);
                label.attr("for", inputID);
                label.show();

            } else {
                self.renderColumn(td, templateTD);
            }
        });
    },
    isSelected: function() {
        var self = this;

        var checkbox = $("td.pki-select-column input", self.$el);

        // skip blank rows
        var value = checkbox.val();
        if (value == "") return false;

        return checkbox.prop("checked");
    },
    get: function(name) {
        var self = this;
        var attribute = self.table.columnMappings[name] || name;
        return self.entry[attribute];
    },
    renderColumn: function(td, templateTD) {
        var self = this;

        // copy content from template
        var content = templateTD.html();
        var newContent = "";

        // substitute ${attribute} with attribute value
        var pattern = /\${([^}]*)}/;

        while (content.length) {
            // search for ${attribute} pattern
            var index = content.search(pattern);
            if (index < 0) {
                newContent += content;
                break;
            }

            // get attribute name
            var fullName = RegExp.$1;

            // split attribute names
            var names = fullName.split(".");

            // get the value from the leaf object
            var value;
            for (var i=0; i<names.length; i++) {
                var name = names[i];
                if (i == 0) {
                    value = self.get(name);
                } else {
                    value = value[name];
                }
                if (! value) break;
            }

            if (value === undefined || value === null) value = "";
            if (value instanceof Date) value = value.toUTCString();

            // replace pattern occurance with attribute value
            newContent += content.substring(0, index) + _.escape(value);

            // process the remaining content
            content = content.substring(index + fullName.length + 3);
        }

        td.html(newContent);
    }
});

var Table = Backbone.View.extend({
    initialize: function(options) {
        var self = this;
        options = options || {};
        Table.__super__.initialize.call(self, options);

        self.entries = options.entries || [];
        self.columnMappings = options.columnMappings || {};
        self.mode = options.mode || "view";
        self.parent = options.parent;

        self.searchFilter = "";
        self.searchAttributes = {};

        self.addDialog = options.addDialog;
        self.editDialog = options.editDialog;
        self.viewDialog = options.viewDialog;
        self.tableItem = options.tableItem || TableItem;

        // number of table rows
        self.pageSize = options.pageSize || 15;

        // current page: 1, 2, 3, ...
        self.page = 1;
        self.totalPages = 1;

        self.thead = $("thead", self.$el);
        self.buttons = $(".pki-table-buttons", self.thead);
        self.addButton = $("[name='add']", self.buttons);
        self.removeButton = $("[name='remove']", self.buttons);

        // setup search field handler
        self.searchField = $("input[name='search']", self.thead);
        self.searchField.keypress(function(e) {
            if (e.which == 13) {

                self.searchFilter = self.searchField.val();

                // show the first page of search results
                self.page = 1;
                self.render();
            }
        });

        // setup add button handler
        self.addButton.click(function(e) {
            self.add();
        });

        // setup remove button handler
        self.removeButton.click(function(e) {
            var items = [];
            var message = "<p>Are you sure you want to remove the following entries?</p>\n<ul>\n";

            // get selected items
            $("input:checked", self.tbody).each(function(index) {
                var input = $(this);
                var id = input.val();
                if (id == "") return;
                items.push(id);
                message = message + "<li>" + id + "</li>\n";
            });

            message = message + "</ul>\n";

            if (items.length == 0) return;

            var dialog = new Dialog({
                el: $("#confirm-dialog"),
                content: message
            });

            dialog.handler("ok", function() {
                self.remove(items);
                dialog.close();
            });

            dialog.open();
        });

        // setup select all handler
        self.selectAllCheckbox = $("input[type='checkbox']", self.thead);
        self.selectAllCheckbox.click(function(e) {
            var checked = $(this).is(":checked");
            $("input[type='checkbox']", self.tbody).prop("checked", checked);
        });

        self.tbody = $("tbody", self.$el);
        self.template = $("tr", self.tbody).detach();

        // create empty rows
        self.items = [];
        for (var i = 0; i < self.pageSize; i++) {
            var tr = self.template.clone();
            var item = new self.tableItem({
                el: tr,
                table: self
            });
            self.items.push(item);
            self.tbody.append(tr);
        }

        self.tfoot = $("tfoot", self.$el);
        self.totalEntriesField = $("span[name='totalEntries']", self.tfoot);
        self.pageField = $("input[name='page']", self.tfoot);
        self.totalPagesField = $("span[name='totalPages']", self.tfoot);

        // setup page jump handler
        self.pageField.keypress(function(e) {
            if (e.which == 13) {
                // parse user entered page number
                self.page = parseInt(self.pageField.val());
                if (isNaN(self.page)) self.page = 1;

                // make sure 1 <= page <= total pages
                self.page = Math.max(self.page, 1);
                self.page = Math.min(self.page, self.totalPages);
                self.render();
            }
        });

        // setup handlers for first, prev, next, and last buttons
        $("a[name='first']", self.tfoot).click(function(e) {
            self.page = 1;
            self.render();
            e.preventDefault();
        });
        $("a[name='prev']", self.tfoot).click(function(e) {
            self.page = Math.max(self.page - 1, 1);
            self.render();
            e.preventDefault();
        });
        $("a[name='next']", self.tfoot).click(function(e) {
            self.page = Math.min(self.page + 1, self.totalPages);
            self.render();
            e.preventDefault();
        });
        $("a[name='last']", self.tfoot).click(function(e) {
            self.page = self.totalPages;
            self.render();
            e.preventDefault();
        });
    },
    render: function() {
        var self = this;

        // perform manual filter
        self.filteredEntries = [];

        _(self.entries).each(function(item, index) {
            if (!self.matchesFilter(item, self.searchFilter)) return;
            self.filteredEntries.push(item);
        });

        self.sort();

        // update controls
        self.renderControls();

        // display entries
        _(self.items).each(function(item, index) {
            self.renderRow(item, index);
        });
    },
    sort: function() {
        var self = this;
        // by default the list is not sorted
    },
    matchesFilter: function(entry, filter) {
        var self = this;

        // check filter against all values in the entry
        var matches = false;
        _(entry).each(function(value, key) {
            if (value && value.indexOf(filter) >= 0) matches = true;
        });

        return matches;
    },
    renderControls: function() {
        var self = this;

        if (self.mode == "view") {
            self.addButton.hide();
            self.removeButton.hide();

        } else { // self.mode == "edit"
            self.addButton.show();
            self.removeButton.show();
        }

        // clear selection
        self.selectAllCheckbox.attr("checked", false);

        // display total entries
        self.totalEntriesField.text(self.totalEntries());

        // display current page number
        self.pageField.val(self.page);

        // calculate and display total number of pages
        self.totalPages = Math.floor(Math.max(0, self.totalEntries() - 1) / self.pageSize) + 1;
        self.totalPagesField.text(self.totalPages);
    },
    renderRow: function(item, index) {
        var self = this;
        var i = (self.page - 1) * self.pageSize + index;
        if (i < self.filteredEntries.length) {
            // show entry in existing row
            item.entry = self.filteredEntries[i];
            item.render();

        } else {
            // clear unused row
            item.reset();
        }
    },
    getSelectedRows: function() {
        var self = this;
        return _.filter(self.items, function(item) { return item.isSelected(); });
    },
    totalEntries: function() {
        var self = this;
        return self.filteredEntries.length;
    },
    open: function(item) {
        var self = this;

        var dialog;
        if (self.mode == "view") {
            dialog = self.viewDialog;

        } else { // self.mode == "edit"
            dialog = self.editDialog;

            dialog.handler("save", function() {

                // save changes
                dialog.save();
                _.extend(item.entry, dialog.entry);

                // redraw table
                self.render();
                dialog.close();
            });
        }

        dialog.entry = _.clone(item.entry);

        dialog.open();
    },
    add: function() {
        var self = this;

        var dialog = self.addDialog;
        dialog.entry = {};

        dialog.handler("add", function() {

            // save new entry
            dialog.save();
            dialog.close();

            try {
                self.addEntry(dialog.entry);

                // redraw table
                self.render();

            } catch (exception) {
                // display the error in an error dialog,
                // then reopen the original dialog

                var errorDialog = new ErrorDialog({
                    el: $("#error-dialog"),
                    content: exception
                });
                errorDialog.on("close", function() {
                    dialog.open();
                });
                errorDialog.open();
            }
        });

        dialog.open();
    },
    addEntry: function(entry) {
        var self = this;

        self.entries.push(entry);
    },
    remove: function(items) {
        var self = this;

        // remove selected entries
        self.entries = _.reject(self.entries, function(entry) {
            return _.contains(items, entry.id);
        });

        // redraw table
        self.render();
    }
});

var ModelTable = Table.extend({
    initialize: function(options) {
        var self = this;
        options = options || {};
        options.mode = options.mode || "edit";
        ModelTable.__super__.initialize.call(self, options);

        self.collection = options.collection;
    },
    render: function() {
        var self = this;

        // if collection is undefined, don't fetch data, just draw the controls
        if (!self.collection) {
            self.renderControls();
            return;
        }

        // set query based on current page, page size, and filter
        var params = {
            start: (self.page - 1) * self.pageSize,
            size: self.pageSize
        };

        if (self.searchFilter != null) {
            params["filter"] = self.searchFilter;
        }

        if (!_.isEmpty(self.searchAttributes)) {
            _.extend(params, self.searchAttributes);
        }

        self.collection.query(params);

        // fetch data based on query
        self.collection.fetch({
            reset: true,
            success: function(collection, response, options) {

                // update controls
                self.renderControls();

                // display entries
                _(self.items).each(function(item, index) {
                    self.renderRow(item, index);
                });
            },
            error: function(collection, response, options) {
                new ErrorDialog({
                    el: $("#error-dialog"),
                    response: response
                }).open();
            }
        });
    },
    renderRow: function(item, index) {
        var self = this;
        if (index < self.collection.length) {
            // show entry in existing row
            var model = self.collection.at(index);
            item.entry = _.clone(model.attributes);
            item.render();

        } else {
            // clear unused row
            item.reset();
        }
    },
    totalEntries: function() {
        var self = this;
        if (!self.collection)
            return 0;
        return self.collection.total;
    },
    open: function(item) {
        var self = this;

        var model = self.collection.get(item.entry.id);

        var dialog = self.editDialog;
        dialog.entry = item.entry;

        dialog.handler("save", function() {

            // save attribute changes
            dialog.save();
            model.set(dialog.entry);

            // if nothing has changed, return
            var changedAttributes = model.changedAttributes();
            if (!changedAttributes) return;

            // save changed attributes with PATCH
            model.save(changedAttributes, {
                patch: true,
                wait: true,
                success: function(model, response, options) {
                    // redraw table after saving entries
                    self.render();
                    dialog.close();
                },
                error: function(model, response, options) {
                    if (response.status == 200) {
                        // redraw table after saving entries
                        self.render();
                        dialog.close();
                        return;
                    }
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        response: response
                    }).open();
                }
            });
        });

        // load data from server
        model.fetch({
            success: function(model, response, options) {
                dialog.open();
            },
            error: function(model, response, options) {
                new ErrorDialog({
                    el: $("#error-dialog"),
                    response: response
                }).open();
            }
        });
    },
    add: function() {
        var self = this;

        var dialog = self.addDialog;

        var model = self.collection.model.call(self.collection);
        dialog.entry = _.clone(model.attributes);

        dialog.handler("add", function() {

            // save new attributes
            dialog.save();
            var entry = {};
            _.each(dialog.entry, function(value, key) {
                if (value == "") return;
                entry[key] = value;
            });

            // save new entry with POST
            model.save(entry, {
                wait: true,
                success: function(model, response, options) {
                    // redraw table after adding new entry
                    self.render();
                    dialog.close();
                },
                error: function(model, response, options) {
                    if (response.status == 201) {
                        // redraw table after adding new entry
                        self.render();
                        dialog.close();
                        return;
                    }
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        response: response
                    }).open();
                }
            });
        });

        dialog.open();
    },
    remove: function(items) {
        var self = this;

        // remove selected entries
        _.each(items, function(id, index) {
            var model = self.collection.get(id);
            model.destroy({
                wait: true,
                success: function(model, response, options) {
                    self.render();
                },
                error: function(model, response, options) {
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        response: response
                    }).open();
                }
            });
        });
    }
});

var EntryPage = Page.extend({
    initialize: function(options) {
        var self = this;
        options = options || {};
        EntryPage.__super__.initialize.call(self, options);

        self.model = options.model;
        self.mode = options.mode || "view";
        self.title = options.title;
        self.editable = options.editable || [];
        self.parentPage = options.parentPage;
        self.parentHash = options.parentHash;
    },
    load: function() {
        var self = this;

        self.setup();
        self.render();
    },
    setup: function() {
        var self = this;

        self.actions = self.$(".pki-actions");

        self.viewMenu = $(".pki-actions-menu[name='view']", self.actions);
        self.editAction = $("[name='edit']", self.viewMenu);

        self.editMenu = $(".pki-actions-menu[name='edit']", self.actions);
        self.cancelAction = $("[name='cancel']", self.editMenu);
        self.saveAction = $("[name='save']", self.editMenu);

        self.idField = self.$("input[name='id']");
        self.statusField = self.$("input[name='status']");

        $("a", self.editAction).click(function(e) {
            self.mode = "edit";
            self.render();
            e.preventDefault();
        });

        self.cancelAction.click(function(e) {
            self.cancel();
            e.preventDefault();
        });

        self.saveAction.click(function(e) {
            e.preventDefault();
            try {
                self.saveEntry();
            } catch (exception) {
                new ErrorDialog({
                    el: $("#error-dialog"),
                    title: "ERROR",
                    content: exception
                }).open();
            }
        });

    },
    render: function() {
        var self = this;

        if (self.mode == "add") {
            self.renderContent();
            return;
        }

        self.model.fetch({
            success: function(model, response, options) {
                self.renderContent();
            }
        });
    },
    renderContent: function() {
        var self = this;

        if (self.mode == "add") {
            // Use blank entry.
            self.entry = {};

            // Replace title.
            self.$("span[name='title']").text(self.title);

        } else {
            // Use fetched entry.
            self.entry = _.clone(self.model.attributes);

            // Update title with entry attributes.
            self.$("span[name='title']").each(function() {
                var title = $(this);
                var text = title.text();
                title.text(PKI.substitute(text, self.entry));
            });

        }

        if (self.mode == "view") {
            // All fields are read-only.
            self.$(".pki-fields input, select, textarea").each(function(index) {
                var input = $(this);
                input.attr("readonly", "readonly");
            });

            self.viewMenu.show();
            self.editMenu.hide();

        } else {

            // Show editable fields.
            self.$(".pki-fields input, select, textarea").each(function(index) {
                var input = $(this);
                var name = input.attr("name");
                if (_.contains(self.editable, name)) {
                    input.removeAttr("readonly");
                } else {
                    input.attr("readonly", "readonly");
                }
            });

            self.viewMenu.hide();
            self.editMenu.show();
        }

        self.$(".pki-fields input, select, textarea").each(function(index) {
            var input = $(this);
            self.loadField(input);
        });
    },
    loadField: function(input) {
        var self = this;
        var name = input.attr("name");
        var value = self.entry[name];
        if (value === undefined) value = "";
        if (value instanceof Date) value = value.toUTCString();
        input.val(value);
    },
    close: function() {
        var self = this;

        if (self.parentHash) {
            window.location.hash = self.parentHash;

        } else if (self.parentPage) {
            self.parentPage.open();

        } else {
            self.mode = "view";
            self.render();
        }
    },
    cancel: function() {
        var self = this;
        self.close();
    },
    saveEntry: function() {
        var self = this;

        self.saveFields();

        if (self.mode == "add") {
            // save new entry with POST
            self.model.save(self.entry, {
                wait: true,
                success: function(model, response, options) {
                    self.close();
                },
                error: function(model, response, options) {
                    if (response.status == 201) {
                        self.close();
                        return;
                    }
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        response: response
                    }).open();
                }
            });
        } else {
            // save changed entry with PATCH
            self.model.save(self.entry, {
                patch: true,
                wait: true,
                success: function(model, response, options) {
                    self.close();
                },
                error: function(model, response, options) {
                    if (response.status == 200) {
                        self.close();
                        return;
                    }
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        response: response
                    }).open();
                }
            });
        }
    },
    saveFields: function() {
        var self = this;

        self.$(".pki-fields input").each(function(index) {
            var input = $(this);
            self.saveField(input);
        });
    },
    saveField: function(input) {
        var self = this;

        var name = input.attr("name");
        var value = input.val();
        // save all values including empty ones
        self.entry[name] = value;
    },
    changeStatus: function(action, message) {
        var self = this;

        var dialog = new Dialog({
            el: $("#confirm-dialog"),
            content: message
        });

        dialog.handler("ok", function() {

            self.model.changeStatus(action, {
                success: function(data, textStatus, response) {
                    self.entry = _.clone(self.model.attributes);
                    self.render();
                },
                error: function(response, textStatus, errorThrown) {
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        response: response
                    }).open();
                }
            });

            dialog.close();
        });

        dialog.open();
    }
});

var HomePage = Page.extend({
    load: function() {
        var self = this;
        self.update();
    },
    update: function() {
        if (!PKI.user) return;
        var roles = PKI.user.Roles.Role;

        var home_accounts = self.$("[name=home-accounts]");
        if (_.contains(roles, "Administrators")) {
            home_accounts.show();
        } else {
            home_accounts.hide();
        }
    }
});
