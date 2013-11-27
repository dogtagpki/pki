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

var TableItemView = Backbone.View.extend({
    render: function() {
        var self = this;
        $("td", self.el).each(function(index) {
            var item = $(this);
            var name = item.attr("name");
            var value = self.model.get(name);
            item.text(value);
        });
    }
});

var TableView = Backbone.View.extend({
    initialize: function() {
        var self = this;
        self.tbody = $("tbody", self.el);
        self.template = $("tr", self.tbody).detach();
        self.render();
    },
    render: function() {
        var self = this;
        self.collection.fetch({
            success: function() {
                _(self.collection.models).each(function(item) {
                    var itemView = new TableItemView({
                        el: self.template.clone(),
                        model: item
                    });
                    itemView.render();
                    self.tbody.append(itemView.el);
                }, self);
            }
        });
    }
});
