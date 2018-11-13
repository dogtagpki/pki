<!-- --- BEGIN COPYRIGHT BLOCK ---
     This program is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published by
     the Free Software Foundation; version 2 of the License.

     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU General Public License for more details.

     You should have received a copy of the GNU General Public License along
     with this program; if not, write to the Free Software Foundation, Inc.,
     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

     Copyright (C) 2018 Red Hat, Inc.
     All rights reserved.
     --- END COPYRIGHT BLOCK --- -->
<html>
<head>
    <title>Certificate Authority</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="/pki/css/patternfly.css" rel="stylesheet" media="screen, print">
    <link href="/pki/css/pki-ui.css" rel="stylesheet" type="text/css">
    <script src="/pki/js/jquery.js"></script>
    <script src="/pki/js/underscore.js"></script>
    <script src="/pki/js/backbone.js"></script>
    <script src="/pki/js/bootstrap.js"></script>
    <script src="/pki/js/patternfly.js"></script>
    <script src="/pki/js/pki.js"></script>
    <script src="/pki/js/pki-ui.js"></script>
    <script src="/pki/js/pki-banner.js"></script>
    <script src="/pki/js/pki-account.js"></script>
    <script src="/pki/js/pki-group.js"></script>
    <script src="/pki/js/pki-user.js"></script>
    <script src="/ca/js/cert.js"></script>
    <script>
$(function() {

    var content = $("#content");

    var router = new Backbone.Router();

    router.route("", "home", function() {
        new HomePage({
            el: content,
            url: "/ca/ui/home.html"
        }).open();
    });

    router.route("certs", "certs", function() {
        new CertificatesPage({
            el: content,
            url: "certs.html",
            collection: new CertificateCollection()
        }).open();
    });

    router.route("certs/:id", "cert", function(id) {
        new CertificatePage({
            el: content,
            url: "cert.html",
            model: new CertificateModel({ id: id })
        }).open();
    });

    router.route("users", "users", function() {
        new UsersPage({
            el: content,
            collection: new UserCollection(null, {
                urlRoot: "/ca/rest/admin/users"
            }),
            url: "/pki/ui/users.html"
        }).open();
    });

    router.route("users/:id", "user", function(id) {
        new UserPage({
            el: content,
            url: "/pki/ui/user.html",
            model: new UserModel({ id: id }, {
                urlRoot: "/ca/rest/admin/users"
            }),
            editable: ["fullName", "email"]
        }).open();
    });

    router.route("users/:id/roles", "user-roles", function(id) {
        new UserRolesPage({
            el: content,
            url: "/pki/ui/user-roles.html",
            collection: new UserRoleCollection(null, {
                userID: id,
                urlRoot: "/ca/rest/admin/users/" + id + "/memberships"
            })
        }).open();
    });

    router.route("users/:id/certs", "user-certs", function(id) {
        new UserCertsPage({
            el: content,
            url: "/pki/ui/user-certs.html",
            collection: new UserCertCollection(null, {
                userID: id,
                urlRoot: "/ca/rest/admin/users/" + id + "/certs"
            })
        }).open();
    });

    router.route("new-user", "new-user", function() {
        new UserPage({
            el: content,
            url: "/pki/ui/user.html",
            model: new UserModel(null, {
                urlRoot: "/ca/rest/admin/users"
            }),
            mode: "add",
            title: "New User",
            editable: ["userID", "fullName", "email"],
            parentHash: "#users"
        }).open();
    });

    router.route("groups", "groups", function() {
        new GroupsPage({
            el: content,
            collection: new GroupCollection(null, {
                urlRoot: "/ca/rest/admin/groups"
            }),
            url: "/pki/ui/groups.html"
        }).open();
    });

    router.route("groups/:id", "group", function(id) {
        new GroupPage({
            el: content,
            url: "/pki/ui/group.html",
            model: new GroupModel({ id: id }, {
                urlRoot: "/ca/rest/admin/groups"
            }),
            editable: ["description"]
        }).open();
    });

    router.route("new-group", "new-group", function() {
        new GroupPage({
            el: content,
            url: "/pki/ui/group.html",
            model: new GroupModel(null, {
                urlRoot: "/ca/rest/admin/groups"
            }),
            mode: "add",
            title: "New Group",
            editable: ["groupID", "description"],
            parentHash: "#groups"
        }).open();
    });

    router.route("logout", "logout", function() {
        // destroy server session
        account.logout({
            success: function() {
                // clear browser cache
                PKI.logout({
                    success: function() {
                        window.location.href = "/ca";
                    },
                    error: function() {
                        alert("Logout not supported by the browser. Please clear Active Logins or close the browser.");
                    }
                });
            },
            error: function() {
                alert("Logout failed. Please close the browser.");
            }
        });
    });

    var account = new Account("/ca/rest/account");

    account.login({
        success: function(data, textStatus, jqXHR) {
            var roles = PKI.user.Roles.Role;

            var user = $("#navigation [name=account] [name=username]");
            user.text(PKI.user.FullName);

            var accounts_menu = $("#navigation [name=accounts]");
            if (_.contains(roles, "Administrators")) {
                accounts_menu.show();
            } else {
                accounts_menu.hide();
            }

            Backbone.history.start();
        },
        error: function(jqXHR, textStatus, errorThrown) {
            window.location.href = "/ca";
        }
    });
});
    </script>
</head>
<body>

<nav id="navigation" class="navbar navbar-default navbar-pf" role="navigation">
<div class="navbar-header">
    <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse-1">
        <span class="sr-only">Toggle navigation</span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
    </button>
    <a class="navbar-brand" href="/ca">
        <b>Certificate Authority</b>
    </a>
</div>
<div class="collapse navbar-collapse navbar-collapse-1">
    <ul class="nav navbar-nav navbar-utility">
<!--
    <li name="status"><a href="#">Status</a></li>
-->
    <li name="account" class="dropdown">
        <a href="#" class="dropdown-toggle" data-toggle="dropdown">
        <span class="pficon pficon-user"></span>
        <span name="username"></span><b class="caret"></b>
        </a>
        <ul class="dropdown-menu">
        <li name="logout"><a href="#logout">Logout</a></li>
        </ul>
    </li>
    </ul>
    <ul class="nav navbar-nav navbar-primary">

    <li name="home"><a href="#"><span class="glyphicon glyphicon-home"></span> Home</a></li>

    <li name="certs"><a href="#certs">Certificates</a></li>

    <li name="accounts" class="dropdown context" style="display: none;">
      <a href="#" class="dropdown-toggle" data-toggle="dropdown">
        Accounts
        <b class="caret"></b>
      </a>
      <ul class="dropdown-menu">
        <li><a href="#users">Users</a></li>
        <li><a href="#groups">Groups</a></li>
      </ul>
    </li>
    </ul>
</div>
</nav>

<div id="content">
</div>

<div id="confirm-dialog" class="modal">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-hidden="true">
                    <span class="pficon pficon-close"></span>
                </button>
                <h4 class="modal-title">Confirmation</h4>
            </div>
            <div class="modal-body">
            </div>
            <div class="modal-footer">
                <button name="ok" class="btn btn-danger">OK</button>
                <button name="cancel" class="btn btn-default" data-dismiss="modal">Cancel</button>
            </div>
        </div>
    </div>
</div>

<div id="error-dialog" class="modal">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-hidden="true">
                    <span class="pficon pficon-close"></span>
                </button>
                <h4 class="modal-title">Error</h4>
            </div>
            <div class="modal-body">
		        <fieldset>
		            <span name="content"></span>
		        </fieldset>
            </div>
            <div class="modal-footer">
                <button name="close" class="btn btn-primary">Close</button>
            </div>
        </div>
    </div>
</div>

</body>
</html>
