//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

function getDirectory(options) {
    $.get({
        url: "directory",
        dataType: "json"
    }).done(function(data, textStatus, jqXHR) {
        if (options.success) options.success.call(self, data, textStatus, jqXHR);
    }).fail(function(jqXHR, textStatus, errorThrown) {
        if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
    });
}

function getLoginInfo(options) {
    $.get({
        url: "login",
        dataType: "json"
    }).done(function(data, textStatus, jqXHR) {
        if (options.success) options.success.call(self, data, textStatus, jqXHR);
    }).fail(function(jqXHR, textStatus, errorThrown) {
        if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
    });
}

function login(options) {
    $.post({
        url: "login",
        dataType: "json"
    }).done(function(data, textStatus, jqXHR) {
        if (options.success) options.success.call(self, data, textStatus, jqXHR);
    }).fail(function(jqXHR, textStatus, errorThrown) {
        if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
    });
}

function logout(options) {
    $.post({
        url: "logout",
        dataType: "json"
    }).done(function(data, textStatus, jqXHR) {
        if (options.success) options.success.call(self, data, textStatus, jqXHR);
    }).fail(function(jqXHR, textStatus, errorThrown) {
        if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
    });
}

function enable(options) {
    $.post({
        url: "enable"
    }).done(function(data, textStatus, jqXHR) {
        if (options.success) options.success.call(self, data, textStatus, jqXHR);
    }).fail(function(jqXHR, textStatus, errorThrown) {
        if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
    });
}

function disable(options) {
    $.post({
        url: "disable"
    }).done(function(data, textStatus, jqXHR) {
        if (options.success) options.success.call(self, data, textStatus, jqXHR);
    }).fail(function(jqXHR, textStatus, errorThrown) {
        if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
    });
}

function updateHomePage() {
    getDirectory({
        success: function(data, textStatus, jqXHR) {
            $("#metadata-termsOfService").text(data.meta.termsOfService);
            $("#metadata-termsOfService").attr("href", data.meta.termsOfService);
            $("#metadata-website").text(data.meta.website);
            $("#metadata-website").attr("href", data.meta.website);
            $("#metadata-caaIdentities").text(data.meta.caaIdentities.join(", "));
            $("#metadata-externalAccountRequired").text(data.meta.externalAccountRequired);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (jqXHR.status == 503) {
                $("#metadata-termsOfService").text("");
                $("#metadata-termsOfService").attr("href", "#");
                $("#metadata-website").text("");
                $("#metadata-website").attr("href", "#");
                $("#metadata-caaIdentities").text("");
                $("#metadata-externalAccountRequired").text("");
            } else {
                alert('ERROR: ' + errorThrown);
            }
        }
    });
}

function updateConfigPage() {
    getDirectory({
        success: function(data, textStatus, jqXHR) {
            $("#service-status").text("Available");
            $("#service-enable").hide();
            $("#service-disable").show();
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (jqXHR.status == 503) {
                $("#service-status").text("Unavailable");
                $("#service-disable").hide();
                $("#service-enable").show();
            } else {
                alert('ERROR: ' + errorThrown);
            }
        }
    });
}

function updateBaseURL() {

    // replace BASE_URL with actual base URL
    var i = window.location.href.lastIndexOf('/');
    var base_url = window.location.href.substring(0, i);

    $("pre").each(function() {
        var content = this.innerText;
        this.innerText = content.replace("BASE_URL", base_url);
    });
}

function setUserProfile(data) {
    $("#profile-fullName").text(data.FullName);
    $(".login-menu").hide();
    $(".logout-menu").show();

    if (data.Roles.Role.includes("Administrators")) {
        $(".config-menu").show();
    }
}

function clearUserProfile() {
    $("#profile-fullName").text("");
    $(".login-menu").show();
    $(".logout-menu").hide();
    $(".config-menu").hide();

    $("#sidebar a").removeClass("pf-m-current");
    $(".home-menu a").addClass("pf-m-current");

    loadPage("home.jsp", function() {
        updateHomePage();
    });
}

function updateLoginInfo() {
    getLoginInfo({
        success: function(data, textStatus, jqXHR) {
            if (jqXHR.status == 200) {
                setUserProfile(data);
            } else {
                clearUserProfile();
            }

        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert('ERROR: ' + errorThrown);
        }
    });
}

function showProfileMenu() {

    var button = $("#profile-menu");
    button.attr("aria-expanded", true);

    var parent = button.parent();
    parent.addClass("pf-m-expanded");

    var menu = $("ul[aria-labelledby='profile-menu']");
    menu.attr("hidden", false);
}

function hideProfileMenu() {

    var button = $("#profile-menu");
    button.attr("aria-expanded", false);

    var parent = button.parent();
    parent.removeClass("pf-m-expanded");

    var menu = $("ul[aria-labelledby='profile-menu']");
    menu.attr("hidden", true);
}

function activateProfileMenu() {

    $("#profile-menu").on({
        click: function() {
            var collapsed = $(this).attr("aria-expanded") == "false";
            if (collapsed) {
                showProfileMenu();
            } else {
                hideProfileMenu();
            }
        },
        keydown: function (e) {
            if (e.which === 27) {
                hideProfileMenu();
                e.preventDefault();
            }
        }
    });

    $(".login-menu a").on({
        click: function() {
            hideProfileMenu();
            login({
                success: function(data, textStatus, jqXHR) {
                    if (jqXHR.status == 200) {
                        setUserProfile(data);
                    } else {
                        clearUserProfile();
                    }
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    alert('ERROR: ' + errorThrown);
                }
            });
        },
        keydown: function (e) {
            if (e.which === 27) {
                hideProfileMenu();
                e.preventDefault();
            }
        }
    });

    $(".logout-menu a").on({
        click: function() {
            hideProfileMenu();
            logout({
                success: function(data, textStatus, jqXHR) {
                    clearUserProfile();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    alert('ERROR: ' + errorThrown);
                }
            });
        },
        keydown: function (e) {
            if (e.which === 27) {
                hideProfileMenu();
                e.preventDefault();
            }
        }
    });
}

function activateConfigMenu() {

    $("#service-enable a").on({
        click: function() {
            enable({
                success: function(data, textStatus, jqXHR) {
                    updateConfigPage();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    alert('ERROR: ' + errorThrown);
                }
            });
        }
    });

    $("#service-disable a").on({
        click: function() {
            disable({
                success: function(data, textStatus, jqXHR) {
                    updateConfigPage();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    alert('ERROR: ' + errorThrown);
                }
            });
        }
    });
}

function loadPage(url, callback) {
    $(".pf-c-content").load(url, callback);
}

function activateSidebarMenu() {

    $(".home-menu a").on({
        click: function() {
            $("#sidebar a").removeClass("pf-m-current");
            $(this).addClass("pf-m-current");
            loadPage("home.jsp", function() {
                updateHomePage();
            });
        }
    });

    $(".services-menu a").on({
        click: function() {
            $("#sidebar a").removeClass("pf-m-current");
            $(this).addClass("pf-m-current");
            loadPage("services.jsp", function() {
                updateBaseURL();
            });
        }
    });

    $(".config-menu a").on({
        click: function() {
            $("#sidebar a").removeClass("pf-m-current");
            $(this).addClass("pf-m-current");
            loadPage("config.jsp", function() {
                updateConfigPage();
                activateConfigMenu();
            });
        }
    });
}

function activateSidebarToggle() {

    $("#sidebar-toggle").click(function() {
        var sidebar = $(".pf-c-page__sidebar");
        var width = $(window).width();

        if (width >= 1200) {
            sidebar.removeClass("pf-m-expanded");
            var collapsed = sidebar.hasClass("pf-m-collapsed");
            if (collapsed) {
                sidebar.removeClass("pf-m-collapsed");
            } else {
                sidebar.addClass("pf-m-collapsed");
            }

        } else {
            sidebar.removeClass("pf-m-collapsed");
            var expanded = sidebar.hasClass("pf-m-expanded");
            if (expanded) {
                sidebar.removeClass("pf-m-expanded");
            } else {
                sidebar.addClass("pf-m-expanded");
            }
        }
    });

    $(".pf-c-page__main").click(function() {
        var sidebar = $(".pf-c-page__sidebar");
        sidebar.removeClass("pf-m-expanded");
    });
}
