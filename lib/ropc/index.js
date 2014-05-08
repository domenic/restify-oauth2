"use strict";

var makeSetup = require("../common/makeSetup");
var grantToken = require("./grantToken");

var grantTypes = ["password", "refresh_token"];
var requiredHooks = ["validateClient", "grantUserToken", "authenticateToken"];

module.exports = makeSetup(grantTypes, requiredHooks, grantToken);
