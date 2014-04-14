"use strict";

var makeSetup = require("../common/makeSetup");
var grantToken = require("./grantToken");

var grantTypes = "password";
var reqPropertyName = "username";
// validateClient hook is not required if {clientType: "public"} is passed as an option
var requiredHooks = ["validateClient", "grantUserToken", "authenticateToken"];

module.exports = makeSetup(grantTypes, reqPropertyName, requiredHooks, grantToken);
