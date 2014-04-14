"use strict";

var makeSetup = require("../common/makeSetup");
var grantToken = require("./grantToken");

var grantTypes = "client_credentials";
var requiredHooks = ["grantClientToken", "authenticateToken"];

module.exports = makeSetup(grantTypes, requiredHooks, grantToken);
