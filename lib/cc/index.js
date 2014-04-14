"use strict";

var makeSetup = require("../common/makeSetup");
var grantToken = require("./grantToken");

var grantTypes = "client_credentials";
var reqPropertyName = "clientId";
var requiredHooks = function (options) {
	return ["grantClientToken", "authenticateToken"];
}

module.exports = makeSetup(grantTypes, reqPropertyName, requiredHooks, grantToken);
