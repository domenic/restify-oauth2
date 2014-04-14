"use strict";

var makeSetup = require("../common/makeSetup");
var grantToken = require("./grantToken");

var grantTypes = "password";
var reqPropertyName = "username";
var requiredHooks = function (options) {
	if (options.clientType === "public") {
		return ["grantUserToken", "authenticateToken"];
	}
	return ["validateClient", "grantUserToken", "authenticateToken"];
}

module.exports = makeSetup(grantTypes, reqPropertyName, requiredHooks, grantToken);
