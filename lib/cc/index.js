"use strict";

var makeEntryPoint = require("../common/makeEntryPoint");
var grantToken = require("./grantToken");

var grantTypes = "client_credentials";
var reqPropertyName = "clientId";
var requiredHooks = ["grantClientToken", "authenticateToken"];

module.exports = makeEntryPoint(grantTypes, reqPropertyName, requiredHooks, grantToken);
