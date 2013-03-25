"use strict";

var makeEntryPoint = require("../common/makeEntryPoint");
var grantToken = require("./grantToken");

var grantTypes = "password";
var reqPropertyName = "username";
var requiredHooks = ["validateClient", "grantUserToken", "authenticateToken"];

module.exports = makeEntryPoint(grantTypes, reqPropertyName, requiredHooks, grantToken);
