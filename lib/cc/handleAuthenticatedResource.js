"use strict";

var errorSenders = require("./errorSenders");
module.exports = require("../common/handleAuthenticatedResource")("clientId", errorSenders);
