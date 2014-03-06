"use strict";

module.exports = function makeHandleAuthorizeResource(reqPropertyName, errorSenders) {
    return function makeHandleAuthorizeResource(req, res, next, options) {
        req.pause();
        options.hooks.authorizeToken(req[reqPropertyName] || null, req, function (error, authorized) {
            req.resume();

            if (error) {
                return errorSenders.sendWithHeaders(res, options, error);
            }

            if (!authorized) {
                return res.send(400, new Error('Additional Authorization Required'));
            }

            next();
        });
    };
};
