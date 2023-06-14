var exec = require('cordova/exec');

function validateStringParam(param, paramName) {
    if (!(typeof param === "string")) throw new Error(`Parameter ${paramName} must be a string`);
    if (param.length === 0) throw new Error(`Parameter ${paramName} was empty`);
}

function validateStringProp(obj, objName, propName) {
    if (!(typeof obj[propName] === "string")) throw new Error(`Property '${propName}' in ${objName} must be a string`);
    if (obj[propName].length === 0) throw new Error(`Property '${propName}' in ${objName} must not be empty`);
}

function validateCredentials(credentials) {
    for (propName of ["username", "password", "server"]) {
        validateStringProp(credentials, "credentials", propName);
    }
}

var BiometricSecrets = {
    addCredentials: function (credentials) {
        return new Promise((resolve, reject) => {
            validateCredentials(credentials);
            exec(resolve, reject, "BiometricSecrets", "addCredentials", [credentials]);
        });
    },
    readCredentials: function (server) {
        return new Promise((resolve, reject) => {
            validateStringParam(server, "server");
            exec(resolve, reject, "BiometricSecrets", "readCredentials", [server]);
        });
    },
    removeCredentials: function (server) {
        return new Promise((resolve, reject) => {
            validateStringParam(server, "server");
            exec(resolve, reject, "BiometricSecrets", "removeCredentials", [server]);
        });
    }
}

module.exports = BiometricSecrets;
