import ballerina/http;
import ballerina/jwt;
import ballerina/io;

type RiskResponse record {
    boolean hasRisk;
};

type RiskRequest record {
    string username;
    string loggingIp;
};

service / on new http:Listener(8090) {
    resource function post risk(http:Headers headers, @http:Payload RiskRequest req) returns http:Unauthorized|error|RiskResponse {

        RiskResponse resp = {
            hasRisk: true
        };

        io:println("recieved");

        io:println(getIssuer(headers));

        io:println((check headers.getHeader("x-jwt-assertion")).toString());

        if (getIssuer(headers) == "https://api.asgardeo.io/t/sachinmtestorg2/oauth2/token"){
            if (check checkScopes(headers) ?: false) {
                return resp;
            }
        }
        return http:UNAUTHORIZED;
    }
}

function getIssuer(http:Headers headers) returns string|error {

    var jwtHeader = headers.getHeader("x-jwt-assertion");
    if jwtHeader is http:HeaderNotFoundError {
        var authHeader = headers.getHeader("Authorization");
        if authHeader is http:HeaderNotFoundError {
            return authHeader;
        } else {
            if (authHeader.startsWith("Bearer ")) {
                jwtHeader = authHeader.substring(7);
            }
        }
    }

    if (jwtHeader is http:HeaderNotFoundError) {
        return jwtHeader;
    }

    [jwt:Header, jwt:Payload] [_, payload] = check jwt:decode(jwtHeader);
    return <string>payload.iss;
}

function checkScopes(http:Headers headers) returns boolean|error? {

    var jwtHeader = headers.getHeader("x-jwt-assertion");
    if jwtHeader is http:HeaderNotFoundError {
        var authHeader = headers.getHeader("Authorization");
        if authHeader is http:HeaderNotFoundError {
            return authHeader;
        } else {
            if (authHeader.startsWith("Bearer ")) {
                jwtHeader = authHeader.substring(7);
            }
        }
    }

    if (jwtHeader is http:HeaderNotFoundError) {
        return jwtHeader;
    }

    [jwt:Header, jwt:Payload] [_, payload] = check jwt:decode(jwtHeader);

    if (payload.hasKey("scope")) {
        if (payload["scope"] == "scope1 scope2") {
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}
