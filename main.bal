import ballerina/http;
import ballerina/jwt;
import ballerina/time;
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

        if (getIssuer(headers) == "https://api.asgardeo.io/t/sachinmtestorg2/oauth2/token"){
            if (check checkScopes(headers) ?: false) {
                if (check checkIat(headers) ?: false) {
                    return resp;
                }
            }
        }
        return http:UNAUTHORIZED;
    }
}

function getIssuer(http:Headers headers) returns string|error {

    var authHeader = headers.getHeader("Authorization");
    if authHeader is http:HeaderNotFoundError {
        return authHeader;
    } else {
        if (authHeader.startsWith("Bearer ")) {
            authHeader = authHeader.substring(7);
        }
    }

    if (authHeader is http:HeaderNotFoundError) {
        return authHeader;
    }

    [jwt:Header, jwt:Payload] [_, payload] = check jwt:decode(authHeader);
    return <string>payload.iss;
}

function checkScopes(http:Headers headers) returns boolean|error? {

    var authHeader = headers.getHeader("Authorization");
    if authHeader is http:HeaderNotFoundError {
        return authHeader;
    } else {
        if (authHeader.startsWith("Bearer ")) {
            authHeader = authHeader.substring(7);
        }
    }

    if (authHeader is http:HeaderNotFoundError) {
        return authHeader;
    }

    [jwt:Header, jwt:Payload] [_, payload] = check jwt:decode(authHeader);

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

function checkIat(http:Headers headers) returns boolean|error? {

    var authHeader = headers.getHeader("Authorization");
    if authHeader is http:HeaderNotFoundError {
        return authHeader;
    } else {
        if (authHeader.startsWith("Bearer ")) {
            authHeader = authHeader.substring(7);
        }
    }

    if (authHeader is http:HeaderNotFoundError) {
        return authHeader;
    }

    [jwt:Header, jwt:Payload] [_, payload] = check jwt:decode(authHeader);

    if (payload.hasKey("iat")) {
        int iat = <int>payload["iat"];
        time:Utc currentUtc = time:utcNow();
        int currentTime = currentUtc[0];
        
        // Optional: Define an acceptable time window, e.g., 5 minutes (300 seconds)
        int acceptableWindow = 300;

        io:println("test");
        io:println((currentTime - iat));

        // Check if the iat is within the acceptable time window
        if ((currentTime - iat) <= acceptableWindow) {
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}