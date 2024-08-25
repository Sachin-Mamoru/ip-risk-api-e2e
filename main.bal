import ballerina/http;
import ballerina/jwt;
import ballerina/time;

configurable string issuer = ?;
configurable string requiredScopes = ?;

type RiskResponse record {
    boolean hasRisk;
    RiskRequest data;
};

type User record {
    string firstName;
    string lastName;
};

type UserInfo record {
    User user;
    int age;
};

type RiskRequest record {
    string username;
    string loggingIp;
    UserInfo userInfo;
};

service / on new http:Listener(8090) {
    resource function get risk(http:Headers headers) returns http:Unauthorized|error|RiskResponse {

        // Create a dummy dataset
        RiskRequest req = {
            username: "dummyUser",
            loggingIp: "192.168.1.1",
            userInfo: {
                user: {
                    firstName: "John",
                    lastName: "Doe"
                },
                age: 30
            }
        };
        
        RiskResponse resp = {
            hasRisk: true,
            data: req
        };

        if (getIssuer(headers) == issuer){
            if (check checkScopes(headers) ?: false) {
                if (check checkIat(headers) ?: false) {
                    return resp;
                }
            }
        }
        return http:UNAUTHORIZED;
    }
    resource function post risk(http:Headers headers, @http:Payload RiskRequest req) returns http:Unauthorized|error|RiskResponse {

        RiskResponse resp = {
            hasRisk: true,
            data: req
        };

        if (getIssuer(headers) == issuer){
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
        if (payload["scope"] == requiredScopes) {
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
