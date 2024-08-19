import ballerina/http;

type RiskResponse record {
    boolean hasRisk;
};

type RiskRequest record {
    string username;
    string loggingIp;
};

type ipGeolocationResp record {
    string ip;
    string country_code2;
};

service / on new http:Listener(8090) {
    resource function post risk(@http:Payload RiskRequest req) returns RiskResponse|error? {

        RiskResponse resp = {
            // hasRisk is true if the country code of the IP address is not the specified country code.
            hasRisk: true
        };
        return resp;
    }
}
