# Risk Assessment Service

This is a simple Ballerina service that assesses the risk of an IP address based on its geolocation. The service checks if the IP address belongs to a specific country and returns a risk assessment.

## Prerequisites

- [Ballerina](https://ballerina.io/) installed on your machine.
- An API key for the [ipgeolocation.io](https://ipgeolocation.io/) service.

## Project Structure

├── Ballerina.toml
├── main.bal
└── README.md


- `main.bal`: Contains the Ballerina service implementation.
- `Ballerina.toml`: Configuration file for the project.
- `README.md`: This file.

## Configuration

Before running the service, you need to set the `geoApiKey` with your ipgeolocation.io API key.

- Open the `Ballerina.toml` file (if exists) or use the `ballerina` command to run the service with the `geoApiKey`:

```toml
[build-options]
observabilityIncluded = true

[dependencies]

[configurable]
geoApiKey = "<Your-API-Key-Here>"
