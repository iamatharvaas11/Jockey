# JOCKY Security Model

This document outlines the security architecture, features, and known limitations of the JOCKY forensic framework backend.

## Security Overview

JOCKY is designed with security in mind, employing industry-standard practices for authentication, authorization, and data handling.

### Authentication

*   **JWT (JSON Web Tokens):** All API endpoints require authentication using JWTs.
*   **Password Hashing:** Passwords are hashed using bcrypt before being stored in the database.
*   **Persistent Secret Key:** The JWT signing key (`SECRET_KEY`) must be securely configured via environment variables to ensure sessions persist across server restarts.

### First-Run Setup Process

To prevent unauthorized access out-of-the-box, JOCKY does **not** include hardcoded default credentials.

1.  Upon the first startup, the system checks if an admin user exists.
2.  If no admin exists, a setup routine securely creates the initial administrator account.
3.  The password for this account is derived from the `ADMIN_PASSWORD` environment variable (falling back to a securely generated random string if not provided).

### File Upload Validation

Artifact uploads are validated to prevent malicious file inclusion and path traversal attacks. Filenames are sanitized, and files are stored in a dedicated, isolated directory.

### Cross-Origin Resource Sharing (CORS)

CORS is configured strictly. The backend does not permit wildcard (`*`) origins when credentials are in use. Origins must be explicitly defined in the application configuration.

### Role-Based Access Control (RBAC)

JOCKY implements an RBAC system with the following roles:
*   **ADMIN:** Full access to all endpoints, including user management and system configuration.
*   **ANALYST:** Access to investigation management, reporting, and evidence viewing.

*Note: Registration endpoints validate role assignments to prevent privilege escalation.*

## Known Security Considerations and Unimplemented Features

As an early-stage prototype, several security features are not yet fully implemented:

*   **Full Authorization Enforcement:** While role definitions exist, comprehensive endpoint-level enforcement of analyst vs. admin permissions is still under development.
*   **Audit Logging:** Evidence lifecycle actions are protected by a
    cryptographic chain-of-custody audit trail. Centralized user-access auditing
    and durable external log retention remain incomplete for production use.
*   **Rate Limiting:** API endpoints are not currently rate-limited, making them susceptible to brute-force or denial-of-service attacks.
*   **Endpoint Agent Security:** Endpoint tasks are constrained to an explicit,
    read-only collector allow-list and are revalidated on the endpoint. A
    production deployment still requires mutual TLS, credential rotation,
    durable audit storage and task-approval workflows.

## Reporting Security Issues

If you discover a security vulnerability within JOCKY, please do not disclose it publicly. Instead, report it directly to the project maintainers via the established security contact channels.
