"""
API Security Scanner — VAmPI
============================

Automated scanner for detecting common API vulnerabilities based on
OWASP API Security Top 10. Reads an OpenAPI/Swagger specification and
uses it to generate and execute targeted attack scenarios.

Covered vulnerability classes
------------------------------
- OWASP API1: Broken Object Level Authorization (BOLA / IDOR)
- OWASP API2: Broken Authentication
- OWASP API3: Excessive Data Exposure

How it works
------------
1. Resets the target database and creates two users: attacker and victim.
2. The victim creates a resource (book with a secret).
3. Three independent scanners run sequentially, each returning a
   structured result object.
4. A final report aggregates all findings and prints a summary.

Usage
-----
    python scanner.py

Requirements
------------
- Running VAmPI instance at BASE_URL
- openapi.json file in the working directory
- requests library: pip install requests

Notes
-----
BASE_URL and credentials are hardcoded. This script is intended as a
learning/testing tool and is not designed for use against production systems.
"""

import json
import requests


# --- НАЛАШТУВАННЯ ---

BASE_URL = "http://127.0.0.1:5000"
OPENAPI_FILE = "openapi.json"

ATTACKER = {
    "username": "attacker_user",
    "password": "pass123",
    "email": "attacker@test.com"
}

VICTIM = {
    "username": "victim_user",
    "password": "pass123",
    "email": "victim@test.com"
}

VICTIM_BOOK = {
    "book_title": "victim_secret_book",
    "secret": "secret_from_victim"
}

METHOD_ORDER = {
    "get": 1,
    "post": 2,
    "put": 3,
    "delete": 4
}
"""Defines execution order for HTTP methods within a single path."""

CANDIDATE_METHODS = {"GET", "POST", "PUT", "DELETE"}
"""HTTP methods considered for BOLA scanning."""

RESOURCE_PARAMS = {
    "id", "user_id", "userid", "userId",
    "username", "book", "book_title",
    "resource_id", "owner_id", "account_id"
}
"""
Path parameter names that suggest a resource identifier.
Used to identify BOLA candidates in OpenAPI paths.
"""

PARAM_VALUES = {
    "username": VICTIM["username"],
    "book": VICTIM_BOOK["book_title"],
    "book_title": VICTIM_BOOK["book_title"],
}
"""
Mapping of path parameter names to victim's values.
The attacker uses these values to access resources belonging to the victim.
"""

FIELD_VALUES = {
    "email": "changed_by_attacker@test.com",
    "password": "new_password_by_attacker",
    "book_title": VICTIM_BOOK["book_title"],
    "secret": "new_secret_by_attacker",
}
"""
Mapping of request body field names to attacker-controlled values.
Used when building request bodies from OpenAPI schema definitions.
"""

SENSITIVE_FIELDS = {
    "password", "token", "secret",
    "admin", "is_admin", "role",
    "hash", "debug"
}
"""
Field names considered sensitive in API responses.
Used by the Excessive Data Exposure scanner.
"""

SUCCESS_STATUSES = {
    "GET": [200],
    "POST": [200],
    "PUT": [200, 204],
    "DELETE": [200, 204]
}
"""HTTP status codes that indicate a successful (and potentially unauthorized) response."""

PROTECTED_STATUSES = [401, 403, 404]
"""HTTP status codes that indicate access was correctly denied."""


# --- HTTP ---

def send_request(method, url, token=None, json_data=None):
    """
    Send an HTTP request and return the status code and parsed body.

    Automatically sets Content-Type and Authorization headers when
    applicable. Falls back to raw text if the response body is not
    valid JSON.

    Args:
        method (str): HTTP method (e.g. "GET", "POST").
        url (str): Full request URL.
        token (str | None): Bearer token for Authorization header.
            If None, the header is omitted.
        json_data (dict | None): Request body to serialize as JSON.
            If None, Content-Type header is omitted.

    Returns:
        tuple[int, dict | str]: A tuple of (status_code, body), where
            body is a parsed dict if the response is JSON,
            or a raw string otherwise.
    """
    headers = {"Accept": "application/json"}

    if json_data is not None:
        headers["Content-Type"] = "application/json"

    if token:
        headers["Authorization"] = f"Bearer {token}"

    response = requests.request(
        method=method,
        url=url,
        headers=headers,
        json=json_data,
        timeout=10
    )

    try:
        body = response.json()
    except ValueError:
        body = response.text

    return response.status_code, body


# --- SETUP VAmPI ---

def reset_db():
    """
    Reset the VAmPI database to a clean state.

    Sends GET /createdb to drop and recreate all tables.
    Must be called before registering users to avoid conflicts
    from previous test runs.
    """
    print("[1] Reset database")
    status, body = send_request("GET", f"{BASE_URL}/createdb")
    print("Status:", status)
    print("Response:", body)


def register_user(user):
    """
    Register a new user via the VAmPI registration endpoint.

    Args:
        user (dict): User data with keys: username, password, email.
    """
    print(f"[2] Register user: {user['username']}")

    status, body = send_request(
        "POST",
        f"{BASE_URL}/users/v1/register",
        json_data={
            "email": user["email"],
            "password": user["password"],
            "username": user["username"]
        }
    )

    print("Status:", status)
    print("Response:", body)


def login_user(user):
    """
    Authenticate a user and return their Bearer token.

    Args:
        user (dict): User data with keys: username, password.

    Returns:
        str: JWT Bearer token from the auth_token field.

    Raises:
        Exception: If the server returns a non-200 status code.
    """
    print(f"[3] Login user: {user['username']}")

    status, body = send_request(
        "POST",
        f"{BASE_URL}/users/v1/login",
        json_data={
            "username": user["username"],
            "password": user["password"]
        }
    )

    print("Status:", status)
    print("Response:", body)

    if status != 200:
        raise Exception(f"Login failed for {user['username']}")

    return body["auth_token"]


def create_victim_book(victim_token):
    """
    Create a book resource owned by the victim user.

    The created book serves as the target resource for BOLA and
    Excessive Data Exposure tests. Its title and secret are defined
    in VICTIM_BOOK.

    Args:
        victim_token (str): Bearer token of the victim user.
    """
    print("[4] Victim creates book")

    status, body = send_request(
        "POST",
        f"{BASE_URL}/books/v1",
        token=victim_token,
        json_data={
            "book_title": VICTIM_BOOK["book_title"],
            "secret": VICTIM_BOOK["secret"]
        }
    )

    print("Status:", status)
    print("Response:", body)


# --- OPENAPI PARSING ---

def load_openapi():
    """
    Load and parse the OpenAPI specification from OPENAPI_FILE.

    Returns:
        dict: Parsed OpenAPI document.

    Raises:
        FileNotFoundError: If OPENAPI_FILE does not exist.
        json.JSONDecodeError: If the file contains invalid JSON.
    """
    with open(OPENAPI_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def get_path_params(operation):
    """
    Extract path parameter names from an OpenAPI operation object.

    Filters parameters where ``in`` equals ``"path"``.

    Args:
        operation (dict): OpenAPI operation object (e.g. the value of
            ``paths["/users/v1/{username}"]["get"]``).

    Returns:
        list[str]: List of path parameter names.

    Example:
        For /users/v1/{username} -> ["username"]
        For /books/v1/{book_title} -> ["book_title"]
    """
    return [
        param.get("name")
        for param in operation.get("parameters", [])
        if param.get("in") == "path"
    ]


def is_bola_candidate(http_method, operation):
    """
    Determine whether an endpoint is a candidate for BOLA testing.

    An endpoint qualifies if all three conditions are met:
    1. Its HTTP method is in CANDIDATE_METHODS.
    2. It has at least one path parameter.
    3. At least one path parameter name is in RESOURCE_PARAMS.

    Args:
        http_method (str): HTTP method string (e.g. "get", "post").
        operation (dict): OpenAPI operation object.

    Returns:
        bool: True if the endpoint should be tested for BOLA.
    """
    if http_method.upper() not in CANDIDATE_METHODS:
        return False

    path_params = get_path_params(operation)
    return any(param in RESOURCE_PARAMS for param in path_params)


def get_value_for_path_param(param_name):
    """
    Resolve a concrete value for a given path parameter name.

    Lookup order:
    1. PARAM_VALUES — returns victim's resource identifier.
    2. If param name contains "id" — returns "1" (common integer ID).
    3. Fallback — returns "test".

    Args:
        param_name (str): Name of the path parameter.

    Returns:
        str: Value to substitute into the URL.
    """
    if param_name in PARAM_VALUES:
        return PARAM_VALUES[param_name]

    if "id" in param_name.lower():
        return "1"

    return "test"


def build_url(path, path_params):
    """
    Build a concrete URL by substituting path parameters with victim values.

    Args:
        path (str): OpenAPI path template (e.g. "/users/v1/{username}").
        path_params (list[str]): List of parameter names to substitute.

    Returns:
        str: Full URL with all placeholders replaced.

    Example:
        "/users/v1/{username}" -> "http://127.0.0.1:5000/users/v1/victim_user"
    """
    final_path = path

    for param in path_params:
        value = get_value_for_path_param(param)
        final_path = final_path.replace("{" + param + "}", value)

    return BASE_URL + final_path


def build_body_from_schema(operation):
    """
    Build a JSON request body from an OpenAPI operation's requestBody schema.

    Traverses: requestBody -> content -> application/json -> schema -> properties.
    For each property, resolves a value from FIELD_VALUES. If the field is
    not in FIELD_VALUES, falls back to the schema's own ``example`` value,
    then to the string ``"test"``.

    Note:
        Does not resolve $ref references. Operations with schemas that use
        $ref will produce an empty body (None).

    Args:
        operation (dict): OpenAPI operation object.

    Returns:
        dict | None: Request body dict, or None if no requestBody is defined
            or no properties are found.
    """
    request_body = operation.get("requestBody")

    if not request_body:
        return None

    properties = (
        request_body
        .get("content", {})
        .get("application/json", {})
        .get("schema", {})
        .get("properties", {})
    )

    if not properties:
        return None

    return {
        field_name: FIELD_VALUES.get(field_name, field_schema.get("example", "test"))
        for field_name, field_schema in properties.items()
    }


def get_test_url(path, operation):
    """
    Build the test URL for a given path and operation.

    If the operation has path parameters, substitutes them with victim values.
    Otherwise returns the path appended to BASE_URL as-is.

    Args:
        path (str): OpenAPI path template.
        operation (dict): OpenAPI operation object.

    Returns:
        str: Full URL ready for use in a request.
    """
    path_params = get_path_params(operation)
    return build_url(path, path_params) if path_params else BASE_URL + path


# --- RESULT HELPERS ---

def check_result(method, status):
    """
    Classify a BOLA test result based on HTTP method and response status.

    Args:
        method (str): HTTP method used in the request.
        status (int): HTTP status code returned by the server.

    Returns:
        str: One of:
            - "BOLA FOUND" — status indicates unauthorized access succeeded.
            - "OK: access denied" — status indicates access was correctly blocked.
            - "CHECK MANUALLY: unexpected status" — status is ambiguous, requires human review.
    """
    if status in SUCCESS_STATUSES.get(method.upper(), []):
        return "BOLA FOUND"

    if status in PROTECTED_STATUSES:
        return "OK: access denied"

    return "CHECK MANUALLY: unexpected status"


def make_scan_result(name):
    """
    Create an empty scan result container.

    Args:
        name (str): Human-readable name for the scan (e.g. "BOLA").

    Returns:
        dict: Scan result with keys: name, checked (int), issues (int), items (list).
    """
    return {"name": name, "checked": 0, "issues": 0, "items": []}


def add_scan_item(scan_result, title, method, path, url, status, result, response_body):
    """
    Append a single check result to a scan result container.

    Increments ``checked`` counter unconditionally. Increments ``issues``
    counter if the result string contains "FOUND" or "CHECK MANUALLY".

    Args:
        scan_result (dict): Container returned by make_scan_result().
        title (str): Human-readable label for this check.
        method (str): HTTP method used.
        path (str): Original OpenAPI path template.
        url (str): Actual URL that was tested.
        status (int | None): HTTP status code, or None for non-HTTP checks
            (e.g. user enumeration).
        result (str): Classification string (e.g. "BOLA FOUND", "OK: ...").
        response_body (dict | str): Response body from the server.
    """
    scan_result["checked"] += 1

    if "FOUND" in result or "CHECK MANUALLY" in result:
        scan_result["issues"] += 1

    scan_result["items"].append({
        "title": title,
        "method": method.upper(),
        "path": path,
        "url": url,
        "status": status,
        "result": result,
        "response": response_body
    })


# --- BOLA SCAN ---

def scan_bola(attacker_token, openapi):
    """
    Scan all OpenAPI endpoints for Broken Object Level Authorization (BOLA).

    For each endpoint identified as a BOLA candidate (see is_bola_candidate),
    sends a request authenticated as the attacker but targeting the victim's
    resources. A successful response (2xx) indicates that the server does not
    enforce object-level authorization.

    Endpoints are tested in GET -> POST -> PUT -> DELETE order within each path.

    Args:
        attacker_token (str): Bearer token of the attacker user.
        openapi (dict): Parsed OpenAPI document.

    Returns:
        dict: Scan result container populated with one item per tested endpoint.
    """
    print("[5] Start BOLA scan")

    paths = openapi.get("paths", {})
    scan_result = make_scan_result("BOLA")

    for path, path_item in paths.items():
        methods = sorted(path_item.keys(), key=lambda m: METHOD_ORDER.get(m, 99))

        for http_method in methods:
            operation = path_item.get(http_method)

            if not isinstance(operation, dict):
                continue

            if not is_bola_candidate(http_method, operation):
                continue

            url = get_test_url(path, operation)
            body = build_body_from_schema(operation)

            status, response_body = send_request(
                method=http_method.upper(),
                url=url,
                token=attacker_token,
                json_data=body
            )

            add_scan_item(
                scan_result=scan_result,
                title=operation.get("summary", "No summary"),
                method=http_method,
                path=path,
                url=url,
                status=status,
                result=check_result(http_method, status),
                response_body=response_body
            )

    return scan_result


# --- BROKEN AUTH SCAN ---

def scan_broken_auth(openapi):
    """
    Scan all protected OpenAPI endpoints for Broken Authentication issues.

    An endpoint is considered protected if its OpenAPI operation contains
    a ``security`` field. Each such endpoint is tested twice:

    1. **No token** — request sent without an Authorization header.
    2. **Invalid token** — request sent with a malformed Bearer token.

    Additionally, performs a **user enumeration** check by comparing
    server responses for an existing user with a wrong password versus
    a non-existing user. Different status codes or response bodies
    indicate that the API leaks user existence information.

    Args:
        openapi (dict): Parsed OpenAPI document.

    Returns:
        dict: Scan result container populated with two items per protected
            endpoint plus one item for the enumeration check.
    """
    print("[6] Start Broken Authentication scan")

    paths = openapi.get("paths", {})
    scan_result = make_scan_result("Broken Authentication")
    invalid_token = "invalid.token.value"

    for path, path_item in paths.items():
        for http_method, operation in path_item.items():
            if not isinstance(operation, dict):
                continue

            if "security" not in operation:
                continue

            url = get_test_url(path, operation)
            body = build_body_from_schema(operation)
            summary = operation.get("summary", "No summary")

            for label, token in [("no token", None), ("bad token", invalid_token)]:
                status, response_body = send_request(
                    method=http_method.upper(),
                    url=url,
                    token=token,
                    json_data=body
                )

                if status in SUCCESS_STATUSES.get(http_method.upper(), []):
                    result = f"BROKEN AUTH FOUND: protected endpoint works with {label}"
                elif status in PROTECTED_STATUSES:
                    result = f"OK: access with {label} denied"
                else:
                    result = f"CHECK MANUALLY: unexpected status with {label}"

                add_scan_item(
                    scan_result=scan_result,
                    title=f"{summary} | {label}",
                    method=http_method,
                    path=path,
                    url=url,
                    status=status,
                    result=result,
                    response_body=response_body
                )

    status_existing, body_existing = send_request(
        method="POST",
        url=f"{BASE_URL}/users/v1/login",
        json_data={"username": ATTACKER["username"], "password": "wrong_password_123"}
    )

    status_non_existing, body_non_existing = send_request(
        method="POST",
        url=f"{BASE_URL}/users/v1/login",
        json_data={"username": "user_that_does_not_exist_123", "password": "wrong_password_123"}
    )

    existing_response = json.dumps(body_existing, sort_keys=True, ensure_ascii=False)
    non_existing_response = json.dumps(body_non_existing, sort_keys=True, ensure_ascii=False)

    if status_existing != status_non_existing or existing_response != non_existing_response:
        enumeration_result = (
            "CHECK MANUALLY: login responses are different "
            f"(existing: {status_existing}, non-existing: {status_non_existing})"
        )
    else:
        enumeration_result = "OK: login responses look similar"

    add_scan_item(
        scan_result=scan_result,
        title="User/password enumeration check",
        method="POST",
        path="/users/v1/login",
        url=f"{BASE_URL}/users/v1/login",
        status=None,
        result=enumeration_result,
        response_body={
            "existing_user_wrong_password": body_existing,
            "non_existing_user": body_non_existing
        }
    )

    return scan_result


# --- EXCESSIVE DATA EXPOSURE SCAN ---

def find_sensitive_fields(data, current_path=""):
    """
    Recursively search a JSON structure for sensitive field names.

    Traverses dicts and lists. For each dict key, checks whether its
    lowercase name appears in SENSITIVE_FIELDS. Returns the full
    dot/bracket-notation path to each match, enabling precise location
    of the leak within nested structures.

    Args:
        data (dict | list | any): JSON-decoded response body or any
            nested value within it.
        current_path (str): Dot-notation path accumulated during recursion.
            Should be left as default ("") on the initial call.

    Returns:
        list[str]: Paths to all sensitive fields found.

    Example:
        {"user": {"password": "secret"}} -> ["user.password"]
        [{"token": "abc"}]               -> ["[0].token"]
    """
    found = []

    if isinstance(data, dict):
        for key, value in data.items():
            full_path = f"{current_path}.{key}" if current_path else key

            if key.lower() in SENSITIVE_FIELDS:
                found.append(full_path)

            found.extend(find_sensitive_fields(value, full_path))

    elif isinstance(data, list):
        for index, item in enumerate(data):
            found.extend(find_sensitive_fields(item, f"{current_path}[{index}]"))

    return found


def scan_excessive_data_exposure(token, openapi):
    """
    Scan all GET endpoints for Excessive Data Exposure.

    Sends an authenticated GET request to every endpoint that defines
    a ``get`` operation in the OpenAPI spec. For responses with status 200,
    recursively inspects the response body for fields listed in
    SENSITIVE_FIELDS. A match indicates that the API returns data that
    should not be exposed to the client.

    5xx responses are flagged as CHECK MANUALLY — a server error may
    indicate information disclosure via debug pages or stack traces.

    Endpoints returning other non-200 status codes are skipped (marked as SKIP).

    Args:
        token (str): Bearer token for authentication (attacker's token).
        openapi (dict): Parsed OpenAPI document.

    Returns:
        dict: Scan result container populated with one item per GET endpoint.
    """
    print("[7] Start Excessive Data Exposure scan")

    paths = openapi.get("paths", {})
    scan_result = make_scan_result("Excessive Data Exposure")

    for path, path_item in paths.items():
        operation = path_item.get("get")

        if not isinstance(operation, dict):
            continue

        url = get_test_url(path, operation)
        status, response_body = send_request(method="GET", url=url, token=token)

        if status == 200:
            sensitive_fields = find_sensitive_fields(response_body)
            result = (
                f"EXCESSIVE DATA EXPOSURE FOUND: {sensitive_fields}"
                if sensitive_fields
                else "OK: no sensitive fields found"
            )
        elif status >= 500:
            result = "CHECK MANUALLY: server error — possible information disclosure"
        else:
            result = "OK: endpoint did not return 200"

        add_scan_item(
            scan_result=scan_result,
            title=operation.get("summary", "No summary"),
            method="GET",
            path=path,
            url=url,
            status=status,
            result=result,
            response_body=response_body
        )

    return scan_result


# --- FINAL REPORT ---

def print_final_report(scan_results):
    """
    Print a structured report of all scan results to stdout.

    Outputs a detailed section for each scanner (per-item breakdown),
    followed by a total summary across all scanners.

    Summary counters:
    - **Total checks**: sum of all items across all scanners.
    - **Total found**: items where result contains "FOUND" or "CHECK MANUALLY".
    - **Total ok**: remaining items (total_checks - total_found).

    Args:
        scan_results (list[dict]): List of scan result containers as returned
            by scan_bola(), scan_broken_auth(), scan_excessive_data_exposure().
    """
    print("\n" + "=" * 60)
    print("FINAL SCAN REPORT")
    print("=" * 60)

    for scan_result in scan_results:
        print(f"\n[{scan_result['name']}]")
        print("Checked:", scan_result["checked"])
        print("Potential issues:", scan_result["issues"])

        for item in scan_result["items"]:
            print("\n------------------------------")
            print("Check:", item["title"])
            print("Method:", item["method"])
            print("Swagger path:", item["path"])
            print("Tested URL:", item["url"])
            print("Status:", item["status"])
            print("Result:", item["result"])
            print("Response:", item["response"])

    total_checked = sum(r["checked"] for r in scan_results)
    total_found = sum(r["issues"] for r in scan_results)
    total_ok = total_checked - total_found

    print("\n" + "=" * 60)
    print("TOTAL SUMMARY")
    print("=" * 60)
    print("Total checks:", total_checked)
    print("Total found:", total_found)
    print("Total ok:", total_ok)
    print("\n" + "=" * 60)
    print("END OF REPORT")
    print("=" * 60)


# --- MAIN ---

def main():
    """
    Entry point. Orchestrates environment setup and all scan phases.

    Execution order:
    1. Reset database.
    2. Register attacker and victim users.
    3. Authenticate both users and obtain their tokens.
    4. Victim creates a book resource.
    5. Load OpenAPI specification.
    6. Run BOLA, Broken Authentication, and Excessive Data Exposure scans.
    7. Print the final aggregated report.
    """
    reset_db()

    register_user(ATTACKER)
    register_user(VICTIM)

    attacker_token = login_user(ATTACKER)
    victim_token = login_user(VICTIM)

    create_victim_book(victim_token)

    openapi = load_openapi()

    scan_results = [
        scan_bola(attacker_token, openapi),
        scan_broken_auth(openapi),
        scan_excessive_data_exposure(attacker_token, openapi)
    ]

    print_final_report(scan_results)


if __name__ == "__main__":
    main()