"""
API Security Scanner — VAmPI + Postman Collection
=================================================

Features:
- Uses Postman collection as the only endpoint source.
- Does not use OpenAPI / Swagger.
- Does not use Postman environment.
- Uses hardcoded BASE_URL and VAmPI dummy data.
- Excludes setup endpoints like /createdb from scans.
- Runs:
  1. Excessive Data Exposure
  2. Broken Authentication
  3. BOLA / IDOR
- Prints endpoint-based report.

Usage:
    python scanner.py

Requirements:
    pip install requests

Required file:
    VAmPI.postman_collection.json
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from urllib.parse import urlparse

import requests


# --- CONFIG ---

BASE_URL = "http://127.0.0.1:5000"
POSTMAN_COLLECTION_FILE = "VAmPI.postman_collection.json"
REQUEST_TIMEOUT = 10

ATTACKER = {
    "username": "name2",
    "password": "pass2",
    "email": "mail2@mail.com"
}

VICTIM = {
    "username": "name1",
    "password": "pass1",
    "email": "mail1@mail.com"
}

VICTIM_BOOK = {
    "book_title": "bookTitle77",
    "secret": "secret for bookTitle77"
}

HARDCODED_VALUES = {
    "baseUrl": BASE_URL.rstrip("/"),
    "username": VICTIM["username"],
    "book_title": VICTIM_BOOK["book_title"],
    "book": VICTIM_BOOK["book_title"],
}

# Setup/admin endpoints must not be scanned because they change application state.
EXCLUDED_SCAN_PATHS = {
    "/createdb"
}

# DELETE is destructive, so it is not executed by default in BOLA checks.
ENABLE_DESTRUCTIVE_BOLA = False

SENSITIVE_FIELDS = {
    "password",
    "token",
    "auth_token",
    "secret",
    "hash",
    "debug"
}

SUCCESS_STATUSES = {
    "GET": {200},
    "POST": {200, 201},
    "PUT": {200, 204},
    "PATCH": {200, 204},
    "DELETE": {200, 204}
}

PROTECTED_STATUSES = {401, 403, 404}

BOLA_RESOURCE_KEYS = {
    "id",
    "user_id",
    "userid",
    "username",
    "book",
    "book_title",
    "resource_id",
    "owner_id",
    "account_id"
}

BOLA_METHODS = {"GET", "PUT", "PATCH", "DELETE"}

BOLA_METHOD_ORDER = {
    "GET": 1,
    "PUT": 2,
    "PATCH": 3,
    "DELETE": 4
}

STATUS_FAIL = "FAIL"
STATUS_PASS = "PASS"
STATUS_REVIEW = "REVIEW"
STATUS_NA = "N/A"


# --- MODELS ---

@dataclass(frozen=True)
class Endpoint:
    name: str
    folder: str
    method: str
    raw_url: str
    url: str
    path: str
    resolved_path: str
    headers: dict
    body: dict | list | str | None
    body_mode: str | None
    auth_type: str | None
    path_variables: dict

    @property
    def key(self) -> str:
        return f"{self.method} {self.resolved_path}"

    @property
    def is_excluded_from_scan(self) -> bool:
        return self.resolved_path in EXCLUDED_SCAN_PATHS


@dataclass
class CheckResult:
    status: str
    http_status: int | None = None
    reason: str = ""
    evidence: list[str] | None = None


# --- HTTP CLIENT ---

def send_request(method, url, token=None, body=None, headers=None):
    final_headers = {"Accept": "application/json"}

    if headers:
        final_headers.update(headers)

    # Scanner controls Authorization itself.
    final_headers.pop("Authorization", None)

    if token:
        final_headers["Authorization"] = f"Bearer {token}"

    request_kwargs = {
        "method": method,
        "url": url,
        "headers": final_headers,
        "timeout": REQUEST_TIMEOUT
    }

    if body is not None:
        if isinstance(body, (dict, list)):
            final_headers["Content-Type"] = "application/json"
            request_kwargs["json"] = body
        else:
            request_kwargs["data"] = body

    try:
        response = requests.request(**request_kwargs)

        try:
            response_body = response.json()
        except ValueError:
            response_body = response.text

        return response.status_code, response_body

    except requests.RequestException as error:
        return 0, {"error": str(error)}


def send_endpoint_request(endpoint, token=None, body_override=None):
    body = body_override

    if body is None and endpoint.method in {"POST", "PUT", "PATCH"}:
        body = endpoint.body

    return send_request(
        method=endpoint.method,
        url=endpoint.url,
        token=token,
        body=body,
        headers=endpoint.headers
    )


# --- VAMPI SETUP ---

def setup_vampi():
    print("[1] Reset database")
    status, body = send_request("GET", f"{BASE_URL}/createdb")
    print("Status:", status)

    if status != 200:
        raise RuntimeError(f"Database reset failed: {body}")

    print("[2] Register attacker")
    _register_user(ATTACKER)

    print("[3] Register victim")
    _register_user(VICTIM)

    print("[4] Login attacker")
    attacker_token = login_user(ATTACKER)

    print("[5] Login victim")
    victim_token = login_user(VICTIM)

    print("[6] Create victim's book")
    _create_victim_book(victim_token)

    return attacker_token, victim_token


def _create_victim_book(victim_token):
    """Create the victim's book with the victim's token.

    Idempotent: ignores 'already exists' responses so it is safe to call
    even when /createdb already inserted the book.
    """
    status, body = send_request(
        "POST",
        f"{BASE_URL}/books/v1",
        token=victim_token,
        body={
            "book_title": VICTIM_BOOK["book_title"],
            "secret": VICTIM_BOOK["secret"]
        }
    )
    print("Status:", status, body)

    already_exists = (
        status == 400
        and isinstance(body, dict)
        and any(word in str(body).lower() for word in ("exist", "already", "duplicate"))
    )

    if status not in {200, 201} and not already_exists:
        raise RuntimeError(f"Failed to create victim book: {body}")


def _register_user(user):
    """Register a user, ignoring 'already exists' responses."""
    status, body = send_request(
        "POST",
        f"{BASE_URL}/users/v1/register",
        body={
            "username": user["username"],
            "password": user["password"],
            "email": user["email"]
        }
    )
    print("Status:", status, body)
    # 200/201 = created; 400 with "already exists" = already present — both are fine.
    if status not in {200, 201} and not (
        status == 400
        and isinstance(body, dict)
        and "exist" in str(body).lower()
    ):
        raise RuntimeError(f"Registration failed for {user['username']}: {body}")


def login_user(user):
    status, body = send_request(
        "POST",
        f"{BASE_URL}/users/v1/login",
        body={
            "username": user["username"],
            "password": user["password"]
        }
    )

    print("Status:", status)

    if status != 200 or not isinstance(body, dict) or "auth_token" not in body:
        raise RuntimeError(f"Login failed for {user['username']}: {body}")

    return body["auth_token"]


# --- POSTMAN COLLECTION PARSING ---

def load_postman_collection(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        collection = json.load(file)

    endpoints = []

    def walk(items, folder=""):
        for item in items:
            item_name = item.get("name", "No name")

            if "item" in item:
                next_folder = f"{folder}/{item_name}" if folder else item_name
                walk(item.get("item", []), next_folder)
                continue

            request = item.get("request")

            if request:
                endpoints.append(parse_postman_request(item_name, folder, request))

    walk(collection.get("item", []))

    return endpoints


def parse_postman_request(name, folder, request):
    if isinstance(request, str):
        raw_url = request
        method = "GET"
        url_data = {}
        headers = {}
        auth_type = None
        body_mode = None
        body = None
    else:
        method = request.get("method", "GET").upper()
        url_data = request.get("url", {})
        raw_url = url_data.get("raw", "") if isinstance(url_data, dict) else str(url_data)

        headers = {
            header["key"]: header.get("value", "")
            for header in request.get("header", [])
            if not header.get("disabled") and header.get("key")
        }

        auth = request.get("auth") or {}
        auth_type = auth.get("type")

        body_mode, body = parse_postman_body(request.get("body"))

    path_variables = extract_path_variables(url_data)
    path = extract_postman_path(url_data, raw_url)
    resolved_url = resolve_postman_url(raw_url, path_variables)
    resolved_path = urlparse(resolved_url).path or "/"

    return Endpoint(
        name=name,
        folder=folder,
        method=method,
        raw_url=raw_url,
        url=resolved_url,
        path=path,
        resolved_path=resolved_path,
        headers=headers,
        body=body,
        body_mode=body_mode,
        auth_type=auth_type,
        path_variables=path_variables
    )


def parse_postman_body(body_data):
    if not body_data:
        return None, None

    mode = body_data.get("mode")

    if mode == "raw":
        raw_body = body_data.get("raw", "")

        try:
            return mode, json.loads(raw_body)
        except json.JSONDecodeError:
            return mode, raw_body

    if mode in {"urlencoded", "formdata"}:
        return mode, {
            item["key"]: item.get("value", "")
            for item in body_data.get(mode, [])
            if not item.get("disabled") and item.get("key")
        }

    return mode, body_data


def extract_path_variables(url_data):
    if not isinstance(url_data, dict):
        return {}

    variables = {}

    for variable in url_data.get("variable", []):
        key = variable.get("key")

        if key:
            variables[key] = HARDCODED_VALUES.get(key, variable.get("value", ""))

    return variables


def extract_postman_path(url_data, raw_url):
    if isinstance(url_data, dict) and url_data.get("path"):
        path = "/" + "/".join(str(part) for part in url_data["path"])
        return path if path != "/" else "/"

    if raw_url.startswith("{{baseUrl}}"):
        path = raw_url.replace("{{baseUrl}}", "", 1)
        return path or "/"

    if raw_url.startswith("http://") or raw_url.startswith("https://"):
        return urlparse(raw_url).path or "/"

    return raw_url if raw_url.startswith("/") else f"/{raw_url}"


def resolve_postman_url(raw_url, path_variables):
    resolved_url = raw_url

    for key, value in HARDCODED_VALUES.items():
        resolved_url = resolved_url.replace("{{" + key + "}}", str(value))

    for key, value in path_variables.items():
        resolved_url = resolved_url.replace(":" + key, str(value))

    return resolved_url


# --- SCAN HELPERS ---

def short_response_preview(response_body, max_length=500):
    if response_body is None:
        return ""

    if isinstance(response_body, (dict, list)):
        text = json.dumps(response_body, ensure_ascii=False)
    else:
        text = str(response_body)

    return text if len(text) <= max_length else text[:max_length] + "...[truncated]"


def find_sensitive_fields(data, current_path=""):
    found = []

    if isinstance(data, dict):
        for key, value in data.items():
            full_path = f"{current_path}.{key}" if current_path else key

            if key.lower() in SENSITIVE_FIELDS:
                found.append(full_path)

            found.extend(find_sensitive_fields(value, full_path))

    elif isinstance(data, list):
        for index, item in enumerate(data):
            item_path = f"{current_path}[{index}]" if current_path else f"[{index}]"
            found.extend(find_sensitive_fields(item, item_path))

    return found


def build_bola_body(endpoint):
    if not isinstance(endpoint.body, dict):
        return endpoint.body

    body = dict(endpoint.body)

    if endpoint.resolved_path.endswith("/email"):
        body["email"] = "attacker_changed@mail.com"

    if endpoint.resolved_path.endswith("/password"):
        body["password"] = "attacker_changed_pass"

    return body


# --- DATA EXPOSURE SCAN ---

def scan_data_exposure(endpoints, token):
    print("[7] Scan Excessive Data Exposure")

    results = {}

    for endpoint in endpoints:
        if endpoint.is_excluded_from_scan or endpoint.method != "GET":
            continue

        request_token = token if endpoint.auth_type == "bearer" else None
        status, body = send_endpoint_request(endpoint, token=request_token)

        if status == 200:
            sensitive_fields = find_sensitive_fields(body)

            if sensitive_fields:
                results[endpoint.key] = CheckResult(
                    status=STATUS_FAIL,
                    http_status=status,
                    reason="Response exposes sensitive fields",
                    evidence=[
                        f"Tested URL: {endpoint.url}",
                        f"Sensitive fields found: {', '.join(sensitive_fields)}",
                        "This may indicate Excessive Data Exposure.",
                        "The API should return only fields required by the client.",
                        f"Response preview: {short_response_preview(body)}"
                    ]
                )
            else:
                results[endpoint.key] = CheckResult(
                    status=STATUS_PASS,
                    http_status=status,
                    reason="No sensitive fields found in response"
                )

        elif status >= 500:
            results[endpoint.key] = CheckResult(
                status=STATUS_REVIEW,
                http_status=status,
                reason="Server error, possible information disclosure",
                evidence=[
                    f"Tested URL: {endpoint.url}",
                    f"Response preview: {short_response_preview(body)}"
                ]
            )

        elif status == 0:
            results[endpoint.key] = CheckResult(
                status=STATUS_REVIEW,
                http_status=status,
                reason="Request failed",
                evidence=[
                    f"Tested URL: {endpoint.url}",
                    f"Error: {short_response_preview(body)}"
                ]
            )

        else:
            results[endpoint.key] = CheckResult(
                status=STATUS_PASS,
                http_status=status,
                reason="Endpoint did not return data"
            )

    return results


# --- AUTH SCAN ---

def scan_auth(endpoints):
    print("[8] Scan Broken Authentication")

    results = {}

    for endpoint in endpoints:
        if endpoint.is_excluded_from_scan or endpoint.auth_type != "bearer":
            continue

        failed_cases = []
        review_cases = []

        for label, token in [("missing token", None), ("invalid token", "invalid.token.value")]:
            status, body = send_endpoint_request(endpoint, token=token)

            case = {
                "label": label,
                "status": status,
                "body": body
            }

            if status in SUCCESS_STATUSES.get(endpoint.method, set()):
                failed_cases.append(case)
            elif status not in PROTECTED_STATUSES:
                review_cases.append(case)

        if failed_cases:
            evidence = [
                "Endpoint is marked as bearer-protected in Postman collection.",
                f"Tested URL: {endpoint.url}",
                "Protected endpoint should reject missing or invalid tokens."
            ]

            for case in failed_cases:
                evidence.append(f"Accepted request with {case['label']} | status={case['status']}")
                evidence.append(f"Response preview: {short_response_preview(case['body'])}")

            results[endpoint.key] = CheckResult(
                status=STATUS_FAIL,
                reason="Protected endpoint accepted unauthenticated or invalid-token request",
                evidence=evidence
            )

        elif review_cases:
            evidence = [
                "Endpoint is marked as bearer-protected in Postman collection.",
                f"Tested URL: {endpoint.url}",
                "Expected response for missing/invalid token is usually 401, 403 or 404."
            ]

            for case in review_cases:
                evidence.append(f"Unexpected status with {case['label']} | status={case['status']}")
                evidence.append(f"Response preview: {short_response_preview(case['body'])}")

            results[endpoint.key] = CheckResult(
                status=STATUS_REVIEW,
                reason="Authentication behavior is ambiguous",
                evidence=evidence
            )

        else:
            results[endpoint.key] = CheckResult(
                status=STATUS_PASS,
                reason="Missing and invalid tokens were rejected"
            )

    return results


# --- BOLA SCAN ---

def is_bola_candidate(endpoint):
    if endpoint.is_excluded_from_scan:
        return False

    if endpoint.method not in BOLA_METHODS:
        return False

    if endpoint.method == "DELETE" and not ENABLE_DESTRUCTIVE_BOLA:
        return False

    if endpoint.auth_type != "bearer":
        return False

    if any(key in BOLA_RESOURCE_KEYS for key in endpoint.path_variables):
        return True

    lower_path = endpoint.path.lower()

    return any(
        marker in lower_path
        for marker in [
            ":id",
            ":username",
            ":user_id",
            ":book_title",
            ":account_id",
            ":resource_id"
        ]
    )


def scan_bola(endpoints, attacker_token):
    print("[9] Scan BOLA / IDOR")

    results = {}

    candidates = sorted(
        [endpoint for endpoint in endpoints if is_bola_candidate(endpoint)],
        key=lambda endpoint: BOLA_METHOD_ORDER.get(endpoint.method, 99)
    )

    for endpoint in candidates:
        bola_body = build_bola_body(endpoint)

        status, body = send_endpoint_request(
            endpoint=endpoint,
            token=attacker_token,
            body_override=bola_body
        )

        if status in SUCCESS_STATUSES.get(endpoint.method, set()):
            results[endpoint.key] = CheckResult(
                status=STATUS_FAIL,
                http_status=status,
                reason="Attacker accessed or modified victim-owned object",
                evidence=[
                    f"Tested URL: {endpoint.url}",
                    f"Method: {endpoint.method}",
                    f"Path variables: {json.dumps(endpoint.path_variables, ensure_ascii=False)}",
                    f"Attacker username: {ATTACKER['username']}",
                    f"Victim username: {VICTIM['username']}",
                    f"Victim book title: {VICTIM_BOOK['book_title']}",
                    "The request was sent with attacker token but used victim identifier.",
                    "Successful response may indicate missing object-level authorization.",
                    "This matches BOLA / IDOR vulnerability pattern.",
                    f"Request body: {short_response_preview(bola_body)}",
                    f"Response preview: {short_response_preview(body)}"
                ]
            )

        elif status in PROTECTED_STATUSES:
            results[endpoint.key] = CheckResult(
                status=STATUS_PASS,
                http_status=status,
                reason="Access to victim object was denied"
            )

        elif status == 0:
            results[endpoint.key] = CheckResult(
                status=STATUS_REVIEW,
                http_status=status,
                reason="Request failed",
                evidence=[
                    f"Tested URL: {endpoint.url}",
                    f"Response preview: {short_response_preview(body)}"
                ]
            )

        else:
            results[endpoint.key] = CheckResult(
                status=STATUS_REVIEW,
                http_status=status,
                reason="Unexpected status during BOLA test",
                evidence=[
                    f"Tested URL: {endpoint.url}",
                    f"Expected protected status: {sorted(PROTECTED_STATUSES)}",
                    f"Expected success status for finding: {sorted(SUCCESS_STATUSES.get(endpoint.method, set()))}",
                    f"Actual status: {status}",
                    f"Request body: {short_response_preview(bola_body)}",
                    f"Response preview: {short_response_preview(body)}"
                ]
            )

    return results


# --- REPORT ---

def print_endpoint_report(endpoints, data_results, auth_results, bola_results):
    print("\n" + "=" * 80)
    print("ENDPOINT-BASED SECURITY REPORT")
    print("=" * 80)

    summary = {
        STATUS_FAIL: 0,
        STATUS_PASS: 0,
        STATUS_REVIEW: 0,
        STATUS_NA: 0
    }

    executed_checks = 0
    json_report = {"endpoints": []}

    for endpoint in endpoints:
        results = {
            "bola": bola_results.get(endpoint.key, CheckResult(STATUS_NA)),
            "auth": auth_results.get(endpoint.key, CheckResult(STATUS_NA)),
            "data": data_results.get(endpoint.key, CheckResult(STATUS_NA))
        }

        print(f"\n- {endpoint.method} {endpoint.resolved_path}")
        print(f"  name: {endpoint.name}")
        print(f"  url: {endpoint.url}")

        if endpoint.is_excluded_from_scan:
            print("  note: excluded from scans because it changes application state")

        endpoint_entry = {
            "method": endpoint.method,
            "path": endpoint.resolved_path,
            "name": endpoint.name,
            "url": endpoint.url,
            "excluded": endpoint.is_excluded_from_scan,
            "checks": {}
        }

        for check_name, result in results.items():
            summary[result.status] += 1

            if result.status != STATUS_NA:
                executed_checks += 1

            print_check_result(check_name, result)

            endpoint_entry["checks"][check_name] = {
                "status": result.status,
                "http_status": result.http_status,
                "reason": result.reason,
                "evidence": result.evidence or []
            }

        json_report["endpoints"].append(endpoint_entry)

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print("endpoints:", len(endpoints))
    print("executed checks:", executed_checks)
    print("fail:", summary[STATUS_FAIL])
    print("pass:", summary[STATUS_PASS])
    print("review:", summary[STATUS_REVIEW])
    print("not applicable:", summary[STATUS_NA])

    json_report["summary"] = {
        "endpoints": len(endpoints),
        "executed_checks": executed_checks,
        "fail": summary[STATUS_FAIL],
        "pass": summary[STATUS_PASS],
        "review": summary[STATUS_REVIEW],
        "not_applicable": summary[STATUS_NA]
    }

    report_path = "scan_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(json_report, f, indent=2, ensure_ascii=False)
    print(f"\nJSON report saved: {report_path}")

    return summary[STATUS_FAIL]


def print_check_result(check_name, result):
    if result.status == STATUS_NA:
        print(f"  {check_name}: N/A")
        return

    print(f"  {check_name}: {result.status}")

    if result.http_status is not None:
        print(f"    http_status: {result.http_status}")

    if result.reason:
        print(f"    reason: {result.reason}")

    if result.status in {STATUS_FAIL, STATUS_REVIEW} and result.evidence:
        print("    evidence:")
        for item in result.evidence:
            print(f"      - {item}")


# --- MAIN ---

def main():
    try:
        endpoints = load_postman_collection(POSTMAN_COLLECTION_FILE)

        print("Loaded endpoints:", len(endpoints))
        print("Base URL:", BASE_URL)

        attacker_token, _ = setup_vampi()

        data_results = scan_data_exposure(endpoints, attacker_token)
        auth_results = scan_auth(endpoints)
        bola_results = scan_bola(endpoints, attacker_token)

        fail_count = print_endpoint_report(
            endpoints=endpoints,
            data_results=data_results,
            auth_results=auth_results,
            bola_results=bola_results
        )

        if fail_count > 0:
            sys.exit(1)

    except FileNotFoundError:
        print(f"ERROR: file not found: {POSTMAN_COLLECTION_FILE}")
        print("Put VAmPI.postman_collection.json near scanner.py or change POSTMAN_COLLECTION_FILE.")
        sys.exit(1)

    except json.JSONDecodeError as error:
        print(f"ERROR: invalid JSON in {POSTMAN_COLLECTION_FILE}")
        print("Details:", error)
        sys.exit(1)

    except RuntimeError as error:
        print("ERROR:", error)
        sys.exit(1)


if __name__ == "__main__":
    main()
