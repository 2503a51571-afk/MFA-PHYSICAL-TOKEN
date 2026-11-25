
import os
import re
import json
import time
import hmac
import boto3
import base64
import hashlib
import secrets
from botocore.exceptions import ClientError

db = boto3.resource("dynamodb")
users = db.Table("MFA_Users")
challenges = db.Table("MFA_OTP_Challenges")
attempts_table = db.Table("MFA_Login_Attempts")

ITERATIONS = 600000
OTP_LIFETIME = 300
MAX_OTP_ATTEMPTS = 3
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 900
SESSION_LIFETIME = 900

SESSION_SECRET = os.environ["MFA_SESSION_SECRET"].encode()


def response(status, data):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store"
        },
        "body": json.dumps(data)
    }


def password_hash(password, salt, iterations=ITERATIONS):
    result = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations
    )
    return base64.b64encode(result).decode("ascii")


def otp_hash(code, salt):
    return hashlib.sha256(
        salt.encode() + code.encode()
    ).hexdigest()


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_session(username, now):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + SESSION_LIFETIME,
        "iss": "MFA-Physical-Token-API",
        "mfa": True
    }

    first = b64url(json.dumps(header, separators=(",", ":")).encode())
    second = b64url(json.dumps(payload, separators=(",", ":")).encode())
    content = first + "." + second

    signature = hmac.new(
        SESSION_SECRET,
        content.encode(),
        hashlib.sha256
    ).digest()

    return content + "." + b64url(signature)


def get_login_attempts(username, now):
    result = attempts_table.get_item(
        Key={"userId": username},
        ConsistentRead=True
    )
    item = result.get("Item")

    if not item or int(item.get("expiresAt", 0)) <= now:
        return 0

    return int(item.get("failedCount", 0))


def record_failed_login(username, now):
    for _ in range(3):
        result = attempts_table.get_item(
            Key={"userId": username},
            ConsistentRead=True
        )
        item = result.get("Item")

        try:
            if not item:
                attempts_table.put_item(
                    Item={
                        "userId": username,
                        "failedCount": 1,
                        "expiresAt": now + LOGIN_WINDOW
                    },
                    ConditionExpression="attribute_not_exists(userId)"
                )
                return

            expiry = int(item["expiresAt"])

            if expiry <= now:
                attempts_table.update_item(
                    Key={"userId": username},
                    UpdateExpression=(
                        "SET failedCount = :one, expiresAt = :expiry"
                    ),
                    ConditionExpression="expiresAt <= :now",
                    ExpressionAttributeValues={
                        ":one": 1,
                        ":expiry": now + LOGIN_WINDOW,
                        ":now": now
                    }
                )
                return

            attempts_table.update_item(
                Key={"userId": username},
                UpdateExpression="ADD failedCount :one",
                ConditionExpression="expiresAt > :now",
                ExpressionAttributeValues={
                    ":one": 1,
                    ":now": now
                }
            )
            return

        except ClientError as error:
            if error.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise

    raise RuntimeError("Rate limit update contention")


def register(body):
    username = body.get("username", "")
    password = body.get("password", "")

    if not isinstance(username, str) or not isinstance(password, str):
        return response(400, {"message": "Invalid input"})

    username = username.strip().lower()

    if not re.fullmatch(r"[a-z0-9_]{3,30}", username):
        return response(400, {
            "message": "Username must contain 3-30 letters, numbers or underscores"
        })

    if not 12 <= len(password) <= 128:
        return response(400, {
            "message": "Password must be 12-128 characters"
        })

    salt = secrets.token_bytes(16)

    try:
        users.put_item(
            Item={
                "userId": username,
                "passwordHash": password_hash(password, salt),
                "passwordSalt": base64.b64encode(salt).decode(),
                "passwordIterations": ITERATIONS,
                "mfaEnabled": False
            },
            ConditionExpression="attribute_not_exists(userId)"
        )
    except ClientError as error:
        if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return response(409, {"message": "Username already exists"})
        raise

    return response(201, {
        "success": True,
        "message": "Registration successful"
    })


def login(body, now):
    username = body.get("username", "")
    password = body.get("password", "")

    if not isinstance(username, str) or not isinstance(password, str):
        return response(400, {"message": "Invalid input"})

    username = username.strip().lower()

    if not re.fullmatch(r"[a-z0-9_]{3,30}", username):
        return response(400, {"message": "Invalid username"})

    if len(password) > 128:
        return response(400, {"message": "Invalid password"})

    if get_login_attempts(username, now) >= MAX_LOGIN_ATTEMPTS:
        return response(429, {
            "message": "Too many failed attempts. Try again later."
        })

    result = users.get_item(
        Key={"userId": username},
        ConsistentRead=True
    )
    user = result.get("Item")

    if user:
        salt = base64.b64decode(user["passwordSalt"])
        expected = user["passwordHash"]
        iterations = int(user["passwordIterations"])
    else:
        salt = bytes(16)
        expected = password_hash("dummy-password", salt)
        iterations = ITERATIONS

    actual = password_hash(password, salt, iterations)

    if not user or not hmac.compare_digest(actual, expected):
        record_failed_login(username, now)
        return response(401, {
            "success": False,
            "message": "Invalid username or password"
        })

    challenge_id = secrets.token_urlsafe(24)

    challenges.put_item(
        Item={
            "challengeId": challenge_id,
            "userId": username,
            "createdAt": now,
            "expiresAt": now + OTP_LIFETIME,
            "attempts": 0,
            "used": False,
            "status": "pending"
        },
        ConditionExpression="attribute_not_exists(challengeId)"
    )

    return response(200, {
        "success": True,
        "message": "Password verified. MFA required.",
        "challengeId": challenge_id,
        "mfaRequired": True
    })


def verify_otp(body, now):
    challenge_id = body.get("challengeId", "")
    code = body.get("otp", "")

    if not isinstance(challenge_id, str) or not isinstance(code, str):
        return response(400, {"message": "Invalid input"})

    if not challenge_id or not re.fullmatch(r"\d{6}", code):
        return response(400, {"message": "Invalid OTP request"})

    result = challenges.get_item(
        Key={"challengeId": challenge_id},
        ConsistentRead=True
    )
    challenge = result.get("Item")

    if not challenge:
        return response(401, {"message": "Invalid or expired challenge"})

    if (
        challenge.get("used")
        or int(challenge["expiresAt"]) <= now
        or int(challenge["attempts"]) >= MAX_OTP_ATTEMPTS
    ):
        return response(401, {"message": "Invalid or expired challenge"})

    if challenge.get("status") != "ready":
        return response(409, {"message": "Token not generated yet"})

    correct = hmac.compare_digest(
        otp_hash(code, challenge["otpSalt"]),
        challenge["otpHash"]
    )

    if not correct:
        try:
            challenges.update_item(
                Key={"challengeId": challenge_id},
                UpdateExpression="ADD attempts :one",
                ConditionExpression=(
                    "used = :false AND expiresAt > :now "
                    "AND attempts < :max AND #st = :ready"
                ),
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={
                    ":one": 1,
                    ":false": False,
                    ":now": now,
                    ":max": MAX_OTP_ATTEMPTS,
                    ":ready": "ready"
                }
            )
        except ClientError as error:
            if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return response(401, {"message": "Challenge unavailable"})
            raise

        return response(401, {
            "success": False,
            "message": "Incorrect OTP"
        })

    try:
        challenges.update_item(
            Key={"challengeId": challenge_id},
            UpdateExpression="SET used = :true, #st = :verified",
            ConditionExpression=(
                "used = :false AND expiresAt > :now "
                "AND attempts < :max AND #st = :ready"
            ),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":true": True,
                ":false": False,
                ":now": now,
                ":max": MAX_OTP_ATTEMPTS,
                ":verified": "verified",
                ":ready": "ready"
            }
        )
    except ClientError as error:
        if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return response(401, {"message": "Challenge unavailable"})
        raise

    token = create_session(challenge["userId"], now)

    return response(200, {
        "success": True,
        "message": "MFA verification successful",
        "accessToken": token,
        "tokenType": "Bearer",
        "expiresIn": SESSION_LIFETIME
    })


def lambda_handler(event, context):
    try:
        http = event.get("requestContext", {}).get("http", {})
        method = http.get("method", "")
        path = event.get("rawPath", "")

        if method != "POST":
            return response(404, {"message": "Route not found"})

        routes = {
            "/register": register,
            "/login": login,
            "/verify-otp": verify_otp
        }

        if path not in routes:
            return response(404, {"message": "Route not found"})

        body = event.get("body", "{}")

        if isinstance(body, str):
            if event.get("isBase64Encoded"):
                body = base64.b64decode(body).decode()
            body = json.loads(body)

        if not isinstance(body, dict):
            return response(400, {"message": "Invalid JSON body"})

        now = int(time.time())

        if path == "/register":
            return register(body)
        if path == "/login":
            return login(body, now)

        return verify_otp(body, now)

    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return response(400, {"message": "Invalid request"})
    except ClientError:
        return response(500, {"message": "Database operation failed"})
    except Exception:
        return response(500, {"message": "Internal server error"})
