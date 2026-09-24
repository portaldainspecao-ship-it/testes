import hmac
import logging
import os

from flask import Flask, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)


@app.get("/")
def health():
    return "Assistente Henfel: webhook ativo", 200


@app.get("/webhook")
def verify_webhook():
    secret = os.environ.get("VERIFY_TOKEN", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if (
        request.args.get("hub.mode") == "subscribe"
        and secret
        and hmac.compare_digest(token, secret)
        and challenge
    ):
        return challenge, 200, {"Content-Type": "text/plain; charset=utf-8"}

    return "Forbidden", 403


@app.post("/webhook")
def receive_webhook():
    secret = os.environ.get("META_APP_SECRET", "")
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not secret or not signature.startswith("sha256="):
        return "Forbidden", 403

    digest = hmac.new(secret.encode(), request.get_data(), "sha256").hexdigest()
    if not hmac.compare_digest(signature[7:], digest):
        return "Forbidden", 403

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return "Bad Request", 400

    app.logger.info("Evento Meta recebido: %s", payload.get("object", "desconhecido"))
    return "EVENT_RECEIVED", 200
