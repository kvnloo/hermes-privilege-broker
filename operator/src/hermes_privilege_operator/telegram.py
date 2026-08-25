import json
import argparse
import re
import socket
import sys
import os
import urllib.parse
import urllib.request
from hermes_privilege_broker.daemon import receive_frame, send_frame
from hermes_privilege_broker.protocol import canonical_digest

_BIDI = dict.fromkeys(map(ord, "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"), None)


def render_approval(request, max_bytes=1024):
    value = json.dumps(request, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    value = value.translate(_BIDI).replace("```", "` ` `").replace("<", "\\u003c").replace(">", "\\u003e")
    raw = value.encode()[:max_bytes]
    return raw.decode("utf-8", "ignore")


def parse_callback(callback, allowed_user_ids):
    sender = callback.get("from") if isinstance(callback, dict) else None
    if not isinstance(sender, dict) or sender.get("id") not in allowed_user_ids:
        raise PermissionError("Telegram operator is not allowed")
    data = callback.get("data")
    if not isinstance(data, str) or not re.fullmatch(r"(approve|deny):[A-Za-z0-9_.-]{1,128}:[0-9a-f]{64}", data):
        raise ValueError("invalid callback")
    action, request_id, digest = data.split(":")
    return action, request_id, digest


def send_decision(operator_socket, callback, allowed_user_ids):
    action, request_id, digest = parse_callback(callback, allowed_user_ids)
    message = {"method": action, "request_id": request_id, "request_digest": digest}
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(operator_socket)
    send_frame(connection, message)
    response = receive_frame(connection)
    connection.close()
    result = json.loads(response)
    if not result.get("ok"):
        raise RuntimeError("broker refused decision")
    return result["result"]


def fetch_pending(operator_socket, request_id):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", request_id):
        raise ValueError("invalid request id")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(operator_socket)
    send_frame(connection, {"method": "status", "request_id": request_id})
    response = json.loads(receive_frame(connection))
    connection.close()
    if not response.get("ok") or response["result"].get("state") != "pending":
        raise RuntimeError("request is not pending")
    pending = response["result"]
    if canonical_digest(pending["request"]) != pending["request_digest"]:
        raise RuntimeError("pending request digest mismatch")
    return pending


def render_pending(pending):
    view = {"request": pending["request"], "request_digest": pending["request_digest"], "catalog_digest": pending["catalog_digest"], "requester": {"uid": pending["uid"], "pid": pending["pid"], "start_time": pending["start_time"]}}
    return render_approval(view)


def telegram_api(token, method, payload):
    if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{20,}", token):
        raise ValueError("invalid Telegram bot token")
    request = urllib.request.Request(f"https://api.telegram.org/bot{token}/{method}", data=urllib.parse.urlencode(payload).encode(), method="POST")
    with urllib.request.urlopen(request, timeout=40) as response:
        result = json.load(response)
    if not result.get("ok"):
        raise RuntimeError("Telegram API refused request")
    return result["result"]


def serve_telegram(operator_socket, token, allowed_user_ids, chat_id):
    offset = 0
    while True:
        updates = telegram_api(token, "getUpdates", {"offset": offset, "timeout": 30, "allowed_updates": '["callback_query"]'})
        for update in updates:
            offset = max(offset, update["update_id"] + 1)
            callback = update.get("callback_query")
            if not callback:
                continue
            try:
                message = callback.get("message") if isinstance(callback, dict) else None
                chat = message.get("chat") if isinstance(message, dict) else None
                callback_chat = chat.get("id") if isinstance(chat, dict) else None
                if callback_chat != chat_id:
                    raise PermissionError("callback is from the wrong chat")
                action, request_id, digest = parse_callback(callback, allowed_user_ids)
                pending = fetch_pending(operator_socket, request_id)
                if pending["request_digest"] != digest:
                    raise RuntimeError("Telegram callback digest is stale")
                send_decision(operator_socket, callback, allowed_user_ids)
                telegram_api(token, "answerCallbackQuery", {"callback_query_id": callback["id"], "text": f"{action} recorded"})
            except (AttributeError, KeyError, TypeError, ValueError, PermissionError, RuntimeError):
                callback_id = callback.get("id") if isinstance(callback, dict) else None
                if callback_id:
                    try:
                        telegram_api(token, "answerCallbackQuery", {"callback_query_id": callback_id, "text": "Approval rejected", "show_alert": "true"})
                    except (OSError, ValueError, RuntimeError):
                        pass
                continue


def publish_pending(operator_socket, token, chat_id, request_id):
    pending = fetch_pending(operator_socket, request_id)
    digest = pending["request_digest"]
    keyboard = {"inline_keyboard": [[{"text": "Approve once", "callback_data": f"approve:{request_id}:{digest}"}, {"text": "Deny", "callback_data": f"deny:{request_id}:{digest}"}]]}
    return telegram_api(token, "sendMessage", {"chat_id": chat_id, "text": render_pending(pending), "reply_markup": json.dumps(keyboard, separators=(",", ":"))})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("publish", "serve"))
    parser.add_argument("--operator-socket", required=True)
    parser.add_argument("--request-id")
    parser.add_argument("--allowed-user-id", action="append", type=int, default=[])
    parser.add_argument("--chat-id", type=int, required=True)
    args = parser.parse_args()
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if args.action == "publish":
        if not args.request_id:
            parser.error("publish requires --request-id")
        publish_pending(args.operator_socket, token, args.chat_id, args.request_id)
    else:
        if not args.allowed_user_id:
            parser.error("serve requires --allowed-user-id")
        serve_telegram(args.operator_socket, token, set(args.allowed_user_id), args.chat_id)
