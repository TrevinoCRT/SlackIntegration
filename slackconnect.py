from flask import Flask, request, jsonify
import os
import requests
import time
from dotenv import load_dotenv
import hashlib
import hmac
import json
from flask import Flask
from oauthoption import oauth_bp  

load_dotenv()  # Load environment variables

# Load Slack credentials
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")

app = Flask(__name__)
# Register the Blueprint with the app
app.register_blueprint(oauth_bp, url_prefix='/oauth')

# Assuming the environment variables are set for the URLs of the oauthoption.py endpoints
OAUTH_JIRA_URL = os.getenv("OAUTH_JIRA_URL", "http://localhost:5001/start-oauth-jira")
OAUTH_SHEETS_URL = os.getenv("OAUTH_SHEETS_URL", "http://localhost:5001/start-oauth-sheets")
PROCESS_MESSAGE_URL = os.getenv("PROCESS_MESSAGE_URL", "http://localhost:5001/process-message")
START_ASSISTANT_URL = os.getenv("START_ASSISTANT_URL", "http://localhost:5001/start-assistant")
GET_LATEST_MESSAGES_URL = "http://localhost:5001/get-latest-messages"

def verify_slack_request(request):
    request_body = request.get_data().decode('utf-8')
    timestamp = request.headers.get('X-Slack-Request-Timestamp')
    
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False
    
    sig_basestring = f"v0:{timestamp}:{request_body}"
    my_signature = 'v0=' + hmac.new(
        bytes(SLACK_SIGNING_SECRET, 'utf-8'),
        bytes(sig_basestring, 'utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    slack_signature = request.headers.get('X-Slack-Signature')
    
    return hmac.compare_digest(my_signature, slack_signature)

@app.route('/slack/interactions', methods=['POST'])
def slack_interactions():
    payload = json.loads(request.form["payload"])
    action_id = payload["actions"][0]["action_id"]

    if action_id == "action_jira_oauth":
        # Redirect user to Jira OAuth URL
        oauth_url = OAUTH_JIRA_URL
    elif action_id == "action_sheets_oauth":
        # Redirect user to Google Sheets OAuth URL
        oauth_url = OAUTH_SHEETS_URL
    else:
        return jsonify({"error": "Unknown action"}), 400

    # Respond with a message directing the user to initiate OAuth in their browser
    response_message = {
        "text": f"Please click the link to authorize: {oauth_url}",
        "replace_original": "true"
    }
    return jsonify(response_message)

@app.route("/slack/events", methods=["POST"])
def slack_events():
    if not verify_slack_request(request):
        return jsonify({"error": "Verification failed"}), 403

    slack_event = request.json

    if slack_event.get("type") == "url_verification":
        return jsonify({"challenge": slack_event["challenge"]})

    if slack_event.get("type") == "event_callback":
        event = slack_event.get("event", {})

        if event.get("type") == "message" and not event.get("bot_id"):  # Ignore bot messages
            channel_id = event.get("channel")
            user_message = event.get("text", "").lower()

            if "start assistant" in user_message:
                # Trigger the assistant start
                start_response = requests.post(START_ASSISTANT_URL, json={"text": user_message}, timeout=5)
                # Assuming the assistant immediately sends a response which we fetch
                time.sleep(3)  # Adjust the delay as needed
                messages_response = requests.get(GET_LATEST_MESSAGES_URL)
                latest_messages = messages_response.json()
                latest_assistant_message = next((msg for msg in latest_messages if msg["role"] == "assistant"), None)
                if latest_assistant_message:
                    send_message_to_slack(channel_id, latest_assistant_message.get("text", "No message found."))
                else:
                    send_message_to_slack(channel_id, "Failed to get a response from the assistant.")
            else:                
                requests.post(PROCESS_MESSAGE_URL, json={"text": user_message})
                # Assuming the assistant immediately sends a response which we fetch
                time.sleep(3)  # Adjust the delay as needed
                messages_response = requests.get(GET_LATEST_MESSAGES_URL)
                latest_messages = messages_response.json()
                latest_assistant_message = next((msg for msg in latest_messages if msg["role"] == "assistant"), None)
                if latest_assistant_message:
                    send_message_to_slack(channel_id, latest_assistant_message.get("text", "No message found."))
                else:
                    send_message_to_slack(channel_id, "Failed to get a response from the assistant.")
        return jsonify({"status": "Event received"}), 200

def send_message_to_slack(channel_id, text):
    url = "https://slack.com/api/chat.postMessage"
    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}"}
    payload = {
        "channel": channel_id,
        "text": text
    }
    response = requests.post(url, headers=headers, json=payload)
    if not response.ok:
        print(f"Error sending message to Slack: {response.text}")

if __name__ == "__main__":
    app.run(port=3000, debug=True)