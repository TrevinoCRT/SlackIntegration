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
import logging

load_dotenv()  # Load environment variables

# Load Slack credentials
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")

app = Flask(__name__)
# Register the Blueprint with the app
app.register_blueprint(oauth_bp) 

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger()

# Ensure that the Flask app's logger uses the same configuration
app.logger.handlers = logger.handlers
app.logger.setLevel(logger.level)


# Assuming the environment variables are set for the URLs of the oauthoption.py endpoints
OAUTH_JIRA_URL = os.getenv("OAUTH_JIRA_URL", "https://jiraslackgpt-592ed3dfdc03.herokuapp.com/start-oauth-jira")
OAUTH_SHEETS_URL = os.getenv("OAUTH_SHEETS_URL", "https://jiraslackgpt-592ed3dfdc03.herokuapp.com/start-oauth-sheets")
PROCESS_MESSAGE_URL = os.getenv("PROCESS_MESSAGE_URL", "https://jiraslackgpt-592ed3dfdc03.herokuapp.com/process-message")
START_ASSISTANT_URL = os.getenv("START_ASSISTANT_URL", "https://jiraslackgpt-592ed3dfdc03.herokuapp.com/start-assistant")
GET_LATEST_MESSAGES_URL = os.getenv("GET_LATEST_MESSAGES_URL", "https://jiraslackgpt-592ed3dfdc03.herokuapp.com/get-latest-messages")
PROCESS_MESSAGE_URL = os.getenv("PROCESS_MESSAGE_URL", "https://jiraslackgpt-592ed3dfdc03.herokuapp.com/process-message")

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

def send_app_home_ui(user_id):
    url = "https://slack.com/api/views.publish"
    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}", "Content-Type": "application/json"}
    block_kit_payload = {
        "type": "home",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Welcome to the *Jira Story and Epic ID Bot*! This bot integrates Jira and Google Sheets with Slack, allowing you to manage projects and data seamlessly from within Slack."
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "To get started, you'll need to authorize the bot to access your Jira and Google Sheets accounts. Please click the buttons below to initiate the OAuth process."
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Authorize Jira",
                            "emoji": True
                        },
                        "value": "jira_oauth",
                        "url": OAUTH_JIRA_URL
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Authorize Google Sheets",
                            "emoji": True
                        },
                        "value": "sheets_oauth",
                        "url": OAUTH_SHEETS_URL
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "After authorization, you can start interacting with the bot by sending messages. For example, you can ask it to fetch data from Google Sheets or create and manage Jira issues directly from Slack."
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "If you need help or want to learn more about what you can do, just type `help` to see a list of commands and features."
                }
            }
        ]
    }
    payload = {
        "user_id": user_id,
        "view": json.dumps(block_kit_payload)  # Ensure the view payload is JSON-encoded
    }
    response = requests.post(url, headers=headers, json=payload)
    if not response.ok:
        logging.error(f"Error sending Block Kit UI to App Home: {response.text}")
    else:
        logging.info(f"Successfully sent Block Kit UI to App Home: {response.json()}")
        print(response.json())  # Debug: Print the response


@app.route('/slack/interactions', methods=['POST'])
def slack_interactions():
    logging.info("Received Slack interaction.")
    try:
        payload = json.loads(request.form["payload"])
        action_id = payload["actions"][0]["action_id"]
        logging.info(f"Action ID: {action_id}")

        if action_id == "action_jira_oauth":
            oauth_url = OAUTH_JIRA_URL
        elif action_id == "action_sheets_oauth":
            oauth_url = OAUTH_SHEETS_URL
        else:
            logging.warning(f"Unknown action: {action_id}")
            return jsonify({"error": "Unknown action"}), 400

        logging.info(f"Directing user to OAuth URL: {oauth_url}")
        response_message = {
            "text": f"Please click the link to authorize: {oauth_url}",
            "replace_original": "true"
        }
        return jsonify(response_message)
    except Exception as e:
        logging.error(f"Error handling Slack interaction: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500



@app.route("/slack/events", methods=["POST"])
def slack_events():
    logging.info("Received Slack event.")
    if not verify_slack_request(request):
        logging.warning("Verification failed for Slack event.")
        return jsonify({"error": "Verification failed"}), 403

    slack_event = request.json
    logging.info(f"Slack event type: {slack_event.get('type')}")

    if slack_event.get("type") == "url_verification":
        logging.info("URL verification event received.")
        return jsonify({"challenge": slack_event["challenge"]})
    
    if slack_event.get('type') == 'app_home_opened':
        user_id = slack_event.get('user')  # User ID who opened the App Home
        send_app_home_ui(user_id)
        return jsonify({"status": "App Home UI sent"}), 200
    
    if slack_event.get("type") == "event_callback":
        event = slack_event.get("event", {})
        logging.info(f"Event callback received. Event type: {event.get('type')}")

        if event.get("type") == "message" and not event.get("bot_id"):  # Ignore bot messages
            channel_id = event.get("channel")
            user_message = event.get("text", "").lower()
            logging.info(f"Message received in channel {channel_id}: {user_message}")

            if "start assistant" in user_message:
                logging.info("Starting assistant based on user message.")
                # Ensure START_ASSISTANT_URL is correct and payload is as expected
                start_response = requests.post(START_ASSISTANT_URL, json={"text": user_message}, timeout=5)
                if start_response.status_code != 200:
                    logging.error(f"Failed to start assistant: {start_response.text}")
                    send_message_to_slack(channel_id, "Failed to start the assistant.")
                    return jsonify({"status": "Assistant start failed"}), 200

                # Assuming the assistant immediately sends a response which we fetch
                time.sleep(3)  # Adjust the delay as needed
                messages_response = requests.get(GET_LATEST_MESSAGES_URL)
                try:
                    latest_messages = messages_response.json()
                except json.JSONDecodeError:
                    logging.error("Failed to decode JSON from latest messages response.")
                    send_message_to_slack(channel_id, "Failed to decode latest messages.")
                    return jsonify({"status": "JSON decode error"}), 200

                latest_assistant_message = next((msg for msg in latest_messages if msg.get("role") == "assistant"), None)
                if latest_assistant_message:
                    send_message_to_slack(channel_id, latest_assistant_message.get("text", "No message found."))
                else:
                    send_message_to_slack(channel_id, "Failed to get a response from the assistant.")
            else:               
                logging.info("Processing user message without starting assistant.")
                process_message_response = requests.post(PROCESS_MESSAGE_URL, json={"text": user_message})
                if process_message_response.status_code != 200:
                    logging.error(f"Failed to process user message: {process_message_response.text}")
                    send_message_to_slack(channel_id, "Failed to process your message.")
                    return jsonify({"status": "Message processing failed"}), 200

                # Assuming the assistant immediately sends a response which we fetch
                time.sleep(3)  # Adjust the delay as needed
                try:
                    messages_response = requests.get(GET_LATEST_MESSAGES_URL)
                    messages_response.raise_for_status()  # Raises an HTTPError for bad responses
                    latest_messages = messages_response.json()
                except requests.exceptions.HTTPError as http_err:
                    logging.error(f"HTTP error occurred: {http_err}")
                    send_message_to_slack(channel_id, "Failed to fetch latest messages due to a server error.")
                    return jsonify({"status": "HTTP error"}), 200
                except json.JSONDecodeError:
                    logging.error("Failed to decode JSON from latest messages response.")
                    send_message_to_slack(channel_id, "Failed to decode latest messages.")
                    return jsonify({"status": "JSON decode error"}), 200
                except Exception as err:
                    logging.error(f"An unexpected error occurred: {err}")
                    send_message_to_slack(channel_id, "An unexpected error occurred.")
                    return jsonify({"status": "Unexpected error"}), 200

                latest_assistant_message = next((msg for msg in latest_messages if msg.get("role") == "assistant"), None)
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