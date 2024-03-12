from flask import Flask, request, jsonify
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.signature import SignatureVerifier
import os
import requests
import json

app = Flask(__name__)

# Initialize a Web client with your OAuth token
slack_token = os.environ["SLACK_BOT_TOKEN"]
client = WebClient(token=slack_token)

signature_verifier = SignatureVerifier(os.environ["SLACK_SIGNING_SECRET"])

@app.route("/slack/interactions", methods=["POST"])
def slack_interactions():
    if not signature_verifier.is_valid_request(request.get_data(), request.headers):
        return "Invalid request", 400

    payload = request.form.get("payload")
    if payload:
        payload = json.loads(payload)
        action_id = payload["actions"][0]["action_id"]

        if action_id == "oauth_jira_setup":
            # Trigger OAuth flow for Jira
            pass  # Implement the logic here
        elif action_id == "oauth_sheets_setup":
            # Trigger OAuth flow for Sheets
            pass  # Implement the logic here

    return jsonify({"status": "ok"})

@app.route("/slack/events", methods=["POST"])
def slack_events():
    # Extract the request's JSON body
    slack_event = request.json
    
    # Verify the request came from Slack
    if "challenge" in slack_event:
        return jsonify({"challenge": slack_event["challenge"]})
    
    # Handle the event (this is where you'll add your logic)
    if "event" in slack_event:
        event = slack_event["event"]
        
        # Check if the event is a message without a subtype
        if event["type"] == "message" and "subtype" not in event:
            channel_id = event["channel"]
            user_message = event["text"]
            lower_message = user_message.lower()

            # Respond to a message event
            try:
                response = client.chat_postMessage(
                    channel=channel_id,
                    text=f"Received your message: {user_message}"
                )
            except SlackApiError as e:
                print(f"Error sending message: {e}")

            # Start assistant or trigger OAuth flow based on the message
            if "start assistant" in lower_message:
                response = requests.post("http://localhost:5001/start-assistant")
                message = "Assistant started and training data sent." if response.status_code == 200 else "Failed to start assistant."
            elif "start oauth jira" in lower_message:
                response = requests.get("http://localhost:5001/start-oauth-jira")
                message = "Jira OAuth initiated." if response.status_code == 200 else "Failed to initiate Jira OAuth."
            elif "start oauth sheets" in lower_message:
                response = requests.get("http://localhost:5001/start-oauth-sheets")
                message = "Sheets OAuth initiated." if response.status_code == 200 else "Failed to initiate Sheets OAuth."
            else:
                # Send the message to oauthoption.py for processing
                response = requests.post("http://localhost:5001/process-message", json={"text": user_message})
                message = response.json().get("response") if response.status_code == 200 else "Failed to process message."
            
            # Send the response back to the Slack channel
            try:
                client.chat_postMessage(channel=channel_id, text=message)
            except SlackApiError as e:
                print(f"Error sending message: {e}")
        
        return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(debug=True, port=3000)