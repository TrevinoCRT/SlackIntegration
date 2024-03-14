import requests
from requests.exceptions import RequestException, Timeout
import json
import time
import openai
import threading
import traceback
import webbrowser
import os
import re
import configparser
import random
import atexit
import signal
import sys
from flask import Flask, request, jsonify, Blueprint, redirect, current_app, url_for
import queue

# Additional imports specific to Google Sheets API and OAuth
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

from http.server import HTTPServer, BaseHTTPRequestHandler, SimpleHTTPRequestHandler
import socketserver
import urllib.parse
import urllib.request
from urllib.parse import urlparse, parse_qs
import uuid
import logging
import base64
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_state_parameter():
    return str(uuid.uuid4())


# Load environment variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ASSISTANT_ID = os.getenv("ASSISTANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
TOKEN_URL = os.getenv("TOKEN_URL")
# For SCOPES, since it's a space-separated list, ensure it's properly formatted if needed
JIRA_SCOPES = os.getenv("JIRA_SCOPES", "read:jira-work write:jira-work manage:jira-project manage:jira-webhook manage:jira-configuration read:me read:account")
SPREADSHEET_ID = os.getenv("SPREADSHEET_ID")

# URLs for OAuth and message processing
OAUTH_JIRA_URL = os.getenv("OAUTH_JIRA_URL")
OAUTH_SHEETS_URL = os.getenv("OAUTH_SHEETS_URL")
PROCESS_MESSAGE_URL = os.getenv("PROCESS_MESSAGE_URL")
GET_LATEST_MESSAGES_URL = os.getenv("GET_LATEST_MESSAGES_URL")
START_ASSISTANT_URL = os.getenv("START_ASSISTANT_URL")

# Update the AUTHORIZATION_URL to use the environment variables
AUTHORIZATION_URL = f'https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id={CLIENT_ID}&scope={JIRA_SCOPES}&redirect_uri={REDIRECT_URI}&state={generate_state_parameter()}&response_type=code&prompt=consent'

# Update for Google Sheets API
GOOGLE_SCOPES = os.getenv("GOOGLE_SCOPES")
API_SERVICE_NAME = 'sheets'
API_VERSION = 'v4'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

thread_id = None
last_displayed_message_id = None
displayed_message_ids = set()  # Keep track of displayed message IDs
# OAuth and Google Sheets Integration
# Function to start the OAuth process and server for Google Sheets API
# Inside your existing function or setup
# Declare `flow` as a global variable
global flow


# Function to save Google Sheets API credentials to a file
def save_credentials(credentials):
    directory = os.path.dirname(os.path.realpath(__file__))
    credentials_file = os.path.join(directory, 'credentials.json')
    os.makedirs(os.path.dirname(credentials_file), exist_ok=True)
    with open(credentials_file, 'w') as file:
        file.write(credentials.to_json())
    os.chmod(credentials_file, 0o600)

# Function to authenticate with Google Sheets API using saved credentials
def google_authenticate():
    directory = os.path.dirname(os.path.realpath(__file__))
    credentials_file = os.path.join(directory, 'credentials.json')
    with open(credentials_file, 'r') as file:
        credentials_json = file.read()
    credentials = Credentials.from_authorized_user_info(json.loads(credentials_json))
    service = build(API_SERVICE_NAME, API_VERSION, credentials=credentials)
    return service

# Function to retrieve values from column A of a specified Google Sheet
def retrieve_values_from_column_a(service, spreadsheet_id):
    result = service.spreadsheets().values().get(
        spreadsheetId=spreadsheet_id, range="A:A").execute()
    values = result.get('values', [])
    return values

def edit_spreadsheet(spreadsheet_id, range_name, value_input_option, value_range_body):
    """
    Edit the specified range of a spreadsheet with the provided values.
    Args:
        spreadsheet_id (str): The ID of the spreadsheet to update.
        range_name (str): The A1 notation of the range to update.
        value_input_option (str): How the input data should be interpreted.
        value_range_body (dict): The data to be written. Must contain a 'values' key.
    """
    service = google_authenticate()  # Reuse the existing authentication function

    try:
        # Call the Sheets API to update the spreadsheet
        request = service.spreadsheets().values().update(
            spreadsheetId=spreadsheet_id, range=range_name,
            valueInputOption=value_input_option, body=value_range_body)
        response = request.execute()
        print('Spreadsheet updated successfully!')
    except Exception as error:
        print(f"An error occurred: {error}")
        response = None

def retrieve_and_send_data(channel_id, slack_bot_token, displayed_message_ids):
    global thread_id

    if not thread_id:
        print("[ERROR] Thread not initialized. Exiting retrieve_and_send_data function.")
        return

    try:
        print("[INFO] Starting Google Sheets data retrieval...")
        service = google_authenticate()
        values = retrieve_values_from_column_a(service, SPREADSHEET_ID)  # Data retrieval for internal use
        if not values:
            print("[ERROR] No values retrieved from Google Sheets. Check the sheet's content and access permissions.")
            return
        training_data_message = "The bot has been updated with the latest user stories training data."

        add_message_response = add_message_to_thread(thread_id, "user", training_data_message)
        if add_message_response.get("error"):
            print(f"[ERROR] Failed to add message to thread: {add_message_response['error']}")
            return
        print("[INFO] Training data update message added to thread.")

        run_status_response = run_thread(thread_id, ASSISTANT_ID)
        if "error" in run_status_response:
            print(f"[ERROR] Failed to initiate run thread: {run_status_response['error']}")
            return
        run_id = run_status_response.get("id")  # Extract the run ID from the response
        if not run_id:
            print("[ERROR] No run ID received from run_thread function. Check OpenAI API response.")
            return
        print(f"[INFO] Run thread initiated. Run ID: {run_id[:10]}... (truncated for log)")

        check_and_display_new_messages(run_id, channel_id, slack_bot_token, displayed_message_ids)

    except Exception as e:
        print(f"[ERROR] Error updating training data: {str(e)[:100]}... (truncated for log)")
        traceback.print_exc()


# Jira OAuth Flow and API Integration
# Function to exchange authorization code for an access token with Jira API
def exchange_code_for_token(code):
    payload = {
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    response = requests.post(TOKEN_URL, data=payload)
    if response.status_code == 200:
        return response.json().get('access_token')
    else:
        logging.error(f"Failed to obtain access token. Error response: {response.json()}")
        raise Exception("Failed to obtain access token.")

# Function to save Jira API access token to a file
def save_access_token(token):
    with open('access_token.json', 'w') as token_file:
        json.dump({'access_token': token}, token_file)


# Function to retrieve the saved Jira API access token from a file
def get_saved_access_token():
    try:
        with open('access_token.json', 'r') as token_file:
            data = json.load(token_file)
            return data.get('access_token')
    except (FileNotFoundError, json.JSONDecodeError):
        print("Error decoding access token JSON.")
        return None

def update_issue_summary_and_description(issue_id_or_key, summary, description):
    """
    Updates the summary and description of a given issue.

    Args:
        issue_id_or_key (str): The ID or key of the issue to update.
        summary (str): The new summary for the issue.
        description (str): The new description for the issue.

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    # Retrieve the access token
    token = get_saved_access_token()
    if not token:
        print("[ERROR] No access token found. User needs to authenticate.")
        return False

    # Use a predefined or retrieved cloud ID
    cloud_id = '911ae68a-c409-4a8b-830a-5cda394f67ec'  # Replace with your actual Jira Cloud ID

    url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/2/issue/{issue_id_or_key}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {
        "fields": {
            "summary": summary,
            "description": description
        }
    }

    response = requests.put(url, headers=headers, json=payload)
    if response.status_code == 204:
        print(f"[SUCCESS] Issue {issue_id_or_key} updated successfully.")
        return True
    else:
        print(f"[ERROR] Failed to update issue {issue_id_or_key}. Status code: {response.status_code}, Response: {response.text}")
        return False


# Function to get issue details from Jira using the API
def get_issue_details(token, cloud_id, issue_id_or_key, fields=None, fields_by_keys=False, expand=None, properties=None, update_history=False):
    url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/2/issue/{issue_id_or_key}"
    print(f"[INFO] Fetching issue details for {issue_id_or_key[:10]}... from cloud ID: {cloud_id[:10]}")  # Added content limit to print statement

    # Prepare query parameters
    params = {
        'fields': ','.join(fields) if fields else None,
        'fieldsByKeys': fields_by_keys,
        'expand': expand,
        'properties': ','.join(properties) if properties else None,
        'updateHistory': update_history
    }
    print(f"[DEBUG] Query params: {str(params)[:100]}...")  # Added content limit to print statement

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    print(f"[DEBUG] Authorization header set with token limited to first 10 chars: {token[:10]}...")  # Added content limit to print statement

    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        response_json = response.json()
        print(f"[SUCCESS] Issue details fetched successfully for {issue_id_or_key[:10]}... Response size: {len(str(response_json))} characters")  # Added content limit to print statement
        return response_json
    else:
        print(f"[ERROR] Failed to fetch issue details for {issue_id_or_key[:10]}... Status code: {response.status_code}, Response: {str(response.json())[:100]}...")  # Added content limit to print statement
        return None

# Function to Retrieve Jira Issue
def retrieve_jira_issue(issue_key):
    if not issue_key:
        print("[WARNING] No Jira Issue Key provided. Operation aborted.")  # Added robust print statement
        return

    token = get_saved_access_token()
    if not token:
        print("[ERROR] No access token found. User needs to authenticate.")  # Added robust print statement
        return

    cloud_id = '911ae68a-c409-4a8b-830a-5cda394f67ec'  # Replace with your actual Jira Cloud ID
    try:
        print(f"[INFO] Attempting to retrieve issue with key: {issue_key[:10]}... from cloud ID: {cloud_id}")  # Added content limit to print statement
        issue_details = get_issue_details(token, cloud_id, issue_key)
        print(f"[SUCCESS] Issue retrieved successfully. Issue details (limited): {str(issue_details)[:100]}...")  # Added content limit to print statement
        return issue_details
    except Exception as e:
        print(f"[ERROR] Exception occurred while retrieving issue from Jira. Error: {str(e)[:100]}...")  # Added content limit to print statement
        return None

def get_epic_details(epic_id_or_key):
    """
    Retrieves details of a specific epic, including its summary and description.

    Args:
        epic_id_or_key (str): The ID or key of the epic.

    Returns:
        dict: The epic's details if successful, None otherwise.
    """
    # Use the same setup for token, cloud_id, and headers as in get_issues_for_epic
    token = get_saved_access_token()
    cloud_id = '911ae68a-c409-4a8b-830a-5cda394f67ec'
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # The endpoint for getting a single issue (the epic in this case)
    url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/2/issue/{epic_id_or_key}"

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        epic_details = response.json()
        return {
            "Key": epic_details.get('key'),
            "Summary": epic_details.get('fields', {}).get('summary', 'No summary provided'),
            "Description": epic_details.get('fields', {}).get('description', 'No description provided')
        }
    else:
        print(f"[ERROR] Failed to retrieve epic details for {epic_id_or_key}. Status code: {response.status_code}, Response: {response.text}")
        return None

def get_issues_for_epic(epic_id_or_key):
    """
    Retrieves the details of a specific epic along with all issues that are children of this epic.
    
    Args:
        epic_id_or_key (str): The ID or key of the epic.
    
    Returns:
        dict: A dictionary containing the epic's details and a list of child issues.
    """
    # Fetch the epic details
    epic_details = get_epic_details(epic_id_or_key)
    
    # Fetch the child issues for the epic
    child_issues = get_child_issues_for_epic(epic_id_or_key)
    
    # Combine both into a single dictionary
    combined_details = {
        "EpicDetails": epic_details,
        "ChildIssues": child_issues
    }
    
    return combined_details

def get_child_issues_for_epic(epic_id_or_key):
    """
    Retrieves all issues that are children of a specific epic in a team-managed project.

    Args:
        epic_id_or_key (str): The ID or key of the epic.

    Returns:
        list: A list of child issues if successful, None otherwise.
    """
    token = get_saved_access_token()
    if not token:
        print("[ERROR] No access token found. User needs to authenticate.")
        return None

    cloud_id = '911ae68a-c409-4a8b-830a-5cda394f67ec'  # Replace with your actual Jira Cloud ID
    url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/2/search"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # Adjusted JQL query to find all issues that are children of the specific epic in a team-managed project
    jql_query = f'parent = {epic_id_or_key}'

    payload = {
        "jql": jql_query,
        "startAt": 0,
        "maxResults": 50,  # Adjust this value as per your needs
        "fields": ["id", "key", "summary", "status", "assignee"]  # Specify the fields you are interested in
    }

    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 200:
        issues = response.json().get('issues', [])
        return issues
    else:
        print(f"[ERROR] Failed to retrieve child issues for epic {epic_id_or_key}. Status code: {response.status_code}, Response: {response.text}")
        return None


def format_linked_issues(combined_details):
    """
    Formats the combined epic details and list of linked child issues for display or further processing.

    Args:
        combined_details (dict): A dictionary containing epic details and a list of child issues.

    Returns:
        dict: Formatted epic details and a list of formatted child issues.
    """
    formatted_issues_list = []
    if not combined_details or "ChildIssues" not in combined_details or not combined_details["ChildIssues"]:
        print("[INFO] No linked issues found to format.")
        return {"EpicDetails": combined_details.get("EpicDetails", {}), "ChildIssues": formatted_issues_list}

    linked_issues = combined_details["ChildIssues"]
    print(f"[INFO] Formatting {len(linked_issues)} linked issues.")
    for issue in linked_issues:
        # Similar formatting logic as before
        fields = issue.get('fields', {})
        formatted_issue = {
            "Key": issue.get('key'),
            "Summary": fields.get('summary', 'No summary provided'),
            "Description": fields.get('description', 'No description provided'),
            # Additional fields as needed
        }
        formatted_issues_list.append(formatted_issue)
    
    return {
        "EpicDetails": combined_details.get("EpicDetails", {}),
        "ChildIssues": formatted_issues_list
    }

# Function to Send Jira Data to OpenAI
def format_jira_issue(raw_issue_details):
    issue = raw_issue_details.get('fields', {})
    formatted_issue = {
        "Summary": issue.get('summary', 'No summary provided'),
        "Description": issue.get('description', 'No description provided'),
        "Issue Type": issue.get('issuetype', {}).get('name', 'N/A'),
        "Status": issue.get('status', {}).get('name', 'N/A'),
        # Add more fields here as needed
    }
    return formatted_issue


# Initialize the global variable to track the last displayed message ID

def delete_thread(thread_id):
    logging.info(f"Attempting to delete thread with ID: {thread_id}")
    url = f"https://api.openai.com/v1/threads/{thread_id}"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "OpenAI-Beta": "assistants=v1",
        "Content-Type": "application/json"
    }
    response = requests.delete(url, headers=headers)
    if response.status_code == 200:
        logging.info("Thread deleted successfully.")
        print("Thread deleted successfully.")
    else:
        logging.error(f"Failed to delete thread: {response.text}")
        print(f"Failed to delete thread: {response.text}")

def cleanup():
    global thread_id  # Ensure thread_id is declared as global if it's not already
    if thread_id is not None:
        try:
            delete_thread(thread_id)  # Delete the thread
        except Exception as e:
            print(f"Failed to delete thread on exit: {str(e)}")

atexit.register(cleanup)

def create_thread(messages=None, metadata=None):
    global thread_id
    url = "https://api.openai.com/v1/threads"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
        "OpenAI-Beta": "assistants=v1"
    }
    data = {
        "messages": [
            {"role": "user", "content": "Initial message"}
        ]
    }
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        thread_id = response.json()['id']
        welcome_message = "Hey there - I’m the Kohl’s Jira User Story and Issue Assistance Bot, to begin please set up your oAuth for Jira and Sheets, with their corressponding buttons, and then type out the issue key you would like me to work on, or the epic-id you would like me to analyze the issues of-."

def add_message_to_thread(thread_id, role, content, file_ids=None, metadata=None):
    url = f"https://api.openai.com/v1/threads/{thread_id}/messages"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
        "OpenAI-Beta": "assistants=v1"
    }

    payload = {
        "role": role,
        "content": content,
        "file_ids": file_ids if file_ids else [],
        "metadata": metadata if metadata else {}
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=25)
        response.raise_for_status()  # Raises an HTTPError for bad responses
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return {"status": "error", "message": str(e)}

def run_thread(thread_id, assistant_id, model=None, instructions=None, additional_instructions=None, tools=None, metadata=None):
    # Start a new run
    url = f"https://api.openai.com/v1/threads/{thread_id}/runs"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
        "OpenAI-Beta": "assistants=v1"
    }

    # Define the get_jiraissue and update_jiraissue functions in tools if not provided
    tools = tools or [
        {
            "type": "function",
            "function": {
                "name": "get_jiraissue",
                "description": "Retrieve details of a Jira issue",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "issue_id": {
                            "type": "string",
                            "description": "The Jira issue ID, formatted as (boardid)-(issueid#)"
                        }
                    },
                    "required": ["issue_id"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_issues_for_epic",
                "description": "Retrieves all issues linked to a specific epic in Jira.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "epic_id_or_key": {
                            "type": "string",
                            "description": "The ID or key of the epic to retrieve issues for."
                        }
                    },
                    "required": ["epic_id_or_key"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "update_jiraissue",
                "description": "Using the previous issue key provided by the user, submit the revised user story as a summary and all other text as description",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "issue_id": {
                            "type": "string",
                            "description": "The Jira issue ID to update"
                        },
                        "summary": {
                            "type": "string",
                            "description": "The new summary for the Jira issue"
                        },
                        "description": {
                            "type": "string",
                            "description": "The new description for the Jira issue"
                        }
                    },
                    "required": ["issue_id", "summary", "description"]
                }
            }
        },
        {
            "type": "retrieval",
        }
    ]

    payload = {
        "assistant_id": assistant_id,
        "model": model,
        "instructions": instructions,
        "additional_instructions": additional_instructions,
        "tools": tools,
        "metadata": metadata or {}
    }
    response = requests.post(url, headers=headers, json=payload)
    run_id = response.json().get('id')  # Get the run ID from the response
    print(f"Run ID: {run_id}")  # Debug print statement
    return response.json()

def submit_function_outputs(thread_id, run_id, tool_call_id, tool_outputs):
    """
    Submits the outputs from the called functions back to the run, allowing it to continue.
    Includes error handling and retry logic for rate limiting.
    """
    print(f"Initiating submission of function outputs for thread_id: {thread_id[:8]}..., run_id: {run_id[:8]}..., tool_call_id: {tool_call_id[:8]}...")
    url = f"https://api.openai.com/v1/threads/{thread_id}/runs/{run_id}/submit_tool_outputs"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
        "OpenAI-Beta": "assistants=v1"
    }

    # Ensure each output is converted to a string
    formatted_tool_outputs = [{"tool_call_id": tool_call_id, "output": str(output)} for output in tool_outputs]
    data = {"tool_outputs": formatted_tool_outputs}

    max_retries = 3
    retry_delay = 1  # Initial delay in seconds

    # Attempt to submit the tool outputs with retry logic
    for attempt in range(max_retries):
        try:
            response = requests.post(url, json=data, headers=headers, timeout=10)  # Set a timeout of 10 seconds
            response.raise_for_status()  # Check for HTTP errors
            print("Submission successful.")
            return response.json()
        except Timeout:
            print("The request timed out. Retrying...")
        except RequestException as e:
            if e.response.status_code == 429:  # Rate limit exceeded
                print("Rate limit exceeded. Retrying with exponential backoff...")
                time.sleep(retry_delay)
                retry_delay *= 2  # Double the delay for exponential backoff
            else:
                print(f"An error occurred while submitting tool outputs: {e}")
                break  # Exit the loop for non-rate-limit errors
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            break  # Exit the loop for unexpected errors

    print("Failed to submit tool outputs after retries.")
    return {"status": "error", "message": "Failed to submit after retries."}

def get_run_steps(thread_id, run_id, limit=20, order="desc", after=None, before=None):
    url = f"https://api.openai.com/v1/threads/{thread_id}/runs/{run_id}/steps"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
        "OpenAI-Beta": "assistants=v1"
    }
    params = {
        "limit": limit,
        "order": order,
        "after": after,
        "before": before
    }

    response = requests.get(url, headers=headers, params=params)
    return response.json()

def get_run_status(thread_id, run_id):
    global should_continue_polling
    url = f"https://api.openai.com/v1/threads/{thread_id}/runs/{run_id}"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
        "OpenAI-Beta": "assistants=v1"
    }

    try:
        response = requests.get(url, headers=headers, timeout=25)
        if response.status_code == 200:
            run_status = response.json().get('status')
            if run_status in ['queued', 'in_progress']:
                return {"status": run_status, "message": "Run is either queued or in progress."}
            elif run_status == 'completed':
                # When the run is completed, stop polling
                should_continue_polling = False
                return {"status": run_status, "message": "Run has successfully completed!"}
            elif run_status == 'requires_action':
                tool_call_id = response.json().get('required_action', {}).get('submit_tool_outputs', {}).get('tool_calls', [{}])[0].get('id', None)
                return {"status": run_status, "message": "Run requires action. Please submit the required tool outputs.", "tool_call_id": tool_call_id}
            elif run_status == 'expired':
                return {"status": run_status, "message": "Run has expired. Outputs were not submitted in time."}
            elif run_status == 'cancelling':
                return {"status": run_status, "message": "Run is currently cancelling."}
            elif run_status == 'cancelled':
                return {"status": run_status, "message": "Run was successfully cancelled."}
            elif run_status == 'failed':
                last_error = response.json().get('last_error', 'No error information available.')
                return {"status": run_status, "message": f"Run failed. Error: {last_error}"}
            else:
                return {"status": "unknown", "message": "Unknown run status."}
        else:
            return {"status": "error", "message": f"Error: {response.status_code} - {response.text}"}
    except requests.exceptions.Timeout:
        return {"status": "error", "message": "Request timed out."}
    except requests.exceptions.RequestException as e:
        return {"status": "error", "message": f"Request failed: {e}"}

def retry_with_exponential_backoff(func):
    def wrapper(*args, **kwargs):
        max_retries = 5
        retry_delay = 1.0  # Start with a 1-second delay
        for attempt in range(max_retries):
            result = func(*args, **kwargs)
            # Determine if result is a response object or a dictionary
            if isinstance(result, dict):  # Error case, result is a dictionary
                status_code = result.get('status_code', 500)  # Default to 500 if status_code is not in dictionary
            else:  # Success case, result is a response object
                status_code = result.status_code
            
            if status_code == 429:  # Rate limit exceeded
                sleep_time = retry_delay * (2 ** attempt) + random.uniform(0, 1)
                print(f"Rate limit exceeded. Retrying in {sleep_time:.2f} seconds...")
                time.sleep(sleep_time)
            else:
                return result
        return func(*args, **kwargs)  # Final attempt outside of loop
    return wrapper

def load_messages_from_cache(thread_id):
    cache_file = f"cache_{thread_id}.json"
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as file:
            return json.load(file)
    return None

def save_messages_to_cache(thread_id, messages):
    cache_file = f"cache_{thread_id}.json"
    with open(cache_file, 'w') as file:
        json.dump(messages, file)

@retry_with_exponential_backoff
def get_messages(thread_id, limit=100, order="asc", after=None, before=None):
    print(f"Fetching messages for thread_id: {thread_id[:10]}... Limit: {limit}, Order: {order}, After: {str(after)[:10]}, Before: {str(before)[:10]}")
    url = f"https://api.openai.com/v1/threads/{thread_id}/messages"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
        "OpenAI-Beta": "assistants=v1"
    }
    params = {
        "limit": limit,
        "order": order,
        "after": after,
        "before": before
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            try:
                new_messages = response.json()
            except json.JSONDecodeError:
                logging.error("Failed to decode JSON. Attempting to fetch messages using a fallback method.")
                # Fallback method or retry logic here
                # For example, you might want to log this error and return a default response
                # or attempt to parse the response text manually if it's expected to be simple JSON
                return {"data": [], "error": "Failed to decode JSON, used fallback."}

            print(f"Successfully fetched messages. Response size: {len(str(new_messages))} characters")
            
            cached_messages = load_messages_from_cache(thread_id) or {"data": []}
            all_messages = cached_messages.get("data", []) + new_messages.get("data", [])
            unique_messages = {msg['id']: msg for msg in all_messages}.values()
            
            save_messages_to_cache(thread_id, {"data": list(unique_messages)})
            
            return {"data": list(unique_messages)}
        else:
            error_message = {"error": f"Error fetching messages: {response.status_code} - {response.text[:100]}", "status_code": response.status_code}
            print(error_message['error'])
            return error_message
    except requests.exceptions.RequestException as e:
        logging.error(f"Request to fetch messages failed: {e}")
        # Handle request errors (e.g., network issues) here
        return {"data": [], "error": "Request failed, used fallback."}

def save_last_message_id_to_cache(thread_id, last_message_id):
    cache_file = f"last_message_id_cache_{thread_id}.json"
    with open(cache_file, 'w') as file:
        json.dump({"last_message_id": last_message_id}, file)

def load_last_message_id_from_cache(thread_id):
    cache_file = f"last_message_id_cache_{thread_id}.json"
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as file:
            data = json.load(file)
            return data.get("last_message_id")
    return None

def get_last_message_id(thread_id):
    logging.debug("Fetching the last message ID for thread_id: %s", thread_id)

    # Attempt to load the last message ID from cache first
    cached_last_message_id = load_last_message_id_from_cache(thread_id)
    if cached_last_message_id:
        logging.debug("Last message ID loaded from cache: %s", cached_last_message_id)
        return cached_last_message_id

    # If not found in cache, fetch the latest messages in descending order (most recent first)
    messages_response = get_messages(thread_id, limit=1, order="desc")

    if isinstance(messages_response, dict) and messages_response.get("object") == "list":
        messages = messages_response.get("data", [])
        if messages:
            # Get the ID of the very last message, regardless of the sender
            last_message_id = messages[0].get("id")
            logging.debug("Last message ID found: %s", last_message_id)
            # Save the last message ID to cache
            save_last_message_id_to_cache(thread_id, last_message_id)
            return last_message_id

    logging.warning("No messages found in the thread")
    return None

def save_runs_to_cache(thread_id, runs):
    cache_file = f"runs_cache_{thread_id}.json"
    with open(cache_file, 'w') as file:
        json.dump(runs, file)

def load_runs_from_cache(thread_id):
    cache_file = f"runs_cache_{thread_id}.json"
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as file:
            return json.load(file)
    return None

def get_runs(thread_id, limit=100, order="desc", after=None, before=None):
    cached_runs = load_runs_from_cache(thread_id)
    if cached_runs:
        print("Loaded runs from cache.")
        return cached_runs

    url = f"https://api.openai.com/v1/threads/{thread_id}/runs"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
        "OpenAI-Beta": "assistants=v1"
    }
    params = {
        "limit": limit,
        "order": order,
        "after": after,
        "before": before
    }

    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        runs = response.json()
        # Save the fetched runs to cache
        save_runs_to_cache(thread_id, runs)
        return runs
    else:
        error_message = f"Error: {response.status_code} - {response.text}"
        print(error_message)
        return {"error": error_message}



def handle_run_status(thread_id, run_id):
    print("Starting to check the status of the run in a loop with a delay.")
    run_status = None
    while run_status not in ['completed', 'requires_action']:
        print(f"Checking run status for thread_id: {thread_id}, run_id: {run_id}")
        status_response = get_run_status(thread_id, run_id)
        run_status = status_response.get('status')
        print(f"Current run status: {run_status}")
        if run_status == 'requires_action':
            print("Run status requires action. Handling 'requires_action' status.")
            tool_call_id = status_response.get('tool_call_id')
            if tool_call_id:
                print(f"Found tool_call_id: {tool_call_id}. Fetching run steps.")
                steps_response = get_run_steps(thread_id, run_id)
                for step in steps_response.get('data', []):
                    for tool_call in step.get('step_details', {}).get('tool_calls', []):
                        if tool_call.get('type') == 'function' and tool_call.get('function', {}).get('name') == 'get_jiraissue':
                            print("Found 'get_jiraissue' function call. Parsing arguments.")
                            arguments_str = tool_call.get('function', {}).get('arguments', '{}')
                            arguments_dict = json.loads(arguments_str)
                            jira_issue_id = arguments_dict.get('issue_id')
                            if jira_issue_id:
                                print(f"Jira issue ID found: {jira_issue_id}. Retrieving issue details.")
                                # Perform Jira operations
                                issue_details = retrieve_jira_issue(jira_issue_id)  # Ensure this function accepts the issue ID as an argument
                                if issue_details:
                                    # Extract the summary and additional fields from the issue details
                                    formatted_issue_details = format_jira_issue(issue_details)
                                    formatted_output = "\n".join(f"{key}: {value}" for key, value in formatted_issue_details.items())
                                    print(f"Jira issue details extracted and formatted. Preparing tool output.")
                                    # Prepare the tool output with the formatted issue details and tool_call_id
                                    tool_output = {"tool_call_id": tool_call_id, "output": formatted_output}
                                    # Submit the tool outputs
                                    print("Submitting tool outputs.")
                                    submit_function_outputs(thread_id, run_id, tool_call_id, [tool_output])
                         # New branch to handle update_jiraissue function call
                        elif tool_call.get('type') == 'function' and tool_call.get('function', {}).get('name') == 'update_jiraissue':
                            print("Found 'update_jiraissue' function call. Parsing arguments.")
                            arguments_str = tool_call.get('function', {}).get('arguments', '{}')
                            arguments_dict = json.loads(arguments_str)
                            jira_issue_id = arguments_dict.get('issue_id')
                            summary = arguments_dict.get('summary')
                            description = arguments_dict.get('description')
                            if jira_issue_id and summary and description:
                                print(f"Updating Jira issue ID: {jira_issue_id} with new summary and description.")
                                # Perform Jira operations to update the issue
                                update_success = update_issue_summary_and_description(jira_issue_id, summary, description) # Ensure this function is defined and accepts the necessary arguments
                                if update_success:
                                    print(f"Jira issue ID: {jira_issue_id} updated successfully. Preparing tool output.")
                                    # Prepare the tool output indicating success and tool_call_id
                                    tool_output = {"tool_call_id": tool_call_id, "output": "Issue updated successfully."}
                                    # Submit the tool outputs
                                    print("Submitting tool outputs.")
                                    submit_function_outputs(thread_id, run_id, tool_call_id, [tool_output])
                        elif tool_call.get('type') == 'function' and tool_call.get('function', {}).get('name') == 'get_issues_for_epic':
                            print("Found 'get_issues_for_epic' function call. Parsing arguments.")
                            arguments_str = tool_call.get('function', {}).get('arguments', '{}')
                            arguments_dict = json.loads(arguments_str)
                            epic_id_or_key = arguments_dict.get('epic_id_or_key')
                            if epic_id_or_key:
                                print(f"Epic ID or key found: {epic_id_or_key}. Retrieving epic details and linked issues.")
                                combined_details = get_issues_for_epic(epic_id_or_key)  # This now calls our wrapper function
                                if combined_details and combined_details.get("ChildIssues"):
                                    formatted_combined_details = format_linked_issues(combined_details)
                                    if formatted_combined_details and formatted_combined_details.get("ChildIssues"):
                                        epic_details = formatted_combined_details["EpicDetails"]
                                        formatted_output = f"Epic Summary: {epic_details['Summary']}\nEpic Description: {epic_details['Description']}\n\nChild Issues:\n"
                                        formatted_output += "\n".join(f"{issue['Key']}: {issue['Summary']}" for issue in formatted_combined_details["ChildIssues"])
                                        print("Epic details and linked issues retrieved and formatted. Preparing tool output.")
                                        tool_output = {"tool_call_id": tool_call_id, "output": formatted_output}
                                        print("Submitting tool outputs.")
                                        submit_function_outputs(thread_id, run_id, tool_call_id, [tool_output])
                                    else:
                                        print("[ERROR] No issues formatted. Check the format_linked_issues function.")
                                else:
                                    print("[ERROR] No linked issues found. Check the get_issues_for_epic function.")
        elif run_status != 'completed':
            print("Run status not completed. Waiting for 3 seconds before checking the status again.")
            time.sleep(3)  # Wait for 3 seconds before checking the status again
        else:
            print("Run completed or requires action handled. Exiting loop.")
            break

    print("Fetching and displaying the assistant's response after the run is completed.")
    # After the run is completed, fetch and display the assistant's response
    check_and_display_new_messages(run_id)


def send_message_to_slack(channel_id, message, slack_bot_token):
    url = "https://slack.com/api/chat.postMessage"
    headers = {
        "Authorization": f"Bearer {slack_bot_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "channel": channel_id,
        "text": message
    }
    response = requests.post(url, headers=headers, json=payload)
    if not response.ok:
        print(f"Error sending message to Slack: {response.text}")

def display_message(message_id, role, content, channel_id, slack_bot_token, displayed_message_ids):
    if message_id in displayed_message_ids:
        return

    # Assuming 'role' could be used to customize the message, e.g., prefixing with "Assistant:" or "User:"
    prefix = "Assistant:" if role == "assistant" else "User:"
    full_message = f"{prefix} {content}"
    send_message_to_slack(channel_id, full_message, slack_bot_token)

    # Mark the message as displayed
    displayed_message_ids.add(message_id)

def check_and_display_new_messages(run_id, channel_id, slack_bot_token, displayed_message_ids):
    global thread_id
    polling_interval = 3  # Initial polling interval in seconds
    logging.debug(f"Polling for new messages with interval: {polling_interval} seconds")
    should_continue_polling = True

    def poll_messages(run_id):
        nonlocal polling_interval, should_continue_polling
        logging.debug(f"Polling messages for run_id: {run_id[:10]}...")
        
        run_status_response = get_run_status(thread_id, run_id)
        logging.debug(f"Run status response (limited): {str(run_status_response)[:50]}")
        
        if run_status_response['status'] in ['completed', 'requires_action']:
            should_continue_polling = False
            logging.info(f"Polling stopped. Run status: {run_status_response['status']}")
            if run_status_response['status'] == 'completed':
                fetch_and_display_messages(run_id, channel_id, slack_bot_token, displayed_message_ids)
        else:
            logging.info(f"Scheduling next poll in {polling_interval} seconds.")
            if polling_interval < 15:
                polling_interval += 3
            threading.Timer(polling_interval, lambda: poll_messages(run_id)).start()

    poll_messages(run_id)

def fetch_and_display_messages(run_id, channel_id, slack_bot_token, displayed_message_ids):
    global thread_id
    logging.info(f"[INFO] Initiating fetch for messages. Thread ID: {thread_id[:10]}, Run ID: {run_id[:10]}")
    messages_response = get_messages(thread_id, order="asc")
    logging.debug(f"[DEBUG] Messages response (truncated): {str(messages_response)[:100]}")

    if messages_response.get("data"):
        messages = messages_response["data"]
        logging.info(f"[INFO] Total messages fetched: {len(messages)}")

        new_messages = [msg for msg in messages if msg["id"] not in displayed_message_ids]
        logging.info(f"[INFO] New messages identified for display: {len(new_messages)}")

        for message in new_messages:
            role = message["role"]
            content_parts = [part["text"]["value"] for part in message["content"] if part["type"] == "text"]
            content = "".join(content_parts)
            display_message(message["id"], role, content, channel_id, slack_bot_token, displayed_message_ids)

        if new_messages:
            last_displayed_message_id = new_messages[-1]["id"]
            logging.info(f"[UPDATE] Last displayed message ID updated to: {last_displayed_message_id}")
        else:
            logging.info("[INFO] No new messages to display. Last displayed message ID remains unchanged.")


# Create a Blueprint for OAuth-related routes
oauth_bp = Blueprint('oauth_bp', __name__)

@oauth_bp.route('/start-oauth-jira', methods=['GET'])
def start_oauth_jira():
    logging.info("Initiating Jira OAuth flow.")
    try:
        # Ensure JIRA_SCOPES is a space-separated string of scopes
        scopes_string = " ".join(JIRA_SCOPES) if isinstance(JIRA_SCOPES, list) else JIRA_SCOPES

        # Generate the authorization URL using scopes_string
        authorization_url = f'https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id={CLIENT_ID}&scope={urllib.parse.quote(scopes_string)}&redirect_uri={urllib.parse.quote(REDIRECT_URI)}&state={generate_state_parameter()}&response_type=code&prompt=consent'
        
        # Redirect the user to the authorization URL
        return redirect(authorization_url)
    except Exception as e:
        logging.error(f"Failed to initiate Jira OAuth flow: {e}", exc_info=True)
        return jsonify({"status": "Failed to initiate Jira OAuth flow", "error": str(e)})

@oauth_bp.route('/jira-callback', methods=['GET'])
def jira_oauth_callback():
    logging.info("Received Jira OAuth callback request.")
    error = request.args.get('error')
    code = request.args.get('code')
    
    if error:
        logging.error(f"Error received from authorization server: {error}")
        return jsonify({"error": f"Authorization server error: {error}"}), 400
    if not code:
        logging.warning("Authorization failed or was cancelled by the user.")
        return "Authorization failed or was cancelled by the user.", 400

    try:
        logging.info("Jira OAuth code received, exchanging for token.")
        access_token = exchange_code_for_token(code)
        save_access_token(access_token)
        logging.info("Jira OAuth token fetched and saved successfully.")
        return "Authorization successful. You may close this window."
    except Exception as e:
        logging.error(f"Failed to fetch token: {e}", exc_info=True)
        return jsonify({"error": "Failed to complete authorization"}), 500

@oauth_bp.route('/start-oauth-sheets', methods=['GET'])
def start_oauth_sheets():
    logging.info("Initiating Google Sheets OAuth flow.")
    try:
        global flow  # Indicate that we are using the global `flow` variable

        # Decode the client secrets from an environment variable
        client_secrets_json = base64.b64decode(os.getenv("GOOGLE_CLIENT_SECRET_BASE64")).decode('utf-8')
        client_secrets = json.loads(client_secrets_json)

        # Initialize OAuth flow with client secrets and scopes
        flow = Flow.from_client_config(client_secrets, GOOGLE_SCOPES)
        flow.redirect_uri = 'https://jiraslackgpt-592ed3dfdc03.herokuapp.com/sheets-callback'

        # Generate the authorization URL
        auth_url, _ = flow.authorization_url(prompt='consent')

        # Redirect the user to the authorization URL
        return redirect(auth_url)
    except Exception as e:
        logging.error(f"Failed to initiate Google Sheets OAuth flow: {e}", exc_info=True)
        return jsonify({"status": "Failed to initiate Google Sheets OAuth flow", "error": str(e)})

@oauth_bp.route('/sheets-callback', methods=['GET'])
def sheets_oauth_callback():
    global flow
    logging.info("Received Google Sheets OAuth callback request.")
    
    if 'code' not in request.args:
        logging.warning("Google Sheets OAuth callback received without code.")
        # No code in query string, so OAuth flow was not completed.
        return "Authorization failed or was cancelled by the user.", 400

    # Fetch the authorization code from the query string
    authorization_response = request.url
    try:
        logging.info("Google Sheets OAuth code received, fetching token.")
        # Use the authorization code to fetch the token
        flow.fetch_token(authorization_response=authorization_response)
        # Store the credentials
        creds = flow.credentials
        save_credentials(creds)
        logging.info("Google Sheets OAuth token fetched and credentials saved successfully.")
        # Redirect or respond that the authorization was successful
        return "Authorization successful. You may close this window."
    except Exception as e:
        current_app.logger.error(f"Failed to fetch token: {e}")
        return "Failed to complete authorization.", 500
    
def initiate_and_send_data_with_delay(channel_id, slack_bot_token, displayed_message_ids):
    create_thread()  # Assuming this function initializes a thread and sets `thread_id`
    # Now passing the required arguments
    retrieve_and_send_data(channel_id, slack_bot_token, displayed_message_ids)

@oauth_bp.route('/start-assistant', methods=['POST'])
def start_assistant():
    # Extract required data from the request's JSON payload
    data = request.get_json()
    channel_id = data.get('channel_id')
    slack_bot_token = data.get('slack_bot_token')
    displayed_message_ids = data.get('displayed_message_ids')

    # Check if all required arguments are provided
    if not all([channel_id, slack_bot_token, displayed_message_ids]):
        return jsonify({"error": "Missing required parameters"}), 400

    # Start the thread with the extracted arguments
    threading.Thread(target=initiate_and_send_data_with_delay, args=(channel_id, slack_bot_token, displayed_message_ids), daemon=True).start()
    return jsonify({"status": "Assistant start command received, initiating in 3 seconds"})

def wait_for_run_completion(thread_id, run_id, max_wait_time=60):
    logging.info(f"Starting to wait for run completion. Thread ID: {thread_id}, Run ID: {run_id}")
    start_time = time.time()
    polling_interval = 1  # Start with a 1-second delay

    for attempt in range(int(max_wait_time / polling_interval)):
        elapsed_time = time.time() - start_time
        if elapsed_time > max_wait_time:
            logging.warning("Max wait time exceeded for run completion.")
            return False

        logging.debug(f"Checking run status. Attempt: {attempt + 1}, Polling Interval: {polling_interval} seconds")
        run_status_response = get_run_status(thread_id, run_id)
        logging.debug(f"Run status response: {run_status_response}")

        if run_status_response['status'] in ['completed', 'requires_action']:
            logging.info(f"Run completed or requires action. Status: {run_status_response['status']}")
            return True

        time.sleep(polling_interval)
        polling_interval = min(polling_interval * 2, 15)  # Increase the interval, up to a maximum of 15 seconds

    return False

@oauth_bp.route('/get-latest-messages', methods=['GET'])
def get_latest_messages():
    global thread_id, displayed_message_ids, last_run_id

    logging.info("Fetching latest messages.")
    try:
        if not wait_for_run_completion(thread_id, last_run_id):
            logging.error("Run did not complete in the expected time frame.")
            return jsonify({"error": "Run did not complete in the expected time frame"}), 408

        logging.info("Run completed. Fetching messages.")
        messages_response = get_messages(thread_id, order="asc")
        if messages_response.get("data"):
            messages = messages_response["data"]
            new_messages = [msg for msg in messages if msg["id"] not in displayed_message_ids]
            displayed_message_ids.update([msg["id"] for msg in new_messages])
            logging.info(f"New messages fetched: {len(new_messages)}")
            return jsonify(new_messages)
        else:
            logging.warning("No new messages found.")
            return jsonify({"error": "No new messages found"}), 404
    except Exception as e:
        logging.exception("Failed to fetch latest messages")
        return jsonify({"error": str(e)}), 500

@oauth_bp.route('/process-message', methods=['POST'])
def process_message():
    """
    Endpoint to process incoming messages.
    """
    try:
        data = request.get_json()  # Use get_json() to parse the JSON data
        user_message = data.get("text", "")

        if not user_message:
            return jsonify({"text": "[ERROR] No message provided."}), 400

        if not thread_id:
            return jsonify({"text": "[ERROR] Thread not initialized. Unable to process message."}), 400

        # Send the user's message to the thread
        # Assuming add_message_to_thread is a function that adds a message to a thread
        # and run_thread initiates processing of the thread
        add_message_to_thread(thread_id, "user", user_message)
        logging.info(f"[INFO] Message processed. Message (truncated to 100 chars): {user_message[:100]}")

        # Call run_thread to process the user message
        run_status_response = run_thread(thread_id, ASSISTANT_ID)
        run_id = run_status_response.get("id")  # Extract the run ID from the response
        logging.info(f"[INFO] Run thread initiated. Run ID: {run_id}")

        # Handle the run status in a separate function
        # Assuming handle_run_status is a function that handles the run status
        response_text = handle_run_status(thread_id, run_id)
        return jsonify({"text": response_text})

    except Exception as e:
        logging.exception("Failed to process message")
        return jsonify({"text": f"[ERROR] An error occurred while processing message. Error: {str(e)[:100]}"}), 500



