import requests
from requests.exceptions import RequestException, Timeout
from tkinter import scrolledtext, messagebox, font, simpledialog
import customtkinter as ctk
import tkinter as tk
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
from flask import Flask, request, jsonify
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
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_state_parameter():
    return str(uuid.uuid4())

CLIENT_ID = 'client id'
CLIENT_SECRET = 'client secret'
REDIRECT_URI = 'http://localhost:8080/jira-callback'
TOKEN_URL = 'https://auth.atlassian.com/oauth/token'
SCOPES = 'read:jira-work write:jira-work manage:jira-project manage:jira-webhook manage:jira-configuration read:me read:account'  # Replace with actual scopes
AUTHORIZATION_URL = 'https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id={client_id}&scope={scopes}&redirect_uri={redirect_uri}&state={state}&response_type=code&prompt=consent'.format(
    client_id=CLIENT_ID,
    scopes=SCOPES,
    redirect_uri=REDIRECT_URI,
    state=generate_state_parameter()
)
# Hardcoded Spreadsheet ID
SPREADSHEET_ID = "1Ua0bb50NXtE70rhkhY27LYS5LTiJNmFSqx_O_n6BtoM"  # Replace with your actual spreadsheet ID

# Update for Google Sheets API
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]
API_SERVICE_NAME = 'sheets'
API_VERSION = 'v4'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

directory = os.path.dirname(os.path.realpath(__file__))
CLIENT_SECRETS_FILE = os.path.join(directory, 'client_secret.json')


# Global flag to control polling

last_displayed_message_id = None
displayed_message_ids = set()  # Keep track of displayed message IDs
# OAuth and Google Sheets Integration
# Function to start the OAuth process and server for Google Sheets API
def start_oauth_and_server():
    # Initialize OAuth flow with client secrets and scopes
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
    flow.redirect_uri = 'http://localhost:8081/sheets-callback'

    # Open the authorization URL in the user's browser
    auth_url, _ = flow.authorization_url(prompt='consent')
    webbrowser.open(auth_url)

    # Start a local server to listen for the authorization response
    class OAuthHandler(SimpleHTTPRequestHandler):
        def do_GET(self):
            # Parse the authorization response URL
            self.send_response(200)
            self.end_headers()
            query = urlparse(self.path).query
            auth_response = dict(parse_qs(query))
            flow.fetch_token(authorization_response=self.path)

            # Store the credentials
            creds = flow.credentials
            save_credentials(creds)

            self.wfile.write(b'Authorization successful. You may close this window.')

    # Start the server
    with socketserver.TCPServer(("", 8081), OAuthHandler) as httpd:
        httpd.handle_request()
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

def retrieve_and_send_data():
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

        conversation_text.config(state='normal')
        conversation_text.insert(tk.END, f"You: {training_data_message}\n")
        conversation_text.config(state='disabled')
        print("[INFO] GUI updated with training data update message.")

        run_status_response = run_thread(thread_id, ASSISTANT_ID)
        if "error" in run_status_response:
            print(f"[ERROR] Failed to initiate run thread: {run_status_response['error']}")
            return
        run_id = run_status_response.get("id")  # Extract the run ID from the response
        if not run_id:
            print("[ERROR] No run ID received from run_thread function. Check OpenAI API response.")
            return
        print(f"[INFO] Run thread initiated. Run ID: {run_id[:10]}... (truncated for log)")

        check_and_display_new_messages(run_id)

    except Exception as e:
        print(f"[ERROR] Error updating training data: {str(e)[:100]}... (truncated for log)")
        traceback.print_exc()


# Jira OAuth Flow and API Integration
# Class to handle OAuth callback for Jira API
class JiraOAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

        # Parse the query parameters to get the authorization code
        query = urlparse(self.path).query
        query_components = parse_qs(query)
        code = query_components.get('code', None)

        if code:
            self.wfile.write(b'Authorization successful. You may close this window.')
            exchange_code_for_token(code[0])  # Exchange the code for a token
        else:
            self.wfile.write(b'Authorization failed.')

# Function to start a local server for handling Jira OAuth callback
def run_server():
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, JiraOAuthHandler)
    httpd.handle_request()

# Function to exchange authorization code for an access token with Jira API
def exchange_code_for_token(code):
    payload = {
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    response = requests.post(TOKEN_URL, json=payload)

    if response.status_code == 200:
        access_token = response.json().get('access_token')
        save_access_token(access_token)
    else:
        print('Failed to obtain access token. Error response:', response.json())

# Function to save Jira API access token to a file
def save_access_token(token):
    with open('access_token.json', 'w') as token_file:
        json.dump({'access_token': token}, token_file)

# Function to initiate the Jira OAuth flow by starting the local server and opening the authorization URL
def start_oauth_flow():
    threading.Thread(target=run_server, daemon=True).start()
    time.sleep(2)  # Ensure the server is running
    webbrowser.open(AUTHORIZATION_URL)

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
        messagebox.showwarning("Warning", "Please enter a Jira Issue Key")
        print("[WARNING] No Jira Issue Key provided. Operation aborted.")  # Added robust print statement
        return

    token = get_saved_access_token()
    if not token:
        messagebox.showerror("Error", "No access token found. Please authenticate with Jira first.")
        print("[ERROR] No access token found. User needs to authenticate.")  # Added robust print statement
        return

    cloud_id = '911ae68a-c409-4a8b-830a-5cda394f67ec'  # Replace with your actual Jira Cloud ID
    try:
        print(f"[INFO] Attempting to retrieve issue with key: {issue_key[:10]}... from cloud ID: {cloud_id}")  # Added content limit to print statement
        issue_details = get_issue_details(token, cloud_id, issue_key)
        print(f"[SUCCESS] Issue retrieved successfully. Issue details (limited): {str(issue_details)[:100]}...")  # Added content limit to print statement
        return issue_details
    except Exception as e:
        messagebox.showerror("Error", f"Error retrieving issue from Jira: {e}")
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

#Start of Assistants API Functions
def get_openai_api_key():
    config = configparser.ConfigParser()
    directory = os.path.dirname(os.path.realpath(__file__))
    config_file = os.path.join(directory, 'config.ini')
    if not os.path.exists(config_file):
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        # Use Tkinter dialog to prompt for the OpenAI API key
        root = tk.Tk()
        root.withdraw()  # Hide the main window
        openai_api_key = simpledialog.askstring("OpenAI API Key", "Enter your OpenAI API key:", parent=root)
        if openai_api_key:
            config['DEFAULT'] = {'OpenAI_API_Key': openai_api_key}
            with open(config_file, 'w') as configfile:
                config.write(configfile)
        root.destroy()
    else:
        config.read(config_file)
        openai_api_key = config['DEFAULT']['OpenAI_API_Key']
    return openai_api_key

OPENAI_API_KEY = get_openai_api_key()
ASSISTANT_ID = "asst_S1BeMtNw12Zi763tbTE4y4Tg"
thread_id = None
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
        conversation_text.config(state='normal')
        conversation_text.tag_configure('assistant_author', foreground='pink')
        conversation_text.insert(tk.END, "Kohl's Jira Assistant: ", 'assistant_author')
        conversation_text.insert(tk.END, f"{welcome_message}\n")
        conversation_text.config(state='disabled')

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
            update_status_message(run_status)
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

    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        new_messages = response.json()
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


def send_message():
    global thread_id

    if not thread_id:
        print("[ERROR] Thread not initialized. Unable to send message.")
        return

    user_message = message_entry.get("1.0", "end-1c")

    # Clear the entry widget
    message_entry.delete("1.0", "end")

    # Send the user's message to the thread
    add_message_to_thread(thread_id, "user", user_message)
    print(f"[INFO] Message sent to thread. Message (truncated to 100 chars): {user_message[:100]}")

    # Display the message directly without the typing effect
    conversation_text.config(state='normal')
    conversation_text.insert(tk.END, f"User: {user_message}\n", 'user_message')
    conversation_text.config(state='disabled')
    print("[INFO] Message displayed in GUI.")

    try:
        # Call run_thread to process the user message
        run_status_response = run_thread(thread_id, ASSISTANT_ID)
        run_id = run_status_response.get("id")  # Extract the run ID from the response
        print(f"[INFO] Run thread initiated. Run ID: {run_id}")

        # Handle the run status in a separate function
        handle_run_status(thread_id, run_id)
    except Exception as e:
        print(f"[ERROR] An error occurred while sending message or initiating run thread. Error: {str(e)[:100]}")  # Truncate error message

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

def check_and_display_new_messages(run_id):
    global thread_id
    global last_displayed_message_id  # Ensure this global variable is accessible within this function
    polling_interval = 3  # Initial polling interval in seconds
    logging.debug(f"Polling for new messages with interval: {polling_interval} seconds")
    should_continue_polling = True  # Flag to indicate whether polling should continue

    def poll_messages(run_id):
        nonlocal polling_interval, should_continue_polling  # Ensure these are accessible
        print(f"Polling messages for run_id: {run_id[:10]}...")  # Limiting run_id printout for brevity
        
        run_status_response = get_run_status(thread_id, run_id)
        print(f"Run status response (limited): {str(run_status_response)[:50]}")  # Limiting content for brevity
        
        if run_status_response['status'] in ['completed', 'requires_action']:
            should_continue_polling = False  # Stop polling if run is completed or requires action
            print(f"Polling stopped. Run status: {run_status_response['status']}")
            if run_status_response['status'] == 'completed':
                fetch_and_display_messages(run_id)
        else:
            print(f"Scheduling next poll in {polling_interval} seconds.")
            if polling_interval < 15:
                polling_interval += 3  # Increment the polling interval by 3 seconds, up to a maximum of 15 seconds
            threading.Timer(polling_interval, lambda: poll_messages(run_id)).start()

    def fetch_and_display_messages(run_id):
        global thread_id
        global last_displayed_message_id
        global displayed_message_ids

        print(f"[INFO] Initiating fetch for messages. Thread ID: {thread_id[:10]}, Run ID: {run_id[:10]}")
        messages_response = get_messages(thread_id, order="asc")
        print(f"[DEBUG] Messages response (truncated): {str(messages_response)[:100]}")

        if messages_response.get("data"):
            messages = messages_response["data"]
            print(f"[INFO] Total messages fetched: {len(messages)}")

            # Filter out messages that have already been displayed
            new_messages = [msg for msg in messages if msg["id"] not in displayed_message_ids]
            print(f"[INFO] New messages identified for display: {len(new_messages)}")

            for message in new_messages:
                role = message["role"]
                content_parts = [part["text"]["value"] for part in message["content"] if part["type"] == "text"]
                content = "".join(content_parts)
                print(f"[DISPLAY] Message ID: {message['id']}, Role: {role}, Content (truncated): {content[:100]}")

                # Display the message and then mark it as displayed
                display_message(message["id"], role, content)
                # Note: The addition to displayed_message_ids should now happen inside display_message

            if new_messages:
                # Update last_displayed_message_id based on the last message in the new_messages list
                last_displayed_message_id = new_messages[-1]["id"]
                print(f"[UPDATE] Last displayed message ID updated to: {last_displayed_message_id}")
            else:
                print("[INFO] No new messages to display. Last displayed message ID remains unchanged.")

    poll_messages(run_id)

def update_gui(message_id, role, content, displayed_message_ids, conversation_text, root):
    if message_id in displayed_message_ids:
        return

    conversation_text.config(state='normal')

    if conversation_text.get("end-2l", tk.END).strip() == "Assistant is typing...":
        end_line_index = conversation_text.index("end-1c linestart")
        conversation_text.delete(end_line_index, tk.END)

    tag = 'user_author' if role == "user" else 'assistant_author'
    author = "You" if role == "user" else "Assistant"

    conversation_text.tag_configure('assistant_author', foreground='pink')
    conversation_text.tag_configure('user_author', foreground='lightblue')

    # Insert the author tag
    conversation_text.insert(tk.END, f"\n{author}: ", tag)

    # Process and insert the content
    process_and_insert_content(content, conversation_text)

    conversation_text.config(state='disabled')
    displayed_message_ids.add(message_id)

def display_message(message_id, role, content):
    global displayed_message_ids
    global thread_id
    global root  # Ensure root is globally accessible

    # Pass necessary parameters to update_gui
    update_gui(message_id, role, content, displayed_message_ids, conversation_text, root)

def process_and_insert_content(content, conversation_text):
    # Define insert_with_url_detection at the beginning of the function
    def insert_with_url_detection(text):
        # Regular expression to match URLs
        url_pattern = r'https?://[^\s]+'
        start = 0
        for match in re.finditer(url_pattern, text):
            # Insert text up to the URL
            conversation_text.insert(tk.END, text[start:match.start()])
            # Insert leading space for padding (make clickable area larger)
            conversation_text.insert(tk.END, " ")
            # Insert the URL with a hyperlink tag
            url = match.group()
            hyperlink_tag = "hyperlink_" + str(uuid.uuid4())  # Unique tag for each hyperlink
            conversation_text.tag_configure(hyperlink_tag, foreground="blue", underline=1)
            # Apply the tag to the URL and surrounding spaces
            conversation_text.insert(tk.END, " " + url + " ", hyperlink_tag)
            # Bind the click event to open the URL in a web browser
            conversation_text.tag_bind(hyperlink_tag, "<Button-1>", lambda event, url=url: webbrowser.open(url))
            # Insert trailing space for padding (make clickable area larger)
            conversation_text.insert(tk.END, " ")
            start = match.end()
        # Insert any remaining text after the last URL
        conversation_text.insert(tk.END, text[start:])

    lines = content.split('\n')
    for line in lines:
        # Existing formatting logic
        if line.startswith("### "):
            line = line[4:]
            title_tag = "title_text"
            conversation_text.tag_configure(title_tag, font=("Roboto", 18, "bold"))
            conversation_text.insert(tk.END, f"{line}\n", title_tag)
        elif re.match(r'^(\-|\*|\d+\.) \*\*.*\*\*$', line):
            line = re.sub(r'\*\*(.*)\*\*', r'\1', line)
            bold_tag = "list_bold_text"
            conversation_text.tag_configure(bold_tag, font=("Roboto", 17, "bold"))
            conversation_text.insert(tk.END, f"{line}\n", bold_tag)
        elif line.startswith("**") and line.endswith("**"):
            line = line[2:-2]
            bold_tag = "bold_text"
            conversation_text.tag_configure(bold_tag, font=("Roboto", 18, "bold"))
            conversation_text.insert(tk.END, f"{line}\n", bold_tag)
        elif re.match(r'^(\-|\*|\d+\.) \*\*.*\*\*$', line):
            line = re.sub(r'\*\*(.*)\*\*', r'\1', line)
            bold_tag = "list_bold_text"
            conversation_text.tag_configure(bold_tag, font=("Roboto", 17, "bold"))
            conversation_text.insert(tk.END, f"{line}\n", bold_tag)
        elif re.match(r'^(\d+\.) \*\*.*\*\*$', line):
            line = re.sub(r'\*\*(.*)\*\*', r'\1', line)
            bold_tag = "list_bold_text"
            conversation_text.tag_configure(bold_tag, font=("Roboto", 17, "bold"))
            conversation_text.insert(tk.END, f"{line}\n", bold_tag)
        elif re.match(r'^([a-zA-Z]\.) \*\*.*\*\*$', line):
            line = re.sub(r'\*\*(.*)\*\*', r'\1', line)
            bold_tag = "list_bold_text"
            conversation_text.tag_configure(bold_tag, font=("Roboto", 17, "bold"))
            conversation_text.insert(tk.END, f"{line}\n", bold_tag)
        elif line.startswith("#### "):
            line = line[5:]
            subtitle_tag = "subtitle_text"
            conversation_text.tag_configure(subtitle_tag, font=("Roboto", 16, "bold"))
            conversation_text.insert(tk.END, f"{line}\n", subtitle_tag)
        else:
            insert_with_url_detection(line + '\n')  # Call the URL detection function for regular text

def create_scrolled_text(root):
    # Create a frame to hold the text widget and the scrollbar
    frame = tk.Frame(root)
    frame.grid(row=0, column=0, columnspan=2, padx=50, sticky="nsew")

    # Create a text widget with the desired appearance, including line spacing
    text_widget = tk.Text(frame, font=("Roboto", 16), wrap=tk.WORD, padx=50, pady=10, borderwidth=0, highlightthickness=0, bg=root.cget('bg'), spacing3=0.5)
    text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Create a scrollbar that blends with the background
    scrollbar = ctk.CTkScrollbar(frame, command=text_widget.yview, fg_color=root.cget('bg'))
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Configure the text widget to use the scrollbar
    text_widget.config(yscrollcommand=scrollbar.set)

    return text_widget


def create_message_entry(root):
    # Create a frame to hold the text widget and the scrollbar
    entry_frame = tk.Frame(root)
    entry_frame.grid(row=1, column=0, sticky="ew", padx=60)
    root.grid_rowconfigure(1, weight=1)
    root.grid_columnconfigure(0, weight=1)

    # Fetch the background color of the root window
    bg_color = root.cget('bg')

    # Create a text widget for multiline input with a matching background color
    message_entry = tk.Text(entry_frame, height=4, wrap="word", font=("Roboto", 16), padx=10, pady=10, borderwidth=0, highlightthickness=0, bg=bg_color)
    message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Bind the Enter key while focusing on message_entry to send_message function
    # and prevent default newline insertion unless Shift is pressed
    def handle_enter_key(event):
        if event.state & 0x0001:  # Shift key is down
            return "break"  # Proceed with the default behavior (insert newline)
        else:
            send_message()  # Call the send_message function
            return "break"  # Prevent the default behavior

    message_entry.bind("<Return>", handle_enter_key)

    # Continue with the scrollbar setup and return statement...
    scrollbar = tk.Scrollbar(entry_frame, command=message_entry.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    message_entry.config(yscrollcommand=scrollbar.set)
    scrollbar.config(bg=bg_color)

    return message_entry

app = Flask(__name__)
command_queue = queue.Queue()

def flask_thread_function():
    app.run(port=5001, debug=True, use_reloader=False)

@app.route('/start-oauth-jira', methods=['GET'])
def start_oauth_jira():
    try:
        start_oauth_flow()  # Function to initiate Jira OAuth flow
        return jsonify({"status": "Jira OAuth flow initiated. Check your browser."})
    except Exception as e:
        return jsonify({"status": "Failed to initiate Jira OAuth flow", "error": str(e)})

@app.route('/start-oauth-sheets', methods=['GET'])
def start_oauth_sheets():
    try:
        start_oauth_and_server()  # Function to initiate Google Sheets OAuth flow
        return jsonify({"status": "Google Sheets OAuth flow initiated. Check your browser."})
    except Exception as e:
        return jsonify({"status": "Failed to initiate Google Sheets OAuth flow", "error": str(e)})

@app.route('/start-assistant', methods=['POST'])
def start_assistant():
    command_queue.put(("create_thread", None))
    return jsonify({"status": "Assistant start command received"})

@app.route('/process-message', methods=['POST'])
def process_message():
    data = request.json
    user_message = data.get("text")

    if not thread_id:
        return jsonify({"text": "[ERROR] Thread not initialized. Unable to process message."})

    # Send the user's message to the thread
    add_message_to_thread(thread_id, "user", user_message)
    print(f"[INFO] Message processed. Message (truncated to 100 chars): {user_message[:100]}")

    try:
        # Call run_thread to process the user message
        run_status_response = run_thread(thread_id, ASSISTANT_ID)
        run_id = run_status_response.get("id")  # Extract the run ID from the response
        print(f"[INFO] Run thread initiated. Run ID: {run_id}")

        # Handle the run status in a separate function
        response_text = handle_run_status(thread_id, run_id)
    except Exception as e:
        response_text = f"[ERROR] An error occurred while processing message. Error: {str(e)[:100]}"  # Truncate error message
        print(response_text)

    return jsonify({"text": response_text})

# Assuming initiate_and_send_data and other functions are defined here
def initiate_and_send_data():
    create_thread()  # Start the assistant by creating a new thread with the OpenAI's 'Assistants' API
    for i in range(10, 0, -1):  # Countdown from 5 to 1
        conversation_text.config(state='normal')
        conversation_text.insert(tk.END, f"Sending Sheets Training Data in {i}...\n")
        conversation_text.config(state='disabled')
        root.update()  # Update the GUI to display the countdown
        time.sleep(1)  # Wait for 1 second
    retrieve_and_send_data()  # Fetch the latest training data from Google Sheets and send it to the OpenAI's 'Assistants' API for processing

def process_commands(root):
    try:
        while True:
            command, args = command_queue.get_nowait()
            if command == "start_assistant":
                initiate_and_send_data()
            # Add more commands as needed
    except queue.Empty:
        pass
    finally:
        root.after(100, process_commands, root)

if __name__ == "__main__":
    flask_thread = threading.Thread(target=flask_thread_function)
    flask_thread.start()
    root = ctk.CTk()
    root.title("Chat with Jira Auto Bot")
    root.resizable(True, True)

    # Set the appearance mode and color theme
    ctk.set_appearance_mode("dark")  # or "dark"
    ctk.set_default_color_theme("blue")  # or any other color

    # Configure grid for dynamic resizing
    root.grid_rowconfigure(1, weight=1)
    root.grid_columnconfigure(0, weight=1)

    conversation_text = scrolledtext.ScrolledText(root, state='disabled', height=30, width=100, font=("Roboto", 16), wrap=tk.WORD, padx=50, pady=10, bg=root.cget('bg'), borderwidth=0, highlightthickness=0, spacing3=0.5)
    conversation_text.grid(row=0, column=0, columnspan=2, padx=50)

    # Message Entry with 50 pixels of indent space on either side
    conversation_text = create_scrolled_text(root)
    # Message Entry with 50 pixels of indent space on either side
    # Replace the single-line entry with the multiline message entry
    message_entry = create_message_entry(root)

    # Send Button - This button sends the user's message to the OpenAI's 'Assistants' API and displays the assistant's response in the conversation text area.
    send_button = ctk.CTkButton(root, text="Send", command=send_message)
    send_button.grid(row=1, column=1, padx=60, pady=10)

    # Combined Button - This button starts the assistant and informs the user that the sheets training data is going to be sent with a countdown.
    combined_button = ctk.CTkButton(root, text="Start Assistant & Send Training Data", command=initiate_and_send_data)
    combined_button.grid(row=2, column=0, padx=60, pady=10)

    auth_button = ctk.CTkButton(root, text="Start OAuth for Sheets API", command=lambda: threading.Thread(target=start_oauth_and_server).start())
    auth_button.grid(row=4, column=0, padx=60, pady=10)

    # OAuth Button for Jira API - This button initiates the OAuth flow for Jira API, allowing the user to authenticate and authorize the application to access their Jira data.
    btn_oauth = ctk.CTkButton(root, text="Start OAuth for Jira API", command=start_oauth_flow)
    btn_oauth.grid(row=5, column=0, padx=60, pady=10)

    # Step 1: Add a Status Display Field at the bottom of the GUI
    status_label = ctk.CTkLabel(root, text="Status: Initializing...", anchor="w")
    status_label.grid(row=6, column=0, columnspan=2, padx=60, pady=10, sticky="ew")

    def update_status_message(message):
        """
        Updates the status message display in a thread-safe manner.
        """
        def _update():
            status_label.configure(text=f"Status: {message}")
        root.after(0, _update)

    # Your existing Tkinter GUI code goes here
    root.mainloop()