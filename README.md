# JiraStoryBot25: Your Slack-based Jira Assistant

## Overview
**JiraStoryBot25** is an innovative Slack-based assistant crafted to streamline the refinement of user stories and the analysis of epics within Jira. Powered by the cutting-edge **OpenAI's GPT-4**, it offers unparalleled insights and recommendations to ensure your user stories are not only clear and focused but also complete. This guide is designed to walk developers through the setup and usage process seamlessly.

## Prerequisites
Before diving into the setup, ensure you have the following:
- **Python 3.8** or higher
- Access to a **Slack Workspace** with Bot Permissions
- **Jira and Google Sheets API** access
- An **OpenAI API Key**

## Setup Instructions

### Step 1: Clone the Repository
Begin by cloning the **JiraStoryBot25** repository onto your local machine.

### Step 2: Install Dependencies
Navigate to your local **JiraStoryBot25** directory. Here, you'll install all the necessary Python packages to get you up and running.

### Step 3: Configure API Keys and Tokens
This step is crucial for the seamless operation of your assistant:
- **OpenAI API Key**: Locate the `config.ini` file and replace `apikey` with your personal OpenAI API key OR just run the oauthoption.py script and set it through the config window :)
- **Jira Credentials**: Edit the `config2.ini` file to include your Jira username and API token.
- **Slack Bot Token and Signing Secret**: Ensure the `SLACK_BOT_TOKEN` and `SLACK_SIGNING_SECRET` environment variables are set with your Slack bot token and signing secret, respectively.

### Step 4: Secure `client_secret.json`
Upon receiving a new project directory, you'll find the `client_secret.json` file encrypted for security. To access the Google Sheets and Jira API configurations:
- Run the provided decryption tool and enter the password given to you.
- Once decrypted, the `client_secret.json` will be accessible for the application's use and remains unlocked indefinitely.

### Step 5: Jira OAuth Setup
Prior to launching the application, it's essential to have a Jira app set up with the necessary scopes. Make sure you've obtained the client secret and client ID, which should be pre-coded in the header of `oauthoption.py`.

### Step 6: Launch the Application
Execute `oauthoption.py` to start the GUI application. If your OpenAI API key hasn't been configured yet, you'll be prompted to do so upon launch.

### Step 7: Initiate OAuth Flows
- **Google Sheets API**: Use the GUI's "Start OAuth for Sheets API" button to kick off the OAuth flow for Google Sheets.
- **Jira API**: Similarly, click the "Start OAuth for Jira API" button to initiate the OAuth flow for Jira.

### Step 8: Start the Assistant
Hit the "Start Assistant & Send Training Data" button. A 10-second countdown will appear on the GUI, after which it will reference a publicly available URL for the spreadsheet ID. This ID points to a "training" dataset of stories, serving as a formatting guide for the assistant.

### Step 9: Use the Assistant
With the initial setup and training data in place, the assistant will inquire which mode you wish to initiate (`/story` or `/epicanalysis`). Follow the prompts in the Slack channel to interact with the assistant.

## System Flow
1. **OAuth Flows**: Initiate OAuth for Google Sheets and Jira APIs to grant the assistant access to necessary data.
2. **Start Assistant**: Launches the assistant and sends training data to OpenAI for processing.
3. **Mode Selection**: Choose between single issue analysis and refinement (`/story`) or comprehensive analysis of user stories within an epic (`/epicanalysis`).
4. **Interaction**: Engage with the assistant's prompts in Slack to refine user stories or analyze epics.

## Files Reference
- `slackconnect.py`: Manages Slack interactions and events.
- `oauthoption.py`: Oversees OAuth flows and GUI interactions.
- `requirements.txt`: Enumerates all the necessary Python packages.
- `config.ini` and `config2.ini`: Hold configuration settings for API keys and Jira credentials.
- `assistantsystemprompt.txt`: Outlines the assistant's logic and processing steps.
- `client_secret.json`: Encrypted file for Google Sheets credentials access.

## Additional Notes
Remember to securely store all API keys and tokens, ensuring they're not exposed in public repositories. Adhere to the OAuth flow instructions meticulously to prevent authentication issues.
