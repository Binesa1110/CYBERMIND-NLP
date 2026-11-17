# 🛡️ CyberMind NLP
# AI-Powered Cyber Threat Detection and Email Security System

CyberMind NLP is an AI-powered cybersecurity project that uses Natural Language Processing (NLP), Machine Learning, and rule-based analysis to identify potentially malicious content and suspicious URLs.
The project aims to help users recognize cyber threats through intelligent text analysis, URL inspection, and Gmail inbox monitoring.

# Key Features

### 1. NLP-Based Threat Detection
- Analyzes text to identify potentially malicious or suspicious content.
- Uses NLP and machine learning techniques for threat classification.
- Detects suspicious keywords and patterns.
- Provides analysis results to help users understand potential threats.

### 2. Suspicious URL Analysis
- Examines URLs for potentially harmful patterns.
- Identifies suspicious URL characteristics.
- Combines URL analysis with threat detection logic.

### 3. Intelligent Threat Analysis
- Combines machine learning predictions, keyword analysis, and heuristic rules.
- Uses a decision engine to evaluate potential threats.
- Provides a structured threat analysis result.

### 4. Gmail Security Integration
- Connects to Gmail through Google OAuth 2.0 authentication.
- Supports read-only Gmail access.
- Monitors the inbox when the user explicitly enables monitoring.
- Processes Gmail updates using Google Cloud Pub/Sub.
- Includes duplicate-event handling and retry mechanisms.
- Uses secure session management and encrypted token storage.

### 5. Web-Based Dashboard
- Provides a user-friendly interface.
- Displays threat analysis results.
- Includes a Gmail monitoring dashboard.
- Supports responsive layouts.

## **🧰 Technologies Used**

- **Programming Language:** Python
- **AI / NLP:** Natural Language Processing, Machine Learning
- **Backend:** FastAPI
- **Frontend:** HTML, CSS, JavaScript
- **Authentication:** Google OAuth 2.0
- **Email Integration:** Gmail API
- **Cloud Messaging:** Google Cloud Pub/Sub
- **Security:** Encrypted Token Storage, Signed Sessions
- **Development Tools:** VS Code, Git, GitHub

## 🏗️ Project Architecture

CyberMind NLP follows a modular architecture:

1. **Frontend:** Provides the interface for users to interact with the application.
2. **Backend:** Handles requests and coordinates the analysis process using FastAPI.
3. **NLP Engine:** Processes text and identifies suspicious patterns.
4. **Machine Learning Model:** Performs threat classification.
5. **URL Analyzer:** Examines URLs for potentially malicious characteristics.
6. **Gmail Integration:** Connects to Gmail and processes inbox updates securely.

## 📧 Gmail Integration Setup

CyberMind NLP supports Gmail integration through Google's official APIs.

To configure Gmail integration:

1. Create a project in Google Cloud Console.
2. Enable the Gmail API and Cloud Pub/Sub API.
3. Configure OAuth 2.0 credentials.
4. Add the application's authorized redirect URI.
5. Configure the required environment variables.
6. Authenticate your Gmail account through the application.

Gmail monitoring requires additional Pub/Sub configuration for event processing.

The application uses read-only Gmail access and does not download email attachments.

## 🔐 Security and Privacy

Security is an important part of CyberMind NLP.

- Gmail authentication uses Google OAuth 2.0.
- Gmail access is read-only.
- Session data is protected using signed sessions.
- OAuth tokens are stored using encryption.
- CSRF protection is implemented for browser authentication flows.
- Gmail monitoring requires user opt-in.
- Email attachments are not downloaded.
- Gmail message bodies are not stored by the monitoring workflow.

Users should keep credentials and environment secrets private.

---

## 🎯 Project Objectives

- Explore the application of AI and NLP in cybersecurity.
- Identify potentially malicious messages and suspicious URLs.
- Understand machine learning
