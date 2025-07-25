Flask Knowledge Base (KB) App

This is a self-contained Flask application that provides a simple knowledge base system with a modern UI, AI-powered Q&A, and article creation features.
Features

    Modern UI: A clean, responsive, dashboard-style interface inspired by modern web apps.

    Web-Based Settings: Configure all API keys through a user-friendly Settings page in the app. No more .env files. Configuration is saved to a local config.json.

    KB Management: Create, categorize, and view knowledge base articles.

    AI-Powered Q&A: Ask a question and get answers from multiple sources:

        Google Search

        Google Gemini

        OpenAI ChatGPT

    AI-Powered Synthesis: Select multiple answers from the Q&A results and use Gemini to synthesize them into a new, coherent knowledge base article.

    Simple & Local: Uses a local SQLite database file (kb.db) for easy setup and portability.

Setup and Installation

Follow these steps to get the application running locally.
1. Prerequisites

    Python 3.7+

    pip for installing packages

2. Download Files

Download all the provided files (app.py, requirements.txt, and the templates/ directory with its contents) and place them in a single project directory.
3. Install Dependencies

Open your terminal or command prompt in the project directory and run:

pip install -r requirements.txt

4. Run the Application

Once the dependencies are installed, run the Flask app from your terminal:

python app.py

You should see output indicating the server is running, similar to this:

* Serving Flask app 'app'
* Running on http://127.0.0.1:5050
Press CTRL+C to quit

5. Configure the Application

a. Access the Web Interface:

Open your web browser and navigate to:

http://127.0.0.1:5050

b. Go to the Settings Page:

On the left-hand sidebar, click on the "Settings" link.

c. Enter Your API Keys:

Fill in the form with your API keys for the services you wish to use (Google Gemini, Google Custom Search, OpenAI). Click "Save Settings".

The application is now configured. Your keys will be saved in a config.json file in your project directory. The app will automatically create the kb.db database file as well.