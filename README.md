
# Flask Knowledge Base (KB) App

This is a self-contained Flask application that provides a simple knowledge base system with a modern UI, AI-powered Q&A, and article creation features.

## Features

-   **Modern UI:** A clean, responsive, dashboard-style interface with a floating search bar.
    
-   **Intelligent Search:**
    
    -   Searches your local knowledge base first, highlighting relevant existing articles.
        
    -   Simultaneously queries Google Search, Google Gemini, and OpenAI ChatGPT.
        
    -   Displays a progress bar and status updates during the search process.
        
-   **Advanced Article Management:**
    
    -   **Rich Content:** Articles are rendered with full Markdown support, including syntax-highlighted code blocks.
        
    -   **Metadata:** Add notes, multi-line references, and comma-separated tags to any article.
        
    -   **Editing & Deleting:** Easily edit or delete individual articles.
        
    -   **Bulk Actions:** Multi-select articles to update their tags, notes, and references, or delete them in a single action.
        
-   **Robust Grouping System:**
    
    -   Organize articles into color-coded groups (formerly categories).
        
    -   Create and manage nested groups through a dedicated interface in the Settings page.
        
    -   Add new groups on-the-fly directly from the "Create Article" modal.
        
    -   Groups in the sidebar are collapsible to keep the view tidy.
        
-   **Efficient Workflow:**
    
    -   The "Create Article" button appears conveniently next to the search bar after a search.
        
    -   The article title is automatically pre-filled from your search query.
        
    -   Existing tags are displayed as clickable buttons to speed up tagging.
        
    -   Links from selected Google Search results are automatically added to the References field.
        
-   **Web-Based Settings:** Configure all API keys through a user-friendly Settings page. Configuration is saved to a local `config.json`.
    
-   **Resilient & Informative:**
    
    -   Gracefully handles API failures, such as a rate limit on one service, without crashing.
        
    -   Displays a clear on-screen warning if an API quota (e.g., Gemini's free tier) has been exceeded.
        

## Setup and Installation

Follow these steps to get the application running locally.

### 1. Prerequisites

-   Python 3.7+
    
-   `pip` for installing packages
    

### 2. Download Files

Download all the provided files (`app.py`, `requirements.txt`, and the `templates/` directory with its contents) and place them in a single project directory.

### 3. Create and Activate Virtual Environment

It is highly recommended to use a virtual environment to keep project dependencies isolated.

**On macOS/Linux:**

```
# Create the virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

```

**On Windows:**

```
# Create the virtual environment
python -m venv venv

# Activate the virtual environment
.\venv\Scripts\activate

```

You will know the environment is active when you see `(venv)` at the beginning of your command prompt line.

### 4. Install Dependencies

With your virtual environment active, run:

```
pip install -r requirements.txt

```

### 5. **IMPORTANT**: Database Setup

If you have run a previous version of this application, you **must delete the `kb.db` file** in your project directory. This version contains significant database changes, and deleting the old file will allow the application to create a new, correct one on startup.

### 6. Run the Application

#### For Development

```
python app.py

```

#### For Production

Use a production-ready WSGI server like Waitress:

```
waitress-serve --host 127.0.0.1 --port=5050 app:app

```

### 7. Configure the Application & Get API Keys

**a. Get Your API Keys**

You will need to get API keys from the following services to enter into the application's settings page.

-   **Google Gemini API Key**: Get from [Google AI Studio](https://aistudio.google.com/).
    
-   **Google Custom Search API Key & Search Engine ID**: See the detailed instructions in the project documentation for creating both of these.
    
-   **OpenAI API Key**: Get from the [OpenAI API platform](https://platform.openai.com/api-keys).
    

**b. Run the App and Enter Keys**

1.  Run the application using one of the commands from Step 6.
    
2.  Open your web browser and navigate to **[http://127.0.0.1:5050](https://www.google.com/search?q=http://127.0.0.1:5050)**.
    
3.  Click the **Settings icon** in the top-right corner.
    
4.  Paste your copied API keys into the appropriate fields and click **Save Settings**.
    
5.  Use the "Manage Groups" section to create your initial set of groups and nested groups.
    

The application is now fully configured.
