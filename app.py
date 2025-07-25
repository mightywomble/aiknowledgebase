import os
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

# --- APP SETUP & CONFIGURATION ---

app = Flask(__name__)

# Configure the database
# The database will be created in the `instance` folder
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- CONFIG FILE HANDLING ---

CONFIG_FILE = 'config.json'

def load_config():
    """Loads API keys and settings from config.json."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    # Default structure if file doesn't exist
    return {
        "GEMINI_API_KEY": "",
        "GOOGLE_API_KEY": "",
        "SEARCH_ENGINE_ID": "",
        "OPENAI_API_KEY": ""
    }

def save_config(new_config):
    """Saves the configuration dictionary to config.json."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(new_config, f, indent=4)

# Load initial config
config = load_config()

# --- DATABASE MODELS ---

class Category(db.Model):
    """Model for KB article categories."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    articles = db.relationship('Article', backref='category', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Category {self.name}>'

class Article(db.Model):
    """Model for KB articles."""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text, nullable=True) # New field for notes
    references = db.Column(db.Text, nullable=True) # New field for links
    tags = db.Column(db.String(255), nullable=True) # New field for tags
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

    def __repr__(self):
        return f'<Article {self.title}>'

# --- HELPER FUNCTIONS FOR API CALLS ---

def query_gemini(prompt):
    """Sends a prompt to the Gemini API and returns the response."""
    api_key = config.get('GEMINI_API_KEY')
    if not api_key:
        return "Error: Gemini API key not configured in Settings."
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Gemini API Error: {e}")
        return f"Error communicating with Gemini API: {e}"

def query_google_search(query_text):
    """Performs a Google search and returns formatted results."""
    api_key = config.get('GOOGLE_API_KEY')
    search_id = config.get('SEARCH_ENGINE_ID')
    if not api_key or not search_id:
        return [{"title": "Error", "link": "#", "snippet": "Google Search API key or Search Engine ID not configured in Settings."}]
    try:
        from googleapiclient.discovery import build
        service = build("customsearch", "v1", developerKey=api_key)
        res = service.cse().list(q=query_text, cx=search_id, num=5).execute()
        items = res.get('items', [])
        return [{"title": item.get('title'), "link": item.get('link'), "snippet": item.get('snippet')} for item in items]
    except Exception as e:
        print(f"Google Search API Error: {e}")
        return [{"title": "Error", "link": "#", "snippet": f"Error with Google Search API: {e}"}]

def query_chatgpt(prompt):
    """Sends a prompt to the OpenAI/ChatGPT API."""
    api_key = config.get('OPENAI_API_KEY')
    if not api_key:
        return "Error: OpenAI API key not configured in Settings."
    try:
        import openai
        openai.api_key = api_key
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"OpenAI API Error: {e}")
        return f"Error communicating with OpenAI API: {e}"

# --- FLASK ROUTES ---

@app.route('/')
def index():
    """Main page, displays all articles grouped by category."""
    categories = Category.query.order_by(Category.name).all()
    return render_template('index.html', categories=categories)

@app.route('/settings', methods=['GET'])
def settings_page():
    """Displays the settings page."""
    return render_template('settings.html', current_config=config)

@app.route('/save_settings', methods=['POST'])
def save_settings_route():
    """Saves the submitted settings to config.json."""
    global config
    new_config = {
        "GEMINI_API_KEY": request.form.get('gemini_api_key', ''),
        "GOOGLE_API_KEY": request.form.get('google_api_key', ''),
        "SEARCH_ENGINE_ID": request.form.get('search_engine_id', ''),
        "OPENAI_API_KEY": request.form.get('openai_api_key', '')
    }
    save_config(new_config)
    config = new_config
    return redirect(url_for('index'))

@app.route('/get/article/<int:article_id>')
def get_article(article_id):
    """Fetches a single article by its ID and returns it as JSON."""
    article = Article.query.get_or_404(article_id)
    return jsonify({
        'title': article.title,
        'content': article.content,
        'notes': article.notes,
        'references': article.references,
        'tags': article.tags
    })

@app.route('/ask', methods=['POST'])
def ask():
    """Handles the user's question, calls APIs, and returns JSON."""
    data = request.get_json()
    question = data.get('question')
    if not question:
        return jsonify({"error": "No question provided"}), 400
    
    gemini_answer = query_gemini(question)
    google_results = query_google_search(question)
    chatgpt_answer = query_chatgpt(question)

    return jsonify({
        "gemini": gemini_answer,
        "google": google_results,
        "chatgpt": chatgpt_answer
    })

@app.route('/synthesize', methods=['POST'])
def synthesize_and_save():
    """Takes selected text and new fields, synthesizes an article, and saves it."""
    data = request.get_json()
    title = data.get('title')
    category_name = data.get('category')
    notes = data.get('notes')
    references = data.get('references')
    tags = data.get('tags')
    selected_texts = data.get('texts')

    if not all([title, category_name, selected_texts]):
        return jsonify({"error": "Missing title, category, or selected texts"}), 400

    synthesis_prompt = f"""
    Based on the following pieces of information, write a clear, concise, and well-structured knowledge base article.
    The title of the article is: "{title}"
    Combine the key points from the information provided below into a coherent article.
    Format the output using Markdown for readability (e.g., use headings, lists, bold text).
    ---
    Information Snippets:
    {json.dumps(selected_texts, indent=2)}
    ---
    Begin the article now:
    """
    synthesized_content = query_gemini(synthesis_prompt)

    if synthesized_content.startswith("Error:"):
        return jsonify({"error": synthesized_content}), 500

    category = Category.query.filter_by(name=category_name).first()
    if not category:
        category = Category(name=category_name)
        db.session.add(category)
    
    new_article = Article(
        title=title, 
        content=synthesized_content, 
        notes=notes,
        references=references,
        tags=tags,
        category=category
    )
    db.session.add(new_article)
    db.session.commit()

    return jsonify({"success": True, "message": "New KB article created successfully!"})

@app.route('/delete/article/<int:article_id>', methods=['POST'])
def delete_article(article_id):
    """Deletes an article from the database."""
    article = Article.query.get_or_404(article_id)
    db.session.delete(article)
    db.session.commit()
    return jsonify({"success": True, "message": "Article deleted."})

# --- MAIN EXECUTION ---

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5050, debug=True)
