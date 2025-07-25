import os
import json
import random
import traceback
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, or_

# --- APP SETUP & CONFIGURATION ---

app = Flask(__name__)

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- CONFIG FILE HANDLING ---

CONFIG_FILE = 'config.json'

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f: return json.load(f)
    return {"GEMINI_API_KEY": "", "GOOGLE_API_KEY": "", "SEARCH_ENGINE_ID": "", "OPENAI_API_KEY": ""}

def save_config(new_config):
    with open(CONFIG_FILE, 'w') as f: json.dump(new_config, f, indent=4)

config = load_config()

# --- DATABASE MODELS (RENAMED CATEGORY TO GROUP) ---

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(20), nullable=False, default='#E5E7EB')
    parent_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    parent = db.relationship('Group', remote_side=[id], backref='children')
    articles = db.relationship('Article', backref='group', lazy='dynamic', cascade="all, delete-orphan")

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    references = db.Column(db.Text, nullable=True)
    tags = db.Column(db.String(255), nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)

# --- API HELPER FUNCTIONS ---

def query_gemini(prompt):
    api_key = config.get('GEMINI_API_KEY')
    if not api_key: return "Error: Gemini API key not configured."
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        return model.generate_content(prompt).text
    except Exception as e: return f"Error: {e}"

def query_google_search(query_text):
    api_key = config.get('GOOGLE_API_KEY')
    search_id = config.get('SEARCH_ENGINE_ID')
    if not api_key or not search_id: return [{"title": "Error", "snippet": "Google Search not configured."}]
    try:
        from googleapiclient.discovery import build
        service = build("customsearch", "v1", developerKey=api_key)
        res = service.cse().list(q=query_text, cx=search_id, num=5).execute()
        return [{"title": i.get('title'), "link": i.get('link'), "snippet": i.get('snippet')} for i in res.get('items', [])]
    except Exception as e: return [{"title": "Error", "snippet": f"API Error: {e}"}]

def query_chatgpt(prompt):
    api_key = config.get('OPENAI_API_KEY')
    if not api_key: return "Error: OpenAI API key not configured."
    try:
        import openai
        openai.api_key = api_key
        response = openai.chat.completions.create(model="gpt-3.5-turbo", messages=[{"role": "user", "content": prompt}])
        return response.choices[0].message.content
    except Exception as e: return f"Error: {e}"

# --- FLASK ROUTES ---

@app.route('/')
def index():
    search_term = request.args.get('search', '')
    sort_by = request.args.get('sort', 'group')
    filter_group_id = request.args.get('group', type=int)
    filter_tag = request.args.get('tag', '')
    
    query = Article.query.join(Group)

    if search_term:
        query = query.filter(or_(Article.title.ilike(f"%{search_term}%"), Article.tags.ilike(f"%{search_term}%")))
    if filter_group_id:
        query = query.filter(Article.group_id == filter_group_id)
    if filter_tag:
        query = query.filter(Article.tags.ilike(f"%{filter_tag}%"))

    if sort_by == 'title_asc': query = query.order_by(Article.title)
    elif sort_by == 'title_desc': query = query.order_by(desc(Article.title))
    elif sort_by == 'newest': query = query.order_by(desc(Article.id))
    else: query = query.order_by(Group.name, Article.title)
    
    articles = query.all()
    
    all_tags_query = db.session.query(Article.tags).filter(Article.tags.isnot(None)).distinct().all()
    all_tags = sorted(list(set(tag.strip() for tags_tuple in all_tags_query for tag in tags_tuple[0].split(',') if tag.strip())))
    
    all_groups = Group.query.order_by(Group.name).all()
    groups_for_js = [{'id': g.id, 'name': g.name, 'parent_id': g.parent_id} for g in all_groups]

    return render_template('index.html', articles=articles, all_tags=all_tags, all_groups=all_groups, groups_for_js=groups_for_js, 
                             search_term=search_term, sort_by=sort_by, filter_group_id=filter_group_id, filter_tag=filter_tag)

@app.route('/settings', methods=['GET', 'POST'])
def settings_page():
    if request.method == 'POST':
        global config
        new_config = {
            "GEMINI_API_KEY": request.form.get('gemini_api_key', ''),
            "GOOGLE_API_KEY": request.form.get('google_api_key', ''),
            "SEARCH_ENGINE_ID": request.form.get('search_engine_id', ''),
            "OPENAI_API_KEY": request.form.get('openai_api_key', '')
        }
        save_config(new_config)
        config = new_config
        return redirect(url_for('settings_page'))
    
    groups = Group.query.order_by(Group.name).all()
    return render_template('settings.html', current_config=config, groups=groups)

@app.route('/group/add', methods=['POST'])
def add_group():
    name = request.form.get('name')
    parent_id = request.form.get('parent_id')
    if name:
        colors = ['#FEE2E2', '#FEF3C7', '#D1FAE5', '#DBEAFE', '#E0E7FF', '#F3E8FF']
        new_group = Group(name=name, color=random.choice(colors))
        if parent_id and parent_id.isdigit():
            new_group.parent_id = int(parent_id)
        db.session.add(new_group)
        db.session.commit()
    return redirect(url_for('settings_page'))

@app.route('/group/delete/<int:id>', methods=['POST'])
def delete_group(id):
    group = Group.query.get_or_404(id)
    for child in group.children:
        child.parent_id = group.parent_id
    db.session.delete(group)
    db.session.commit()
    return redirect(url_for('settings_page'))

@app.route('/get/article/<int:article_id>')
def get_article(article_id):
    article = Article.query.get_or_404(article_id)
    return jsonify({
        'id': article.id, 'title': article.title, 'content': article.content,
        'notes': article.notes, 'references': article.references, 'tags': article.tags,
        'group_id': article.group.id
    })

@app.route('/edit/article/<int:article_id>', methods=['POST'])
def edit_article(article_id):
    article = Article.query.get_or_404(article_id)
    data = request.get_json()
    
    article.title = data['title']
    article.group_id = data['group_id']
    article.notes = data['notes']
    article.references = data['references']
    article.tags = data['tags']
    
    db.session.commit()
    return jsonify({"success": True, "message": "Article updated."})

@app.route('/ask', methods=['POST'])
def ask():
    question = request.get_json().get('question')
    if not question: return jsonify({"error": "No question"}), 400
    return jsonify({
        "gemini": query_gemini(question), "google": query_google_search(question), "chatgpt": query_chatgpt(question)
    })

@app.route('/synthesize', methods=['POST'])
def synthesize_and_save():
    try:
        data = request.get_json()
        if not all(k in data for k in ['title', 'group_id', 'texts']):
            return jsonify({"error": "Missing required fields"}), 400

        synthesized_content = ""
        if len(data['texts']) == 1:
            synthesized_content = data['texts'][0]
        elif len(data['texts']) > 1:
            info_block = "\n\n---\n\n".join(data['texts'])
            synthesis_prompt = f"Synthesize the following information into an article titled '{data['title']}':\n\n{info_block}"
            gemini_result = query_gemini(synthesis_prompt)
            synthesized_content = gemini_result if not gemini_result.startswith("Error:") else info_block
        
        if not synthesized_content: return jsonify({"error": "No content to save."}), 400

        new_article = Article(
            title=data['title'], content=synthesized_content, notes=data.get('notes'),
            references=data.get('references'), tags=data.get('tags'), 
            group_id=data['group_id']
        )
        db.session.add(new_article)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        traceback.print_exc()
        db.session.rollback()
        return jsonify({"error": f"An unexpected server error occurred: {e}"}), 500

@app.route('/bulk_action', methods=['POST'])
def bulk_action():
    data = request.get_json()
    action, ids = data.get('action'), data.get('ids')
    if not all([action, ids]): return jsonify({"error": "Missing action or IDs"}), 400
    
    articles = Article.query.filter(Article.id.in_(ids)).all()
    if action == 'delete':
        for article in articles: db.session.delete(article)
    elif action == 'update':
        update_data = data.get('data', {})
        for article in articles:
            if update_data.get('notes'): article.notes = (article.notes or '') + '\n' + update_data['notes']
            if update_data.get('references'): article.references = (article.references or '') + '\n' + update_data['references']
            if update_data.get('tags'):
                existing = set(t.strip() for t in (article.tags or '').split(',') if t.strip())
                new = set(t.strip() for t in update_data['tags'].split(',') if t.strip())
                article.tags = ', '.join(sorted(existing.union(new)))
    db.session.commit()
    return jsonify({"success": True})

# --- MAIN EXECUTION ---

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5050, debug=True)
