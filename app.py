import os
import json
import random
import traceback
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, or_
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- APP SETUP & CONFIGURATION ---

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- CONFIG FILE HANDLING ---

CONFIG_FILE = 'config.json'

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f: return json.load(f)
    return {
        "GEMINI_API_KEY": "", "GOOGLE_API_KEY": "", "SEARCH_ENGINE_ID": "", "OPENAI_API_KEY": "", "DEBUG_MODE": False
    }

def save_config(new_config):
    with open(CONFIG_FILE, 'w') as f: json.dump(new_config, f, indent=4)

config = load_config()

# --- DATABASE MODELS ---

roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    is_admin = db.Column(db.Boolean, default=False)
    can_add_kb = db.Column(db.Boolean, default=False)
    can_edit_kb = db.Column(db.Boolean, default=False)
    can_delete_kb = db.Column(db.Boolean, default=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    name = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(100), unique=True, nullable=True)
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

    def has_permission(self, permission_name):
        return any(getattr(role, permission_name, False) for role in self.roles)

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

# --- LOGIN & SESSION MANAGEMENT ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.has_permission(permission):
                flash("You do not have permission to perform this action.")
                return redirect(request.referrer or url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- API & LOCAL SEARCH HELPER FUNCTIONS ---

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

def query_local_kb(search_term):
    """Searches the local database for relevant articles."""
    search_like = f"%{search_term}%"
    articles = Article.query.filter(
        or_(Article.title.ilike(search_like), Article.content.ilike(search_like), Article.tags.ilike(search_like))
    ).limit(3).all()
    return [{'id': a.id, 'title': a.title, 'content': a.content} for a in articles]

# --- FLASK ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password_hash and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
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
@login_required
@permission_required('is_admin')
def settings_page():
    global config
    if request.method == 'POST':
        updated_config = {
            "GEMINI_API_KEY": request.form.get('gemini_api_key', config.get('GEMINI_API_KEY')),
            "GOOGLE_API_KEY": request.form.get('google_api_key', config.get('GOOGLE_API_KEY')),
            "SEARCH_ENGINE_ID": request.form.get('search_engine_id', config.get('SEARCH_ENGINE_ID')),
            "OPENAI_API_KEY": request.form.get('openai_api_key', config.get('OPENAI_API_KEY')),
            "DEBUG_MODE": 'debug_mode' in request.form
        }
        save_config(updated_config)
        config = load_config()
        flash('Settings saved successfully!', 'success')
        return redirect(url_for('settings_page'))
    
    groups = Group.query.order_by(Group.name).all()
    roles = Role.query.all()
    
    debug_headers = {k: v for k, v in request.headers}

    return render_template('settings.html', current_config=config, groups=groups, roles=roles, debug_headers=debug_headers)

@app.route('/user_management')
@login_required
@permission_required('is_admin')
def user_management():
    users = User.query.all()
    roles = Role.query.all()
    return render_template('user_management.html', users=users, roles=roles)


# --- All other routes remain the same ---

@app.route('/user/add', methods=['POST'])
@login_required
@permission_required('is_admin')
def add_user():
    username = request.form.get('username')
    password = request.form.get('password')
    if username and password and not User.query.filter_by(username=username).first():
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password_hash=hashed_password, name=username)
        user_role = Role.query.filter_by(name='User').first()
        if user_role: new_user.roles.append(user_role)
        db.session.add(new_user)
        db.session.commit()
    return redirect(url_for('user_management'))

@app.route('/user/delete/<int:id>', methods=['POST'])
@login_required
@permission_required('is_admin')
def delete_user(id):
    user = User.query.get_or_404(id)
    if user.username == 'admin': # Prevent admin deletion
        flash("Cannot delete the default admin user.")
        return redirect(url_for('user_management'))
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('user_management'))

@app.route('/user/assign_role/<int:user_id>/<int:role_id>', methods=['POST'])
@login_required
@permission_required('is_admin')
def assign_role(user_id, role_id):
    user = User.query.get_or_404(user_id)
    role = Role.query.get_or_404(role_id)
    if role not in user.roles:
        user.roles.append(role)
        db.session.commit()
    return redirect(url_for('user_management'))

@app.route('/user/remove_role/<int:user_id>/<int:role_id>', methods=['POST'])
@login_required
@permission_required('is_admin')
def remove_role(user_id, role_id):
    user = User.query.get_or_404(user_id)
    role = Role.query.get_or_404(role_id)
    if user.username == 'admin' and role.name == 'Admin':
        flash("Cannot remove Admin role from the default admin user.")
        return redirect(url_for('user_management'))
    if role in user.roles:
        user.roles.remove(role)
        db.session.commit()
    return redirect(url_for('user_management'))

@app.route('/role/add', methods=['POST'])
@login_required
@permission_required('is_admin')
def add_role():
    name = request.form.get('name')
    if name and not Role.query.filter_by(name=name).first():
        new_role = Role(
            name=name,
            is_admin='is_admin' in request.form,
            can_add_kb='can_add_kb' in request.form,
            can_edit_kb='can_edit_kb' in request.form,
            can_delete_kb='can_delete_kb' in request.form
        )
        db.session.add(new_role)
        db.session.commit()
    return redirect(url_for('settings_page'))

@app.route('/group/add', methods=['POST'])
@login_required
@permission_required('is_admin')
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
@login_required
@permission_required('is_admin')
def delete_group(id):
    group = Group.query.get_or_404(id)
    for child in group.children:
        child.parent_id = group.parent_id
    db.session.delete(group)
    db.session.commit()
    return redirect(url_for('settings_page'))

@app.route('/get/article/<int:article_id>')
@login_required
def get_article(article_id):
    article = Article.query.get_or_404(article_id)
    return jsonify({
        'id': article.id, 'title': article.title, 'content': article.content,
        'notes': article.notes, 'references': article.references, 'tags': article.tags,
        'group_id': article.group.id
    })

@app.route('/edit/article/<int:article_id>', methods=['POST'])
@login_required
@permission_required('can_edit_kb')
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
@login_required
def ask():
    question = request.get_json().get('question')
    if not question: return jsonify({"error": "No question"}), 400
    
    return jsonify({
        "local_kb": query_local_kb(question),
        "gemini": query_gemini(question), 
        "google": query_google_search(question),
        "chatgpt": query_chatgpt(question)
    })

@app.route('/synthesize', methods=['POST'])
@login_required
@permission_required('can_add_kb')
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
            synthesis_prompt = f"Synthesize the following into an article titled '{data['title']}':\n\n{info_block}"
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
@login_required
def bulk_action():
    data = request.get_json()
    action, ids = data.get('action'), data.get('ids')
    if not all([action, ids]): return jsonify({"error": "Missing action or IDs"}), 400
    
    if action == 'delete' and not current_user.has_permission('can_delete_kb'):
        return jsonify({"error": "Permission denied"}), 403
    if action == 'update' and not current_user.has_permission('can_edit_kb'):
        return jsonify({"error": "Permission denied"}), 403

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
        # Create default roles and admin user if they don't exist
        if not Role.query.filter_by(name='Admin').first():
            db.session.add(Role(name='Admin', is_admin=True, can_add_kb=True, can_edit_kb=True, can_delete_kb=True))
        if not Role.query.filter_by(name='User').first():
            db.session.add(Role(name='User', can_add_kb=True, can_edit_kb=True))
        
        if not User.query.filter_by(username='admin').first():
            hashed_password = generate_password_hash('admin', method='pbkdf2:sha256')
            admin_user = User(username='admin', password_hash=hashed_password, name='Admin')
            admin_role = Role.query.filter_by(name='Admin').first()
            user_role = Role.query.filter_by(name='User').first()
            admin_user.roles.append(admin_role)
            admin_user.roles.append(user_role)
            db.session.add(admin_user)
        
        db.session.commit()

    app.run(host='0.0.0.0', port=5050, debug=True)