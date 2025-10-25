import os
import json
import random
import traceback
import zipfile
import io
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, or_
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from requests_oauthlib import OAuth2Session
import requests

# --- APP SETUP & CONFIGURATION ---

app = Flask(__name__)

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

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
        "GEMINI_API_KEY": "", "GOOGLE_API_KEY": "", "SEARCH_ENGINE_ID": "", "OPENAI_API_KEY": "",
        "GITHUB_CLIENT_ID": "", "GITHUB_CLIENT_SECRET": "", "DEBUG_MODE": False,
        "GITHUB_BACKUP_REPO": "", "GITHUB_TOKEN": "", "GEMINI_MODEL": "gemini-2.5-pro"
    }

def save_config(new_config):
    with open(CONFIG_FILE, 'w') as f: json.dump(new_config, f, indent=4)

config = load_config()

# --- DATABASE MODELS ---

roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

article_roles = db.Table('article_roles',
    db.Column('article_id', db.Integer, db.ForeignKey('article.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
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
    github_id = db.Column(db.String(100), unique=True, nullable=True)
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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_shared = db.Column(db.Boolean, default=False, nullable=False)
    roles = db.relationship('Role', secondary=article_roles, backref=db.backref('articles', lazy='dynamic'))
    author = db.relationship('User', backref='articles')

# --- DATABASE INITIALIZATION (for WSGI) ---

def init_db():
    with app.app_context():
        db.create_all()
        # Seed roles and default admin user if missing
        if not Role.query.filter_by(name='Admin').first():
            db.session.add(Role(name='Admin', is_admin=True, can_add_kb=True, can_edit_kb=True, can_delete_kb=True))
        if not Role.query.filter_by(name='User').first():
            db.session.add(Role(name='User', can_add_kb=True, can_edit_kb=True))
        if not User.query.filter_by(username='admin').first():
            hashed_password = generate_password_hash('admin', method='pbkdf2:sha256')
            admin_user = User(username='admin', password_hash=hashed_password, name='Admin')
            admin_role = Role.query.filter_by(name='Admin').first()
            user_role = Role.query.filter_by(name='User').first()
            if admin_role:
                admin_user.roles.append(admin_role)
            if user_role:
                admin_user.roles.append(user_role)
            db.session.add(admin_user)
        db.session.commit()

# Ensure DB exists when the module is imported (e.g., under waitress / gunicorn)
init_db()

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
    # MODIFIED: Read the selected model from the config file
    model_name = config.get('GEMINI_MODEL', 'gemini-2.5-pro') 
    if not api_key: return "Error: Gemini API key not configured."
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        # MODIFIED: Use the model name from the config
        model = genai.GenerativeModel(model_name)
        return model.generate_content(prompt).text
    except Exception as e:
        error_str = str(e).lower()
        if 'quota' in error_str or 'resource_exhausted' in error_str:
            return "Error: Quota exceeded."
        return f"Error: {e}"

def query_google_search(query_text):
    api_key = config.get('GOOGLE_API_KEY')
    search_id = config.get('SEARCH_ENGINE_ID')
    if not api_key or not search_id: return []
    try:
        from googleapiclient.discovery import build
        service = build("customsearch", "v1", developerKey=api_key)
        res = service.cse().list(q=query_text, cx=search_id, num=5).execute()
        return [
            {
                "title": i.get('title'), 
                "url": i.get('link'), 
                "snippet": i.get('snippet'),
                "source": i.get('displayLink'),
                "date": i.get('pagemap', {}).get('metatags', [{}])[0].get('article:published_time')
            } 
            for i in res.get('items', [])
        ]
    except Exception as e: 
        print(f"Google Search API Error: {e}")
        return []

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

@app.route('/github_login')
def github_login():
    if not config.get('GITHUB_CLIENT_ID') or not config.get('GITHUB_CLIENT_SECRET'):
        flash('GitHub SSO is not configured.')
        return redirect(url_for('login'))
    
    github = OAuth2Session(config['GITHUB_CLIENT_ID'], scope=['read:user', 'user:email'])
    authorization_url, state = github.authorization_url('https://github.com/login/oauth/authorize')
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/github_callback')
def github_callback():
    github = OAuth2Session(config['GITHUB_CLIENT_ID'], state=session.get('oauth_state'))
    token = github.fetch_token('https://github.com/login/oauth/access_token', client_secret=config['GITHUB_CLIENT_SECRET'], authorization_response=request.url)
    
    user_info = github.get('https://api.github.com/user').json()
    
    user = User.query.filter_by(github_id=user_info['id']).first()
    if not user:
        user = User(
            github_id=str(user_info['id']),
            name=user_info.get('name') or user_info.get('login'),
            username=user_info.get('login'),
            email=user_info.get('email')
        )
        user_role = Role.query.filter_by(name='User').first()
        if user_role:
            user.roles.append(user_role)
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    return redirect(url_for('index'))


@app.route('/')
@login_required
def index():
    search_term = request.args.get('search', '')
    sort_by = request.args.get('sort', 'group')
    filter_group_id = request.args.get('group', type=int)
    filter_tag = request.args.get('tag', '')
    filter_visibility = request.args.get('visibility', 'all')

    user_role_ids = [role.id for role in current_user.roles]
    
    query = Article.query.join(Group).outerjoin(article_roles, Article.id == article_roles.c.article_id)
    
    visibility_filter = or_(
        Article.user_id == current_user.id,
        article_roles.c.role_id.in_(user_role_ids)
    )
    query = query.filter(visibility_filter)
    
    if filter_visibility == 'local':
        query = query.filter(Article.user_id == current_user.id, Article.is_shared == False)
    elif filter_visibility == 'shared':
        query = query.filter(Article.is_shared == True)

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
    
    articles = query.distinct().all()
    
    all_tags_query = db.session.query(Article.tags).filter(Article.tags.isnot(None)).distinct().all()
    all_tags = sorted(list(set(tag.strip() for tags_tuple in all_tags_query for tag in tags_tuple[0].split(',') if tag.strip())))
    
    all_groups = Group.query.order_by(Group.name).all()
    groups_for_js = [{'id': g.id, 'name': g.name, 'parent_id': g.parent_id} for g in all_groups]

    return render_template('index.html', articles=articles, all_tags=all_tags, all_groups=all_groups, groups_for_js=groups_for_js, 
                             search_term=search_term, sort_by=sort_by, filter_group_id=filter_group_id, filter_tag=filter_tag, filter_visibility=filter_visibility)

# --- MODULAR SETTINGS ROUTES ---

@app.route('/settings/')
@login_required
@permission_required('is_admin')
def settings_redirect():
    return redirect(url_for('settings_page', page='api'))

@app.route('/settings/<page>')
@login_required
@permission_required('is_admin')
def settings_page(page):
    template_map = {
        'api': 'settings_api.html',
        'sso': 'settings_sso.html',
        'backup': 'settings_backup.html',
        'groups': 'settings_groups.html',
        'roles': 'settings_roles.html'
    }
    if page not in template_map:
        return redirect(url_for('settings_redirect'))

    template_data = {'current_config': config, 'active_page': page}
    if page == 'sso':
        template_data['github_redirect_uri'] = url_for('github_callback', _external=True)
    elif page == 'groups':
        template_data['groups'] = Group.query.order_by(Group.name).all()
    elif page == 'roles':
        template_data['roles'] = Role.query.order_by(Role.name).all()

    return render_template(template_map[page], **template_data)

@app.route('/settings/save', methods=['POST'])
@login_required
@permission_required('is_admin')
def save_settings():
    global config
    updated_config = config.copy()
    
    for key, value in request.form.items():
        if key in updated_config:
            updated_config[key] = value

    save_config(updated_config)
    config = load_config()
    flash('Settings saved successfully!', 'success')
    return redirect(request.referrer or url_for('settings_redirect'))

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
    if user.username == 'admin':
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
    return redirect(url_for('settings_page', page='roles'))

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
    return redirect(url_for('settings_page', page='groups'))

@app.route('/group/delete/<int:id>', methods=['POST'])
@login_required
@permission_required('is_admin')
def delete_group(id):
    group = Group.query.get_or_404(id)
    for child in group.children:
        child.parent_id = group.parent_id
    db.session.delete(group)
    db.session.commit()
    return redirect(url_for('settings_page', page='groups'))

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
    if not question: 
        return jsonify({"error": "No question"}), 400
    results = {
        "local_kb": query_local_kb(question),
        "gemini": query_gemini(question),
        "google_search": query_google_search(question),
        "openai": query_chatgpt(question)
    }
    return render_template('_search_results.html', results=results)

@app.route('/create_article', methods=['POST'])
@login_required
@permission_required('can_add_kb')
def create_article():
    try:
        data = request.get_json()
        if not all(k in data for k in ['title', 'group_id', 'texts']):
            return jsonify({"error": "Missing required fields"}), 400

        compiled_content = "\n\n---\n\n".join(data['texts'])
        if not compiled_content: 
            return jsonify({"error": "No content to save."}), 400

        references_list = data.get('references', [])
        references_str = ""
        if references_list:
            md_links = []
            for ref in references_list:
                if ref.get('url'):
                    name = ref.get('name') or ref.get('url')
                    md_links.append(f"- [{name}]({ref['url']})")
            references_str = "\n".join(md_links)

        new_article = Article(
            title=data['title'],
            content=compiled_content,
            notes=data.get('notes'),
            references=references_str,
            tags=data.get('tags'), 
            group_id=data['group_id'],
            user_id=current_user.id,
            is_shared=False
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
        share_mode = update_data.get('share_mode')
        role_ids = update_data.get('role_ids')

        for article in articles:
            if update_data.get('notes'): article.notes = (article.notes or '') + '\n' + update_data['notes']
            if update_data.get('references'): article.references = (article.references or '') + '\n' + update_data['references']
            if update_data.get('tags'):
                existing = set(t.strip() for t in (article.tags or '').split(',') if t.strip())
                new = set(t.strip() for t in update_data['tags'].split(',') if t.strip())
                article.tags = ', '.join(sorted(existing.union(new)))
            
            if share_mode and role_ids is not None:
                new_roles = Role.query.filter(Role.id.in_(role_ids)).all()
                if share_mode == 'replace':
                    article.roles = new_roles
                elif share_mode == 'add':
                    existing_roles = set(article.roles)
                    for role in new_roles:
                        if role not in existing_roles:
                            article.roles.append(role)
                article.is_shared = len(article.roles) > 0

    db.session.commit()
    return jsonify({"success": True})

# --- BACKUP & RESTORE ROUTES ---

@app.route('/backup_restore')
@login_required
@permission_required('is_admin')
def backup_restore_page():
    return render_template('backup_restore.html')

@app.route('/backup/file')
@login_required
@permission_required('is_admin')
def backup_to_file():
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        articles = Article.query.all()
        articles_data = [{'id': a.id, 'title': a.title, 'content': a.content, 'notes': a.notes, 
                          'references': a.references, 'tags': a.tags, 'group_id': a.group_id} for a in articles]
        zf.writestr('articles.json', json.dumps(articles_data, indent=4))
        groups = Group.query.all()
        groups_data = [{'id': g.id, 'name': g.name, 'color': g.color, 'parent_id': g.parent_id} for g in groups]
        zf.writestr('groups.json', json.dumps(groups_data, indent=4))
        zf.writestr('config.json', json.dumps(config, indent=4))
    memory_file.seek(0)
    return send_file(memory_file, download_name='kb_backup.zip', as_attachment=True)

@app.route('/backup/github', methods=['POST'])
@login_required
@permission_required('is_admin')
def backup_to_github():
    repo_name = config.get('GITHUB_BACKUP_REPO')
    token = config.get('GITHUB_TOKEN')
    if not all([repo_name, token]):
        return jsonify({"success": False, "error": "GitHub repo or token not configured."})

    headers = {"Authorization": f"token {token}"}
    articles = Article.query.all()
    articles_data = [{'id': a.id, 'title': a.title, 'content': a.content, 'notes': a.notes, 
                      'references': a.references, 'tags': a.tags, 'group_id': a.group_id} for a in articles]
    groups = Group.query.all()
    groups_data = [{'id': g.id, 'name': g.name, 'color': g.color, 'parent_id': g.parent_id} for g in groups]
    files = {
        "articles.json": json.dumps(articles_data, indent=4),
        "groups.json": json.dumps(groups_data, indent=4)
    }
    for filename, content in files.items():
        url = f"https://api.github.com/repos/{repo_name}/contents/{filename}"
        get_res = requests.get(url, headers=headers)
        sha = None
        if get_res.status_code == 200: sha = get_res.json().get('sha')
        import base64
        content_b64 = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        data = {"message": f"Backup {filename}", "content": content_b64, "branch": "dev"}
        if sha: data['sha'] = sha
        put_res = requests.put(url, headers=headers, json=data)
        if put_res.status_code not in [200, 201]:
            return jsonify({"success": False, "error": f"Failed to backup {filename}: {put_res.json()}"})
    return jsonify({"success": True})

@app.route('/restore/upload', methods=['POST'])
@login_required
@permission_required('is_admin')
def restore_from_upload():
    if 'backup_file' not in request.files: return jsonify({"error": "No file part"}), 400
    file = request.files['backup_file']
    if file.filename == '': return jsonify({"error": "No selected file"}), 400
    try:
        backup_data = {}
        with zipfile.ZipFile(file, 'r') as zf:
            if 'articles.json' in zf.namelist(): backup_data['articles'] = json.loads(zf.read('articles.json'))
            if 'groups.json' in zf.namelist(): backup_data['groups'] = json.loads(zf.read('groups.json'))
            if 'config.json' in zf.namelist(): backup_data['config'] = json.loads(zf.read('config.json'))
        return jsonify(backup_data)
    except Exception as e:
        return jsonify({"error": f"Invalid backup file: {e}"}), 400

@app.route('/restore/execute', methods=['POST'])
@login_required
@permission_required('is_admin')
def execute_restore():
    global config
    data = request.get_json()
    if 'config' in data:
        new_config = config.copy()
        new_config.update(data['config'])
        save_config(new_config)
        config = load_config()
    if 'groups' in data:
        for group_data in data['groups']:
            group = Group.query.get(group_data['id'])
            if not group:
                group = Group(id=group_data['id'])
                db.session.add(group)
            group.name = group_data['name']
            group.color = group_data['color']
            group.parent_id = group_data['parent_id']
    if 'articles' in data:
        for article_data in data['articles']:
            article = Article.query.get(article_data['id'])
            if not article:
                article = Article(id=article_data['id'])
                db.session.add(article)
            article.title = article_data['title']
            article.content = article_data['content']
            article.notes = article_data['notes']
            article.references = article_data['references']
            article.tags = article_data['tags']
            article.group_id = article_data['group_id']
    db.session.commit()
    return jsonify({"success": True})

# --- SHARING ROUTES ---
@app.route('/article/sharing_details/<int:article_id>')
@login_required
def get_sharing_details(article_id):
    article = Article.query.get_or_404(article_id)
    if not (current_user.id == article.user_id or current_user.has_permission('is_admin')):
        return jsonify({"error": "Permission denied"}), 403
    
    all_roles = Role.query.all()
    shared_with_ids = [role.id for role in article.roles]
    
    roles_data = [{"id": role.id, "name": role.name, "shared": role.id in shared_with_ids} for role in all_roles]
    
    return jsonify({
        "article_id": article.id,
        "is_shared": article.is_shared,
        "roles": roles_data
    })

@app.route('/article/share', methods=['POST'])
@login_required
def share_article():
    data = request.get_json()
    article_id = data.get('article_id')
    role_ids = data.get('role_ids', [])
    
    article = Article.query.get_or_404(article_id)
    if not (current_user.id == article.user_id or current_user.has_permission('is_admin')):
        return jsonify({"error": "Permission denied"}), 403

    article.roles = Role.query.filter(Role.id.in_(role_ids)).all()
    article.is_shared = len(article.roles) > 0
    
    db.session.commit()
    return jsonify({"success": True})

@app.route('/get/roles')
@login_required
@permission_required('is_admin')
def get_roles():
    roles = Role.query.all()
    return jsonify([{"id": role.id, "name": role.name} for role in roles])

# --- MAIN EXECUTION ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
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
