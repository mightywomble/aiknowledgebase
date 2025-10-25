# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Development Commands

### Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Running the Application
```bash
# Development mode (debug enabled)
python app.py

# Production mode
waitress-serve --host 127.0.0.1 --port=5050 app:app
```

The application runs on `http://127.0.0.1:5050` and requires login with default credentials (admin/admin).

### Linting & Code Quality
No official linting setup exists in the project. When making changes, adhere to PEP 8 standards and the existing code style.

## Architecture Overview

### Monolithic Flask Application
The project is a single-file Flask application (`app.py`, ~988 lines) with no modular separation of concerns. All routes, models, and business logic are in one file.

### Core Components

**Database Models (SQLAlchemy):**
- `User`: Authentication and role assignment
- `Role`: Permission management (can_add_kb, can_edit_kb, can_delete_kb, is_admin)
- `Article`: Main knowledge base content with Markdown support
- `Group`: Hierarchical organization with color coding and parent-child relationships

**Key Features:**
1. **Multi-API Search**: Simultaneously queries local SQLite DB, Google Search, Google Gemini, and OpenAI ChatGPT
2. **User Management**: Admin-controlled user creation, role assignment, and GitHub SSO integration
3. **Article Management**: Full CRUD operations with Markdown rendering, bulk actions, tagging, and visibility controls
4. **GitHub Backup**: Scheduled backups via APScheduler with configurable cron expressions
5. **Role-Based Access Control**: Fine-grained permissions for KB operations

### Data Flow: Search Request
```
User Query → Flask /ask endpoint
  ↓
Parallel queries:
  - Local KB: SQLite full-text search on title/content/tags
  - Google Search API: External web search
  - Gemini API: AI-generated response (configurable model)
  - ChatGPT API: Alternative AI response
  ↓
Results aggregated in _search_results.html template
  ↓
User can create article from results
```

### Template Structure
Templates in `templates/` use Jinja2 with modular organization:
- `_base_layout.html`: Main layout with sidebar and header
- `index.html`: Dashboard with search, article list, and filters
- `settings_*.html`: Modular settings pages (api, sso, backup, schedule, groups, roles)
- `_modals.html`: Article create/edit modals
- `_scripts_index.html`: Frontend JavaScript logic

### Configuration Management
- `config.json`: Runtime configuration file (auto-created) storing API keys, backup settings, and preferences
- `load_config()` / `save_config()`: Helper functions for persistent config management
- APScheduler: Background task scheduler for GitHub backups

## Important Implementation Details

### API Integration
- **Gemini Model Configuration**: The model is configurable via `GEMINI_MODEL` in config.json (default: "gemini-2.5-pro"). Changed from outdated "google" module to `google-generativeai`.
- **Error Handling**: Graceful degradation when APIs fail; quota errors are caught and displayed to users
- **Rate Limiting**: Each API has a 5-result limit to minimize quota usage

### Authentication & Authorization
- Default admin user: username=`admin`, password=`admin` (hash-based)
- GitHub OAuth2 for SSO
- Permission checks use `@permission_required()` decorator on routes
- Articles have visibility controls: private, shared (with role restrictions), or public

### Database
- SQLite (`kb.db`) for lightweight local storage
- Articles linked to users and groups
- Role-based article access via `article_roles` junction table
- Cascade deletes on group deletion (children inherit parent_id)

### Backup System
- Manual backup: ZIP file download or GitHub repository push
- Scheduled backup: APScheduler runs `perform_scheduled_backup()` on cron schedule
- Backs up: articles, groups, and API keys (sensitive data stays local)

## Common Development Tasks

### Adding a New API Integration
1. Create query function in app.py (e.g., `query_new_api()`)
2. Add API key field to config structure and settings_api.html
3. Call the function in `/ask` route and add results to response
4. Add error handling and rate limiting

### Modifying Article Model
1. Update `Article` class in database models section (~line 145)
2. Update `/create_article` route to handle new fields
3. Update `/edit/article/<id>` route accordingly
4. Update GET endpoint and templates to display/edit new fields
5. Delete `kb.db` to force schema recreation on next run

### Adding Settings Page
1. Create `settings_XXX.html` template
2. Add route handler in `settings_page()` function's template_map
3. Add form POST handler if needed
4. Add to navigation in `settings_layout.html`

## Testing Note

No formal test framework is set up. Manual testing checklist from README:
1. Search with/without APIs enabled
2. Article CRUD operations
3. Group management and hierarchy
4. Settings persistence and form validation
5. Permission/role-based access control
6. Bulk operations (delete, tag, update)

## User Preferences

The project preferentially uses the `gemini-2.5-flash` Gemini model (via `google-generativeai` module) over the outdated `google` module for all AI-powered responses.
