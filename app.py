from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
from functools import wraps

from config import Config
from models import db, User, Article, Comment, LoginAttempt, IPRateLimit

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def check_rate_limit(username, ip_address):
    blocked_info = {}
    
    user_attempts = LoginAttempt.query.filter(
        LoginAttempt.username == username,
        LoginAttempt.timestamp > datetime.utcnow() - timedelta(seconds=Config.LOGIN_ATTEMPTS_TIMEOUT)
    ).order_by(LoginAttempt.timestamp.desc()).limit(Config.LOGIN_ATTEMPTS_LIMIT + 5).all()
    
    failed_user_attempts = [a for a in user_attempts if not a.successful]
    if len(failed_user_attempts) >= Config.LOGIN_ATTEMPTS_LIMIT:
        last_attempt = failed_user_attempts[0]
        retry_after = Config.LOGIN_ATTEMPTS_TIMEOUT - (datetime.utcnow() - last_attempt.timestamp).seconds
        blocked_info['user_blocked'] = True
        blocked_info['user_retry_after'] = max(retry_after, 0)
    
    ip_limit = IPRateLimit.query.filter_by(ip_address=ip_address).first()
    if ip_limit and ip_limit.blocked_until and ip_limit.blocked_until > datetime.utcnow():
        retry_after = (ip_limit.blocked_until - datetime.utcnow()).seconds
        blocked_info['ip_blocked'] = True
        blocked_info['ip_retry_after'] = max(retry_after, 0)
    
    if ip_limit and ip_limit.failed_attempts >= Config.IP_ATTEMPTS_LIMIT:
        if not ip_limit.blocked_until or ip_limit.blocked_until < datetime.utcnow():
            ip_limit.blocked_until = datetime.utcnow() + timedelta(seconds=Config.IP_ATTEMPTS_TIMEOUT)
    
    return blocked_info

def record_failed_attempt(username, ip_address):
    attempt = LoginAttempt(username=username, ip_address=ip_address, successful=False)
    db.session.add(attempt)
    
    ip_limit = IPRateLimit.query.filter_by(ip_address=ip_address).first()
    if not ip_limit:
        ip_limit = IPRateLimit(ip_address=ip_address, failed_attempts=1)
        db.session.add(ip_limit)
    else:
        ip_limit.failed_attempts += 1
    
    db.session.commit()

def record_successful_attempt(username, ip_address):
    attempt = LoginAttempt(username=username, ip_address=ip_address, successful=True)
    db.session.add(attempt)
    
    ip_limit = IPRateLimit.query.filter_by(ip_address=ip_address).first()
    if ip_limit:
        ip_limit.failed_attempts = 0
        ip_limit.blocked_until = None
    
    db.session.commit()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    user = User(username=data['username'], email=data['email'])
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully', 'user_id': user.id}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    ip_address = request.remote_addr
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400
    
    username = data['username']
    
    blocked_info = check_rate_limit(username, ip_address)
    if blocked_info.get('ip_blocked'):
        return jsonify({
            'error': 'Too many attempts from this IP',
            'retry_after': blocked_info['ip_retry_after']
        }), 429
    
    if blocked_info.get('user_blocked'):
        return jsonify({
            'error': 'Too many failed login attempts',
            'retry_after': blocked_info['user_retry_after']
        }), 429
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(data['password']):
        record_failed_attempt(username, ip_address)
        return jsonify({'error': 'Invalid username or password'}), 401
    
    record_successful_attempt(username, ip_address)
    login_user(user)
    
    return jsonify({'message': 'Login successful'}), 200

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/articles', methods=['POST'])
@login_required
def create_article():
    data = request.get_json()
    
    if not data or not data.get('title') or not data.get('content'):
        return jsonify({'error': 'Missing title or content'}), 400
    
    article = Article(
        title=data['title'],
        content=data['content'],
        author_id=current_user.id
    )
    
    db.session.add(article)
    db.session.commit()
    
    return jsonify({
        'message': 'Article created',
        'article': {
            'id': article.id,
            'title': article.title,
            'content': article.content,
            'author_id': article.author_id,
            'created_at': article.created_at.isoformat()
        }
    }), 201

@app.route('/articles', methods=['GET'])
def get_articles():
    articles = Article.query.order_by(Article.created_at.desc()).all()
    
    return jsonify([{
        'id': a.id,
        'title': a.title,
        'content': a.content,
        'author_id': a.author_id,
        'author_username': a.author.username,
        'created_at': a.created_at.isoformat()
    } for a in articles]), 200

@app.route('/articles/<int:article_id>', methods=['GET'])
def get_article(article_id):
    article = Article.query.get(article_id)
    
    if not article:
        return jsonify({'error': 'Article not found'}), 404
    
    return jsonify({
        'id': article.id,
        'title': article.title,
        'content': article.content,
        'author_id': article.author_id,
        'author_username': article.author.username,
        'created_at': article.created_at.isoformat(),
        'updated_at': article.updated_at.isoformat()
    }), 200

@app.route('/articles/<int:article_id>', methods=['PUT'])
@login_required
def update_article(article_id):
    article = Article.query.get(article_id)
    
    if not article:
        return jsonify({'error': 'Article not found'}), 404
    
    if article.author_id != current_user.id:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    
    if data.get('title'):
        article.title = data['title']
    if data.get('content'):
        article.content = data['content']
    
    article.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'message': 'Article updated',
        'article': {
            'id': article.id,
            'title': article.title,
            'content': article.content,
            'updated_at': article.updated_at.isoformat()
        }
    }), 200

@app.route('/articles/<int:article_id>', methods=['DELETE'])
@login_required
def delete_article(article_id):
    article = Article.query.get(article_id)
    
    if not article:
        return jsonify({'error': 'Article not found'}), 404
    
    if article.author_id != current_user.id:
        return jsonify({'error': 'Permission denied'}), 403
    
    db.session.delete(article)
    db.session.commit()
    
    return jsonify({'message': 'Article deleted'}), 200

@app.route('/comments', methods=['GET', 'POST'])
@login_required
def create_comment():
    if request.method == 'GET':
        article_id = request.args.get('article_id')
        if not article_id:
            return jsonify({'error': 'Missing article_id'}), 400
        
        comments = Comment.query.filter_by(article_id=article_id).order_by(Comment.created_at.desc()).all()
        return jsonify([{
            'id': c.id,
            'content': c.content,
            'author_id': c.author_id,
            'author_username': c.author.username,
            'created_at': c.created_at.isoformat()
        } for c in comments]), 200
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()
    
    if not data or not data.get('article_id') or not data.get('content'):
        return jsonify({'error': 'Missing article_id or content'}), 400
    
    article = db.session.get(Article, data['article_id'])
    if not article:
        return jsonify({'error': 'Article not found'}), 404
    
    comment = Comment(
        content=data['content'],
        article_id=data['article_id'],
        author_id=current_user.id
    )
    
    db.session.add(comment)
    db.session.commit()
    
    return jsonify({
        'message': 'Comment added',
        'comment': {
            'id': comment.id,
            'content': comment.content,
            'article_id': comment.article_id,
            'author_id': comment.author_id,
            'created_at': comment.created_at.isoformat()
        }
    }), 201

@app.route('/articles/<int:article_id>/comments', methods=['GET'])
def get_comments(article_id):
    article = Article.query.get(article_id)
    
    if not article:
        return jsonify({'error': 'Article not found'}), 404
    
    comments = Comment.query.filter_by(article_id=article_id).order_by(Comment.created_at.desc()).all()
    
    return jsonify([{
        'id': c.id,
        'content': c.content,
        'author_id': c.author_id,
        'author_username': c.author.username,
        'created_at': c.created_at.isoformat()
    } for c in comments]), 200

@app.route('/register/', methods=['GET', 'POST'])
def register_page():
    if current_user.is_authenticated:
        return redirect(url_for('get_articles_page'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        ip_address = request.remote_addr
        
        blocked_info = check_rate_limit('', ip_address)
        if blocked_info.get('ip_blocked'):
            print(f"[BLOCKED] IP '{ip_address}' blocked for {blocked_info['ip_retry_after']} seconds")
            return render_template('register.html', error=f'Слишком много попыток с вашего IP. Попробуйте через {blocked_info["ip_retry_after"]} секунд.')
        
        if not username or not email or not password:
            return render_template('register.html', error='Заполните все поля')
        
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Пользователь с таким именем уже существует')
        
        if User.query.filter_by(email=email).first():
            return render_template('register.html', error='Email уже используется')
        
        user = User(username=username, email=email, ip_address=ip_address)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        print(f"[REGISTER] User '{username}' registered from IP '{ip_address}'")
        flash('Регистрация успешна! Войдите в систему.')
        return redirect(url_for('login_page'))
    
    return render_template('register.html')

@app.route('/login/', methods=['GET', 'POST'])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('get_articles_page'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr
        
        if not username or not password:
            return render_template('login.html', error='Заполните все поля')
        
        blocked_info = check_rate_limit(username, ip_address)
        if blocked_info.get('ip_blocked'):
            print(f"[BLOCKED] IP '{ip_address}' blocked for {blocked_info['ip_retry_after']} seconds")
            return render_template('login.html', error=f'Слишком много попыток с вашего IP. Попробуйте через {blocked_info["ip_retry_after"]} секунд.')
        
        if blocked_info.get('user_blocked'):
            print(f"[BLOCKED] User '{username}' blocked for {blocked_info['user_retry_after']} seconds")
            return render_template('login.html', error=f'Слишком много попыток. Попробуйте через {blocked_info["user_retry_after"]} секунд.', retry_after=blocked_info['user_retry_after'])
        
        user = User.query.filter_by(username=username).first()
        
        if user.ip_address:
            saved_ip_record = IPRateLimit.query.filter_by(ip_address=user.ip_address).first()
            if saved_ip_record and saved_ip_record.blocked_until and saved_ip_record.blocked_until > datetime.utcnow():
                retry_after = (saved_ip_record.blocked_until - datetime.utcnow()).seconds
                print(f"[BLOCKED] User '{username}' has blocked IP '{user.ip_address}', blocked for {retry_after} seconds")
                return render_template('login.html', error=f'Ваш IP заблокирован. Попробуйте через {retry_after} секунд.')
        
        if not user or not user.check_password(password):
            record_failed_attempt(username, ip_address)
            print(f"[LOGIN FAILED] User '{username}' from IP '{ip_address}' - invalid credentials")
            return render_template('login.html', error='Неверное имя пользователя или пароль')
        
        user.ip_address = ip_address
        db.session.commit()
        
        record_successful_attempt(username, ip_address)
        login_user(user)
        print(f"[LOGIN SUCCESS] User '{username}' logged in from IP '{ip_address}'")
        
        return redirect(url_for('get_articles_page'))
    
    return render_template('login.html')

@app.route('/logout/')
@login_required
def logout_page():
    print(f"[LOGOUT] User '{current_user.username}' logged out")
    logout_user()
    flash('Вы вышли из системы.')
    return redirect(url_for('login_page'))

@app.route('/articles/create/', methods=['GET', 'POST'])
@login_required
def create_article_page():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        
        if not title or not content:
            return render_template('article_form.html', error='Заполните все поля')
        
        article = Article(title=title, content=content, author_id=current_user.id)
        
        db.session.add(article)
        db.session.commit()
        
        print(f"[ARTICLE CREATED] User '{current_user.username}' created article '{title}' (ID: {article.id})")
        flash('Статья создана!')
        return redirect(url_for('get_article_page', article_id=article.id))
    
    return render_template('article_form.html')

@app.route('/articles/')
def get_articles_page():
    articles = Article.query.order_by(Article.created_at.desc()).all()
    articles_data = [{
        'id': a.id,
        'title': a.title,
        'content': a.content,
        'author_id': a.author_id,
        'author_username': a.author.username,
        'created_at': a.created_at
    } for a in articles]
    
    return render_template('articles.html', articles=articles_data)

@app.route('/articles/<int:article_id>/', methods=['GET', 'POST'])
def get_article_page(article_id):
    article = db.session.get(Article, article_id)
    
    if not article:
        return render_template('article.html', error='Статья не найдена'), 404
    
    if request.method == 'POST' and current_user.is_authenticated:
        content = request.form.get('content')
        
        if content:
            comment = Comment(content=content, article_id=article_id, author_id=current_user.id)
            db.session.add(comment)
            db.session.commit()
            print(f"[COMMENT ADDED] User '{current_user.username}' commented on article ID {article_id}")
            flash('Комментарий добавлен!')
            return redirect(url_for('get_article_page', article_id=article_id))
    
    comments = Comment.query.filter_by(article_id=article_id).order_by(Comment.created_at.desc()).all()
    comments_data = [{
        'id': c.id,
        'content': c.content,
        'author_id': c.author_id,
        'author_username': c.author.username,
        'created_at': c.created_at
    } for c in comments]
    
    return render_template('article.html', article=article, comments=comments_data)

@app.route('/articles/<int:article_id>/edit/', methods=['GET', 'POST'])
@login_required
def update_article_page(article_id):
    article = db.session.get(Article, article_id)
    
    if not article:
        return render_template('article_form.html', error='Статья не найдена'), 404
    
    if article.author_id != current_user.id:
        return redirect(url_for('get_article_page', article_id=article_id))
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        
        if not title or not content:
            return render_template('article_form.html', article=article, error='Заполните все поля')
        
        article.title = title
        article.content = content
        article.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        print(f"[ARTICLE UPDATED] User '{current_user.username}' updated article ID {article_id}")
        flash('Статья обновлена!')
        return redirect(url_for('get_article_page', article_id=article_id))
    
    return render_template('article_form.html', article=article)

@app.route('/articles/<int:article_id>/delete/', methods=['POST'])
@login_required
def delete_article_page(article_id):
    article = db.session.get(Article, article_id)
    
    if not article:
        return redirect(url_for('get_articles_page'))
    
    if article.author_id != current_user.id:
        return redirect(url_for('get_article_page', article_id=article_id))
    
    db.session.delete(article)
    db.session.commit()
    
    print(f"[ARTICLE DELETED] User '{current_user.username}' deleted article ID {article_id}")
    flash('Статья удалена.')
    return redirect(url_for('get_articles_page'))

@app.route('/')
def index():
    return redirect(url_for('get_articles_page'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
