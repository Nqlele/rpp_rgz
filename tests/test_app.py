import pytest
from app import app, db
from models import User, Article, Comment, LoginAttempt, IPRateLimit

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.drop_all()

@pytest.fixture
def auth_client(client):
    with app.app_context():
        user = User(username='testuser', email='test@example.com')
        user.set_password('testpass')
        db.session.add(user)
        db.session.commit()
    
    client.post('/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    return client

def test_register(client):
    response = client.post('/register', json={
        'username': 'newuser',
        'email': 'new@example.com',
        'password': 'newpass'
    })
    assert response.status_code == 201
    assert b'registered successfully' in response.data

def test_register_duplicate_username(client):
    client.post('/register', json={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'pass'
    })
    
    response = client.post('/register', json={
        'username': 'testuser',
        'email': 'another@example.com',
        'password': 'pass'
    })
    assert response.status_code == 400
    assert b'already exists' in response.data

def test_login_success(client):
    with app.app_context():
        user = User(username='testuser', email='test@example.com')
        user.set_password('testpass')
        db.session.add(user)
        db.session.commit()
    
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    assert response.status_code == 200
    assert b'Login successful' in response.data

def test_login_wrong_password(client):
    with app.app_context():
        user = User(username='testuser', email='test@example.com')
        user.set_password('testpass')
        db.session.add(user)
        db.session.commit()
    
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'wrongpass'
    })
    assert response.status_code == 401

def test_create_article(auth_client):
    response = auth_client.post('/articles', json={
        'title': 'Test Article',
        'content': 'Test content'
    })
    assert response.status_code == 201
    assert b'Article created' in response.data

def test_get_articles(client):
    with app.app_context():
        user = User(username='testuser', email='test@example.com')
        user.set_password('testpass')
        db.session.add(user)
        db.session.commit()
        
        article = Article(title='Test', content='Content', author_id=user.id)
        db.session.add(article)
        db.session.commit()
    
    response = client.get('/articles')
    assert response.status_code == 200

def test_get_article(client):
    with app.app_context():
        user = User(username='testuser', email='test@example.com')
        user.set_password('testpass')
        db.session.add(user)
        db.session.commit()
        
        article = Article(title='Test', content='Content', author_id=user.id)
        db.session.add(article)
        db.session.commit()
        article_id = article.id
    
    response = client.get(f'/articles/{article_id}')
    assert response.status_code == 200

def test_update_article(auth_client):
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        article = Article(title='Original', content='Original content', author_id=user.id)
        db.session.add(article)
        db.session.commit()
        article_id = article.id
    
    response = auth_client.put(f'/articles/{article_id}', json={
        'title': 'Updated',
        'content': 'Updated content'
    })
    assert response.status_code == 200
    assert b'updated' in response.data

def test_update_other_user_article(auth_client):
    with app.app_context():
        user2 = User(username='otheruser', email='other@example.com')
        user2.set_password('pass')
        db.session.add(user2)
        db.session.commit()
        
        article = Article(title='Other', content='Content', author_id=user2.id)
        db.session.add(article)
        db.session.commit()
        article_id = article.id
    
    response = auth_client.put(f'/articles/{article_id}', json={
        'title': 'Hacked'
    })
    assert response.status_code == 403

def test_delete_article(auth_client):
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        article = Article(title='To Delete', content='Content', author_id=user.id)
        db.session.add(article)
        db.session.commit()
        article_id = article.id
    
    response = auth_client.delete(f'/articles/{article_id}')
    assert response.status_code == 200

def test_create_comment(auth_client):
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        article = Article(title='Test', content='Content', author_id=user.id)
        db.session.add(article)
        db.session.commit()
        article_id = article.id
    
    response = auth_client.post('/comments', json={
        'article_id': article_id,
        'content': 'Great article!'
    })
    assert response.status_code == 201
    assert b'Comment added' in response.data

def test_rate_limit_user_block(client):
    with app.app_context():
        user = User(username='testuser', email='test@example.com')
        user.set_password('testpass')
        db.session.add(user)
        db.session.commit()
    
    for _ in range(5):
        client.post('/login', json={'username': 'testuser', 'password': 'wrong'})
    
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    assert response.status_code == 429
    assert b'too many failed login attempts' in response.data.lower() or b'too many attempts' in response.data.lower()

def test_logout(auth_client):
    response = auth_client.post('/logout')
    assert response.status_code == 200
