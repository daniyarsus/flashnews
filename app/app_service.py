from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
from flasgger import Swagger
from flask_limiter import Limiter
from flask_bcrypt import Bcrypt, check_password_hash

app = Flask(__name__)
swagger = Swagger(app)
limiter = Limiter(app)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'bebra228'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Вам необходимо войти, чтобы получить доступ к этой странице.'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user = db.relationship('User', backref='comments')


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref='posts')
    comments = db.relationship('Comment', backref='post', lazy='dynamic')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
@limiter.limit("3 per second")
def index():
    """
    Главная страница
    ---
    responses:
      200:
        description: Успех
      400:
        description: Ошибка
    """
    posts = Post.query.all()
    return render_template('index.html', title="Главная страница", posts=posts)


@app.route('/register', methods=['GET','POST'])
@limiter.limit("3 per second")
def register():
    """
    Регистрация
    ---
    parameters:
      - name: username
        in: formData
        type: string
        required: true
        description: Имя пользователя
      - name: email
        in: formData
        type: string
        required: true
        description: Электронная почта
      - name: password
        in: formData
        type: string
        required: true
        description: Пароль
    responses:
      200:
        description: Успех
      400:
        description: Ошибка
    """
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter((User.username == username) or (User.email == email)).first()

        if existing_user:
            flash('Пользователь с похожим именем пользователя или почтой уже существует. Пожалуйста, выберите другие учетные данные.', 'error')
        else:
            # Хешируйте пароль перед сохранением в базу данных
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            # Автоматически авторизовать пользователя после регистрации
            login_user(new_user)

            flash('Вы успешно зарегистрировались.', 'success')

    return render_template('register.html', title="Регистрация")


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("3 per second")
def login():
    """
    Вход
    ---
    parameters:
      - name: email
        in: formData
        type: string
        required: true
        description: Электронная почта
      - name: password
        in: formData
        type: string
        required: true
        description: Пароль
    responses:
      200:
        description: Успешная авторизация
      400:
        description: Неверная почта или пароль
    """
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            #flash('Вы авторизованы')
            return redirect(url_for('index'))
        else:
            flash('Неверная почта или пароль.')

    return render_template('login.html', title="Вход")


@app.route('/new_post', methods=['GET', 'POST'])
@limiter.limit("3 per second")
@login_required
def new_post():
    """
    Создать новый пост
    ---
    parameters:
      - name: title
        in: formData
        type: string
        required: true
        description: Заголовок поста
      - name: content
        in: formData
        type: string
        required: true
        description: Содержание поста
    responses:
      200:
        description: Пост успешно создан
      302:
        description: Редирект на главную страницу
    """
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        post = Post(title=title, content=content, user_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('new_post.html', title='Создать пост')


@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@limiter.limit("3 per second")
@login_required
def edit_post(post_id):
    """
    Редактировать пост
    ---
    parameters:
      - name: post_id
        in: path
        type: integer
        required: true
        description: Идентификатор поста
      - name: title
        in: formData
        type: string
        required: true
        description: Новый заголовок поста
      - name: content
        in: formData
        type: string
        required: true
        description: Новое содержание поста
    responses:
      200:
        description: Пост успешно отредактирован
      302:
        description: Редирект на главную страницу
    """
    post = Post.query.get(post_id)

    if not post:
        flash('Пост не найден.', 'error')
        return redirect(url_for('index'))

    if post.user_id != current_user.id:
        flash('Вы не можете редактировать чужой пост.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        post.title = request.form['title']  # Update title
        post.content = request.form['content']  # Update content
        db.session.commit()
        flash('Пост успешно отредактирован.', 'success')
        return redirect(url_for('index'))

    return render_template('edit_post.html', title='Редактирование поста', post=post)


@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
@limiter.limit("3 per second")
def view_post(post_id):
    """
    Просмотр поста и добавление комментария
    ---
    parameters:
      - name: post_id
        in: path
        type: integer
        required: true
        description: Идентификатор поста
      - name: comment_text
        in: formData
        type: string
        description: Текст комментария
    responses:
      200:
        description: Успешное отображение поста
      302:
        description: Редирект на главную страницу
    """
    post = Post.query.get(post_id)
    if not post:
        flash('Пост не найден.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        if current_user.is_authenticated:
            comment_text = request.form['comment_text']
            new_comment = Comment(text=comment_text, user_id=current_user.id, post_id=post.id)  # Set the post_id
            db.session.add(new_comment)
            db.session.commit()
            flash('Комментарий добавлен.', 'success')

    comments = Comment.query.filter_by(post_id=post.id).all()
    users = User.query.all()  # Retrieve all users

    return render_template('view_post.html', title=f'{post.title}', post=post, comments=comments, users=users)


@app.route('/edit_username', methods=['GET', 'POST'])
@limiter.limit("3 per second")
@login_required
def edit_username():
    """
    Изменить имя пользователя
    ---
    parameters:
      - name: new_username
        in: formData
        type: string
        required: true
        description: Новое имя пользователя
      - name: password_confirmation
        in: formData
        type: string
        required: true
        description: Подтверждение пароля
    responses:
      200:
        description: Имя пользователя успешно изменено
      302:
        description: Редирект на профиль пользователя
      400:
        description: Ошибка при изменении имени пользователя
    """
    if request.method == 'POST':
        new_username = request.form['new_username']
        password_confirmation = request.form['password_confirmation']

        # Проверка, совпадает ли пароль с текущим пользовательским паролем
        if check_password_hash(current_user.password, password_confirmation):
            # Обновите имя пользователя
            current_user.username = new_username
            db.session.commit()
            flash('Имя пользователя успешно изменено.', 'success')
            return redirect(url_for('my_profile'))
        else:
            flash('Пароль неверен. Изменение имени пользователя не выполнено.', 'error')

    return render_template('edit_username.html', title='Изменить имя пользователя')


@app.route('/edit_email', methods=['GET', 'POST'])
@limiter.limit("3 per second")
@login_required
def edit_email():
    """
    Изменить адрес электронной почты
    ---
    parameters:
      - name: new_email
        in: formData
        type: string
        required: true
        description: Новый адрес электронной почты
      - name: password_confirmation
        in: formData
        type: string
        required: true
        description: Подтверждение пароля
    responses:
      200:
        description: Адрес электронной почты успешно изменен
      302:
        description: Редирект на профиль пользователя
      400:
        description: Ошибка при изменении адреса электронной почты
    """
    if request.method == 'POST':
        # Обработка изменения адреса электронной почты
        new_email = request.form['new_email']
        password_confirmation = request.form['password_confirmation']

        # Проверка, совпадает ли пароль с текущим пользовательским паролем
        if check_password_hash(current_user.password, password_confirmation):
            # Обновите адрес электронной почты в базе данных
            current_user.email = new_email
            db.session.commit()
            flash('Адрес электронной почты успешно изменен.', 'success')
            return redirect(url_for('my_profile'))
        else:
            flash('Пароль неверен. Изменение адреса электронной почты не выполнено.', 'error')

    return render_template('edit_email.html', title='Изменить адрес электронной почты')


@app.route('/edit_password', methods=['GET', 'POST'])
@limiter.limit("3 per second")
@login_required
def edit_password():
    """
    Изменить пароль
    ---
    parameters:
      - name: old_password
        in: formData
        type: string
        required: true
        description: Старый пароль
      - name: new_password
        in: formData
        type: string
        required: true
        description: Новый пароль
    responses:
      200:
        description: Пароль успешно изменен
      302:
        description: Редирект на профиль пользователя
      400:
        description: Ошибка при изменении пароля
    """
    if request.method == 'POST':
        # Обработка изменения пароля
        old_password = request.form['old_password']
        new_password = request.form['new_password']

        if check_password_hash(current_user.password, old_password):
            # Хешируйте новый пароль и обновите его в базе данных
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            current_user.password = hashed_password
            db.session.commit()
            flash('Пароль успешно изменен.', 'success')
            return redirect(url_for('my_profile'))
        else:
            flash('Старый пароль неверен.', 'error')

    return render_template('edit_password.html', title='Изменить пароль')


@app.route('/delete_post/<int:post_id>', methods=['POST'])
@limiter.limit("3 per second")
@login_required
def delete_post(post_id):
    """
    Удалить пост
    ---
    parameters:
      - name: post_id
        in: path
        type: integer
        required: true
        description: Идентификатор поста для удаления
    responses:
      302:
        description: Пост успешно удален
      400:
        description: Ошибка при удалении поста
    """
    post = Post.query.get(post_id)

    if not post:
        flash('Пост не найден.', 'error')
    elif post.user_id != current_user.id:
        flash('Вы не можете удалять чужие посты.', 'error')
    else:
        # Delete associated comments first
        Comment.query.filter_by(post_id=post.id).delete()
        db.session.delete(post)
        db.session.commit()
        flash('Пост успешно удален.', 'success')

    return redirect(url_for('index'))


@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@limiter.limit("3 per second")
@login_required
def delete_comment(comment_id):
    """
    Удалить комментарий
    ---
    parameters:
      - name: comment_id
        in: path
        type: integer
        required: true
        description: Идентификатор комментария для удаления
    responses:
      302:
        description: Комментарий успешно удален
      400:
        description: Ошибка при удалении комментария
    """
    comment = Comment.query.get(comment_id)

    if not comment:
        flash('Комментарий не найден.', 'error')
    elif comment.user_id != current_user.id:
        flash('Вы не можете удалять чужие комментарии.', 'error')
    else:
        post_id = comment.post_id  # Получаем post_id
        db.session.delete(comment)
        db.session.commit()
        flash('Комментарий успешно удален.', 'success')

    return redirect(url_for('view_post', post_id=post_id))


@app.route('/edit_comment/<int:comment_id>', methods=['GET', 'POST'])
@limiter.limit("3 per second")
@login_required
def edit_comment(comment_id):
    """
    Редактировать комментарий
    ---
    parameters:
      - name: comment_id
        in: path
        type: integer
        required: true
        description: Идентификатор комментария для редактирования
      - name: edited_comment_text
        in: formData
        type: string
        required: true
        description: Отредактированный текст комментария
    responses:
      302:
        description: Комментарий успешно отредактирован
      400:
        description: Ошибка при редактировании комментария
    """
    comment = Comment.query.get(comment_id)

    if not comment:
        flash('Комментарий не найден.', 'error')
    elif comment.user_id != current_user.id:
        flash('Вы не можете редактировать чужой комментарий.', 'error')
    else:
        edited_comment_text = request.form['edited_comment_text']
        comment.text = edited_comment_text
        db.session.commit()
        flash('Комментарий успешно отредактирован.', 'success')

    return redirect(url_for('view_post', post_id=comment.post.id))


@app.route('/my_profile', methods=['GET'])
@limiter.limit("3 per second")
@login_required
def my_profile():
    """
    Просмотр профиля пользователя
    ---
    responses:
      200:
        description: Успешный просмотр профиля
      302:
        description: Редирект на профиль пользователя
    """
    user_posts = Post.query.filter_by(user_id=current_user.id).all()
    return render_template('my_profile.html', title='Мой профиль', user=current_user, user_posts=user_posts)


@app.route('/logout')
@limiter.limit("3 per second")
@login_required
def logout():
    """
    Выход из системы
    ---
    responses:
      302:
        description: Выход из системы успешно выполнен
    """
    logout_user()
    return redirect('/')