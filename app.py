from flask import Flask, render_template, request, redirect, url_for, flash, session, g
import sqlite3, os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from datetime import datetime
from functools import wraps


app = Flask(__name__)
app.secret_key = 'your_super_secret_key_change_this'
DATABASE = 'database.db'

# ---------------- Database ----------------
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        conn = get_db_connection()
        g.user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        if g.user is None:
            session.clear()

@app.context_processor
def inject_user():
    return dict(user=getattr(g, 'user', None))

# ---------------- Google OAuth ----------------
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Allow HTTP for dev
google_bp = make_google_blueprint(
    client_id="44670871253-rro5dfqqb5l4gqmva91tdii25mtt1qgg.apps.googleusercontent.com",
    client_secret="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",
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_to="google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")

@app.route("/google_login")
def google_login():
    # If user is not authorized with Google, send them to login
    if not google.authorized:
        return redirect(url_for("google.login"))

    # Get user info from Google
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Google login failed.", "danger")
        return redirect(url_for("login"))

    info = resp.json()
    email = info["email"]
    full_name = info.get("name", "")
    username = email.split("@")[0]  # fallback if no name

    # Check if user already exists in DB
    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()

    if not user:
        # Create new account with Google user info
        conn.execute(
            "INSERT INTO users (username, email, password_hash, full_name) VALUES (?, ?, ?, ?)",
            (
                username,
                email,
                generate_password_hash(os.urandom(12).hex()),  # random dummy password
                full_name,
            ),
        )
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    conn.close()

    # Log the user in
    session.clear()
    session["user_id"] = user["id"]

    flash("Logged in with Google successfully!", "success")
    return redirect(url_for("dashboard"))


# ---------------- Mail Setup ----------------
app.config.update(
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME="your_email@gmail.com",   # change this
    MAIL_PASSWORD="your_app_password",      # use app password, not Gmail password
    MAIL_DEFAULT_SENDER="your_email@gmail.com"
)
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

# ---------------- Forgot Password ----------------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()
        if not user:
            flash("No account found with that email.", "danger")
            return redirect(url_for('forgot_password'))

        token = s.dumps(email, salt='password-reset-salt')
        reset_url = url_for('reset_password', token=token, _external=True)

        msg = Message("Password Reset Request", recipients=[email])
        msg.body = f"Click the link to reset your password: {reset_url}\n\nIf you did not request this, ignore."
        mail.send(msg)

        flash("Password reset link sent to your email!", "info")
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # 1 hour
    except (SignatureExpired, BadSignature):
        flash("Reset link is invalid or expired.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        hashed = generate_password_hash(password)
        conn = get_db_connection()
        conn.execute("UPDATE users SET password_hash = ? WHERE email = ?", (hashed, email))
        conn.commit()
        conn.close()
        flash("Password reset successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/')
def index():
    conn = get_db_connection()
    all_quizzes = conn.execute('SELECT * FROM quizzes ORDER BY id').fetchall()
    conn.close()
    return render_template('index.html', quizzes=all_quizzes)

# --- Other static routes ---
@app.route('/about')
def about(): return render_template('about.html')
@app.route('/for_whom')
def for_whom(): return render_template('for_whom.html')
@app.route('/contact')
def contact(): return render_template('contact.html')
@app.route('/book-trainer')
def book_trainer(): return render_template('book_trainer.html')
@app.route('/change_password')
def change_password(): return "Change Password Page" 

@app.route('/quizzes')
def quizzes():
    if not g.user:
        flash('You must be logged in to view the quizzes.', 'warning')
        return redirect(url_for('login'))
    conn = get_db_connection()
    all_quizzes = conn.execute('SELECT * FROM quizzes ORDER BY name').fetchall()
    conn.close()
    return render_template('quizzes.html', quizzes=all_quizzes)

@app.route('/dashboard')
def dashboard():
    if not g.user: return redirect(url_for('login'))
    conn = get_db_connection()
    total_quizzes_count = conn.execute('SELECT COUNT(id) FROM quizzes').fetchone()[0]
    user_results = conn.execute('SELECT * FROM quiz_results WHERE user_id = ?', (g.user['id'],)).fetchall()
    recent_results = conn.execute('''SELECT q.name, r.id, r.score, r.total_questions, r.timestamp FROM quiz_results r JOIN quizzes q ON r.quiz_id = q.id WHERE r.user_id = ? ORDER BY r.timestamp DESC LIMIT 5''', (g.user['id'],)).fetchall()
    conn.close()
    completed_quiz_ids = {result['quiz_id'] for result in user_results}
    completed_quizzes_count = len(completed_quiz_ids)
    not_attempted_count = total_quizzes_count - completed_quizzes_count
    overall_progress_percentage = (completed_quizzes_count / total_quizzes_count) * 100 if total_quizzes_count > 0 else 0
    if user_results:
        total_score_percentage = sum((res['score'] / res['total_questions']) * 100 for res in user_results if res['total_questions'] > 0)
        valid_results_count = sum(1 for res in user_results if res['total_questions'] > 0)
        average_score_percentage = total_score_percentage / valid_results_count if valid_results_count > 0 else 0
    else:
        average_score_percentage = 0
    return render_template('dashboard.html', results=recent_results, completed_quizzes_count=completed_quizzes_count, in_progress_count=0, not_attempted_count=not_attempted_count, total_quizzes_count=total_quizzes_count, overall_progress_percentage=overall_progress_percentage, average_score_percentage=average_score_percentage)

@app.route('/quiz/<slug>/start')
def start_quiz(slug):
    if not g.user: return redirect(url_for('login'))
    if 'quiz_progress' in session:
        session['quiz_progress'].pop(slug, None)
        session.modified = True
    return redirect(url_for('run_quiz', slug=slug, q_num=1))

@app.route('/quiz/<slug>/<int:q_num>')
def run_quiz(slug, q_num):
    if not g.user: return redirect(url_for('login'))
    conn = get_db_connection()
    quiz = conn.execute('SELECT * FROM quizzes WHERE slug = ?', (slug,)).fetchone()
    if not quiz: return redirect(url_for('quizzes'))
    questions = conn.execute('SELECT id FROM questions WHERE quiz_id = ? ORDER BY id', (quiz['id'],)).fetchall()
    total_questions = len(questions)
    if not (1 <= q_num <= total_questions): return redirect(url_for('quizzes'))
    question_data = conn.execute('SELECT * FROM questions WHERE id = ?', (questions[q_num - 1]['id'],)).fetchone()
    answers = conn.execute('SELECT * FROM answers WHERE question_id = ? ORDER BY id', (questions[q_num - 1]['id'],)).fetchall()
    conn.close()
    return render_template('quiz-page.html', quiz=quiz, question=question_data, answers=answers, current_q_num=q_num, total_questions=total_questions)

@app.route('/quiz/<slug>/submit', methods=['POST'])
def submit_answer(slug):
    if not g.user: return redirect(url_for('login'))
    question_id, answer_id = request.form.get('question_id'), request.form.get('answer')
    current_q_num, total_questions = int(request.form.get('current_q_num')), int(request.form.get('total_questions'))
    is_bookmarked = 1 if 'bookmark' in request.form else 0
    progress = session.setdefault('quiz_progress', {}).setdefault(slug, {})
    progress[question_id] = {'answer_id': answer_id, 'is_bookmarked': is_bookmarked}
    session.modified = True
    if current_q_num < total_questions:
        return redirect(url_for('run_quiz', slug=slug, q_num=current_q_num + 1))
    return redirect(url_for('score_quiz', slug=slug))

@app.route('/quiz/<slug>/score')
def score_quiz(slug):
    if not g.user: return redirect(url_for('login'))
    user_progress = session.get('quiz_progress', {}).get(slug, {})
    if not user_progress: return redirect(url_for('quizzes'))
    conn = get_db_connection()
    quiz = conn.execute('SELECT * FROM quizzes WHERE slug = ?', (slug,)).fetchone()
    correct_answers_cursor = conn.execute('SELECT q.id, a.id as correct_answer_id FROM questions q JOIN answers a ON q.id = a.question_id WHERE q.quiz_id = ? AND a.is_correct = 1', (quiz['id'],))
    correct_answers = {str(r['id']): str(r['correct_answer_id']) for r in correct_answers_cursor}
    score = sum(1 for q_id, data in user_progress.items() if data.get('answer_id') == correct_answers.get(q_id))
    cursor = conn.cursor()
    cursor.execute('INSERT INTO quiz_results (user_id, quiz_id, score, total_questions) VALUES (?, ?, ?, ?)', (g.user['id'], quiz['id'], score, len(correct_answers)))
    new_result_id = cursor.lastrowid
    for q_id, data in user_progress.items():
        conn.execute('INSERT INTO user_answers (result_id, question_id, selected_answer_id, is_bookmarked) VALUES (?, ?, ?, ?)', (new_result_id, int(q_id), int(data.get('answer_id')) if data.get('answer_id') else None, data.get('is_bookmarked', 0)))
    conn.commit()
    conn.close()
    session.get('quiz_progress', {}).pop(slug, None)
    session.modified = True
    flash(f"You completed the '{quiz['name']}' quiz! Your score is {score}/{len(correct_answers)}.", 'success')
    return redirect(url_for('dashboard'))

@app.route('/results/<int:result_id>/review')
def review_quiz_result(result_id):
    if not g.user: return redirect(url_for('login'))
    conn = get_db_connection()
    result = conn.execute('SELECT * FROM quiz_results WHERE id = ? AND user_id = ?', (result_id, g.user['id'])).fetchone()
    if not result:
        flash('Result not found or you do not have permission to view it.', 'danger')
        return redirect(url_for('dashboard'))
    quiz = conn.execute('SELECT * FROM quizzes WHERE id = ?', (result['quiz_id'],)).fetchone()
    questions = conn.execute('SELECT * FROM questions WHERE quiz_id = ? ORDER BY id', (quiz['id'],)).fetchall()
    review_data, bookmarked_count = [], 0
    for question in questions:
        answers = conn.execute('SELECT * FROM answers WHERE question_id = ? ORDER BY id', (question['id'],)).fetchall()
        user_answer = conn.execute('SELECT selected_answer_id, is_bookmarked FROM user_answers WHERE result_id = ? AND question_id = ?', (result_id, question['id'])).fetchone()
        correct_answer = conn.execute('SELECT id FROM answers WHERE question_id = ? AND is_correct = 1', (question['id'],)).fetchone()
        is_bookmarked = user_answer['is_bookmarked'] == 1 if user_answer else False
        if is_bookmarked: bookmarked_count += 1
        review_data.append({'question': question, 'answers': answers, 'user_answer_id': user_answer['selected_answer_id'] if user_answer else None, 'correct_answer_id': correct_answer['id'] if correct_answer else None, 'is_bookmarked': is_bookmarked})
    conn.close()
    score_percent = (result['score'] / result['total_questions']) * 100 if result['total_questions'] > 0 else 0
    return render_template('review_questions.html', quiz=quiz, result=result, review_data=review_data, score_percent=score_percent, correct_count=result['score'], incorrect_count=result['total_questions'] - result['score'], bookmarked_count=bookmarked_count)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user: # If already logged in, redirect based on admin status
        if g.user.get('role') == 'admin': # Assuming 'role' is a column in g.user
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email, password = request.form['email'], request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            flash('You have been successfully logged in!', 'success')
            # --- MODIFIED REDIRECTION ---
            if user['role'] == 'admin': 
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if g.user: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username, email, password = request.form['username'], request.form['email'], request.form['password']
        conn = get_db_connection()
        if conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone():
            flash('An account with this email already exists. Please log in.', 'warning')
            conn.close()
            return redirect(url_for('login'))
        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', (username, email, hashed_password))
        conn.commit()
        new_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        session.clear()
        session['user_id'] = new_user['id']
        flash(f'Welcome, {new_user["username"]}! Your account has been created.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    if not g.user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        country = request.form.get('country')
        organization = request.form.get('organization')
        job_title = request.form.get('job_title')

        conn = get_db_connection()
        conn.execute(
            'UPDATE users SET full_name = ?, country = ?, organization = ?, job_title = ? WHERE id = ?',
            (full_name, country, organization, job_title, g.user['id'])
        )
        conn.commit()
        conn.close()

        flash('Your profile has been updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('update_profile.html', user_data=g.user)
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user or g.user['role'] != 'admin':
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Admin Dashboard
@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    
    # Get statistics
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    total_quizzes = conn.execute('SELECT COUNT(*) FROM quizzes').fetchone()[0]
    total_attempts = conn.execute('SELECT COUNT(*) FROM quiz_results').fetchone()[0]
    # total_bookings = conn.execute('SELECT COUNT(*) FROM bookings').fetchone()[0]
    # pending_bookings = conn.execute('SELECT COUNT(*) FROM bookings WHERE status = "Pending"').fetchone()[0]
    
    # Recent activity
    recent_attempts = conn.execute('''
        SELECT u.username, q.name, r.score, r.total_questions, r.timestamp 
        FROM quiz_results r 
        JOIN users u ON r.user_id = u.id 
        JOIN quizzes q ON r.quiz_id = q.id 
        ORDER BY r.timestamp DESC 
        LIMIT 5
    ''').fetchall()
    
    # Performance by topic
    topic_performance = conn.execute('''
        SELECT q.name, 
               COUNT(r.id) as attempt_count,
               AVG(r.score * 100.0 / r.total_questions) as avg_score
        FROM quiz_results r
        JOIN quizzes q ON r.quiz_id = q.id
        GROUP BY q.id
        ORDER BY attempt_count DESC
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin/dashboard.html', 
                         total_users=total_users,
                         total_quizzes=total_quizzes,
                         total_attempts=total_attempts,
                        #  total_bookings=total_bookings,
                        #  pending_bookings=pending_bookings,
                         recent_attempts=recent_attempts,
                         topic_performance=topic_performance,
                         now=datetime.now())

# Admin Users Management
@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users ORDER BY id').fetchall()
    conn.close()
    
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    if user_id == g.user['id']:
        flash('You cannot delete your own account.', 'warning')
        return redirect(url_for('admin_users'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@admin_required
def admin_toggle_admin(user_id):
    if user_id == g.user['id']:
        flash('You cannot change your own admin status.', 'warning')
        return redirect(url_for('admin_users'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    new_status = 0 if user['is_admin'] else 1
    conn.execute('UPDATE users SET is_admin = ? WHERE id = ?', (new_status, user_id))
    conn.commit()
    conn.close()
    
    status = "granted" if new_status else "revoked"
    flash(f'Admin privileges {status} successfully.', 'success')
    return redirect(url_for('admin_users'))

# Admin Quizzes Management
@app.route('/admin/quizzes')
@admin_required
def admin_quizzes():
    conn = get_db_connection()
    quizzes = conn.execute('SELECT * FROM quizzes ORDER BY id').fetchall()
    conn.close()
    
    return render_template('admin/quizzes.html', quizzes=quizzes)

@app.route('/admin/quiz/add', methods=['GET', 'POST'])
@admin_required
def admin_add_quiz():
    if request.method == 'POST':
        name = request.form['name']
        slug = request.form['slug']
        description = request.form['description']
        
        conn = get_db_connection()
        conn.execute('INSERT INTO quizzes (name, slug, description) VALUES (?, ?, ?)', 
                    (name, slug, description))
        conn.commit()
        conn.close()
        
        flash('Quiz added successfully.', 'success')
        return redirect(url_for('admin_quizzes'))
    
    return render_template('admin/add_quiz.html')

@app.route('/admin/quiz/<int:quiz_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_quiz(quiz_id):
    conn = get_db_connection()
    
    if request.method == 'POST':
        name = request.form['name']
        slug = request.form['slug']
        description = request.form['description']
        
        conn.execute('UPDATE quizzes SET name = ?, slug = ?, description = ? WHERE id = ?', 
                    (name, slug, description, quiz_id))
        conn.commit()
        conn.close()
        
        flash('Quiz updated successfully.', 'success')
        return redirect(url_for('admin_quizzes'))
    
    quiz = conn.execute('SELECT * FROM quizzes WHERE id = ?', (quiz_id,)).fetchone()
    conn.close()
    
    if not quiz:
        flash('Quiz not found.', 'danger')
        return redirect(url_for('admin_quizzes'))
    
    return render_template('admin/edit_quiz.html', quiz=quiz)

@app.route('/admin/quiz/<int:quiz_id>/delete', methods=['POST'])
@admin_required
def admin_delete_quiz(quiz_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM quizzes WHERE id = ?', (quiz_id,))
    conn.commit()
    conn.close()
    
    flash('Quiz deleted successfully.', 'success')
    return redirect(url_for('admin_quizzes'))

@app.route('/admin/quiz/<int:quiz_id>/questions')
@admin_required
def admin_quiz_questions(quiz_id):
    conn = get_db_connection()
    quiz = conn.execute('SELECT * FROM quizzes WHERE id = ?', (quiz_id,)).fetchone()
    questions = conn.execute('''
        SELECT q.*, GROUP_CONCAT(a.answer_text, '|') as answer_texts, 
               GROUP_CONCAT(a.is_correct, '|') as is_corrects
        FROM questions q
        LEFT JOIN answers a ON q.id = a.question_id
        WHERE q.quiz_id = ?
        GROUP BY q.id
        ORDER BY q.id
    ''', (quiz_id,)).fetchall()
    conn.close()
    
    if not quiz:
        flash('Quiz not found.', 'danger')
        return redirect(url_for('admin_quizzes'))
    
    return render_template('admin/quiz_questions.html', quiz=quiz, questions=questions)

# Admin Bookings Management
@app.route('/admin/bookings')
@admin_required
def admin_bookings():
    status_filter = request.args.get('status', 'All')
    
    conn = get_db_connection()
    
    if status_filter == 'All':
        bookings = conn.execute('''
            SELECT b.*, u.username 
            FROM bookings b 
            LEFT JOIN users u ON b.user_id = u.id 
            ORDER BY b.created_at DESC
        ''').fetchall()
    else:
        bookings = conn.execute('''
            SELECT b.*, u.username 
            FROM bookings b 
            LEFT JOIN users u ON b.user_id = u.id 
            WHERE b.status = ?
            ORDER BY b.created_at DESC
        ''', (status_filter,)).fetchall()
    
    conn.close()
    
    return render_template('admin/bookings.html', bookings=bookings, status_filter=status_filter)

@app.route('/admin/booking/<int:booking_id>/update_status', methods=['POST'])
@admin_required
def admin_update_booking_status(booking_id):
    new_status = request.form['status']
    
    conn = get_db_connection()
    conn.execute('UPDATE bookings SET status = ? WHERE id = ?', (new_status, booking_id))
    conn.commit()
    conn.close()
    
    flash('Booking status updated successfully.', 'success')
    return redirect(url_for('admin_bookings'))

@app.route('/admin/booking/<int:booking_id>/delete', methods=['POST'])
@admin_required
def admin_delete_booking(booking_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM bookings WHERE id = ?', (booking_id,))
    conn.commit()
    conn.close()
    
    flash('Booking deleted successfully.', 'success')
    return redirect(url_for('admin_bookings'))

# Admin Analytics
@app.route('/admin/analytics')
@admin_required
def admin_analytics():
    conn = get_db_connection()
    
    # User registration trend (last 30 days)
    registration_trend = conn.execute('''
        SELECT DATE(created_at) as date, COUNT(*) as count 
        FROM users 
        WHERE created_at >= date('now', '-30 days')
        GROUP BY DATE(created_at) 
        ORDER BY date
    ''').fetchall()
    
    # Quiz performance by topic
    topic_performance = conn.execute('''
        SELECT q.name, 
               COUNT(r.id) as attempt_count,
               AVG(CAST(r.score AS FLOAT) * 100.0 / r.total_questions) as avg_score
        FROM quiz_results r
        JOIN quizzes q ON r.quiz_id = q.id
        WHERE r.total_questions > 0
        GROUP BY q.id, q.name
        ORDER BY attempt_count DESC
    ''').fetchall()
    
    # User activity
    active_users = conn.execute('''
        SELECT u.username, 
               COUNT(r.id) as quiz_count, 
               MAX(r.timestamp) as last_activity,
               AVG(CAST(r.score AS FLOAT) * 100.0 / r.total_questions) as avg_score
        FROM users u
        JOIN quiz_results r ON u.id = r.user_id
        WHERE r.total_questions > 0
        GROUP BY u.id, u.username
        HAVING COUNT(r.id) > 0
        ORDER BY quiz_count DESC
        LIMIT 10
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin/analytics.html', 
                         registration_trend=registration_trend,
                         topic_performance=topic_performance,
                         active_users=active_users,
                         now=datetime.now())

# Admin Login Route (separate from regular login)
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if g.user and g.user.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ? AND is_admin = 1', (email,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials or insufficient privileges.', 'danger')
    
    return render_template('admin/login.html')

# Admin Logout
@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('You have been logged out from admin panel.', 'info')
    return redirect(url_for('index'))

# Update book trainer route to save bookings
@app.route('/submit-booking', methods=['POST'])
def submit_booking():
    if not g.user:
        flash('You need to be logged in to book a trainer.', 'warning')
        return redirect(url_for('login'))
    
    organization_name = request.form['organization_name']
    contact_person = request.form['contact_person']
    email = request.form['email']
    phone = request.form['phone']
    participants_count = request.form.get('participants_count')
    preferred_date = request.form.get('preferred_date')
    training_topic = request.form.get('training_topic')
    message = request.form.get('message')
    
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO bookings (user_id, organization_name, contact_person, email, phone, 
                             participants_count, preferred_date, training_topic, message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (g.user['id'], organization_name, contact_person, email, phone, 
          participants_count, preferred_date, training_topic, message))
    conn.commit()
    conn.close()
    
    flash('Your training request has been submitted successfully! We will contact you soon.', 'success')
    return redirect(url_for('book_trainer'))

# Update your before_request to handle admin status
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        conn = get_db_connection()
        g.user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        if g.user is None:
            session.clear()

if __name__ == '__main__':
    app.run(debug=True)