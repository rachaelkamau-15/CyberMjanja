from flask import Flask, render_template, request, redirect, url_for, flash, session, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_change_this'
DATABASE = 'database.db'

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
    if g.user: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email, password = request.form['email'], request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            flash('You have been successfully logged in!', 'success')
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

if __name__ == '__main__':
    app.run(debug=True)