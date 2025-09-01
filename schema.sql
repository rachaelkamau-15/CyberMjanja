-- Delete existing tables to start fresh. This ensures a clean setup.
DROP TABLE IF EXISTS user_answers;
DROP TABLE IF EXISTS quiz_results;
DROP TABLE IF EXISTS answers;
DROP TABLE IF EXISTS questions;
DROP TABLE IF EXISTS quizzes;
DROP TABLE IF EXISTS users;

-- Create the users table with all necessary fields.
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT,          -- Added for user profile
    country TEXT,            -- Added for user profile
    organization TEXT,       -- Added for user profile
    job_title TEXT           -- Added for user profile
);

-- Create the quizzes table.
CREATE TABLE quizzes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL, -- A URL-friendly version of the name
    description TEXT
);

-- Create the questions table.
CREATE TABLE questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    quiz_id INTEGER NOT NULL,
    question_text TEXT NOT NULL,
    explanation TEXT,          -- For the review page
    FOREIGN KEY (quiz_id) REFERENCES quizzes (id)
);

-- Create the answers table.
CREATE TABLE answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id INTEGER NOT NULL,
    answer_text TEXT NOT NULL,
    is_correct BOOLEAN NOT NULL CHECK (is_correct IN (0, 1)), -- 1 for true, 0 for false
    FOREIGN KEY (question_id) REFERENCES questions (id)
);

-- Create the quiz_results table to store scores for each attempt.
CREATE TABLE quiz_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    quiz_id INTEGER NOT NULL,
    score INTEGER NOT NULL,
    total_questions INTEGER NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (quiz_id) REFERENCES quizzes (id)
);

-- Create the user_answers table to store each specific answer for review.
CREATE TABLE user_answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id INTEGER NOT NULL,
    question_id INTEGER NOT NULL,
    selected_answer_id INTEGER,
    FOREIGN KEY (result_id) REFERENCES quiz_results (id),
    FOREIGN KEY (question_id) REFERENCES questions (id),
    FOREIGN KEY (selected_answer_id) REFERENCES answers (id)
);