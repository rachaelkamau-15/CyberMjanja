document.addEventListener('DOMContentLoaded', () => {
    // This object holds all questions for all 18 quizzes.
    // The key (e.g., 'social-engineering') MUST match the category in the button's link.
    const quizData = {
        'social-engineering': [
            { question: "What is the primary goal of social engineering?", options: ["To install malware", "To gain unauthorized access to systems or information", "To crash a system", "To steal hardware"], answer: "To gain unauthorized access to systems or information" },
            { question: "Which technique involves creating a fake scenario to manipulate a victim?", options: ["Phishing", "Baiting", "Pretexting", "Quid pro quo"], answer: "Pretexting" },
            { question: "What is 'baiting' in the context of social engineering?", options: ["Leaving a malware-infected device for someone to find and use", "Sending a deceptive email to steal credentials", "Making a false promise in exchange for information", "Impersonating a trusted individual over the phone"], answer: "Leaving a malware-infected device for someone to find and use" },
            { question: "Which of the following is a common defense against social engineering?", options: ["Using a strong firewall", "Encrypting all data", "Regularly training and educating employees", "Installing antivirus software"], answer: "Regularly training and educating employees" },
            { question: "What is 'tailgating'?", options: ["Following an authorized person into a secure area", "Sending a series of harassing emails", "Overloading a server with traffic", "Stealing a company's trash to find sensitive information"], answer: "Following an authorized person into a secure area" },
            { question: "Phishing, vishing, and smishing are all forms of what?", options: ["Malware attacks", "Denial-of-service attacks", "Social engineering attacks", "Physical security breaches"], answer: "Social engineering attacks" },
            { question: "What psychological trigger does an urgent-sounding email from a 'CEO' exploit?", options: ["Scarcity", "Authority", "Likability", "Social proof"], answer: "Authority" },
            { question: "What is 'quid pro quo' in social engineering?", options: ["A promise of something in return for information or access", "Creating a sense of urgency", "Impersonating a help desk employee", "Using a celebrity endorsement to build trust"], answer: "A promise of something in return for information or access" },
            { question: "What is the best way to verify a suspicious request made over the phone?", options: ["Call them back at the number they provide", "Hang up and call the organization using a known, trusted number", "Provide only non-sensitive information", "Ask them to send an email instead"], answer: "Hang up and call the organization using a known, trusted number" },
            { question: "Why is social engineering so effective?", options: ["It exploits human trust and willingness to help", "It uses advanced hacking tools", "It can bypass all security software", "It only targets people who are not tech-savvy"], answer: "It exploits human trust and willingness to help" }
        ],
        'phishing': [ { question: "Common sign of a phishing email?", options: ["Generic greeting", "Urgent request", "Too good to be true offer", "All of the above"], answer: "All of the above" } /* Add 9 more */ ],
        'vishing': [ { question: "Vishing is done via?", options: ["Email", "Telephone", "Text", "Website"], answer: "Telephone" } /* Add 9 more */ ],
        'smishing': [ { question: "Smishing is done via?", options: ["SMS", "Social media", "Email", "Pop-ups"], answer: "SMS" } /* Add 9 more */ ],
        'password-hygiene': [ { question: "Strongest password?", options: ["password123", "pet's name", "Long phrase with mixed characters", "12345678"], answer: "Long phrase with mixed characters" } /* Add 9 more */ ],
        'ransomware': [ { question: "Goal of ransomware?", options: ["Steal data", "Encrypt files for a ransom", "Spy on you", "Delete files"], answer: "Encrypt files for a ransom" } /* Add 9 more */ ],
        'spyware': [ { question: "What does spyware do?", options: ["Locks files", "Monitors and collects your info", "Floods network", "Shows ads"], answer: "Monitors and collects your info" } /* Add 9 more */ ],
        'strong-passwords': [ { question: "How often to change passwords?", options: ["Daily", "Every 3-6 months", "Yearly", "Never"], answer: "Every 3-6 months" } /* Add 9 more */ ],
        'malware-awareness': [ { question: "What is a Trojan Horse?", options: ["A virus", "Malware disguised as legit software", "Spyware", "A worm"], answer: "Malware disguised as legit software" } /* Add 9 more */ ],
        '2fa': [ { question: "What does 2FA require?", options: ["Two passwords", "Something you know and something you have", "Password and security question", "Fingerprint and face scan"], answer: "Something you know and something you have" } /* Add 9 more */ ],
        'safe-browsing': [ { question: "What does HTTPS indicate?", options: ["Fast site", "Good content", "Encrypted and secure connection", "Mobile-friendly"], answer: "Encrypted and secure connection" } /* Add 9 more */ ],
        'data-privacy': [ { question: "What is PII?", options: ["Favorite color", "Full name and address", "Movie opinion", "Car type"], answer: "Full name and address" } /* Add 9 more */ ],
        'social-media-safety': [ { question: "Risk of oversharing?", options: ["Too many likes", "Criminals can gather info for attacks", "Friends get bored", "Account gets featured"], answer: "Criminals can gather info for attacks" } /* Add 9 more */ ],
        'public-wifi-risks': [ { question: "Main danger of public Wi-Fi?", options: ["Slow connection", "Hackers can intercept data", "Uses battery", "You see ads"], answer: "Hackers can intercept data" } /* Add 9 more */ ],
        'cyberbullying': [ { question: "If you see cyberbullying, what do you do?", options: ["Ignore it", "Join in", "Report and support the victim", "Confront the bully"], answer: "Report and support the victim" } /* Add 9 more */ ],
        'cloud-security': [ { question: "How to protect cloud files?", options: ["Weak password", "Share login", "Strong, unique password and 2FA", "Never upload"], answer: "Strong, unique password and 2FA" } /* Add 9 more */ ],
        'mobile-security': [ { question: "Good mobile security practice?", options: ["Download from unofficial sources", "Keep OS updated", "Ignore permissions", "No passcode"], answer: "Keep OS updated" } /* Add 9 more */ ],
        'identity-theft': [ { question: "How to prevent identity theft?", options: ["Share SSN", "Use same password everywhere", "Regularly check bank/credit reports", "Click suspicious links"], answer: "Regularly check bank/credit reports" } /* Add 9 more */ ],
    };

    const urlParams = new URLSearchParams(window.location.search);
    const category = urlParams.get('category');
    const questions = quizData[category] || [];
    const quizTitle = document.getElementById('quiz-title');
    const questionText = document.getElementById('question-text');
    const optionsContainer = document.getElementById('options-container');
    const feedback = document.getElementById('feedback');
    const nextBtn = document.getElementById('next-btn');
    const resultsContainer = document.getElementById('results-container');
    const scoreText = document.getElementById('score-text');
    const progressText = document.getElementById('progress-text');
    const quizContent = document.getElementById('quiz-content');
    const quizFooter = document.querySelector('.quiz-footer');
    let currentQuestionIndex = 0;
    let score = 0;

    function startQuiz() {
        if (!category || !questions.length) {
            quizTitle.textContent = 'Quiz Not Found';
            quizContent.innerHTML = '<p class="text-center fs-5">This quiz category could not be found. Please return and select a valid quiz.</p>';
            quizFooter.style.display = 'none';
            return;
        }
        const formattedTitle = category.replace(/-/g, ' ').replace(/\b(2fa|and|of|in|to)\b/gi, m => m.toUpperCase()).replace(/\b\w/g, c => c.toUpperCase());
        quizTitle.textContent = formattedTitle;
        showQuestion();
    }

    function showQuestion() {
        const question = questions[currentQuestionIndex];
        questionText.textContent = question.question;
        optionsContainer.innerHTML = '';
        feedback.textContent = '';
        nextBtn.style.display = 'none';
        progressText.textContent = `Question ${currentQuestionIndex + 1} of ${questions.length}`;
        question.options.forEach(option => {
            const button = document.createElement('button');
            button.textContent = option;
            button.classList.add('btn', 'btn-outline-primary');
            button.addEventListener('click', () => selectAnswer(option, question.answer, button));
            optionsContainer.appendChild(button);
        });
    }

    function selectAnswer(selectedOption, correctAnswer, selectedButton) {
        let correctButton;
        Array.from(optionsContainer.children).forEach(button => {
            button.disabled = true;
            if (button.textContent === correctAnswer) correctButton = button;
        });
        if (selectedOption === correctAnswer) {
            score++;
            selectedButton.classList.remove('btn-outline-primary');
            selectedButton.classList.add('btn-success');
            feedback.textContent = "Correct!";
            feedback.style.color = "green";
        } else {
            selectedButton.classList.remove('btn-outline-primary');
            selectedButton.classList.add('btn-danger');
            correctButton.classList.remove('btn-outline-primary');
            correctButton.classList.add('btn-success');
            feedback.textContent = "Incorrect!";
            feedback.style.color = "red";
        }
        nextBtn.textContent = currentQuestionIndex < questions.length - 1 ? 'Next Question' : 'Show Results';
        nextBtn.style.display = 'block';
    }

    nextBtn.addEventListener('click', () => {
        currentQuestionIndex++;
        (currentQuestionIndex < questions.length) ? showQuestion() : showResults();
    });

    function showResults() {
        quizContent.style.display = 'none';
        quizFooter.style.display = 'none';
        resultsContainer.style.display = 'block';
        const percentage = Math.round((score / questions.length) * 100);
        scoreText.textContent = `You scored ${score} out of ${questions.length} (${percentage}%)`;
    }
    startQuiz();
});