import sqlite3
import re
import os

# --- Database Setup ---
DATABASE = 'database.db'

def init_database():
    """
    Performs a MASTER RESET of the database.
    1. Forcefully deletes the old database file.
    2. Creates a new database with the correct, final schema.
    3. Populates the new database with all quiz data.
    """
    print("--- STARTING DATABASE MASTER RESET ---")
    if os.path.exists(DATABASE):
        try:
            os.remove(DATABASE)
            print(f"SUCCESS: The old '{DATABASE}' file was found and deleted.")
        except OSError as e:
            print(f"ERROR: Could not delete the database file. Please close any programs using it and try again. Details: {e}")
            return
    else:
        print(f"INFO: Old '{DATABASE}' file not found. Proceeding to create a new one.")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    print("\nStep 2: Creating all tables from scratch...")
    cursor.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, full_name TEXT, country TEXT, organization TEXT, job_title TEXT);''')
    cursor.execute('''CREATE TABLE quizzes (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, description TEXT);''')
    cursor.execute('''CREATE TABLE questions (id INTEGER PRIMARY KEY AUTOINCREMENT, quiz_id INTEGER NOT NULL, question_text TEXT NOT NULL, explanation TEXT NOT NULL, FOREIGN KEY (quiz_id) REFERENCES quizzes(id));''')
    cursor.execute('''CREATE TABLE answers (id INTEGER PRIMARY KEY AUTOINCREMENT, question_id INTEGER NOT NULL, answer_text TEXT NOT NULL, is_correct INTEGER NOT NULL CHECK(is_correct IN (0, 1)), FOREIGN KEY (question_id) REFERENCES questions(id));''')
    cursor.execute('''CREATE TABLE quiz_results (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, quiz_id INTEGER NOT NULL, score INTEGER NOT NULL, total_questions INTEGER NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (quiz_id) REFERENCES quizzes(id));''')
    cursor.execute('''CREATE TABLE user_answers (id INTEGER PRIMARY KEY AUTOINCREMENT, result_id INTEGER NOT NULL, question_id INTEGER NOT NULL, selected_answer_id INTEGER, is_bookmarked BOOLEAN NOT NULL DEFAULT 0, FOREIGN KEY (result_id) REFERENCES quiz_results (id), FOREIGN KEY (question_id) REFERENCES questions (id), FOREIGN KEY (selected_answer_id) REFERENCES answers (id));''')
    print("--> SUCCESS: All tables created with the correct schema.")

    print("\nStep 3: Populating database with quizzes and questions...")
    
    # --- 1. Populate ALL Quiz Categories ---
    quizzes_to_add = [('Social Engineering', 'social-engineering', 'The art of human manipulation.'), ('Phishing', 'phishing', 'Identifying fraudulent emails.'), ('Vishing', 'vishing', 'Voice-based phishing scams.'), ('Smishing', 'smishing', 'Text message-based scams.'), ('Password Hygiene', 'password-hygiene', 'Best practices for passwords.'), ('Ransomware', 'ransomware', 'Protecting your digital files.'), ('Spyware', 'spyware', 'Keeping your activity private.'), ('Strong Passwords', 'strong-passwords', 'Creating unbreakable codes.'), ('Malware Awareness', 'malware-awareness', 'Spotting viruses, worms, and Trojans.'), ('Two-Factor Authentication (2FA)', '2fa', 'Why an extra layer of security makes all the difference.'), ('Safe Browsing', 'safe-browsing', 'Identifying secure websites and avoiding malicious links.'), ('Data Privacy', 'data-privacy', 'Understanding personal data protection.'), ('Social Media Safety', 'social-media-safety', 'Recognizing risks and scams on social platforms.'), ('Public Wi-Fi Risks', 'public-wifi-risks', 'How to protect your connection on public networks.'), ('Cyberbullying & Online Etiquette', 'cyberbullying', 'Promoting safe and respectful digital behavior.'), ('Cloud Security Basics', 'cloud-security', 'Keeping your files safe in the cloud.'), ('Mobile Security', 'mobile-security', 'Keeping smartphones and tablets safe.'), ('Identity Theft', 'identity-theft', 'Protecting yourself from identity fraud.')]
    cursor.executemany("INSERT INTO quizzes (name, slug, description) VALUES (?, ?, ?)", quizzes_to_add)

    # --- 2. Define ALL Questions, Answers, and Explanations in a single text block ---
    raw_data = """
    Category: Social Engineering
    Q1. What is the main goal of social engineering attacks?
    A) To improve system speed
    B) To trick people into revealing sensitive information
    C) To protect user data
    D) To install antivirus software
    Answer: B
    Explanation: Social engineering relies on psychological manipulation. The primary objective is to deceive individuals into breaking normal security procedures and divulging confidential information.
    ________________________________________
    Q2. Which of the following is an example of social engineering?
    A) A hacker exploiting a software vulnerability
    B) A pop-up ad for software updates
    C) An attacker pretending to be IT support to gain passwords
    D) A firewall blocking suspicious traffic
    Answer: C
    Explanation: Pretending to be a trusted authority figure, like IT support, is a classic social engineering tactic called pretexting. The other options are either technical attacks or legitimate security measures.
    ________________________________________
    Q3. What makes social engineering attacks effective?
    A) High-level coding skills
    B) Human trust and manipulation
    C) Strong encryption methods
    D) Advanced firewalls
    Answer: B
    Explanation: These attacks succeed by exploiting human nature, such as the tendency to trust others or the fear of getting into trouble. They bypass technical defenses by targeting the person directly.
    ________________________________________
    Q4. Which is NOT a common form of social engineering?
    A) Phishing emails
    B) Pretexting
    C) Tailgating
    D) File encryption
    Answer: D
    Explanation: File encryption is what malware like ransomware does *after* an attack succeeds. Phishing, pretexting (creating a fake scenario), and tailgating (following someone into a secure area) are all methods of social engineering.
    ________________________________________
    Q5. How can you defend against social engineering attacks?
    A) Regularly update your operating system
    B) Use strong technical firewalls only
    C) Verify requests before sharing information
    D) Disable automatic updates
    Answer: C
    Explanation: The best defense is a human one. Always be skeptical of unexpected requests for information. Verify the person's identity through a separate, trusted communication channel before proceeding.
    ________________________________________
    Category: Phishing
    Q1. What is the main characteristic of phishing emails?
    A) They always come from your friends
    B) They try to trick you into clicking links or sharing info
    C) They are sent by your antivirus provider
    D) They fix your computer problems automatically
    Answer: B
    Explanation: Phishing attacks use deceptive emails, texts, or messages to lure victims into providing sensitive data or downloading malware. They often impersonate trusted brands or individuals.
    ________________________________________
    Q2. A phishing email usually asks you to:
    A) Change your wallpaper
    B) Provide sensitive details like passwords
    C) Restart your computer
    D) Block unknown senders
    Answer: B
    Explanation: The ultimate goal of phishing is to steal valuable information, such as login credentials, credit card numbers, or personal identifiers. They create a sense of urgency to make you act without thinking.
    ________________________________________
    Q3. Which is a red flag in a phishing email?
    A) Personalized greetings
    B) Spelling mistakes and urgent messages
    C) Receiving from your company domain
    D) Professional signatures
    Answer: B
    Explanation: While some phishing emails are sophisticated, many contain grammatical errors, spelling mistakes, or create a false sense of urgency (e.g., "Your account will be suspended!"). These are clear warning signs.
    ________________________________________
    Q4. Phishing primarily exploits:
    A) Weak Wi-Fi networks
    B) Human psychology
    C) Antivirus software flaws
    D) Cloud storage
    Answer: B
    Explanation: Like social engineering, phishing relies on tricking the human user. It preys on fear, curiosity, and trust to bypass technical security controls.
    ________________________________________
    Q5. What is the safest action when you suspect phishing?
    A) Reply to confirm authenticity
    B) Click the link to check
    C) Report and delete the email
    D) Forward it to friends
    Answer: C
    Explanation: Never click links or reply. Clicking can lead to a malicious site, and replying confirms your email is active. The best action is to report it (if your organization has a process) and then delete it.
    ________________________________________
    Category: Vishing
    Q1. Vishing is carried out through:
    A) Text messages
    B) Phone calls or voice messages
    C) Fake websites
    D) Pop-up ads
    Answer: B
    Explanation: 'Vishing' stands for 'voice phishing.' It is a type of phishing attack that is conducted over the phone, using voice calls or voicemails to deceive victims.
    ________________________________________
    Q2. A common vishing tactic is:
    A) Offering free downloads
    B) Asking for login details over the phone
    C) Sending fake surveys
    D) Installing spyware secretly
    Answer: B
    Explanation: Vishers often impersonate banks, tech support, or government agencies to trick you into verbally providing sensitive information like passwords, PINs, or verification codes.
    ________________________________________
    Q3. Which is the safest response to an unexpected bank call?
    A) Give them your account number to verify
    B) Ask them to email you instead
    C) Hang up and call your bank directly
    D) Ignore the call forever
    Answer: C
    Explanation: Never trust an unsolicited call asking for personal information. The safest method is to hang up and call the official number listed on your bank's website or the back of your card to verify the request.
    ________________________________________
    Q4. Vishing attackers often pretend to be:
    A) Hackers bragging about skills
    B) Customer support or government officials
    C) Your relatives only
    D) Weather reporters
    Answer: B
    Explanation: Attackers choose roles that have authority or a legitimate reason to ask for your information, such as impersonating the IRS, Microsoft Support, or your bank's fraud department.
    ________________________________________
    Q5. One way to avoid vishing is:
    A) Never answering any calls
    B) Installing antivirus
    C) Refusing to share personal details on calls
    D) Using strong Wi-Fi passwords
    Answer: C
    Explanation: Legitimate organizations will rarely, if ever, ask you to provide a full password, social security number, or other highly sensitive data over an unsolicited phone call. Be suspicious of any such request.
    ________________________________________
    Category: Smishing
    Q1. Smishing is short for:
    A) Small phishing
    B) SMS phishing
    C) Smart phishing
    D) Social messaging phishing
    Answer: B
    Explanation: 'Smishing' is a combination of 'SMS' (Short Message Service, or text messages) and 'phishing.' It refers to phishing attacks conducted via text messages.
    ________________________________________
    Q2. A typical smishing message might:
    A) Ask you to click a link in a text message
    B) Offer free Wi-Fi
    C) Teach you coding
    D) Update your antivirus automatically
    Answer: A
    Explanation: Smishing texts often contain urgent-sounding messages (e.g., "A suspicious login was detected on your account") followed by a link to a malicious website designed to steal your credentials.
    ________________________________________
    Q3. Smishing targets which device most often?
    A) Desktop computers
    B) Smart TVs
    C) Mobile phones
    D) Game consoles
    Answer: C
    Explanation: Since smishing is based on SMS text messages, its primary target is mobile phones. People also tend to be less cautious when clicking links on their phones.
    ________________________________________
    Q4. If you receive a suspicious text, you should:
    A) Click the link to confirm
    B) Call the number in the message
    C) Delete or report the message
    D) Share it with friends to check
    Answer: C
    Explanation: Do not engage with the message in any way. Do not click the link, and do not reply. The safest action is to delete the message. You can also report it as spam through your messaging app.
    ________________________________________
    Q5. Smishing primarily exploits:
    A) Weak Wi-Fi
    B) Human curiosity and urgency
    C) Antivirus loopholes
    D) Cloud misconfiguration
    Answer: B
    Explanation: Like other forms of phishing, smishing preys on human emotions. A message about a prize, a problem with a delivery, or a security alert creates a sense of urgency that encourages impulsive clicking.
    ________________________________________
    Category: Password Hygiene
    Q1. Which of the following is a poor password habit?
    A) Using a unique password for each account
    B) Writing your password on a sticky note
    C) Using a password manager
    D) Changing passwords regularly
    Answer: B
    Explanation: Writing passwords on sticky notes and leaving them in plain sight completely undermines the security of the password. It makes them easily accessible to anyone with physical access to your desk.
    ________________________________________
    Q2. Why is reusing the same password risky?
    A) It makes logging in faster
    B) One breach can compromise multiple accounts
    C) It confuses hackers
    D) It helps you remember easily
    Answer: B
    Explanation: If a hacker steals your password from one website, they will try using it on many other popular services (like email, banking, and social media). This is called 'credential stuffing' and is very common.
    ________________________________________
    Q3. A good password hygiene practice is:
    A) Sharing your password with family
    B) Avoiding two-factor authentication
    C) Using long and complex passwords
    D) Saving passwords in your browser only
    Answer: C
    Explanation: A long password that mixes uppercase letters, lowercase letters, numbers, and symbols is much harder for attackers to crack using automated tools.
    ________________________________________
    Q4. What should you do after a data breach?
    A) Continue using the same password
    B) Immediately change your affected passwords
    C) Delete your email account
    D) Ignore the notification
    Answer: B
    Explanation: If a service you use suffers a data breach, you must assume your password is compromised. Change the password for that service and any other service where you reused the same password.
    ________________________________________
    Q5. Password managers help by:
    A) Guessing hacker’s passwords
    B) Creating and storing strong, unique passwords
    C) Removing viruses
    D) Encrypting Wi-Fi
    Answer: B
    Explanation: A password manager is a secure, encrypted vault that generates and stores complex, unique passwords for all your accounts. You only need to remember one master password to access them.
    ________________________________________
    Category: Ransomware
    Q1. What does ransomware do to your files?
    A) Deletes them permanently
    B) Encrypts them and demands payment for access
    C) Makes copies of them
    D) Backs them up to the cloud
    Answer: B
    Explanation: Ransomware is a type of malware that locks up your files using strong encryption. The attackers then demand a ransom payment, usually in cryptocurrency, in exchange for the decryption key.
    ________________________________________
    Q2. What is the attacker’s demand in a ransomware attack?
    A) Free updates
    B) Money, often in cryptocurrency
    C) Antivirus installation
    D) Stronger passwords
    Answer: B
    Explanation: The goal of a ransomware attack is financial gain. Attackers demand payment and often prefer cryptocurrencies like Bitcoin because they are harder to trace.
    ________________________________________
    Q3. How can you best protect against ransomware?
    A) Never use the internet
    B) Keep regular backups of data
    C) Save all files on one device only
    D) Use weak passwords
    Answer: B
    Explanation: If you have a recent, offline backup of your important files, you can restore them after an attack without needing to pay the ransom. This is the single most effective defense.
    ________________________________________
    Q4. Opening which file type can often spread ransomware?
    A) Word documents with macros
    B) Plain text (.txt) files
    C) JPEG images
    D) PDF from a trusted source
    Answer: A
    Explanation: Malicious macros (small scripts) embedded in Office documents are a very common way to deliver ransomware. Always be cautious about enabling macros from untrusted sources.
    ________________________________________
    Q5. If infected with ransomware, the best first step is:
    A) Pay immediately
    B) Disconnect the device from the network
    C) Delete all backups
    D) Restart multiple times
    Answer: B
    Explanation: Immediately disconnecting the infected device from Wi-Fi or unplugging the network cable can prevent the ransomware from spreading to other devices on the same network.
    ________________________________________
    Category: Spyware
    Q1. What does spyware do?
    A) Encrypts files for ransom
    B) Secretly monitors and collects your data
    C) Speeds up your computer
    D) Blocks pop-ups only
    Answer: B
    Explanation: Spyware is a type of malware designed to operate covertly. It gathers information about your activities, such as browsing history, keystrokes (capturing passwords), and personal information, and sends it to an attacker.
    ________________________________________
    Q2. Which is a sign your device may have spyware?
    A) Faster internet speeds
    B) Unknown programs running in the background
    C) Longer battery life
    D) Automatic antivirus updates
    Answer: B
    Explanation: Spyware often causes noticeable performance issues, such as a sluggish system, unexpected pop-ups, or new applications that you don't remember installing.
    ________________________________________
    Q3. Spyware can steal:
    A) Your browsing history and passwords
    B) Antivirus updates only
    C) Public information only
    D) Only non-sensitive files
    Answer: A
    Explanation: Spyware is designed to steal valuable and sensitive information, including login credentials, financial details, and private messages.
    ________________________________________
    Q4. How can spyware get into your device?
    A) Installing unknown apps
    B) Visiting official government sites
    C) Using strong firewalls
    D) Installing antivirus
    Answer: A
    Explanation: Spyware is often bundled with seemingly legitimate software (especially free programs) or can be installed by exploiting software vulnerabilities or tricking the user.
    ________________________________________
    Q5. To remove spyware, you should:
    A) Pay the attacker
    B) Use updated antivirus/anti-spyware tools
    C) Reset your wallpaper
    D) Delete browser history only
    Answer: B
    Explanation: A reputable and updated security software suite is the most effective way to scan for and remove spyware from your system.
    ________________________________________
    Category: Strong Passwords
    Q1. Which of the following is the strongest password?
    A) 123456
    B) P@ssw0rd
    C) MyDog2025
    D) $Tr0ng!P@ssw0rd#2025
    Answer: D
    Explanation: The strongest passwords are long and have a high degree of complexity, mixing uppercase letters, lowercase letters, numbers, and symbols. Simple substitutions (like '0' for 'o') are easily cracked.
    ________________________________________
    Q2. A strong password should include:
    A) Only lowercase letters
    B) A mix of letters, numbers, and symbols
    C) Your date of birth
    D) Just your name
    Answer: B
    Explanation: Using a variety of character types dramatically increases the number of possible combinations, making it much harder for attackers to guess or brute-force your password.
    ________________________________________
    Q3. What is the recommended minimum length of a strong password?
    A) 4 characters
    B) 6 characters
    C) 8 or more characters
    D) 20 characters exactly
    Answer: C
    Explanation: While longer is always better, most security experts recommend a minimum of 8-12 characters for a password to be considered reasonably strong against modern cracking techniques.
    ________________________________________
    Q4. Which password is the weakest?
    A) Summer2025!
    B) qwerty
    C) H@ppyD@y123
    D) Book&River45
    Answer: B
    Explanation: 'qwerty' is a common keyboard pattern and is one of the first things an attacker will try. It offers no complexity and is found at the top of every list of common passwords to check.
    ________________________________________
    Q5. The safest way to manage strong passwords is:
    A) Write them on paper
    B) Save them in browsers only
    C) Use a password manager
    D) Use the same one everywhere
    Answer: C
    Explanation: A dedicated password manager is the most secure and convenient solution. It allows you to use long, complex, unique passwords for every site without needing to memorize them all.
    ________________________________________
    Category: Malware Awareness
    Q1. Malware is:
    A) Helpful software updates
    B) Malicious software designed to harm devices
    C) A type of antivirus program
    D) An email filter
    Answer: B
    Explanation: The term 'malware' is a portmanteau of 'malicious software.' It is a catch-all term for any software created with the intent to cause damage or gain unauthorized access to a computer system.
    ________________________________________
    Q2. Which is NOT a type of malware?
    A) Worms
    B) Spyware
    C) Antivirus
    D) Trojan horse
    Answer: C
    Explanation: Antivirus is security software designed to detect and remove malware. Worms, spyware, and trojans are all common categories of malicious software.
    ________________________________________
    Q3. What is a common sign of malware infection?
    A) Faster battery charging
    B) Slow system performance and pop-ups
    C) Free cloud storage
    D) Automatic backups
    Answer: B
    Explanation: Malware running in the background consumes system resources, leading to slowness, crashes, and unexpected behavior like a flood of pop-up advertisements.
    ________________________________________
    Q4. Which of these can spread malware?
    A) Downloading files from untrusted sites
    B) Using strong passwords
    C) Enabling two-factor authentication
    D) Regular system updates
    Answer: A
    Explanation: One of the most common ways malware spreads is by tricking users into downloading and running infected files from suspicious websites, emails, or peer-to-peer networks.
    ________________________________________
    Q5. The best way to prevent malware is:
    A) Avoid antivirus
    B) Update software and avoid suspicious downloads
    C) Use only one password everywhere
    D) Turn off firewalls
    Answer: B
    Explanation: A multi-layered defense is key. Keeping your operating system and applications patched, combined with cautious browsing and downloading habits, is a highly effective prevention strategy.
    ________________________________________
    Category: Two-Factor Authentication (2FA)
    Q1. What is two-factor authentication?
    A) Using two passwords only
    B) A method requiring two forms of verification
    C) Logging in from two devices
    D) Changing passwords twice a year
    Answer: B
    Explanation: 2FA adds a second layer of security to your logins. It requires you to provide two different types of evidence of your identity, such as something you know (password) and something you have (your phone).
    ________________________________________
    Q2. Which is an example of 2FA?
    A) Password + SMS code
    B) Password + username
    C) Two different usernames
    D) Password only
    Answer: A
    Explanation: A password is the first factor ('something you know'). A one-time code sent to your phone via SMS is the second factor ('something you have'). This combination is a classic example of 2FA.
    ________________________________________
    Q3. Why is 2FA more secure?
    A) It guarantees no hacking
    B) It adds another layer beyond just a password
    C) It prevents Wi-Fi hacking
    D) It encrypts emails automatically
    Answer: B
    Explanation: Even if an attacker steals your password, they still cannot access your account without also having physical access to your second factor (e.g., your phone). This makes stolen passwords much less useful.
    ________________________________________
    Q4. What can be used as a second factor in 2FA?
    A) Security questions, SMS code, or authenticator app
    B) Just your username
    C) Your birthday only
    D) A weak password
    Answer: A
    Explanation: Common second factors include codes from an authenticator app (like Google Authenticator), SMS codes, physical security keys, or biometrics (fingerprint/face ID).
    ________________________________________
    Q5. If you lose your phone with 2FA enabled, you should:
    A) Share login with a friend
    B) Disable all accounts
    C) Use backup codes or recovery options
    D) Ignore and continue
    Answer: C
    Explanation: Most services that offer 2FA provide one-time backup codes when you first set it up. It is crucial to save these codes in a safe place so you can regain access to your account if you lose your primary 2FA device.
    ________________________________________
    Category: Safe Browsing
    Q1. What does HTTPS in a website address indicate?
    A) The site is always fake
    B) The site uses a secure connection
    C) The site has no ads
    D) The site is government-owned
    Answer: B
    Explanation: HTTPS (Hypertext Transfer Protocol Secure) means the data transmitted between your browser and the website is encrypted. This prevents eavesdroppers on the same network from stealing your information.
    ________________________________________
    Q2. Which is a safe browsing practice?
    A) Clicking on pop-up ads for free prizes
    B) Avoiding public Wi-Fi for sensitive logins
    C) Downloading from random websites
    D) Ignoring browser warnings
    Answer: B
    Explanation: Public Wi-Fi networks are often unsecured, making it easy for attackers to intercept your data. It's best to avoid logging into important accounts like banking or email while connected to them.
    ________________________________________
    Q3. What is a browser warning about an untrusted certificate?
    A) A sign of a secure site
    B) A signal you should proceed immediately
    C) A possible security risk
    D) A normal update
    Answer: C
    Explanation: This warning means the browser cannot verify the website's identity. It could be a simple misconfiguration, or it could be an attacker trying to impersonate a legitimate site. You should proceed with caution or not at all.
    ________________________________________
    Q4. Which browser feature helps with safe browsing?
    A) Incognito/Private mode
    B) Unlimited tabs
    C) Auto-play videos
    D) Bookmarks only
    Answer: A
    Explanation: While not a silver bullet for security, Incognito/Private mode prevents the browser from saving your browsing history, cookies, and site data, which can be useful for privacy, especially on shared computers.
    ________________________________________
    Q5. One way to avoid malicious websites is:
    A) Always click suspicious links
    B) Type URLs directly instead of clicking unknown links
    C) Disable antivirus
    D) Use outdated browsers
    Answer: B
    Explanation: Clicking links in emails or on social media can sometimes lead you to a fake or malicious website. Typing the address of a trusted site directly into the address bar ensures you go to the correct place.
    ________________________________________
    Category: Data Privacy
    Q1. What is the main goal of data privacy?
    A) To share all data publicly
    B) To protect personal and sensitive information
    C) To sell user information
    D) To delete all stored data
    Answer: B
    Explanation: Data privacy is about controlling who has access to your personal data and how it is used. It's a fundamental right that helps protect you from fraud, discrimination, and manipulation.
    ________________________________________
    Q2. Which is an example of sensitive personal data?
    A) Favorite color
    B) Social Security Number (SSN)
    C) Hobby list
    D) TV shows watched
    Answer: B
    Explanation: Sensitive data is information that, if exposed, could cause significant harm. This includes government identifiers, financial information, and medical records.
    ________________________________________
    Q3. Why should you review app permissions?
    A) To improve battery life only
    B) To check if apps request unnecessary data access
    C) To speed up downloads
    D) To fix Wi-Fi connections
    Answer: B
    Explanation: Many apps ask for more permissions than they need to function (e.g., a flashlight app asking for your contacts). Reviewing and limiting these permissions helps protect your privacy.
    ________________________________________
    Q4. Data privacy laws like GDPR exist to:
    A) Limit internet speed
    B) Protect user rights and personal data
    C) Stop people from using social media
    D) Ban email use
    Answer: B
    Explanation: Regulations like the GDPR (General Data Protection Regulation) in Europe are designed to give individuals more control over their personal data and to hold companies accountable for how they handle it.
    ________________________________________
    Q5. Which is a good data privacy habit?
    A) Oversharing on social media
    B) Using privacy settings on accounts
    C) Clicking all ads
    D) Giving your password to apps
    Answer: B
    Explanation: Actively managing the privacy settings on your social media and other online accounts allows you to control what information is visible to the public and how your data is used by the platform.
    ________________________________________
    Category: Social Media Safety
    Q1. What is a common risk of oversharing on social media?
    A) More likes
    B) Identity theft or stalking
    C) Faster internet
    D) Free upgrades
    Answer: B
    Explanation: Sharing too much personal information—like your full birthdate, address, or vacation plans—can provide criminals with the details they need to steal your identity or target you for physical crimes.
    ________________________________________
    Q2. Which information should you avoid posting publicly?
    A) Vacation dates and home address
    B) Hobbies and interests
    C) Favorite book titles
    D) Favorite colors
    Answer: A
    Explanation: Posting your address is a direct physical security risk. Announcing you're on vacation tells burglars that your home is empty, making it an attractive target.
    ________________________________________
    Q3. What can help protect your social media accounts?
    A) Weak passwords
    B) Enabling two-factor authentication
    C) Accepting all friend requests
    D) Clicking suspicious links
    Answer: B
    Explanation: Enabling 2FA on your social media accounts is one of the most effective ways to prevent them from being hijacked, even if an attacker manages to steal your password.
    ________________________________________
    Q4. Why should you be careful with friend requests?
    A) Hackers may impersonate people
    B) They always lower internet speed
    C) They cost money
    D) They remove your old friends
    Answer: A
    Explanation: Scammers often create fake profiles pretending to be someone you know to gain your trust. Once connected, they can send you malicious links or try to extract personal information.
    ________________________________________
    Q5. A safe social media practice is:
    A) Clicking every link
    B) Logging in from public computers
    C) Adjusting privacy settings
    D) Posting all personal details
    Answer: C
    Explanation: Regularly reviewing your privacy settings allows you to control who can see your posts and personal information, reducing your exposure to scammers and data miners.
    ________________________________________
    Category: Public Wi-Fi Risks
    Q1. What is the main risk of using public Wi-Fi?
    A) Faster internet speeds
    B) Hackers intercepting your data
    C) Free access to websites
    D) Unlimited downloads
    Answer: B
    Explanation: Most public Wi-Fi networks are unencrypted, meaning that a nearby attacker can easily "listen in" on your connection and capture any data you send, including passwords and personal messages.
    ________________________________________
    Q2. Which activity is most dangerous on public Wi-Fi?
    A) Watching YouTube videos
    B) Logging into your online banking
    C) Reading public news websites
    D) Streaming music
    Answer: B
    Explanation: Accessing sensitive accounts like online banking over an unsecured network is extremely risky. An attacker could intercept your login credentials and gain full access to your finances.
    ________________________________________
    Q3. How can you protect yourself on public Wi-Fi?
    A) Always disable antivirus
    B) Use a VPN for secure connections
    C) Share files with strangers
    D) Turn off your firewall
    Answer: B
    Explanation: A VPN (Virtual Private Network) creates a secure, encrypted tunnel for your internet traffic. This makes your data unreadable to anyone trying to eavesdrop on the public network.
    ________________________________________
    Q4. What is a "man-in-the-middle" attack on public Wi-Fi?
    A) Someone hijacks your internet connection to steal data
    B) Someone speeds up your connection
    C) A legal security check
    D) An antivirus update
    Answer: A
    Explanation: In this attack, a hacker places themselves between your device and the Wi-Fi router, intercepting all your traffic. They can then steal, read, or modify your data without your knowledge.
    ________________________________________
    Q5. The safest option when handling sensitive data is:
    A) Use mobile data instead of public Wi-Fi
    B) Trust any available hotspot
    C) Save passwords in browsers only
    D) Disable phone lock screen
    Answer: A
    Explanation: Your phone's mobile data connection (4G/5G) is encrypted and much more secure than an open public Wi-Fi network. It's the preferred choice for any sensitive activity.
    ________________________________________
    Category: Cyberbullying & Online Etiquette
    Q1. Cyberbullying is best described as:
    A) Online jokes with friends
    B) Harassment, threats, or humiliation via digital platforms
    C) Positive online feedback
    D) Encouraging others politely
    Answer: B
    Explanation: Cyberbullying is the intentional and repeated use of digital communication to harm or harass others. It is a serious issue with real-world consequences.
    ________________________________________
    Q2. Which is an example of good online etiquette?
    A) Respecting others’ opinions online
    B) Insulting others in comments
    C) Sharing fake news
    D) Posting offensive memes
    Answer: A
    Explanation: Good online etiquette, or "netiquette," involves being courteous and respectful in your online interactions, even when you disagree with someone. It helps create a more positive online environment.
    ________________________________________
    Q3. If you witness cyberbullying, you should:
    A) Ignore it completely
    B) Support the bully
    C) Report and support the victim
    D) Share the bullying post further
    Answer: C
    Explanation: Being a responsible digital citizen means not being a bystander. Report the abusive behavior to the platform administrators and offer support to the person being targeted.
    ________________________________________
    Q4. Why is online etiquette important?
    A) It reduces internet speed
    B) It promotes respectful and safe communication
    C) It increases cyber threats
    D) It hides your identity
    Answer: B
    Explanation: Just like in the real world, rules of etiquette make interactions smoother and more pleasant. Online, it helps prevent misunderstandings and fosters a safer, more inclusive community.
    ________________________________________
    Q5. Which is a responsible online behavior?
    A) Oversharing personal details
    B) Using strong and kind communication
    C) Posting private info of others
    D) Threatening strangers
    Answer: B
    Explanation: Responsible digital citizenship involves communicating thoughtfully and kindly, protecting your own privacy, and respecting the privacy of others.
    ________________________________________
    Category: Cloud Security Basics
    Q1. What does cloud security focus on?
    A) Protecting data stored on remote servers
    B) Weather protection for data centers
    C) Making internet faster
    D) Removing malware automatically
    Answer: A
    Explanation: Cloud security is a set of policies, technologies, and controls designed to protect data, applications, and infrastructure hosted in a cloud computing environment.
    ________________________________________
    Q2. Which is a good cloud security practice?
    A) Using weak passwords for cloud accounts
    B) Enabling two-factor authentication
    C) Sharing login with colleagues
    D) Using public Wi-Fi without VPN
    Answer: B
    Explanation: Your cloud accounts often hold your most important files and data. Protecting them with 2FA is a crucial step to prevent unauthorized access.
    ________________________________________
    Q3. What type of data is commonly stored in the cloud?
    A) Personal files, business data, and backups
    B) Only movies
    C) Only video games
    D) Nothing sensitive
    Answer: A
    Explanation: Cloud services are used for a vast range of data, from personal photos and documents to critical business applications and complete system backups.
    ________________________________________
    Q4. A potential risk of cloud storage is:
    A) Losing access if account is hacked
    B) Faster data retrieval
    C) Easy collaboration
    D) Automatic backups
    Answer: A
    Explanation: While the cloud offers many benefits, it also means that if your account credentials are stolen, an attacker could gain access to all the data you have stored there. This makes strong security essential.
    ________________________________________
    Q5. To ensure cloud data safety, you should:
    A) Disable all security settings
    B) Regularly back up and encrypt sensitive data
    C) Share passwords with coworkers
    D) Use outdated cloud services
    Answer: B
    Explanation: Even when storing data in the cloud, it's wise to follow security best practices. Encrypting your most sensitive files before uploading adds an extra layer of protection.
    ________________________________________
    Category: Mobile Security
    Q1. What is the biggest mobile security risk?
    A) Installing apps from unknown sources
    B) Charging your phone overnight
    C) Using Wi-Fi at home
    D) Updating your phone regularly
    Answer: A
    Explanation: Apps from official stores (like Google Play or the Apple App Store) are vetted for security. Apps downloaded from other websites ("sideloading") may contain malware.
    ________________________________________
    Q2. Which is a good mobile security practice?
    A) Keeping your operating system and apps updated
    B) Ignoring app permissions
    C) Using the same password everywhere
    D) Turning off screen lock
    Answer: A
    Explanation: Software updates frequently contain critical security patches that fix vulnerabilities discovered by researchers. Keeping your device updated is a primary defense against malware.
    ________________________________________
    Q3. Why should you enable a screen lock?
    A) To save battery
    B) To prevent unauthorized access
    C) To download apps faster
    D) To avoid software updates
    Answer: B
    Explanation: A screen lock (using a PIN, password, or biometrics) is your first line of defense. It prevents anyone who gets physical access to your phone from accessing your personal data.
    ________________________________________
    Q4. Which tool helps track or erase a stolen phone?
    A) File compressor
    B) Find My Device / Mobile tracking apps
    C) Cloud photo storage only
    D) Calculator app
    Answer: B
    Explanation: Services like Apple's "Find My" and Google's "Find My Device" allow you to locate a lost or stolen phone on a map, make it ring, or remotely wipe all its data to protect your privacy.
    ________________________________________
    Q5. What is a sign of malware on your mobile phone?
    A) Faster battery charging
    B) Sudden pop-ups and overheating
    C) Improved security features
    D) Smooth performance
    Answer: B
    Explanation: Malicious apps running in the background can consume significant processing power, leading to a rapidly draining battery, overheating, and unexpected ads or behavior.
    ________________________________________
    Category: Identity Theft
    Q1. What is identity theft?
    A) Using someone’s personal data for fraud or crimes
    B) Forgetting your own password
    C) Sharing photos online
    D) Creating multiple accounts legally
    Answer: A
    Explanation: Identity theft occurs when a criminal illegally obtains and uses your personal identifying information (like your name, SSN, or credit card number) for their own financial gain.
    ________________________________________
    Q2. Which information is most valuable to identity thieves?
    A) Favorite songs
    B) Social Security numbers, IDs, and credit card details
    C) Movie preferences
    D) Publicly available news articles
    Answer: B
    Explanation: This type of information is known as Personally Identifiable Information (PII) and can be used to open new accounts, file fraudulent tax returns, or commit other crimes in your name.
    ________________________________________
    Q3. Which is a warning sign of identity theft?
    A) Unknown charges on your account
    B) Fast internet speed
    C) Receiving birthday wishes online
    D) Too many friend requests
    Answer: A
    Explanation: Unexpected bills, unfamiliar charges on your credit card statement, or calls from debt collectors for accounts you didn't open are major red flags for identity theft.
    ________________________________________
    Q4. How can you protect against identity theft?
    A) Shred personal documents and use strong online passwords
    B) Post all details on social media
    C) Share bank details in emails
    D) Reuse the same password everywhere
    Answer: A
    Explanation: Protecting against identity theft requires both offline and online diligence. Shredding sensitive documents prevents "dumpster diving," while strong, unique passwords protect your digital accounts.
    ________________________________________
    Q5. What should you do if you suspect identity theft?
    A) Ignore it
    B) Report to your bank and relevant authorities immediately
    C) Share your login info with friends
    D) Create more online accounts
    Answer: B
    Explanation: Acting quickly is crucial to limit the damage. Contact your financial institutions to freeze accounts, report the fraud to credit bureaus, and file a report with the appropriate law enforcement or government agencies.
    """
    
    # --- 3. Parse the raw_data and insert into the database ---
    question_blocks = raw_data.strip().split('________________________________________')
    current_quiz_id = None
    category_pattern = re.compile(r"Category: (.*?)(?:\s*\(\d+\s*Questions\))?$")

    for block in question_blocks:
        block = block.strip()
        if not block:
            continue
        lines = block.split('\n')
        first_line = lines[0].strip()
        category_match = category_pattern.match(first_line)
        if category_match:
            category_name = category_match.group(1).strip()
            cursor.execute("SELECT id FROM quizzes WHERE name = ?", (category_name,))
            quiz_row = cursor.fetchone()
            if quiz_row:
                current_quiz_id = quiz_row[0]
                content = "\n".join(lines[1:])
            else:
                current_quiz_id = None
                continue
        else:
            content = block
        if not current_quiz_id:
            continue
        questions_in_block = re.split(r'\nQ\d+\.\s*', '\n' + content)
        for q_text_with_answers in questions_in_block:
            q_text_with_answers = q_text_with_answers.strip()
            if not q_text_with_answers:
                continue
            q_lines = q_text_with_answers.split('\n')
            question_text = q_lines[0]
            correct_answer_letter = None
            explanation_text = "No explanation provided."
            answer_lines = {}
            for line in q_lines[1:]:
                line = line.strip()
                if line.startswith('Answer:'):
                    correct_answer_letter = line.split(':', 1)[1].strip()
                elif line.startswith('Explanation:'):
                    explanation_text = line.split(':', 1)[1].strip()
                elif re.match(r'^[A-D]\)\s*', line):
                    letter = line[0]
                    text = line[2:].strip()
                    answer_lines[letter] = text
            if not correct_answer_letter or not answer_lines:
                continue
            cursor.execute("INSERT INTO questions (quiz_id, question_text, explanation) VALUES (?, ?, ?)", (current_quiz_id, question_text, explanation_text))
            question_id = cursor.lastrowid
            for letter, text in answer_lines.items():
                is_correct = 1 if letter == correct_answer_letter else 0
                cursor.execute("INSERT INTO answers (question_id, answer_text, is_correct) VALUES (?, ?, ?)", (question_id, text, is_correct))

    conn.commit()
    conn.close()
    print("\n--- DATABASE MASTER RESET COMPLETE ---")
    print("You may now start your Flask application.")

if __name__ == '__main__':
    init_database()