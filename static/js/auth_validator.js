document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    const signupButton = document.getElementById('signup-button');
    
    // Validation criteria elements
    const length = document.getElementById('length');
    const capital = document.getElementById('capital');
    const number = document.getElementById('number');
    const special = document.getElementById('special');
    const match = document.getElementById('match');

    // Show validation box when the user starts typing
    passwordInput.addEventListener('focus', () => {
        document.getElementById('password-strength').style.display = 'block';
    });

    // Main validation function
    function validate() {
        const pass = passwordInput.value;
        const confirmPass = confirmPasswordInput.value;
        
        // --- Regular Expressions ---
        const capitalRegex = /[A-Z]/;
        const numberRegex = /[0-9]/;
        const specialRegex = /[!@#$%^&*(),.?":{}|<>]/;

        // --- Check each criterion ---
        const isLengthValid = pass.length >= 8;
        const hasCapital = capitalRegex.test(pass);
        const hasNumber = numberRegex.test(pass);
        const hasSpecial = specialRegex.test(pass);
        const passwordsMatch = pass && pass === confirmPass;

        // --- Update UI ---
        updateCriterion(length, isLengthValid);
        updateCriterion(capital, hasCapital);
        updateCriterion(number, hasNumber);
        updateCriterion(special, hasSpecial);
        updateCriterion(match, passwordsMatch);
        
        // --- Enable/Disable Button ---
        if (isLengthValid && hasCapital && hasNumber && hasSpecial && passwordsMatch) {
            signupButton.disabled = false;
        } else {
            signupButton.disabled = true;
        }
    }

    // Helper function to update class lists for valid/invalid states
    function updateCriterion(element, isValid) {
        if (isValid) {
            element.classList.remove('invalid');
            element.classList.add('valid');
        } else {
            element.classList.remove('valid');
            element.classList.add('invalid');
        }
    }

    // Add event listeners
    passwordInput.addEventListener('keyup', validate);
    confirmPasswordInput.addEventListener('keyup', validate);
});