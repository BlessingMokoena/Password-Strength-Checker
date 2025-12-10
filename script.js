class PasswordStrengthChecker {
    constructor(password) {
        this.password = password;
        this.criteria = {
            length: { test: () => this.password.length >= 8, label: "Minimum 8 characters" },
            lowercase: { test: () => /[a-z]/.test(this.password), label: "At least one lowercase letter" },
            uppercase: { test: () => /[A-Z]/.test(this.password), label: "At least one uppercase letter" },
            digit: { test: () => /\d/.test(this.password), label: "At least one digit" },
            special: { test: () => /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(this.password), label: "At least one special character" }
        };
    }

    evaluate() {
        const results = {};
        let passedChecks = 0;

        for (const [key, criterion] of Object.entries(this.criteria)) {
            const passed = criterion.test();
            results[key] = passed;
            if (passed) passedChecks++;
        }

        const strength = this.getStrengthLabel(passedChecks);
        const entropy = this.calculateEntropy();
        const crackTime = this.estimateCrackTime(entropy);

        return {
            password: this.password,
            passed: passedChecks,
            total: Object.keys(this.criteria).length,
            strength,
            details: results,
            entropy,
            crackTime
        };
    }

    getStrengthLabel(score) {
        const labels = {
            5: "Very Strong",
            4: "Strong",
            3: "Moderate",
            2: "Weak",
            1: "Very Weak",
            0: "Extremely Weak"
        };
        return labels[score] || "Unknown";
    }

    calculateEntropy() {
        let charsetSize = 0;

        if (/[a-z]/.test(this.password)) charsetSize += 26;
        if (/[A-Z]/.test(this.password)) charsetSize += 26;
        if (/\d/.test(this.password)) charsetSize += 10;
        if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(this.password)) charsetSize += 32;

        if (charsetSize === 0) return 0;

        const entropy = this.password.length * Math.log2(charsetSize);
        return Math.round(entropy * 100) / 100;
    }

    estimateCrackTime(entropy) {
        // Assuming 1 billion guesses per second
        const guessesPerSecond = 1e9;
        const possibleCombinations = Math.pow(2, entropy);
        const seconds = possibleCombinations / (2 * guessesPerSecond);

        if (seconds < 1) return "Instant";
        if (seconds < 60) return `${Math.round(seconds)} seconds`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
        if (seconds < 2592000) return `${Math.round(seconds / 86400)} days`;
        if (seconds < 31536000) return `${Math.round(seconds / 2592000)} months`;
        if (seconds < 315360000) return `${Math.round(seconds / 31536000)} years`;
        return "Centuries";
    }
}

// DOM Elements
const passwordInput = document.getElementById('passwordInput');
const togglePassword = document.getElementById('togglePassword');
const strengthLabel = document.getElementById('strengthLabel');
const strengthBar = document.getElementById('strengthBar');
const entropyValue = document.getElementById('entropyValue');
const entropyFill = document.getElementById('entropyFill');
const passedChecks = document.getElementById('passedChecks');
const passwordLength = document.getElementById('passwordLength');
const crackTime = document.getElementById('crackTime');
const checkBreachBtn = document.getElementById('checkBreachBtn');
const breachResult = document.getElementById('breachResult');

const criteriaElements = {
    length: document.getElementById('criterion-length'),
    lowercase: document.getElementById('criterion-lowercase'),
    uppercase: document.getElementById('criterion-uppercase'),
    digit: document.getElementById('criterion-digit'),
    special: document.getElementById('criterion-special')
};

// Toggle password visibility
togglePassword.addEventListener('click', () => {
    const type = passwordInput.type === 'password' ? 'text' : 'password';
    passwordInput.type = type;
    togglePassword.querySelector('.eye-icon').textContent = type === 'password' ? '👁️' : '🙈';
});

// Real-time password analysis
passwordInput.addEventListener('input', () => {
    const password = passwordInput.value;
    
    if (password.length === 0) {
        resetUI();
        return;
    }

    const checker = new PasswordStrengthChecker(password);
    const result = checker.evaluate();
    
    updateUI(result);
    breachResult.classList.remove('show');
});

function updateUI(result) {
    // Update strength label and bar
    strengthLabel.textContent = result.strength;
    strengthLabel.className = `strength-text strength-${result.strength.toLowerCase().replace(' ', '-')}`;
    strengthBar.className = `meter-fill meter-${result.strength.toLowerCase().replace(' ', '-')}`;

    // Update entropy
    entropyValue.textContent = `${result.entropy} bits`;
    const entropyPercent = Math.min((result.entropy / 100) * 100, 100);
    entropyFill.style.width = `${entropyPercent}%`;

    // Update criteria
    for (const [key, passed] of Object.entries(result.details)) {
        const element = criteriaElements[key];
        if (passed) {
            element.classList.add('passed');
            element.querySelector('.check-icon').textContent = '✓';
        } else {
            element.classList.remove('passed');
            element.querySelector('.check-icon').textContent = '○';
        }
    }

    // Update stats
    passedChecks.textContent = `${result.passed}/${result.total}`;
    passwordLength.textContent = result.password.length;
    crackTime.textContent = result.crackTime;
}

function resetUI() {
    strengthLabel.textContent = '-';
    strengthLabel.className = 'strength-text';
    strengthBar.style.width = '0%';
    strengthBar.className = 'meter-fill';
    
    entropyValue.textContent = '0 bits';
    entropyFill.style.width = '0%';
    
    for (const element of Object.values(criteriaElements)) {
        element.classList.remove('passed');
        element.querySelector('.check-icon').textContent = '○';
    }
    
    passedChecks.textContent = '0/5';
    passwordLength.textContent = '0';
    crackTime.textContent = '-';
    breachResult.classList.remove('show');
}

// Check for data breaches using Have I Been Pwned API
checkBreachBtn.addEventListener('click', async () => {
    const password = passwordInput.value;
    
    if (!password) {
        showBreachResult('Please enter a password first.', 'warning');
        return;
    }

    checkBreachBtn.disabled = true;
    checkBreachBtn.innerHTML = '<span>⏳</span> Checking...';
    breachResult.classList.remove('show');

    try {
        const count = await checkPwnedPassword(password);
        
        if (count === -1) {
            showBreachResult('⚠️ Could not check breach status. Network error.', 'warning');
        } else if (count === 0) {
            showBreachResult('✅ Good news! This password has NOT been found in any known data breaches.', 'safe');
        } else {
            showBreachResult(`⛔ WARNING! This password has appeared in data breaches ${count.toLocaleString()} times. DO NOT USE IT!`, 'danger');
        }
    } catch (error) {
        showBreachResult('⚠️ Error checking breach database. Please try again.', 'warning');
    } finally {
        checkBreachBtn.disabled = false;
        checkBreachBtn.innerHTML = '<span>🔍</span> Check for Data Breaches';
    }
});

async function checkPwnedPassword(password) {
    try {
        // Create SHA-1 hash
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

        // Use k-Anonymity API
        const prefix = hashHex.substring(0, 5);
        const suffix = hashHex.substring(5);

        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        
        if (!response.ok) {
            return -1;
        }

        const text = await response.text();
        const hashes = text.split('\n');

        for (const line of hashes) {
            const [hashSuffix, count] = line.split(':');
            if (hashSuffix === suffix) {
                return parseInt(count, 10);
            }
        }

        return 0;
    } catch (error) {
        console.error('Error checking pwned passwords:', error);
        return -1;
    }
}

function showBreachResult(message, type) {
    breachResult.textContent = message;
    breachResult.className = `breach-result ${type} show`;
}

// Generate random strong password
function generateStrongPassword() {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const digits = '0123456789';
    const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    const all = lowercase + uppercase + digits + special;
    
    let password = '';
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += digits[Math.floor(Math.random() * digits.length)];
    password += special[Math.floor(Math.random() * special.length)];
    
    for (let i = 4; i < 16; i++) {
        password += all[Math.floor(Math.random() * all.length)];
    }
    
    // Shuffle the password
    return password.split('').sort(() => Math.random() - 0.5).join('');
}

// Optional: Add a generate password button if you want
// Uncomment the code below and add a button in HTML with id="generateBtn"
/*
const generateBtn = document.getElementById('generateBtn');
generateBtn.addEventListener('click', () => {
    const password = generateStrongPassword();
    passwordInput.value = password;
    passwordInput.dispatchEvent(new Event('input'));
});
*/