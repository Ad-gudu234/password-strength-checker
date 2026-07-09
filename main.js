/* =====================================================================
   CIPHER PASSWORD STRENGTH SCANNER
   Plain, well-commented JavaScript — no frameworks, no dependencies.
   ===================================================================== */

// ---- Grab the DOM elements we need to read from / write to ----
const passwordInput = document.getElementById('password');
const toggleBtn = document.getElementById('toggleBtn');
const eyeIcon = document.getElementById('eyeIcon');
const strengthLabel = document.getElementById('strengthLabel');
const meterTrack = document.getElementById('meterTrack');
const segments = meterTrack.querySelectorAll('.seg');
const crackTimeEl = document.getElementById('crackTime');
const checklistItems = document.querySelectorAll('#checklist li');
const generateBtn = document.getElementById('generateBtn');
const copyBtn = document.getElementById('copyBtn');
const toast = document.getElementById('toast');

// ---- A short list of very common / weak passwords worth flagging ----
// (Not exhaustive — just enough to catch the obvious offenders.)
const COMMON_PASSWORDS = [
    'password', '123456', '123456789', 'qwerty', 'abc123', 'password1',
    'iloveyou', 'admin', 'letmein', 'welcome', '111111', '12345678',
    'monkey', 'dragon', 'football', 'baseball', 'trustno1', 'sunshine'
];

// ---- Strength tiers: label, color, and minimum score (0-100) required ----
const TIERS = [
    { name: 'Very weak', min: 0, color: 'var(--danger)' },
    { name: 'Weak', min: 20, color: 'var(--danger)' },
    { name: 'Fair', min: 40, color: 'var(--warning)' },
    { name: 'Good', min: 60, color: 'var(--good)' },
    { name: 'Strong', min: 80, color: 'var(--great)' },
];

/**
 * checkRules(password)
 * Returns an object describing which basic composition rules are met.
 */
function checkRules(password) {
    return {
        length: password.length >= 8,
        upper: /[A-Z]/.test(password),
        lower: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        symbol: /[^A-Za-z0-9]/.test(password),
        common: password.length > 0 && !COMMON_PASSWORDS.includes(password.toLowerCase()),
    };
}

/**
 * estimateCharsetSize(password)
 * Figures out how large the "pool" of possible characters is,
 * based on which character types actually appear in the password.
 * This is used to estimate entropy (a measure of unpredictability).
 */
function estimateCharsetSize(password) {
    let size = 0;
    if (/[a-z]/.test(password)) size += 26;
    if (/[A-Z]/.test(password)) size += 26;
    if (/[0-9]/.test(password)) size += 10;
    if (/[^A-Za-z0-9]/.test(password)) size += 32; // approx. printable symbols
    return size || 1;
}

/**
 * calculateEntropy(password)
 * Entropy (in bits) ≈ length × log2(charset size)
 * Higher entropy = more possible combinations = harder to brute-force.
 */
function calculateEntropy(password) {
    if (!password) return 0;
    const charsetSize = estimateCharsetSize(password);
    return password.length * Math.log2(charsetSize);
}

/**
 * scorePassword(password)
 * Converts entropy + rule checks into a single 0-100 score.
 * This is a teaching-friendly heuristic, not a cryptographic standard.
 */
function scorePassword(password) {
    if (!password) return 0;

    const entropy = calculateEntropy(password);
    const rules = checkRules(password);

    // Base score from entropy, capped at 100. ~70+ bits is already very strong.
    let score = Math.min((entropy / 70) * 100, 100);

    // Penalize common passwords heavily, regardless of entropy.
    if (!rules.common) score = Math.min(score, 15);

    // Penalize very short passwords, even if they use varied characters.
    if (password.length < 6) score = Math.min(score, 25);

    // Small bonus for hitting every composition rule ("well-rounded" password).
    const metCount = Object.values(rules).filter(Boolean).length;
    if (metCount === 6) score = Math.min(score + 5, 100);

    return Math.round(score);
}

/**
 * formatCrackTime(entropyBits)
 * Estimates how long a brute-force attack would take, assuming an
 * attacker can try 10 billion guesses per second (a fast offline attack),
 * then formats that duration into a human-readable string.
 */
function formatCrackTime(entropyBits) {
    const guessesPerSecond = 1e10;
    const totalCombinations = Math.pow(2, entropyBits);
    const seconds = totalCombinations / guessesPerSecond;

    if (!isFinite(seconds) || entropyBits === 0) return '—';
    if (seconds < 1) return 'Instantly';

    const units = [
        { label: 'century', secs: 60 * 60 * 24 * 365 * 100 },
        { label: 'year', secs: 60 * 60 * 24 * 365 },
        { label: 'day', secs: 60 * 60 * 24 },
        { label: 'hour', secs: 60 * 60 },
        { label: 'minute', secs: 60 },
        { label: 'second', secs: 1 },
    ];

    for (const unit of units) {
        const value = seconds / unit.secs;
        if (value >= 1) {
            const rounded = Math.round(value);
            // Cap absurdly large numbers so the UI stays readable.
            if (rounded > 999999999999) return '9,999,999,999,999+ centuries'.replace('999999999999', '999+');
            return `${rounded.toLocaleString()} ${unit.label}${rounded !== 1 ? 's' : ''}`;
        }
    }
    return 'Instantly';
}

/**
 * getTier(score)
 * Returns the strength tier (label + color) matching a given score.
 */
function getTier(score) {
    let tier = TIERS[0];
    for (const t of TIERS) {
        if (score >= t.min) tier = t;
    }
    return tier;
}

/**
 * updateChecklist(rules)
 * Toggles the "met" class on each checklist item based on rule results.
 */
function updateChecklist(rules) {
    checklistItems.forEach((item) => {
        const rule = item.getAttribute('data-rule');
        item.classList.toggle('met', !!rules[rule]);
    });
}

/**
 * updateMeter(score, tier)
 * Fills in the segmented strength bar (0-5 segments) and colors it
 * according to the current tier.
 */
function updateMeter(score, tier) {
    const filledSegments = score === 0 ? 0 : Math.max(1, Math.ceil((score / 100) * segments.length));

    segments.forEach((seg, i) => {
        const isOn = i < filledSegments;
        seg.classList.toggle('on', isOn);
        seg.classList.toggle('glow', isOn);
        seg.style.color = tier.color; // 'currentColor' in CSS picks this up
    });
}

/**
 * render()
 * The main update function — called every time the password changes.
 * Reads the input, computes everything, and updates the UI.
 */
function render() {
    const password = passwordInput.value;
    const rules = checkRules(password);
    const entropy = calculateEntropy(password);
    const score = scorePassword(password);
    const tier = getTier(score);

    updateChecklist(rules);
    updateMeter(score, tier);

    strengthLabel.textContent = password ? tier.name : '—';
    strengthLabel.style.color = password ? tier.color : 'var(--muted)';

    crackTimeEl.textContent = password ? formatCrackTime(entropy) : '—';
    crackTimeEl.style.color = password ? tier.color : 'var(--text)';
}

// ---- Show / hide password ----
toggleBtn.addEventListener('click', () => {
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
    toggleBtn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');

    // Swap the eye icon between "open" and "slashed" states
    eyeIcon.innerHTML = isPassword
        ? '<path d="M17.94 17.94A10.94 10.94 0 0 1 12 19c-7 0-11-7-11-7a21.8 21.8 0 0 1 5.06-6.06M9.9 4.24A10.94 10.94 0 0 1 12 4c7 0 11 7 11 7a21.8 21.8 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>'
        : '<path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"></path><circle cx="12" cy="12" r="3"></circle>';
});

/**
 * generatePassword(length)
 * Builds a random password guaranteed to include at least one
 * uppercase letter, lowercase letter, number, and symbol.
 */
function generatePassword(length = 16) {
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}';
    const all = lower + upper + numbers + symbols;

    // Guarantee one character from each category first...
    let chars = [
        lower[Math.floor(Math.random() * lower.length)],
        upper[Math.floor(Math.random() * upper.length)],
        numbers[Math.floor(Math.random() * numbers.length)],
        symbols[Math.floor(Math.random() * symbols.length)],
    ];

    // ...then fill the rest randomly from the full character pool.
    for (let i = chars.length; i < length; i++) {
        chars.push(all[Math.floor(Math.random() * all.length)]);
    }

    // Shuffle so the guaranteed characters aren't always in the same spot.
    for (let i = chars.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }

    return chars.join('');
}

// ---- Generate button ----
generateBtn.addEventListener('click', () => {
    const newPassword = generatePassword(16);
    passwordInput.value = newPassword;
    passwordInput.type = 'text'; // reveal it so the user can see what was generated
    eyeIcon.innerHTML = '<path d="M17.94 17.94A10.94 10.94 0 0 1 12 19c-7 0-11-7-11-7a21.8 21.8 0 0 1 5.06-6.06M9.9 4.24A10.94 10.94 0 0 1 12 4c7 0 11 7 11 7a21.8 21.8 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>';
    render();
    showToast('Strong password generated');
});

// ---- Copy button ----
copyBtn.addEventListener('click', async () => {
    if (!passwordInput.value) {
        showToast('Nothing to copy yet');
        return;
    }
    try {
        await navigator.clipboard.writeText(passwordInput.value);
        showToast('Copied to clipboard');
    } catch (err) {
        showToast('Copy failed — select manually');
    }
});

// ---- Toast helper ----
let toastTimer = null;
function showToast(message) {
    toast.textContent = message;
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 2200);
}

// ---- Wire up live analysis as the user types ----
passwordInput.addEventListener('input', render);

// ---- Initial render on page load ----
render();