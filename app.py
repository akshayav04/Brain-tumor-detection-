from flask import Flask, request, jsonify, render_template_string
import hashlib
import math
import re
import sqlite3
import secrets
import string
import requests
import joblib
import os
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)

MODEL_FILE = "model.pkl"
DB_FILE = "password_history.db"


# =========================================================
# DATABASE
# =========================================================

def init_db():

    conn = sqlite3.connect(DB_FILE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT NOT NULL,
            strength TEXT,
            score INTEGER,
            entropy REAL,
            breach_count INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


# =========================================================
# TRAINING DATA
# =========================================================

def create_training_data():

    data = [
        ([5, 0, 5, 0, 0], "Weak"),
        ([6, 0, 6, 0, 0], "Weak"),
        ([7, 1, 5, 1, 0], "Weak"),

        ([8, 1, 5, 1, 1], "Medium"),
        ([9, 1, 6, 1, 1], "Medium"),
        ([10, 1, 7, 1, 1], "Medium"),
        ([11, 2, 7, 1, 1], "Medium"),

        ([12, 2, 7, 2, 1], "Strong"),
        ([13, 2, 8, 2, 1], "Strong"),
        ([14, 2, 8, 2, 2], "Strong"),
        ([15, 3, 8, 2, 2], "Strong"),
        ([16, 3, 9, 2, 2], "Strong"),
        ([17, 3, 9, 3, 2], "Strong"),
        ([18, 4, 9, 3, 2], "Strong"),
        ([20, 4, 10, 3, 3], "Strong")
    ]

    X = [item[0] for item in data]
    y = [item[1] for item in data]

    return X, y


def train_model():

    X, y = create_training_data()

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    model.fit(X, y)

    joblib.dump(model, MODEL_FILE)

    return model


if os.path.exists(MODEL_FILE):

    try:
        model = joblib.load(MODEL_FILE)

    except Exception:
        model = train_model()

else:
    model = train_model()


# =========================================================
# FEATURE EXTRACTION
# =========================================================

def extract_features(password):

    return [
        len(password),
        len(re.findall(r"[A-Z]", password)),
        len(re.findall(r"[a-z]", password)),
        len(re.findall(r"[0-9]", password)),
        len(re.findall(r"[^A-Za-z0-9]", password))
    ]


# =========================================================
# ENTROPY
# =========================================================

def calculate_entropy(password):

    pool = 0

    if re.search(r"[a-z]", password):
        pool += 26

    if re.search(r"[A-Z]", password):
        pool += 26

    if re.search(r"[0-9]", password):
        pool += 10

    if re.search(r"[^A-Za-z0-9]", password):
        pool += 32

    if pool == 0:
        return 0

    return round(
        len(password) * math.log2(pool),
        2
    )


# =========================================================
# SECURITY SCORE
# =========================================================

def calculate_score(password):

    score = 0

    if len(password) >= 8:
        score += 20

    if len(password) >= 12:
        score += 20

    if re.search(r"[A-Z]", password):
        score += 15

    if re.search(r"[a-z]", password):
        score += 15

    if re.search(r"[0-9]", password):
        score += 15

    if re.search(r"[^A-Za-z0-9]", password):
        score += 15

    return min(score, 100)


# =========================================================
# HIBP BREACH CHECK
# =========================================================

def check_breach(password):

    try:

        sha1 = hashlib.sha1(
            password.encode("utf-8")
        ).hexdigest().upper()

        prefix = sha1[:5]
        suffix = sha1[5:]

        url = (
            "https://api.pwnedpasswords.com/range/"
            + prefix
        )

        response = requests.get(
            url,
            timeout=5,
            headers={
                "User-Agent":
                "AI-Password-Security-Analyzer"
            }
        )

        if response.status_code != 200:

            return {
                "breached": False,
                "count": 0,
                "error": True
            }

        for line in response.text.splitlines():

            parts = line.split(":")

            if len(parts) != 2:
                continue

            hash_suffix = parts[0]
            count = int(parts[1])

            if hash_suffix == suffix:

                return {
                    "breached": True,
                    "count": count,
                    "error": False
                }

        return {
            "breached": False,
            "count": 0,
            "error": False
        }

    except Exception:

        return {
            "breached": False,
            "count": 0,
            "error": True
        }


# =========================================================
# SAVE HISTORY
# =========================================================

def save_history(
    password,
    strength,
    score,
    entropy,
    breach_count
):

    password_hash = hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()

    conn = sqlite3.connect(DB_FILE)

    conn.execute("""
        INSERT INTO history
        (
            password_hash,
            strength,
            score,
            entropy,
            breach_count
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        password_hash,
        strength,
        score,
        entropy,
        breach_count
    ))

    conn.commit()
    conn.close()


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return render_template_string(HTML)


# =========================================================
# ANALYZE PASSWORD
# =========================================================

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    password = data.get("password", "")

    if not password:

        return jsonify({
            "error": "Password cannot be empty"
        }), 400

    features = extract_features(password)

    prediction = model.predict(
        [features]
    )[0]

    score = calculate_score(password)

    entropy = calculate_entropy(password)

    breach = check_breach(password)

    if breach["breached"]:

        risk = "HIGH"

    elif prediction == "Weak":

        risk = "HIGH"

    elif prediction == "Medium":

        risk = "MEDIUM"

    else:

        risk = "LOW"

    if prediction == "Strong":

        mfa = [
            "Enable Multi-Factor Authentication",
            "Use an authenticator application",
            "Consider using passkeys",
            "Avoid password reuse"
        ]

    elif prediction == "Medium":

        mfa = [
            "Enable Multi-Factor Authentication",
            "Increase password length",
            "Use an authenticator application",
            "Avoid personal information"
        ]

    else:

        mfa = [
            "Change this password immediately",
            "Enable Multi-Factor Authentication",
            "Use a password manager",
            "Create a unique password"
        ]

    save_history(
        password,
        prediction,
        score,
        entropy,
        breach["count"]
    )

    return jsonify({

        "prediction": prediction,

        "score": score,

        "entropy": entropy,

        "risk": risk,

        "breached": breach["breached"],

        "breach_count": breach["count"],

        "breach_error": breach["error"],

        "mfa": mfa,

        "features": {

            "length": features[0],

            "uppercase": features[1],

            "lowercase": features[2],

            "digits": features[3],

            "special": features[4]

        }

    })


# =========================================================
# PASSWORD GENERATOR
# =========================================================

@app.route("/generate")
def generate():

    characters = (
        string.ascii_letters
        + string.digits
        + "!@#$%^&*()-_=+"
    )

    password = "".join(
        secrets.choice(characters)
        for _ in range(18)
    )

    return jsonify({
        "password": password
    })


# =========================================================
# HISTORY
# =========================================================

@app.route("/history")
def history():

    conn = sqlite3.connect(DB_FILE)

    rows = conn.execute("""
        SELECT
            strength,
            score,
            entropy,
            breach_count,
            created_at
        FROM history
        ORDER BY id DESC
        LIMIT 20
    """).fetchall()

    conn.close()

    result = []

    for row in rows:

        result.append({

            "strength": row[0],

            "score": row[1],

            "entropy": row[2],

            "breach_count": row[3],

            "created_at": row[4]

        })

    return jsonify(result)


# =========================================================
# COMPLETE FRONTEND
# =========================================================

HTML = r"""

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>
AI Password Security Analyzer
</title>

<style>

*{

    box-sizing:border-box;

    margin:0;

    padding:0;

    font-family:Arial,sans-serif;

}

body{

    background:#050816;

    color:white;

    min-height:100vh;

    transition:.3s;

}

body.light{

    background:#eef2f8;

    color:#111827;

}

nav{

    display:flex;

    justify-content:space-between;

    align-items:center;

    padding:20px 8%;

    position:sticky;

    top:0;

    z-index:10;

    backdrop-filter:blur(20px);

    background:rgba(5,8,22,.85);

    border-bottom:1px solid #1f2937;

}

body.light nav{

    background:white;

}

.logo{

    color:#00f5ff;

    font-size:22px;

    font-weight:bold;

}

button{

    border:none;

    cursor:pointer;

    border-radius:12px;

}

.theme{

    padding:10px 15px;

    background:#00f5ff;

}

.container{

    width:90%;

    max-width:1100px;

    margin:auto;

}

.hero{

    text-align:center;

    padding:70px 20px 40px;

}

.hero h1{

    font-size:48px;

    color:#00f5ff;

    margin-bottom:20px;

}

.hero p{

    color:#cbd5e1;

    line-height:1.7;

}

.card{

    background:rgba(255,255,255,.07);

    border:1px solid rgba(255,255,255,.12);

    backdrop-filter:blur(20px);

    border-radius:22px;

    padding:30px;

    margin:25px 0;

    box-shadow:
    0 0 30px rgba(0,245,255,.08);

}

body.light .card{

    background:white;

    color:#111827;

}

input{

    width:100%;

    padding:17px;

    border-radius:12px;

    border:1px solid #334155;

    background:#0f172a;

    color:white;

    font-size:16px;

    margin:10px 0;

}

body.light input{

    background:#f8fafc;

    color:#111827;

}

.primary{

    width:100%;

    padding:17px;

    background:
    linear-gradient(90deg,#00f5ff,#7b61ff);

    color:white;

    font-weight:bold;

    font-size:16px;

}

.score{

    width:180px;

    height:180px;

    border-radius:50%;

    border:10px solid #00f5ff;

    display:flex;

    justify-content:center;

    align-items:center;

    margin:25px auto;

    font-size:35px;

    font-weight:bold;

    color:#00f5ff;

}

.meter{

    height:15px;

    background:#1e293b;

    border-radius:20px;

    overflow:hidden;

}

.progress{

    height:100%;

    width:0%;

    transition:1s;

    background:#00ff66;

}

.grid{

    display:grid;

    grid-template-columns:
    repeat(auto-fit,minmax(200px,1fr));

    gap:20px;

}

.stat{

    padding:20px;

    border-radius:15px;

    background:rgba(255,255,255,.05);

    text-align:center;

}

.stat h3{

    color:#00f5ff;

    margin-bottom:10px;

}

.safe{

    color:#00ff66;

}

.danger{

    color:#ff4444;

}

.medium{

    color:#ffb400;

}

.recommend{

    margin:10px 0;

    padding:12px;

    border-left:4px solid #00f5ff;

    background:rgba(0,245,255,.05);

}

.small-buttons{

    display:flex;

    gap:10px;

    flex-wrap:wrap;

    margin-top:10px;

}

.small-buttons button{

    padding:12px 18px;

    background:#172033;

    color:white;

}

.voice{

    background:#7b61ff !important;

    color:white;

}

.voice.listening{

    background:#ff1744 !important;

    animation:pulse 1s infinite;

}

@keyframes pulse{

    50%{

        transform:scale(1.05);

    }

}

.voice-status{

    text-align:center;

    margin-top:15px;

    color:#00f5ff;

    min-height:25px;

}

.chat{

    height:250px;

    overflow-y:auto;

    padding:15px;

    background:#020617;

    border-radius:15px;

    margin-bottom:15px;

}

body.light .chat{

    background:#f1f5f9;

}

#lock{

    font-size:70px;

    text-align:center;

    margin:20px;

}

footer{

    text-align:center;

    padding:40px;

    color:#94a3b8;

}

@media(max-width:600px){

    .hero h1{

        font-size:32px;

    }

    nav{

        padding:15px 5%;

    }

}

</style>

</head>


<body>


<nav>

<div class="logo">

🛡 AI Password Security Analyzer

</div>

<button
class="theme"
onclick="toggleTheme()">

🌙

</button>

</nav>


<div class="container">


<section class="hero">

<h1>
AI-Powered Password Security
</h1>

<p>
Machine Learning + Cybersecurity
for Intelligent Password Protection
</p>

</section>


<!-- PASSWORD ANALYZER -->

<div class="card">

<h2>🔐 Password Analyzer</h2>

<br>

<input
type="password"
id="password"
placeholder="Enter password"
>

<div class="small-buttons">

<button onclick="togglePassword()">

👁 Show / Hide

</button>

<button
class="voice"
id="voiceButton"
onclick="startVoice()">

🎤 Speak Password

</button>

</div>


<p
class="voice-status"
id="voiceStatus">

🎤 Click the microphone and speak

</p>


<button
class="primary"
onclick="analyzePassword()">

🤖 Analyze with AI

</button>


<div id="lock">

🔒

</div>


<div class="score" id="score">

0%

</div>


<h2
id="strength"
style="text-align:center">

Enter password

</h2>


<br>


<div class="meter">

<div
class="progress"
id="progress">

</div>

</div>

</div>


<!-- RISK -->

<div class="card">

<h2>🛡 Cyber Risk Analysis</h2>

<br>

<div class="grid">

<div class="stat">

<h3>Brute Force</h3>

<p id="brute">-</p>

</div>

<div class="stat">

<h3>Dictionary</h3>

<p id="dictionary">-</p>

</div>

<div class="stat">

<h3>Credential Stuffing</h3>

<p id="credential">-</p>

</div>

<div class="stat">

<h3>Risk Level</h3>

<p id="risk">-</p>

</div>

</div>

</div>


<!-- BREACH -->

<div class="card">

<h2>🔓 Leaked Password Detection</h2>

<br>

<div id="breach">

Enter a password to check.

</div>

</div>


<!-- STATISTICS -->

<div class="card">

<h2>📊 Password Statistics</h2>

<br>

<div class="grid">

<div class="stat">

<h3>Length</h3>

<p id="length">0</p>

</div>

<div class="stat">

<h3>Uppercase</h3>

<p id="uppercase">0</p>

</div>

<div class="stat">

<h3>Lowercase</h3>

<p id="lowercase">0</p>

</div>

<div class="stat">

<h3>Numbers</h3>

<p id="digits">0</p>

</div>

<div class="stat">

<h3>Special</h3>

<p id="special">0</p>

</div>

<div class="stat">

<h3>Entropy</h3>

<p id="entropy">0 Bits</p>

</div>

</div>

</div>


<!-- MFA -->

<div class="card">

<h2>🔑 MFA Recommendations</h2>

<br>

<div id="mfa">

Analyze your password to receive
MFA recommendations.

</div>

</div>


<!-- PASSWORD GENERATOR -->

<div class="card">

<h2>🔐 Secure Password Generator</h2>

<br>

<input
id="generated"
readonly
placeholder="Generated password"
>

<div class="small-buttons">

<button onclick="generatePassword()">

🔑 Generate

</button>

<button onclick="copyPassword()">

📋 Copy

</button>

</div>

</div>


<!-- AI ASSISTANT -->

<div class="card">

<h2>🧠 AI Security Assistant</h2>

<br>


<div
class="chat"
id="chat">

<p>

🤖 AI: Hello! Ask me about
password or cybersecurity.

</p>

</div>


<input
id="question"
placeholder="Ask a cybersecurity question..."
>


<div class="small-buttons">

<button onclick="askAI()">

🤖 Ask AI

</button>

<button
class="voice"
id="questionVoiceButton"
onclick="voiceQuestion()">

🎤 Ask by Voice

</button>

</div>


<p
class="voice-status"
id="questionVoiceStatus">

🎤 Click Ask by Voice to speak

</p>

</div>


<!-- HISTORY -->

<div class="card">

<h2>🗄 Secure Analysis History</h2>

<br>

<div id="history">

Loading...

</div>

</div>


<!-- REPORT -->

<div class="card">

<h2>📄 Security Report</h2>

<br>

<button
class="primary"
onclick="downloadReport()">

📥 Download Report

</button>

</div>


</div>


<footer>

AI-Powered Password Security Analyzer

<br><br>

AI + Machine Learning + Cybersecurity

</footer>


<script>


// ========================================================
// THEME
// ========================================================

function toggleTheme(){

    document.body.classList.toggle("light");

}


// ========================================================
// SHOW / HIDE PASSWORD
// ========================================================

function togglePassword(){

    const input =
    document.getElementById("password");

    if(input.type === "password"){

        input.type = "text";

    }

    else{

        input.type = "password";

    }

}


// ========================================================
// VOICE RECOGNITION HELPER
// ========================================================

function getSpeechRecognition(){

    return window.SpeechRecognition ||
           window.webkitSpeechRecognition;

}


// ========================================================
// VOICE PASSWORD
// ========================================================

function startVoice(){

    const SpeechRecognition =
    getSpeechRecognition();


    if(!SpeechRecognition){

        alert(
            "Voice recognition is not supported. " +
            "Please use Google Chrome."
        );

        return;

    }


    const recognition =
    new SpeechRecognition();


    recognition.lang = "en-US";

    recognition.continuous = false;

    recognition.interimResults = false;

    recognition.maxAlternatives = 1;


    const button =
    document.getElementById("voiceButton");

    const status =
    document.getElementById("voiceStatus");


    recognition.onstart = function(){

        button.classList.add("listening");

        button.innerText =
        "🔴 Listening...";

        status.innerText =
        "🔴 Listening... Speak now!";

    };


    recognition.onresult =
    function(event){

        const text =
        event.results[0][0].transcript;


        document
        .getElementById("password")
        .value = text;


        status.innerText =
        "✅ Voice captured: " + text;

    };


    recognition.onerror =
    function(event){

        console.log(
            "Voice error:",
            event.error
        );


        if(event.error === "not-allowed"){

            status.innerText =
            "❌ Microphone permission denied.";

            alert(
                "Please allow microphone access in Chrome."
            );

        }

        else if(event.error === "no-speech"){

            status.innerText =
            "⚠ No speech detected. Try again.";

        }

        else{

            status.innerText =
            "❌ Voice error: " +
            event.error;

        }

    };


    recognition.onend =
    function(){

        button.classList.remove(
            "listening"
        );

        button.innerText =
        "🎤 Speak Password";

    };


    try{

        recognition.start();

    }

    catch(error){

        console.log(error);

    }

}


// ========================================================
// VOICE QUESTION
// ========================================================

function voiceQuestion(){

    const SpeechRecognition =
    getSpeechRecognition();


    if(!SpeechRecognition){

        alert(
            "Voice recognition is not supported. " +
            "Please use Google Chrome."
        );

        return;

    }


    const recognition =
    new SpeechRecognition();


    recognition.lang = "en-US";

    recognition.continuous = false;

    recognition.interimResults = false;

    recognition.maxAlternatives = 1;


    const button =
    document.getElementById(
        "questionVoiceButton"
    );


    const status =
    document.getElementById(
        "questionVoiceStatus"
    );


    recognition.onstart = function(){

        button.classList.add("listening");

        button.innerText =
        "🔴 Listening...";

        status.innerText =
        "🔴 Listening... Ask your question!";

    };


    recognition.onresult =
    function(event){

        const text =
        event.results[0][0].transcript;


        document
        .getElementById("question")
        .value = text;


        status.innerText =
        "✅ Question captured";


        askAI();

    };


    recognition.onerror =
    function(event){

        console.log(
            "Voice question error:",
            event.error
        );


        status.innerText =
        "❌ Voice error: " +
        event.error;

    };


    recognition.onend =
    function(){

        button.classList.remove(
            "listening"
        );

        button.innerText =
        "🎤 Ask by Voice";

    };


    try{

        recognition.start();

    }

    catch(error){

        console.log(error);

    }

}


// ========================================================
// TEXT TO SPEECH
// ========================================================

function speak(text){

    if(!("speechSynthesis" in window)){

        return;

    }


    window.speechSynthesis.cancel();


    const speech =
    new SpeechSynthesisUtterance(text);


    speech.lang = "en-US";

    speech.rate = 1;

    speech.pitch = 1;


    window.speechSynthesis.speak(
        speech
    );

}


// ========================================================
// AI CHAT
// ========================================================

function askAI(){

    const input =
    document.getElementById("question");


    const question =
    input.value.trim();


    if(!question){

        return;

    }


    const chat =
    document.getElementById("chat");


    chat.innerHTML +=

    "<p><strong>You:</strong> "
    + escapeHTML(question)
    + "</p>";


    const answer =
    getAIAnswer(
        question.toLowerCase()
    );


    chat.innerHTML +=

    "<p><strong>🤖 AI:</strong> "
    + answer
    + "</p>";


    chat.scrollTop =
    chat.scrollHeight;


    input.value = "";


    // Voice response

    speak(answer);

}


// ========================================================
// AI ANSWERS
// ========================================================

function getAIAnswer(question){

    if(question.includes("strong")){

        return "Use at least 12 characters with uppercase, lowercase, numbers and special characters.";

    }


    if(question.includes("mfa")){

        return "Multi-factor authentication adds another layer of protection even when your password is compromised.";

    }


    if(question.includes("entropy")){

        return "Password entropy measures unpredictability. Higher entropy generally means a password is harder to guess.";

    }


    if(question.includes("breach")){

        return "If your password appears in a known data breach, stop using it and replace it with a unique password.";

    }


    if(question.includes("reuse")){

        return "Avoid password reuse. Use a unique password for every important account.";

    }


    if(question.includes("brute")){

        return "A brute force attack repeatedly tries possible password combinations until the correct password is found.";

    }


    if(question.includes("password")){

        return "Use a long, unique password, avoid personal information, and enable multi-factor authentication.";

    }


    return "For better security, use a long unique password, enable MFA, avoid password reuse, and consider using a password manager.";

}


// ========================================================
// HTML ESCAPE
// ========================================================

function escapeHTML(text){

    return text
    .replace(/&/g,"&amp;")
    .replace(/</g,"&lt;")
    .replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;")
    .replace(/'/g,"&#039;");

}


// ========================================================
// ANALYZE
// ========================================================

async function analyzePassword(){

    const password =
    document.getElementById("password")
    .value;


    if(!password){

        alert(
            "Please enter a password."
        );

        return;

    }


    document.getElementById(
        "strength"
    ).innerText =
    "🤖 AI Analyzing...";


    try{

        const response =
        await fetch(
            "/analyze",
            {

                method:"POST",

                headers:{
                    "Content-Type":
                    "application/json"
                },

                body:JSON.stringify({
                    password:password
                })

            }
        );


        const data =
        await response.json();


        if(data.error){

            alert(data.error);

            return;

        }


        // SCORE

        document.getElementById("score")
        .innerText =
        data.score + "%";


        document.getElementById("progress")
        .style.width =
        data.score + "%";


        // STRENGTH

        const strength =
        document.getElementById(
            "strength"
        );


        strength.innerText =
        data.prediction;


        strength.className =
        data.prediction.toLowerCase();


        // LOCK

        document.getElementById(
            "lock"
        ).innerText = "🔓";


        // RISK

        const risk =
        document.getElementById("risk");


        risk.innerText =
        data.risk;


        risk.className =
        data.risk.toLowerCase();


        // CYBER RISKS

        if(data.prediction === "Weak"){

            document.getElementById("brute")
            .innerText = "HIGH";

            document.getElementById("dictionary")
            .innerText = "HIGH";

            document.getElementById("credential")
            .innerText = "MEDIUM";

        }

        else if(
            data.prediction === "Medium"
        ){

            document.getElementById("brute")
            .innerText = "MEDIUM";

            document.getElementById("dictionary")
            .innerText = "MEDIUM";

            document.getElementById("credential")
            .innerText = "LOW";

        }

        else{

            document.getElementById("brute")
            .innerText = "LOW";

            document.getElementById("dictionary")
            .innerText = "LOW";

            document.getElementById("credential")
            .innerText = "LOW";

        }


        // BREACH

        const breach =
        document.getElementById(
            "breach"
        );


        if(data.breach_error){

            breach.innerHTML =
            "<p>⚠ Unable to connect to breach database.</p>";

        }

        else if(data.breached){

            breach.innerHTML =

            "<h3 class='danger'>"
            +
            "⚠ PASSWORD FOUND IN BREACH DATABASE"
            +
            "</h3>"
            +
            "<br>"
            +
            "This password appeared "
            +
            "<strong>"
            +
            data.breach_count
            +
            "</strong>"
            +
            " times."
            +
            "<br><br>"
            +
            "Please choose another password.";

        }

        else{

            breach.innerHTML =

            "<h3 class='safe'>"
            +
            "✅ PASSWORD NOT FOUND"
            +
            "</h3>"
            +
            "<br>"
            +
            "The password was not found in "
            +
            "the checked breach database.";

        }


        // STATISTICS

        document.getElementById("length")
        .innerText =
        data.features.length;


        document.getElementById("uppercase")
        .innerText =
        data.features.uppercase;


        document.getElementById("lowercase")
        .innerText =
        data.features.lowercase;


        document.getElementById("digits")
        .innerText =
        data.features.digits;


        document.getElementById("special")
        .innerText =
        data.features.special;


        document.getElementById("entropy")
        .innerText =
        data.entropy + " Bits";


        // MFA

        let mfaHTML = "";


        data.mfa.forEach(
            function(item){

                mfaHTML +=
                "<div class='recommend'>"
                +
                "✔ "
                +
                item
                +
                "</div>";

            }
        );


        document.getElementById("mfa")
        .innerHTML =
        mfaHTML;


        loadHistory();

    }

    catch(error){

        console.error(error);

        alert(
            "Unable to connect to Flask server."
        );

    }

}


// ========================================================
// GENERATOR
// ========================================================

async function generatePassword(){

    const response =
    await fetch("/generate");


    const data =
    await response.json();


    document.getElementById(
        "generated"
    ).value =
    data.password;

}


// ========================================================
// COPY
// ========================================================

function copyPassword(){

    const value =
    document.getElementById(
        "generated"
    ).value;


    if(!value){

        alert(
            "Generate a password first."
        );

        return;

    }


    navigator.clipboard
    .writeText(value)
    .then(function(){

        alert(
            "Password copied!"
        );

    });

}


// ========================================================
// HISTORY
// ========================================================

async function loadHistory(){

    try{

        const response =
        await fetch("/history");


        const data =
        await response.json();


        let html = "";


        if(data.length === 0){

            html =
            "No analysis history.";

        }


        data.forEach(
            function(item){

                html += `

                <div class="recommend">

                <strong>
                ${item.strength}
                </strong>

                |

                Score:
                ${item.score}

                |

                Entropy:
                ${item.entropy}
                Bits

                |

                Breaches:
                ${item.breach_count}

                <br>

                ${item.created_at}

                </div>

                `;

            }
        );


        document.getElementById(
            "history"
        ).innerHTML =
        html;

    }

    catch(error){

        document.getElementById(
            "history"
        ).innerText =
        "Unable to load history.";

    }

}


// ========================================================
// REPORT
// ========================================================

function downloadReport(){

    const strength =
    document.getElementById(
        "strength"
    ).innerText;


    const score =
    document.getElementById(
        "score"
    ).innerText;


    const entropy =
    document.getElementById(
        "entropy"
    ).innerText;


    const risk =
    document.getElementById(
        "risk"
    ).innerText;


    const report =

`AI PASSWORD SECURITY REPORT

================================

Password is NOT included
for security reasons.

Strength:
${strength}

Security Score:
${score}

Entropy:
${entropy}

Risk:
${risk}

================================

Recommendations:

- Use unique passwords
- Use long passwords
- Enable MFA
- Avoid password reuse
- Use a password manager

================================

AI-Powered Password Security Analyzer
`;


    const blob =
    new Blob(
        [report],
        {
            type:"text/plain"
        }
    );


    const link =
    document.createElement("a");


    link.href =
    URL.createObjectURL(blob);


    link.download =
    "password_security_report.txt";


    link.click();

}


// ========================================================
// INITIALIZE
// ========================================================

loadHistory();

</script>

</body>

</html>
"""


# =========================================================
# START APPLICATION
# =========================================================

init_db()


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=True
    )