from flask import Flask, render_template, request, jsonify
import re
import hashlib
import secrets
import string
import math

app = Flask(__name__)


# =========================
# HOME PAGE
# =========================
@app.route("/")
def home():
    return render_template("home.html")


# =========================
# PASSWORD ANALYZER
# =========================
@app.route("/password", methods=["GET", "POST"])
def password():

    result = ""
    score = 0
    suggestions = []

    entropy = 0
    charset_size = 0
    password_length = 0
    security_message = ""

    # New pattern warnings
    pattern_warnings = []


    if request.method == "POST":

        pwd = request.form.get("password", "")

        password_length = len(pwd)


        # =================================
        # LENGTH CHECK
        # =================================

        if 8 <= len(pwd) <= 32:

            score += 20

        elif len(pwd) < 8:

            suggestions.append(
                "Use at least 8 characters."
            )

        elif len(pwd) > 32:

            suggestions.append(
                "Password should not exceed 32 characters."
            )


        # =================================
        # UPPERCASE CHECK
        # =================================

        if re.search(r"[A-Z]", pwd):

            score += 20

        else:

            suggestions.append(
                "Add at least one uppercase letter."
            )


        # =================================
        # LOWERCASE CHECK
        # =================================

        if re.search(r"[a-z]", pwd):

            score += 20

        else:

            suggestions.append(
                "Add at least one lowercase letter."
            )


        # =================================
        # NUMBER CHECK
        # =================================

        if re.search(r"[0-9]", pwd):

            score += 20

        else:

            suggestions.append(
                "Add at least one number."
            )


        # =================================
        # SPECIAL CHARACTER CHECK
        # =================================

        if re.search(r"[^A-Za-z0-9]", pwd):

            score += 20

        else:

            suggestions.append(
                "Add at least one special character."
            )


        # =================================
        # PASSWORD STRENGTH
        # =================================

        if score <= 40:

            result = "Weak"

        elif score <= 80:

            result = "Medium"

        else:

            result = "Strong"


        # =================================
        # CHARACTER SET SIZE
        # =================================

        if re.search(r"[a-z]", pwd):

            charset_size += 26

        if re.search(r"[A-Z]", pwd):

            charset_size += 26

        if re.search(r"[0-9]", pwd):

            charset_size += 10

        if re.search(r"[^A-Za-z0-9]", pwd):

            charset_size += 32


        # =================================
        # ENTROPY CALCULATION
        # =================================

        if password_length > 0 and charset_size > 0:

            entropy = round(
                password_length *
                math.log2(charset_size),
                2
            )


        # =================================
        # ENTROPY SECURITY LEVEL
        # =================================

        if entropy < 28:

            security_message = (
                "Very low security. "
                "This password should be improved."
            )

        elif entropy < 36:

            security_message = (
                "Low security. "
                "Consider using a longer and more complex password."
            )

        elif entropy < 60:

            security_message = (
                "Moderate security. "
                "A longer password would provide better protection."
            )

        elif entropy < 80:

            security_message = (
                "Good security. "
                "This password has a reasonable level of complexity."
            )

        else:

            security_message = (
                "Very strong password. "
                "It has high estimated entropy."
            )


        # =================================
        # COMMON PASSWORD DETECTION
        # =================================

        common_passwords = [
            "password",
            "password123",
            "123456",
            "12345678",
            "123456789",
            "qwerty",
            "qwerty123",
            "admin",
            "admin123",
            "welcome",
            "letmein",
            "abc123",
            "iloveyou",
            "monkey",
            "dragon"
        ]


        pwd_lower = pwd.lower()


        for common in common_passwords:

            if common in pwd_lower:

                pattern_warnings.append(
                    "Common password pattern detected."
                )

                break


        # =================================
        # REPEATED CHARACTER DETECTION
        # =================================

        if re.search(r"(.)\1{2,}", pwd):

            pattern_warnings.append(
                "Repeated characters detected."
            )


        # =================================
        # SEQUENTIAL NUMBER DETECTION
        # =================================

        sequences = [
            "0123456789",
            "1234567890",
            "9876543210"
        ]


        for sequence in sequences:

            found_sequence = False

            for i in range(len(sequence) - 2):

                part = sequence[i:i + 3]

                if part in pwd:

                    found_sequence = True

                    break


            if found_sequence:

                pattern_warnings.append(
                    "Sequential number pattern detected."
                )

                break


        # =================================
        # SEQUENTIAL LETTER DETECTION
        # =================================

        alphabet = "abcdefghijklmnopqrstuvwxyz"

        for i in range(len(alphabet) - 2):

            sequence = alphabet[i:i + 3]

            reverse_sequence = sequence[::-1]


            if (
                sequence in pwd_lower
                or
                reverse_sequence in pwd_lower
            ):

                pattern_warnings.append(
                    "Sequential letter pattern detected."
                )

                break


        # =================================
        # SAME CHARACTER TYPE DETECTION
        # =================================

        if len(pwd) >= 8:

            if (
                pwd.isalpha()
                or
                pwd.isdigit()
            ):

                pattern_warnings.append(
                    "Password uses only one character type."
                )


        # =================================
        # STRONG PASSWORD MESSAGE
        # =================================

        if result == "Strong":

            suggestions.append(
                "Excellent! Your password satisfies all basic security checks."
            )


        # =================================
        # LENGTH RECOMMENDATION
        # =================================

        if len(pwd) < 12:

            suggestions.append(
                "For better security, consider using 12 or more characters."
            )


        # =================================
        # PATTERN RECOMMENDATION
        # =================================

        if pattern_warnings:

            suggestions.append(
                "Avoid common words, repeated characters "
                "and predictable sequences."
            )


    return render_template(
        "password.html",

        result=result,

        score=score,

        suggestions=suggestions,

        entropy=entropy,

        charset_size=charset_size,

        password_length=password_length,

        security_message=security_message,

        pattern_warnings=pattern_warnings
    )


# =========================
# STRONG PASSWORD GENERATOR
# =========================
@app.route("/generate-password")
def generate_password():

    try:

        length = int(
            request.args.get(
                "length",
                16
            )
        )

    except ValueError:

        length = 16


    length = max(
        8,
        min(length, 32)
    )


    uppercase = string.ascii_uppercase

    lowercase = string.ascii_lowercase

    numbers = string.digits

    special = "!@#$%^&*"


    password_chars = [

        secrets.choice(uppercase),

        secrets.choice(lowercase),

        secrets.choice(numbers),

        secrets.choice(special)

    ]


    all_chars = (
        uppercase +
        lowercase +
        numbers +
        special
    )


    for _ in range(length - 4):

        password_chars.append(
            secrets.choice(all_chars)
        )


    secrets.SystemRandom().shuffle(
        password_chars
    )


    password = "".join(
        password_chars
    )


    return jsonify({

        "password": password

    })


# =========================
# FILE HASH GENERATOR
# =========================
@app.route("/hash", methods=["GET", "POST"])
def hash_file():

    hashes = {}

    if request.method == "POST":

        file = request.files.get("file")

        if file and file.filename:

            data = file.read()


            hashes["md5"] = hashlib.md5(
                data
            ).hexdigest()


            hashes["sha1"] = hashlib.sha1(
                data
            ).hexdigest()


            hashes["sha256"] = hashlib.sha256(
                data
            ).hexdigest()


    return render_template(
        "hash.html",
        hashes=hashes
    )


# =========================
# FILE INTEGRITY VERIFICATION
# =========================
@app.route("/verify", methods=["GET", "POST"])
def verify():

    result = ""

    if request.method == "POST":

        file = request.files.get("file")

        expected_hash = request.form.get(
            "hash",
            ""
        ).strip()


        if file and file.filename and expected_hash:

            data = file.read()


            generated_hash = hashlib.sha256(
                data
            ).hexdigest()


            if (
                generated_hash.lower()
                ==
                expected_hash.lower()
            ):

                result = "Hash Matched"

            else:

                result = "Hash Mismatch"


    return render_template(
        "verify.html",
        result=result
    )


# =========================
# RUN APPLICATION
# =========================
if __name__ == "__main__":

    app.run(
        debug=True
    )