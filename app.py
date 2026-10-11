from flask import Flask, request, jsonify

import joblib
import os
import socket
import base64
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv


# ==========================================
# FLASK APP
# ==========================================

app = Flask(__name__)


# ==========================================
# LOAD ENVIRONMENT VARIABLES
# ==========================================

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


# ==========================================
# LOAD MACHINE LEARNING MODEL
# ==========================================

MODEL_PATH = "model/phishing_model.pkl"

try:

    saved_model = joblib.load(MODEL_PATH)

    model = saved_model["model"]
    vectorizer = saved_model["vectorizer"]

    print("Machine Learning model loaded successfully.")

except Exception as e:

    print("Error loading Machine Learning model:", e)

    model = None
    vectorizer = None


# ==========================================
# URL VALIDATION
# ==========================================

def validate_url(url):

    if not url:
        return False, "URL is empty."

    # BOTH HTTP AND HTTPS ARE ALLOWED

    if not url.startswith(("http://", "https://")):

        return False, (
            "URL must start with http:// or https://"
        )

    try:

        parsed = urlparse(url)

        if not parsed.netloc:
            return False, "Invalid URL."

        return True, "URL is valid."

    except Exception:

        return False, "Invalid URL."


# ==========================================
# URL PARSING
# ==========================================

def parse_url(url):

    parsed = urlparse(url)

    return {
        "scheme": parsed.scheme,
        "domain": parsed.hostname,
        "path": parsed.path,
        "query": parsed.query
    }


# ==========================================
# DOMAIN / DNS CHECK
# ==========================================

def domain_check(domain):

    if not domain:

        return {
            "valid": False,
            "resolves": False,
            "message": "Domain is missing."
        }

    try:

        ip_address = socket.gethostbyname(domain)

        return {
            "valid": True,
            "resolves": True,
            "ip": ip_address,
            "message": "Domain resolved successfully."
        }

    except socket.gaierror:

        return {
            "valid": False,
            "resolves": False,
            "message": "Domain could not be resolved."
        }

    except Exception as e:

        return {
            "valid": False,
            "resolves": False,
            "message": str(e)
        }


# ==========================================
# HTTP / HTTPS CHECK
# ==========================================

def https_check(scheme):

    scheme = scheme.lower()

    # --------------------------------------
    # HTTPS
    # --------------------------------------

    if scheme == "https":

        return {
            "protocol": "HTTPS",
            "https": True,
            "message": "Website uses HTTPS."
        }

    # --------------------------------------
    # HTTP
    # --------------------------------------

    if scheme == "http":

        return {
            "protocol": "HTTP",
            "https": False,
            "message": "Website uses HTTP."
        }

    # --------------------------------------
    # UNKNOWN
    # --------------------------------------

    return {
        "protocol": scheme.upper(),
        "https": False,
        "message": "Unknown protocol."
    }


# ==========================================
# URL CHARACTERISTICS
# ==========================================

def analyze_url_characteristics(url):

    score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.hostname or ""

    # --------------------------------------
    # URL LENGTH
    # --------------------------------------

    if len(url) > 100:

        score += 1

        reasons.append(
            "Long URL"
        )

    if len(url) > 200:

        score += 1

        reasons.append(
            "Very long URL"
        )

    # --------------------------------------
    # MANY SUBDOMAINS
    # --------------------------------------

    domain_parts = domain.split(".")

    if len(domain_parts) >= 5:

        score += 2

        reasons.append(
            "Many subdomains"
        )

    # --------------------------------------
    # IP ADDRESS AS DOMAIN
    # --------------------------------------

    if domain.replace(".", "").isdigit():

        score += 2

        reasons.append(
            "IP address used instead of domain name"
        )

    # --------------------------------------
    # SUSPICIOUS WORDS
    # --------------------------------------

    suspicious_words = [

        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "signin",
        "banking",
        "wallet",
        "payment",
        "security"

    ]

    url_lower = url.lower()

    found_words = []

    for word in suspicious_words:

        if word in url_lower:

            found_words.append(word)

    if len(found_words) >= 3:

        score += 2

        reasons.append(
            "Multiple suspicious words"
        )

    # --------------------------------------
    # @ SYMBOL
    # --------------------------------------

    if "@" in url:

        score += 2

        reasons.append(
            "@ symbol found in URL"
        )

    # --------------------------------------
    # MANY HYPHENS
    # --------------------------------------

    if domain.count("-") >= 3:

        score += 1

        reasons.append(
            "Many hyphens in domain"
        )

    # --------------------------------------
    # MANY QUERY PARAMETERS
    # --------------------------------------

    if parsed.query:

        parameter_count = len(
            parsed.query.split("&")
        )

        if parameter_count >= 5:

            score += 1

            reasons.append(
                "Many URL parameters"
            )

    # --------------------------------------
    # NO SUSPICIOUS CHARACTERISTICS
    # --------------------------------------

    if score == 0:

        reasons.append(
            "No suspicious URL characteristics detected."
        )

    return {
        "score": score,
        "reasons": reasons
    }


# ==========================================
# VIRUSTOTAL LIVE CHECK
# ==========================================

def threat_database_check(url):

    if not VIRUSTOTAL_API_KEY:

        return {
            "checked": False,
            "threat_found": False,
            "message":
                "VirusTotal API key is not configured."
        }

    try:

        # ----------------------------------
        # CREATE VIRUSTOTAL URL ID
        # ----------------------------------

        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        api_url = (
            "https://www.virustotal.com/api/v3/urls/"
            + url_id
        )

        headers = {
            "x-apikey":
                VIRUSTOTAL_API_KEY
        }

        response = requests.get(
            api_url,
            headers=headers,
            timeout=10
        )

        # ----------------------------------
        # URL REPORT FOUND
        # ----------------------------------

        if response.status_code == 200:

            data = response.json()

            attributes = (
                data
                .get("data", {})
                .get("attributes", {})
            )

            stats = attributes.get(
                "last_analysis_stats",
                {}
            )

            malicious = stats.get(
                "malicious",
                0
            )

            suspicious = stats.get(
                "suspicious",
                0
            )

            harmless = stats.get(
                "harmless",
                0
            )

            undetected = stats.get(
                "undetected",
                0
            )

            threat_found = (
                malicious > 0
                or
                suspicious > 0
            )

            if threat_found:

                message = (
                    "VirusTotal reported "
                    "malicious or suspicious detections."
                )

            else:

                message = (
                    "No malicious detection "
                    "was reported."
                )

            return {
                "checked": True,
                "threat_found": threat_found,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "message": message
            }

        # ----------------------------------
        # URL NOT FOUND
        # ----------------------------------

        if response.status_code == 404:

            return {
                "checked": True,
                "threat_found": False,
                "message": (
                    "URL is not currently present "
                    "in VirusTotal's URL report."
                )
            }

        # ----------------------------------
        # API ERROR
        # ----------------------------------

        return {
            "checked": False,
            "threat_found": False,
            "message": (
                "VirusTotal API returned status "
                + str(response.status_code)
            )
        }

    except requests.RequestException as e:

        return {
            "checked": False,
            "threat_found": False,
            "message": (
                "VirusTotal request failed: "
                + str(e)
            )
        }

    except Exception as e:

        return {
            "checked": False,
            "threat_found": False,
            "message": str(e)
        }


# ==========================================
# MACHINE LEARNING PREDICTION
# ==========================================

def machine_learning_prediction(url):

    if model is None or vectorizer is None:

        return {
            "result": "Unknown",
            "confidence": 0,
            "message":
                "ML model is not loaded."
        }

    try:

        # ----------------------------------
        # TF-IDF FEATURE EXTRACTION
        # ----------------------------------

        url_features = vectorizer.transform(
            [url]
        )

        # ----------------------------------
        # MODEL PREDICTION
        # ----------------------------------

        prediction = model.predict(
            url_features
        )[0]

        # ----------------------------------
        # PREDICTION PROBABILITY
        # ----------------------------------

        probabilities = model.predict_proba(
            url_features
        )[0]

        confidence = max(
            probabilities
        ) * 100

        # ----------------------------------
        # LABEL MEANING
        # ----------------------------------
        #
        # 0 = Phishing
        # 1 = Legitimate
        #

        if prediction == 0:

            result = "Phishing"

        else:

            result = "Legitimate"

        return {
            "result": result,
            "confidence": round(
                confidence,
                2
            )
        }

    except Exception as e:

        return {
            "result": "Unknown",
            "confidence": 0,
            "message": str(e)
        }


# ==========================================
# FINAL DECISION
# ==========================================

def final_decision(
    ml_result,
    url_characteristics,
    domain_result,
    https_result,
    threat_result
):

    risk_score = 0
    reasons = []

    ml_result_value = ml_result.get(
        "result",
        "Unknown"
    )

    ml_confidence = ml_result.get(
        "confidence",
        0
    )

    url_score = url_characteristics.get(
        "score",
        0
    )

    domain_resolves = domain_result.get(
        "resolves",
        False
    )

    threat_found = threat_result.get(
        "threat_found",
        False
    )

    # ======================================
    # 1. VIRUSTOTAL STRONG SIGNAL
    # ======================================

    if threat_found:

        risk_score += 5

        reasons.append(
            "VirusTotal reported a malicious or suspicious threat."
        )

    # ======================================
    # 2. DOMAIN CHECK
    # ======================================

    if not domain_resolves:

        risk_score += 2

        reasons.append(
            "Domain could not be resolved."
        )

    else:

        reasons.append(
            "Domain resolved successfully."
        )

    # ======================================
    # 3. URL CHARACTERISTICS
    # ======================================

    risk_score += url_score

    if url_score > 0:

        reasons.extend(
            url_characteristics.get(
                "reasons",
                []
            )
        )

    else:

        reasons.append(
            "No suspicious URL characteristics detected."
        )

    # ======================================
    # 4. HTTP / HTTPS
    # ======================================

    if https_result.get("https", False):

        reasons.append(
            "Website uses HTTPS."
        )

    else:

        reasons.append(
            "Website uses HTTP."
        )

    # ======================================
    # 5. MACHINE LEARNING
    # ======================================

    if ml_result_value == "Phishing":

        reasons.append(
            "Machine Learning model detected a suspicious URL pattern."
        )

    elif ml_result_value == "Legitimate":

        reasons.append(
            "Machine Learning model classified the URL as legitimate."
        )

    # ======================================
    # 6. FINAL DECISION
    # ======================================

    if threat_found:

        final_result = "Phishing"

        message = (
            "Warning! This website appears "
            "to be phishing or potentially unsafe."
        )

    elif (
        not domain_resolves
        and url_score >= 2
    ):

        final_result = "Phishing"

        message = (
            "Warning! This website appears "
            "to be phishing or potentially unsafe."
        )

    elif (
        ml_result_value == "Phishing"
        and url_score >= 3
    ):

        final_result = "Phishing"

        message = (
            "Warning! This website appears "
            "to be phishing or potentially unsafe."
        )

    elif (
        ml_result_value == "Phishing"
        and ml_confidence >= 99
        and not domain_resolves
    ):

        final_result = "Phishing"

        message = (
            "Warning! This website appears "
            "to be phishing or potentially unsafe."
        )

    else:

        final_result = "Legitimate"

        message = (
            "This website appears to be legitimate."
        )

    return {
        "result": final_result,
        "message": message,
        "risk_score": risk_score,
        "reasons": reasons
    }


# ==========================================
# PREDICT API
# ==========================================

@app.route(
    "/predict",
    methods=["POST"]
)
def predict():

    try:

        data = request.get_json()

        if not data:

            return jsonify({

                "success": False,

                "message":
                    "No JSON data received."

            }), 400

        url = data.get(
            "url",
            ""
        ).strip()

        # ----------------------------------
        # URL VALIDATION
        # ----------------------------------

        valid, validation_message = (
            validate_url(url)
        )

        if not valid:

            return jsonify({

                "success": False,

                "url": url,

                "result": "Invalid",

                "message":
                    validation_message

            }), 400

        # ----------------------------------
        # URL PARSING
        # ----------------------------------

        parsed_data = parse_url(
            url
        )

        domain = parsed_data[
            "domain"
        ]

        scheme = parsed_data[
            "scheme"
        ]

        # ----------------------------------
        # DOMAIN CHECK
        # ----------------------------------

        domain_result = domain_check(
            domain
        )

        # ----------------------------------
        # HTTP / HTTPS CHECK
        # ----------------------------------

        https_result = https_check(
            scheme
        )

        # ----------------------------------
        # URL CHARACTERISTICS
        # ----------------------------------

        url_characteristics = (
            analyze_url_characteristics(
                url
            )
        )

        # ----------------------------------
        # VIRUSTOTAL CHECK
        # ----------------------------------

        threat_result = (
            threat_database_check(
                url
            )
        )

        # ----------------------------------
        # MACHINE LEARNING
        # ----------------------------------

        ml_result = (
            machine_learning_prediction(
                url
            )
        )

        # ----------------------------------
        # FINAL DECISION
        # ----------------------------------

        decision = final_decision(

            ml_result,

            url_characteristics,

            domain_result,

            https_result,

            threat_result

        )


        # ==========================================
        # TERMINAL LIVE RESULT
        # ==========================================

        print()
        print("====================================")
        print("LIVE PHISHING DETECTION")
        print("====================================")

        print(
            "URL:",
            url
        )

        print(
            "Result:",
            decision["result"]
        )

        print(
            "Confidence:",
            ml_result["confidence"],
            "%"
        )

        print(
            "Risk Score:",
            decision["risk_score"]
        )

        print(
            "Message:",
            decision["message"]
        )

        print(
            "===================================="
        )


        # ----------------------------------
        # FINAL RESPONSE
        # ----------------------------------

        return jsonify({

            "success": True,

            "url": url,

            "result":
                decision["result"],

            "message":
                decision["message"],

            "confidence":
                ml_result["confidence"],

            "risk_score":
                decision["risk_score"],

            "checks": {

                "url_validation":
                    True,

                "domain":
                    domain_result,

                "https":
                    https_result,

                "url_characteristics":
                    url_characteristics,

                "threat_database":
                    threat_result,

                "machine_learning":
                    ml_result

            },

            "reasons":
                decision["reasons"]

        })

    except Exception as e:

        return jsonify({

            "success": False,

            "message": (
                "Server error: "
                + str(e)
            )

        }), 500


# ==========================================
# HOME ROUTE
# ==========================================

@app.route("/")
def home():

    return jsonify({

        "success": True,

        "message":
            "Phishing Detection API is running."

    })


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    print(
        "===================================="
    )

    print(
        "Phishing Detection Flask API"
    )

    print(
        "===================================="
    )

    print(
        "Server running at:"
    )

    print(
        "http://127.0.0.1:5000"
    )

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True

    )