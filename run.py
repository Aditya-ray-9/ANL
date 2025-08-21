# main.py
from flask import Flask, render_template, request, jsonify
from ANL_5 import ANL    # adjust to "from anl import ANL" if your file is named anl.py

app = Flask(__name__, template_folder="templates")

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/process", methods=["POST"])
def process():
    try:
        data = request.get_json() or {}
        text = data.get("text") or request.form.get("user_input") or ""
        if not text:
            return jsonify({"error": "no text provided"}), 400

        # call your ANL module (default: 9 char key, 'add' mode)
        obj = ANL.generate_with_key(text, key_text=None, key_length=9, mode="add")
        # obj contains: original, encoded, encoded_binary, key_text, key_binary, secured_binary
        return jsonify({
            "original": obj.get("original"),
            "encoded": obj.get("encoded"),
            "encoded_binary": obj.get("encoded_binary"),
            "key_text": obj.get("key_text"),
            "key_binary": obj.get("key_binary"),
            "secured_binary": obj.get("secured_binary")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/help')
def help_view():
    return render_template("help.html")

if __name__ == "__main__":
    app.run(debug=True)
