# run.py
from flask import Flask, render_template, request, jsonify
from ANL_5 import ANL, binary_to_text, text_to_binary    # keep as your module name (ANL_5.py)

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
        obj = ANL.generate_with_key(text, key_text=None, mode="xor")
        return jsonify({
            "original": obj.get("original"),
            "encoded": obj.get("encoded"),
            "encoded_binary": obj.get("encoded_binary"),
            "key_text": obj.get("key_text"),
            "key_binary": obj.get("key_binary"),
            "secured_binary": binary_to_text(obj.get("secured_binary"))
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/translate", methods=["GET"])
def translate_view():
    return render_template("translate.html")

@app.route("/decode", methods=["POST"])
def decode():
    try:
        data = request.get_json() or {}
        secured_binary = data.get("secured_binary") or request.form.get("secured_binary") or ""
        key_text = data.get("key_text") or request.form.get("key_text") or ""
        if not secured_binary or not key_text:
            return jsonify({"error": "secured_binary and key_text required"}), 400
        secured_binary = text_to_binary(secured_binary)
        obj = {
            "secured_binary": secured_binary,
            "key_text": key_text,
            # include mode only if you used xor; default is add when generating
            # "mode": "add"
        }
        res = ANL.decrypt_from_object(obj, mode="xor")
        if res.get("error"):
            return jsonify({"error": res["error"]}), 400
        return jsonify({
            "recovered_encoded": res.get("recovered_encoded"),
            "decoded": res.get("decoded")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/help')
def help_view():
    return render_template("help.html")

if __name__ == "__main__":
    app.run(debug=True)
