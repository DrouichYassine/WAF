from flask import Flask, render_template, request, flash, redirect, url_for

app = Flask(__name__)
app.secret_key = "demo-secret-key"  # For flashing messages

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        username = request.form.get("username", "")
        feedback = request.form.get("feedback", "")
        # In a real app, you'd do more here, but for demo, just thank the user.
        flash(f"Thank you, {username}, for your feedback!")
        return redirect(url_for("index"))
    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)