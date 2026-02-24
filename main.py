import web_hound
from flask import Flask, request, render_template 

app=Flask(__name__)
@app.route("/", methods=["GET", "POST"])


def index():
    scan_results=None

    if request.method=="POST":
        target= request.form.get('target_url')

        scan_results=web_hound.run_recon(target)

    return render_template("index.html", results=scan_results)
        

if __name__ =="__main__":
    app.run(debug=True)