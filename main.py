import web_hound
from flask import Flask, request, render_template 

app=Flask(__name__)



@app.route("/", methods=["GET", "POST"])


def index():
    message= None

    if request.method=="POST":
        target= request.form.get('target_url')

        message=web_hound.test(target)

    return render_template("index.html", message=message)
        

if __name__ =="__main__":
    app.run(debug=True)