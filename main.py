import web_hound
from urllib.parse import urlparse
from flask import Flask, request, render_template

app = Flask(__name__)


def validate_url(url):
    """Kullanıcıdan gelen URL'i doğrular ve normalize eder."""
    if not url or not url.strip():
        return None, "URL boş olamaz."
    url = url.strip()
    # Protokol yoksa https ekle
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        return None, f"Geçersiz URL formatı: '{url}'"
    return url, None


@app.route("/", methods=["GET", "POST"])
def index():
    scan_results = None

    if request.method == "POST":
        target = request.form.get("target_url", "")
        target, err = validate_url(target)
        if err:
            scan_results = {"error": err}
        else:
            scan_results = web_hound.run_recon(target)

    return render_template("index.html", results=scan_results)


if __name__ == "__main__":
    app.run(debug=True)