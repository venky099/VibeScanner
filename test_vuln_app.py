from flask import Flask, request, Response, redirect
import time

app = Flask(__name__)


@app.route("/")
def index():
    return """
    <html>
      <body>
        <h1>Intentional Test App</h1>
        <ul>
          <li><a href="/xss?q=hello">Reflected XSS test</a></li>
          <li><a href="/textarea?q=hello">Textarea reflection test</a></li>
          <li><a href="/sqli?id=1">SQLi error test</a></li>
          <li><a href="/sqli_bool?id=1">SQLi boolean test</a></li>
          <li><a href="/sqli_time?id=1">SQLi time-based test</a></li>
          <li><a href="/redirect?next=/safe-landing">Open redirect test</a></li>
          <li><a href="/help?topic=intro">False-positive SQL wording test</a></li>
          <li><a href="/forms">Form tests</a></li>
        </ul>
      </body>
    </html>
    """


@app.route("/xss")
def xss():
    payload = request.args.get("q", "")
    return f"<html><body><div>Search result: {payload}</div></body></html>"


@app.route("/textarea")
def textarea():
    payload = request.args.get("q", "")
    return f"<html><body><textarea>{payload}</textarea></body></html>"


@app.route("/sqli")
def sqli():
    item_id = request.args.get("id", "")
    if any(token in item_id for token in ["'", '"', " OR ", "UNION", "--"]):
        return Response(
            "sqlite3.OperationalError: unrecognized token near input",
            mimetype="text/html",
            status=500,
        )
    return f"<html><body>Product {item_id}</body></html>"


@app.route("/sqli_bool")
def sqli_bool():
    item_id = request.args.get("id", "")
    normalized = item_id.upper()

    if "AND 1=2" in normalized or "'1'='2" in normalized:
        return "<html><body><h2>No products found</h2></body></html>"

    if "AND 1=1" in normalized or "'1'='1" in normalized or "OR '1'='1" in normalized:
        return "<html><body><h2>Product 1</h2><div>In stock</div></body></html>"

    return "<html><body><h2>Product 1</h2><div>In stock</div></body></html>"


@app.route("/sqli_time")
def sqli_time():
    item_id = request.args.get("id", "")
    normalized = item_id.upper()

    if "SLEEP(3)" in normalized or "PG_SLEEP(3)" in normalized or "WAITFOR DELAY '0:0:3'" in normalized:
        time.sleep(3.1)
        return "<html><body><h2>Product 1</h2><div>Delayed lookup</div></body></html>"

    if "SLEEP(0)" in normalized or "PG_SLEEP(0)" in normalized or "WAITFOR DELAY '0:0:0'" in normalized:
        return "<html><body><h2>Product 1</h2><div>Delayed lookup</div></body></html>"

    return "<html><body><h2>Product 1</h2><div>Delayed lookup</div></body></html>"


@app.route("/redirect")
def open_redirect():
    target = request.args.get("next", "/safe-landing")
    return redirect(target, code=302)


@app.route("/safe-landing")
def safe_landing():
    return "<html><body><h2>Safe landing page</h2></body></html>"


@app.route("/help")
def help_page():
    topic = request.args.get("topic", "intro")
    return f"""
    <html>
      <body>
        <h2>Help</h2>
        <p>This page explains common syntax error messages and database error examples for topic: {topic}</p>
      </body>
    </html>
    """


@app.route("/forms", methods=["GET"])
def forms():
    return """
    <html>
      <body>
        <form action="/login" method="post">
          <input type="text" name="username" />
          <input type="password" name="password" />
          <input type="submit" value="Login" />
        </form>
        <form action="/feedback" method="post">
          <input type="text" name="comment" />
          <input type="submit" value="Send" />
        </form>
        <form action="/login_time" method="post">
          <input type="text" name="username" />
          <input type="password" name="password" />
          <input type="submit" value="Delayed Login" />
        </form>
        <form action="/bounce" method="get">
          <input type="text" name="next" />
          <input type="submit" value="Continue" />
        </form>
      </body>
    </html>
    """


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if any(token in username or token in password for token in ["'", '"', " OR ", "UNION", "--"]):
        return Response(
            "SQL syntax error: quoted string not properly terminated",
            mimetype="text/html",
            status=500,
        )
    return "<html><body>Login failed</body></html>"


@app.route("/feedback", methods=["POST"])
def feedback():
    comment = request.form.get("comment", "")
    return f"<html><body><textarea>{comment}</textarea></body></html>"


@app.route("/login_time", methods=["POST"])
def login_time():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    combined = f"{username} {password}".upper()

    if "SLEEP(3)" in combined or "PG_SLEEP(3)" in combined or "WAITFOR DELAY '0:0:3'" in combined:
        time.sleep(3.1)
        return "<html><body>Login failed</body></html>"

    return "<html><body>Login failed</body></html>"


@app.route("/bounce", methods=["GET"])
def bounce():
    target = request.args.get("next", "/safe-landing")
    return redirect(target, code=302)


if __name__ == "__main__":
    app.run(port=5001, debug=False, use_reloader=False)
