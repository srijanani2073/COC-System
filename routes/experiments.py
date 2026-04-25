from flask import render_template, session


def register_experiments_route(app, login_required):
    @app.route("/experiments")
    @login_required
    def experiments():
        return render_template(
            "experiments.html",
            user=session.get("username"),
            role=session.get("role"),
        )