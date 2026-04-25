from flask import render_template, session


def register_crypto_page(app, login_required):
    """Register only the /crypto-pipeline page route.
    Seal/unseal endpoints are already in routes/evidence.py.
    """

    @app.route("/crypto-pipeline")
    @login_required
    def crypto_pipeline_page():
        return render_template(
            "crypto_pipeline.html",
            user=session.get("full_name", "User"),
            role=session.get("role", "Unknown"),
        )
