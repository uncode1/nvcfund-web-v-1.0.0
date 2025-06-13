from flask import Flask
from datetime import datetime

def init_app(app: Flask):
    @app.template_filter('moment')
    def moment_filter(date):
        if isinstance(date, str):
            date = datetime.fromisoformat(date)
        return date

    # Register the filter
    app.jinja_env.filters['moment'] = moment_filter
