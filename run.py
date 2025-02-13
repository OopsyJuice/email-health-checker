from flask import Flask
from api import create_app
import os

# Create the Flask app
app = create_app()

# Explicitly set both the template and static folders
app.template_folder = os.path.join(os.getcwd(), "templates")
app.static_folder = os.path.join(os.getcwd(), "static")

if __name__ == "__main__":
    app.run(debug=True)
