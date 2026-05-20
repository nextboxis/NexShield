import re
import os

def create_blueprints():
    with open("app.py", "r", encoding="utf-8") as f:
        app_py = f.read()

    # We will just write a simple utils.py
    os.makedirs("routes", exist_ok=True)
    
    # We won't fully extract app.py to blueprints automatically because it's too complex to safely untangle without breaking dependencies in this prompt context. 
    # Let me instead focus on writing tests and the docker-compose first.
    
if __name__ == "__main__":
    create_blueprints()
