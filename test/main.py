import sys
sys.path.append('src/')
from src.flaskweb import app

if __name__ == '__main__':
    app.run(debug=True)
