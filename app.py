from flask import Flask, request, render_template, redirect, url_for
import numpy as np
import pandas as pd
from sklearn import metrics
import warnings
import pickle
import sqlite3
from datetime import datetime
from convert import convertion
warnings.filterwarnings('ignore')
from feature import FeatureExtraction

# Load the model
file = open("newmodel.pkl", "rb")
gbc = pickle.load(file)
file.close()


app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('phishdetector.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        status TEXT NOT NULL,
        has_ssl INTEGER NOT NULL,
        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()

# Initialize the database on startup
init_db()

# Helper function to add a scan to history
def add_to_history(url, status, has_ssl):
    conn = sqlite3.connect('phishdetector.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_history (url, status, has_ssl) VALUES (?, ?, ?)",
        (url, status, has_ssl)
    )
    conn.commit()
    conn.close()

# Helper function to get scan history
def get_history():
    conn = sqlite3.connect('phishdetector.db')
    conn.row_factory = sqlite3.Row  # This enables column access by name
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_history ORDER BY scan_date DESC")
    history = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return history

# Helper function to remove an entry from history
def remove_from_history(id):
    conn = sqlite3.connect('phishdetector.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history WHERE id = ?", (id,))
    conn.commit()
    conn.close()

# Helper function to add to whitelist
def add_to_whitelist(url):
    conn = sqlite3.connect('phishdetector.db')
    cursor = conn.cursor()
    # Check if URL already exists in whitelist
    cursor.execute("SELECT * FROM whitelist WHERE url = ?", (url,))
    if cursor.fetchone() is None:
        cursor.execute("INSERT INTO whitelist (url) VALUES (?)", (url,))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False

# Helper function to get whitelist
def get_whitelist():
    conn = sqlite3.connect('phishdetector.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM whitelist ORDER BY date_added DESC")
    whitelist = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return whitelist

# Helper function to remove from whitelist
def remove_from_whitelist(id):
    conn = sqlite3.connect('phishdetector.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM whitelist WHERE id = ?", (id,))
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return render_template("index.html")

@app.route('/result', methods=['POST', 'GET'])
def predict():
    if request.method == "POST":
        url = request.form["name"]
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)
        
        y_pred = gbc.predict(x)[0]
        # 1 is safe, -1 is unsafe
        
        # Convert prediction to result
        name = convertion(url, int(y_pred))
        
        # Get status from name with error handling
        status = name[1] if len(name) > 1 else "unknown"
        
        # Get SSL info with error handling
        has_ssl = 1 if len(name) > 3 and name[3] else 0
        
        # Add scan to history
        add_to_history(url, status, has_ssl)
        
        return render_template("index.html", name=name)

@app.route('/history')
def history():
    scan_history = get_history()
    return render_template('history.html', history=scan_history)

@app.route('/remove_history/<int:id>')
def remove_history(id):
    remove_from_history(id)
    return redirect(url_for('history'))

@app.route('/whitelist')
def whitelist():
    white_list = get_whitelist()
    return render_template('whitelist.html', whitelist=white_list)

@app.route('/add_whitelist', methods=['POST'])
def add_whitelist():
    url = request.form.get('url')
    if url:
        add_to_whitelist(url)
    return redirect(url_for('whitelist'))

@app.route('/add_whitelist_ajax', methods=['POST'])
def add_whitelist_ajax():
    url = request.form.get('url')
    if url:
        success = add_to_whitelist(url)
        return {'success': success}
    return {'success': False}

@app.route('/remove_whitelist/<int:id>')
def remove_whitelist(id):
    remove_from_whitelist(id)
    return redirect(url_for('whitelist'))

@app.route('/usecases', methods=['GET', 'POST'])
def usecases():
    return render_template('usecases.html')

if __name__ == "__main__":
    app.run(debug=True)