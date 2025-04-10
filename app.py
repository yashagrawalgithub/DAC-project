from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Database connection helper
def get_db_connection():
    conn = sqlite3.connect('dac_database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Login required decorator with level check
def login_required(level=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))
            if level and session.get('level') != level:
                flash('You do not have permission to access this page', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['level'] = user['level']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required()
def dashboard():
    level = session.get('level')
    username = session.get('username')
    
    conn = get_db_connection()
    
    # Initialize variables
    data = []
    grants_to_medium = []
    grants_to_low = []
    medium_grants_to_low = []
    granted_to_low = {}
    
    if level == 'top':
        # Top level sees all their own data
        data = conn.execute('''
            SELECT id, data, owner_level, access_granted_to 
            FROM sensitive_data 
            WHERE owner_level = 'top'
        ''').fetchall()
        
        # Get all grants made by top to medium
        grants_to_medium = conn.execute('''
            SELECT g.id, sd.id as data_id, sd.data, g.grantee_level 
            FROM grants g
            JOIN sensitive_data sd ON g.data_id = sd.id
            WHERE g.granter_level = 'top' AND g.grantee_level = 'medium'
        ''').fetchall()
        
        # Get all grants made by top to low
        grants_to_low = conn.execute('''
            SELECT g.id, sd.id as data_id, sd.data, g.grantee_level 
            FROM grants g
            JOIN sensitive_data sd ON g.data_id = sd.id
            WHERE g.granter_level = 'top' AND g.grantee_level = 'low'
        ''').fetchall()
        
    elif level == 'medium':
        # Medium sees data granted by top and their own data
        data = conn.execute('''
            SELECT sd.id, sd.data, sd.owner_level, sd.access_granted_to 
            FROM sensitive_data sd
            LEFT JOIN grants g ON sd.id = g.data_id
            WHERE (g.grantee_level = 'medium' AND g.granter_level = 'top') OR 
                  sd.owner_level = 'medium'
            GROUP BY sd.id
        ''').fetchall()
        
        # Get all grants made by this medium to low
        medium_grants_to_low = conn.execute('''
            SELECT g.id as grant_id, sd.id as data_id, sd.data, g.grantee_level 
            FROM grants g
            JOIN sensitive_data sd ON g.data_id = sd.id
            WHERE g.granter_level = 'medium' AND g.grantee_level = 'low'
        ''').fetchall()
        
        # Create mapping of data_id to grant_id for easy lookup
        granted_to_low = {item['data_id']: item['grant_id'] for item in medium_grants_to_low}
        
    else:  # low level
        # Low sees data granted by top/medium and their own data
        data = conn.execute('''
            SELECT sd.id, sd.data, sd.owner_level, sd.access_granted_to 
            FROM sensitive_data sd
            LEFT JOIN grants g ON sd.id = g.data_id
            WHERE (g.grantee_level = 'low' AND g.granter_level IN ('top', 'medium')) OR 
                  sd.owner_level = 'low'
        ''').fetchall()
    
    conn.close()
    
    if level == 'top':
        return render_template(f'dashboard_{level}.html', 
                           username=username, 
                           level=level, 
                           data=data,
                           grants_to_medium=grants_to_medium,
                           grants_to_low=grants_to_low)
    elif level == 'medium':
        return render_template(f'dashboard_{level}.html', 
                            username=username, 
                            level=level, 
                            data=data,
                            medium_grants_to_low=medium_grants_to_low,
                            granted_to_low=granted_to_low)
    else:
        return render_template(f'dashboard_{level}.html', 
                            username=username, 
                            level=level, 
                            data=data)

# Top level operations
@app.route('/top_grant_to_medium', methods=['POST'])
@login_required('top')
def top_grant_to_medium():
    data_id = request.form['data_id']
    
    conn = get_db_connection()
    try:
        # Verify data belongs to top level
        data = conn.execute('SELECT * FROM sensitive_data WHERE id = ? AND owner_level = "top"', (data_id,)).fetchone()
        
        if data:
            # Check if grant already exists
            existing_grant = conn.execute('''
                SELECT id FROM grants 
                WHERE data_id = ? AND granter_level = 'top' AND grantee_level = 'medium'
            ''', (data_id,)).fetchone()
            
            if not existing_grant:
                # Create new grant
                conn.execute('''
                    INSERT INTO grants (data_id, granter_level, grantee_level)
                    VALUES (?, ?, ?)
                ''', (data_id, 'top', 'medium'))
                
                # Update access status
                conn.execute('''
                    UPDATE sensitive_data 
                    SET access_granted_to = 'medium'
                    WHERE id = ?
                ''', (data_id,))
                
                conn.commit()
                flash('Access granted to medium level successfully!', 'success')
            else:
                flash('Medium level already has access to this data', 'warning')
        else:
            flash('You can only grant access to data you own', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('dashboard'))

@app.route('/top_revoke_from_medium', methods=['POST'])
@login_required('top')
def top_revoke_from_medium():
    grant_id = request.form['grant_id']
    
    conn = get_db_connection()
    try:
        # Get grant details
        grant = conn.execute('''
            SELECT g.data_id 
            FROM grants g 
            WHERE g.id = ? AND g.granter_level = 'top' AND g.grantee_level = 'medium'
        ''', (grant_id,)).fetchone()
        
        if grant:
            data_id = grant['data_id']
            
            # Revoke the grant
            conn.execute('DELETE FROM grants WHERE id = ?', (grant_id,))
            
            # Update access status
            conn.execute('''
                UPDATE sensitive_data 
                SET access_granted_to = NULL 
                WHERE id = ? AND access_granted_to = 'medium'
            ''', (data_id,))
            
            # Revoke any dependent low-level grants
            medium_grants_to_low = conn.execute('''
                SELECT g.id 
                FROM grants g
                WHERE g.granter_level = 'medium' 
                AND g.grantee_level = 'low'
                AND g.data_id = ?
            ''', (data_id,)).fetchall()
            
            for grant in medium_grants_to_low:
                conn.execute('DELETE FROM grants WHERE id = ?', (grant['id'],))
                conn.execute('''
                    UPDATE sensitive_data 
                    SET access_granted_to = NULL 
                    WHERE id = ? AND access_granted_to = 'low'
                ''', (data_id,))
            
            conn.commit()
            flash('Access revoked from medium level with cascading effect!', 'success')
        else:
            flash('Grant not found or you cannot revoke this grant', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('dashboard'))

@app.route('/top_grant_to_low', methods=['POST'])
@login_required('top')
def top_grant_to_low():
    data_id = request.form['data_id']
    
    conn = get_db_connection()
    try:
        # Verify data belongs to top level
        data = conn.execute('SELECT * FROM sensitive_data WHERE id = ? AND owner_level = "top"', (data_id,)).fetchone()
        
        if data:
            # Check if grant already exists
            existing_grant = conn.execute('''
                SELECT id FROM grants 
                WHERE data_id = ? AND granter_level = 'top' AND grantee_level = 'low'
            ''', (data_id,)).fetchone()
            
            if not existing_grant:
                # Create new grant
                conn.execute('''
                    INSERT INTO grants (data_id, granter_level, grantee_level)
                    VALUES (?, ?, ?)
                ''', (data_id, 'top', 'low'))
                
                # Update access status
                conn.execute('''
                    UPDATE sensitive_data 
                    SET access_granted_to = 'low'
                    WHERE id = ?
                ''', (data_id,))
                
                conn.commit()
                flash('Access granted to low level successfully!', 'success')
            else:
                flash('Low level already has access to this data', 'warning')
        else:
            flash('You can only grant access to data you own', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('dashboard'))

@app.route('/top_revoke_from_low', methods=['POST'])
@login_required('top')
def top_revoke_from_low():
    grant_id = request.form['grant_id']
    
    conn = get_db_connection()
    try:
        # Get grant details
        grant = conn.execute('''
            SELECT g.data_id 
            FROM grants g 
            WHERE g.id = ? AND g.granter_level = 'top' AND g.grantee_level = 'low'
        ''', (grant_id,)).fetchone()
        
        if grant:
            data_id = grant['data_id']
            
            # Revoke the grant
            conn.execute('DELETE FROM grants WHERE id = ?', (grant_id,))
            
            # Update access status
            conn.execute('''
                UPDATE sensitive_data 
                SET access_granted_to = NULL 
                WHERE id = ? AND access_granted_to = 'low'
            ''', (data_id,))
            
            conn.commit()
            flash('Access revoked from low level successfully!', 'success')
        else:
            flash('Grant not found or you cannot revoke this grant', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('dashboard'))

# Medium level operations
@app.route('/medium_grant_to_low', methods=['POST'])
@login_required('medium')
def medium_grant_to_low():
    data_id = request.form['data_id']
    
    conn = get_db_connection()
    try:
        # Verify medium has access to this data (granted by top)
        data = conn.execute('''
            SELECT sd.id 
            FROM sensitive_data sd
            JOIN grants g ON sd.id = g.data_id
            WHERE sd.id = ? AND g.grantee_level = 'medium' AND g.granter_level = 'top'
        ''', (data_id,)).fetchone()
        
        if data:
            # Check if grant already exists
            existing_grant = conn.execute('''
                SELECT id FROM grants 
                WHERE data_id = ? AND granter_level = 'medium' AND grantee_level = 'low'
            ''', (data_id,)).fetchone()
            
            if not existing_grant:
                # Grant access to low level
                conn.execute('''
                    INSERT INTO grants (data_id, granter_level, grantee_level)
                    VALUES (?, ?, ?)
                ''', (data_id, 'medium', 'low'))
                
                # Update access status
                conn.execute('''
                    UPDATE sensitive_data 
                    SET access_granted_to = 'low'
                    WHERE id = ? AND access_granted_to = 'medium'
                ''', (data_id,))
                
                conn.commit()
                flash('Access granted to low level successfully!', 'success')
            else:
                flash('Low level already has access to this data', 'warning')
        else:
            flash('You can only grant access to data granted to you by top level', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('dashboard'))

@app.route('/medium_revoke_from_low', methods=['POST'])
@login_required('medium')
def medium_revoke_from_low():
    grant_id = request.form['grant_id']
    
    conn = get_db_connection()
    try:
        # Verify this grant exists and belongs to the current medium user
        grant = conn.execute('''
            SELECT g.data_id 
            FROM grants g
            JOIN sensitive_data sd ON g.data_id = sd.id
            WHERE g.id = ? 
            AND g.granter_level = 'medium' 
            AND g.grantee_level = 'low'
            AND sd.access_granted_to = 'low'
        ''', (grant_id,)).fetchone()
        
        if grant:
            data_id = grant['data_id']
            
            # Revoke the grant
            conn.execute('DELETE FROM grants WHERE id = ?', (grant_id,))
            
            # Update access status
            conn.execute('''
                UPDATE sensitive_data 
                SET access_granted_to = 'medium'
                WHERE id = ? AND access_granted_to = 'low'
            ''', (data_id,))
            
            conn.commit()
            flash('Access revoked from low level successfully!', 'success')
        else:
            flash('No such grant found or you cannot revoke this access', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)