from flask import Flask, render_template, request, redirect, session, send_file, make_response
import psycopg2
import socket
from datetime import datetime
import csv
import io
import ipinfo
import smtplib
import requests
from functools import wraps
from email.message import EmailMessage
import re
import os
import psycopg2
from flask import jsonify
import requests
import bcrypt

def hash_password(plain_password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def is_ip_malicious_virustotal(ip_address):
   api_key = 'ff9ba630e04a597946dcb167ad45d0e3f702a6e0f1bc8e87f82568b35060ad73'
   url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
   headers = {"x-apikey": api_key}
   try:
       response = requests.get(url, headers=headers)
       if response.status_code == 200:
           data = response.json()
           stats = data['data']['attributes']['last_analysis_stats']
           malicious = stats.get('malicious', 0)
           suspicious = stats.get('suspicious', 0)
           if malicious > 0 or suspicious > 0:
               return True
       return False
   except Exception as e:
       print(f"VirusTotal IP check failed: {e}")
       return False

def evaluate_risk(data):
    username = data.get("username", "")
    device = data.get("device", "").lower()
    location = data.get("location", "").lower()
    login_time = data.get("time", "")  # format "HH:MM"
    ip_address = data.get("ip", "")  # optional field if you include IP
    weekday = datetime.now().weekday()  # 0 = Monday, 6 = Sunday
 
    risk_score = 0
 
    # Rule 1: Suspicious device
    if device in ["unknown", "linux vm", "tor browser"]:
        risk_score += 2
 
    # Rule 2: Suspicious location
    if location not in ["lebanon", "france", "usa"]:
        risk_score += 2
 
    # Rule 3: Suspicious login time
    try:
        hour = int(login_time.split(":")[0])
        if hour < 6 or hour > 22:
            risk_score += 1
    except:
        risk_score += 1
 
    # Rule 4: Weekend login
    if weekday in [5, 6]:  # Saturday = 5, Sunday = 6
        risk_score += 1
 
    # Rule 5: Suspicious IP pattern (you can customize this)
    if ip_address.startswith("185.") or ip_address.startswith("89.") or ip_address.startswith("37."):
        risk_score += 2
 
    # Rule 6: Admin strict rule
    if username.lower() == "admin":
        risk_score += 1
 
    # Final decision
    if risk_score >= 5:
        return "High"
    elif risk_score >= 3:
        return "Medium"
    else:
        return "Safe"

app = Flask(__name__)
app.secret_key = 'your_secret_key'
 
# --- Database Connection ---
from db_connection import get_db_connection

 
# --- No-Cache After Each Response ---
@app.after_request
def add_no_cache(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response
 
# --- Send Alert Email ---
def send_alert_email(username, ip, country, city, device):
    msg = EmailMessage()
    msg['Subject'] = '🚨 DRBAC High-Risk Login Alert'
    msg['From'] = 'alerts@drbac.local'
    msg['To'] = 'admin@drbac-system.local'
    msg.set_content(f'''
A high-risk login was detected:
 
👤 User: {username}
🌍 Location: {city}, {country}
🖥️ IP Address: {ip}
📱 Device: {device}
 
⚠️ Risk Level: HIGH
Please review this activity immediately.
''')
 
    try:
        with smtplib.SMTP('sandbox.smtp.mailtrap.io', 587) as smtp:
            smtp.starttls()
            smtp.login('53a9909633f5fe', '94fe03c1f616b2')
            smtp.send_message(msg)
            print('✅ Mailtrap alert sent successfully!')
    except Exception as e:
        print(f'❌ Mailtrap send failed: {e}')

# --- Decorator: Login Required ---
def login_required(role=None):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('user'):
                session.clear()
                return redirect('/')
            username = session.get('user')
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM active_sessions WHERE username = %s', (username,))
            active = cur.fetchone()
            cur.close()
            conn.close()
            if not active:
                session.clear()
                return redirect('/')
            if role and session.get('role') != role:
                session.clear()
                return redirect('/')
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

@app.route('/simulate_login', methods=['POST'])
def simulate_login():
    data = request.json
    risk = evaluate_risk(data)
    return jsonify({"risk": risk}) 
# --- Home ---
@app.route('/')
def home():
    if 'user' in session:
        return redirect('/dashboard')
    return make_response(render_template('login.html'))

from flask import jsonify

@app.route('/login', methods=['POST'])

def login():

    username = request.form['username']

    password = request.form['password']

    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

    ua = request.user_agent.string.lower()

    if 'iphone' in ua:

        device = 'iPhone'

    elif 'ipad' in ua:

        device = 'iPad'

    elif 'android' in ua:

        device = 'Android Device'

    elif 'windows' in ua:

        device = 'Windows PC'

    elif 'macintosh' in ua or 'mac os' in ua:

        device = 'Mac'

    elif 'linux' in ua:

        device = 'Linux Device'

    else:

        device = 'Unknown'

    conn = get_db_connection()

    cur = conn.cursor()
    # malicious ip check
    if is_ip_malicious_virustotal(ip_address):
        cur.close()
        conn.close()
        return jsonify({'status': 'error', 'message': '❌ Cannot login: Malicious IP detected.'})
    
    #blacklisted ip check
    cur.execute('SELECT 1 FROM blocked_ips WHERE ip = %s', (ip_address,))
    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({'status': 'error', 'message': '❌ Login blocked: IP is blacklisted.'})
    # Lockdown check

    cur.execute('SELECT active, end_time FROM system_lockdown ORDER BY id DESC LIMIT 1')

    lockdown = cur.fetchone()

    if lockdown:

        active, end_time = lockdown

        if active and end_time > datetime.datetime.now():

            cur.execute('SELECT role FROM users WHERE username = %s', (username,))

            result = cur.fetchone()

            if result is None or result[0] != 'admin':

                cur.close()

                conn.close()

                return jsonify({'status': 'error', 'message': '🚫 System under emergency lockdown.'})

    # Credential check

    cur.execute('SELECT * FROM users WHERE username = %s', (username,))
    user = cur.fetchone()

    if not user:

        cur.close()

        conn.close()

        return jsonify({'status': 'error', 'message': '❌ Invalid credentials'})
    
    stored_hashed_password = user[2]  
    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
        cur.close()
        conn.close()
        return jsonify({'status': 'error', 'message': '❌ Invalid credentials'})



    if user[8] != 'active':

        cur.close()

        conn.close()

        return jsonify({'status': 'error', 'message': '❌ Your account is suspended or deleted.'})

    # Blocked user check

    cur.execute('SELECT 1 FROM blocked_users WHERE username = %s', (username,))

    is_blocked = cur.fetchone()

    if is_blocked:

        cur.close()

        conn.close()

        return jsonify({'status': 'error', 'message': '❌ Your account is blocked by the admin.'})

    # Multi-device check

    cur.execute('SELECT device FROM active_sessions WHERE username = %s', (username,))

    existing_session = cur.fetchone()

    if existing_session and existing_session[0] != device:

        cur.close()

        conn.close()

        return jsonify({'status': 'error', 'message': '❌ Multi-device login detected. Blocked.'})

    # IP info

    access_token = '56dd46be625f08'

    handler = ipinfo.getHandler(access_token)

    try:

        details = handler.getDetails(ip_address)

        info = details.all

        country = info.get('country', 'Unknown')

        city = info.get('city', 'Unknown')

    except:

        country = 'Unknown'

        city = 'Unknown'

    now = datetime.now()

    weekday = now.weekday()

    hour = now.hour

    # Travel detection

    cur.execute('SELECT country, login_time FROM travel_logs WHERE username = %s ORDER BY login_time DESC LIMIT 1', (username,))

    last_travel = cur.fetchone()

    if last_travel:

        last_country, last_login_time = last_travel

        if last_country != country:

            time_diff_hours = (now - last_login_time).total_seconds() / 3600

            if time_diff_hours <= 6:

                cur.close()

                conn.close()

                return jsonify({'status': 'error', 'message': '❌ Travel detected in short time. Contact Admin.'})

    # Insert travel log

    cur.execute('INSERT INTO travel_logs (username, country, login_time) VALUES (%s, %s, %s)', (username, country, now))

    conn.commit()

    # Update session table

    cur.execute('''

        INSERT INTO active_sessions (username, ip, login_time, device)

        VALUES (%s, %s, %s, %s)

        ON CONFLICT (username) DO UPDATE SET ip=EXCLUDED.ip, login_time=EXCLUDED.login_time, device=EXCLUDED.device

    ''', (username, ip_address, now, device))

    conn.commit()

    # Risk Evaluation

    role = user[3]

    risk = 'low'

    risk_reasons = []

    if role == 'admin':

        if weekday >= 5:

            risk = 'high'

            risk_reasons.append("Weekend login")

        if hour < 6:

            risk = 'high'

            risk_reasons.append("Login between 12 AM and 6 AM")

        if device in ['iPhone', 'iPad', 'Android Device']:

            risk = 'high'

            risk_reasons.append("Mobile device used")

        if country.lower() != 'lb':

            risk = 'high'

            risk_reasons.append("Login from outside Lebanon")

    else:

        if hour < 8 or hour >= 18:

            risk = 'high'

            risk_reasons.append("Login outside working hours")

        if weekday >= 5:

            risk = 'high'

            risk_reasons.append("Weekend login")

        if device in ['iPhone', 'iPad', 'Android Device', 'Unknown']:

            risk = 'high'

            risk_reasons.append("Mobile device used")

        if country.lower() != 'lb':

            risk = 'high'

            risk_reasons.append("Login from outside Lebanon")

    # Location mismatch detection

    cur.execute('SELECT city, country FROM access_logs WHERE username = %s ORDER BY login_time DESC LIMIT 1', (username,))

    last_location = cur.fetchone()

    if last_location:

        last_city, last_country = last_location

        if last_city != city or last_country != country:

            risk = 'high'

            risk_reasons.append("Location mismatch with previous login")

    # Insert access log

    cur.execute('''

        INSERT INTO access_logs (username, role, ip, login_time, risk, country, city, device)

        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)

    ''', (username, role, ip_address, now.strftime("%Y-%m-%d %H:%M:%S"), risk, country, city, device))

    conn.commit()

    cur.close()

    conn.close()

    if risk == 'high':

        send_alert_email(username, ip_address, country, city, device)

    session['user'] = username

    session['role'] = role

    session['ip'] = ip_address

    session['device'] = device

    session['risk'] = risk

    session['risk_reason'] = risk_reasons if risk_reasons else ["Normal login conditions"]

    session['time_context'] = 'day' if 8 <= hour < 18 else 'night'

    session['allowed_page'] = 'dashboard'

    return jsonify({'status': 'success', 'redirect': '/dashboard'})
 
# --- Dashboard ---
@app.route('/dashboard')
@login_required()
def dashboard():
    session['allowed_page'] = 'dashboard'
    return make_response(render_template(
        'dashboard.html',
        user=session['user'],
        role=session['role'],
        ip=session['ip'],
        device=session['device'],
        risk=session['risk'],
        time_context=session['time_context'],
        risk_reason=session.get('risk_reason', ['No unusual conditions detected.'])
                    ))
# --- Admin Logs ---
@app.route('/admin_logs')
@login_required(role='admin')
def admin_logs():
   
   session['allowed_page'] = 'admin_logs'
   conn = get_db_connection()
   cur = conn.cursor()
   query = '''
       SELECT * FROM access_logs WHERE 1=1
   '''
   filters = []
   # --- Filter by Risk Level ---
   if request.args.get('risk'):
       query += ' AND risk = %s'
       filters.append(request.args.get('risk'))
   # --- Filter by Date ---
   if request.args.get('date'):
       query += ' AND DATE(login_time) = %s'
       filters.append(request.args.get('date'))
   # --- Pagination Setup ---
   page = request.args.get('page', 1, type=int)
   per_page = 10
   offset = (page - 1) * per_page
   query += ' ORDER BY login_time DESC LIMIT %s OFFSET %s'
   filters += [per_page, offset]
   # --- Execute ---
   cur.execute(query, tuple(filters))
   logs = cur.fetchall()
   # --- Check if Next Page Exists ---
   cur.execute('SELECT COUNT(*) FROM access_logs')
   total_logs = cur.fetchone()[0]
   has_next = (page * per_page) < total_logs
   conn.close()
   return render_template(

        'admin_logs.html',

        logs=logs,

        page=page,

        has_next=has_next,

        role=session['role']  # <-- make sure this is included

    )
 
@app.route('/admin_activity_logs')
@login_required(role='admin')
def admin_activity_logs():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT admin_username, action, target_username, action_time FROM admin_logs ORDER BY action_time DESC')
    logs = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin_activity_logs.html', logs=logs,  role=session['role'])
# --- Block User ---
@app.route('/block_user/<username>')
@login_required(role='admin')
def block_user(username):
    conn = get_db_connection()
    cur = conn.cursor()
 
    # Block user
    cur.execute('INSERT INTO blocked_users (username) VALUES (%s) ON CONFLICT DO NOTHING', (username,))
 
    # Log admin action
    cur.execute('''
        INSERT INTO admin_logs (admin_username, action, target_username)
        VALUES (%s, %s, %s)
    ''', (session['user'], 'Block User', username))
 
    conn.commit()
    cur.close()
    conn.close()
 
    return redirect('/admin_logs')
# --- Unblock User ---
@app.route('/unblock_user/<username>')
@login_required(role='admin')
def unblock_user(username):
    conn = get_db_connection()
    cur = conn.cursor()
 
    # Unblock user
    cur.execute('DELETE FROM blocked_users WHERE username = %s', (username,))
 
    # Log admin action
    cur.execute('''
        INSERT INTO admin_logs (admin_username, action, target_username)
        VALUES (%s, %s, %s)
    ''', (session['user'], 'Unblock User', username))
 
    conn.commit()
    cur.close()
    conn.close()
 
    return redirect('/admin_logs')
# --- Blocked Users List ---
@app.route('/blocked_users')
@login_required(role='admin')
def blocked_users():
    session['allowed_page'] = 'blocked_users'
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT username FROM blocked_users')
    users = cur.fetchall()
    conn.close()
 
    return make_response(render_template('blocked_users.html', users=users,  role=session['role']))
@app.route('/start_lockdown')
@login_required(role='admin')
def start_lockdown():
    conn = get_db_connection()
    cur = conn.cursor()
    now = datetime.now()
    end_time = now + datetime.timedelta(hours=6)  # lockdown lasts 6 hours
    cur.execute('INSERT INTO system_lockdown (active, start_time, end_time) VALUES (TRUE, %s, %s)', (now, end_time))
    conn.commit()
    cur.close()
    conn.close()
    return redirect('/admin_logs')
 
# --- End Lockdown ---
@app.route('/end_lockdown')
@login_required(role='admin')
def end_lockdown():
    conn = get_db_connection()
    cur = conn.cursor()
 
    cur.execute('UPDATE system_lockdown SET active = FALSE WHERE active = TRUE')
 
    # Log admin action
    cur.execute('''
        INSERT INTO admin_activity_logs (admin_username, action)
        VALUES (%s, %s)
    ''', (session['user'], 'End Lockdown'))
 
    conn.commit()
    cur.close()
    conn.close()
 
    return redirect('/admin_logs')
# ✅ Flask Route: /admin_users
# ----- my_logins -------#
@app.route('/my_logins', methods=['GET', 'POST'])
@login_required()
def my_logins():
    username = session.get('user')
    conn = get_db_connection()
    cur = conn.cursor()
    message = None
 
    # Handle suspicious report
    if request.method == 'POST' and 'log_id' in request.form:
        log_id = request.form['log_id']
        reason = request.form['reason']
        cur.execute('SELECT 1 FROM suspicious_reports WHERE username = %s AND log_id = %s', (username, log_id))
        if not cur.fetchone():
            cur.execute('''
                INSERT INTO suspicious_reports (username, log_id, reason, report_time)
                VALUES (%s, %s, %s, NOW())
            ''', (username, log_id, reason))
            conn.commit()
            message = '🚨 Suspicious activity reported successfully.'
        else:
            message = '⚠️ You already reported this login.'
 
    # Pagination setup
    page = request.args.get('page', 1, type=int)
    per_page = 5
    offset = (page - 1) * per_page
 
    # Fetch login logs
    cur.execute('''
        SELECT id, login_time, ip, device, city, country, risk
        FROM access_logs
        WHERE username = %s
        ORDER BY login_time DESC
        LIMIT %s OFFSET %s
    ''', (username, per_page, offset))
    logs = cur.fetchall()
 
    # Check for next page
    cur.execute('SELECT COUNT(*) FROM access_logs WHERE username = %s', (username,))
    total_logs = cur.fetchone()[0]
    has_next = (page * per_page) < total_logs
 
    cur.close()
    conn.close()
 
    return render_template('my_logins.html', logs=logs, message=message, page=page, has_next=has_next,  role=session['role'])

@app.route('/export_my_logins')
@login_required()
def export_my_logins():
   username = session.get('user')
   conn = get_db_connection()
   cur = conn.cursor()
   cur.execute('''
       SELECT ip, device, login_time, risk, country, city
       FROM access_logs
       WHERE username = %s
       ORDER BY login_time DESC
   ''', (username,))
   rows = cur.fetchall()
   import io, csv
   output = io.StringIO()
   writer = csv.writer(output)
   writer.writerow(['IP', 'Device', 'Login Time', 'Risk', 'Country', 'City'])
   for row in rows:
       writer.writerow(row)
   output.seek(0)
   cur.close()
   conn.close()
   from flask import send_file
   return send_file(
       io.BytesIO(output.getvalue().encode()),
       mimetype='text/csv',
       as_attachment=True,
       download_name='my_login_history.csv'
   )

# --- Admin View: Suspicious Reports Panel ---
@app.route('/admin_suspicious_reports')
@login_required(role='admin')
def admin_suspicious_reports():
   page = request.args.get('page', 1, type=int)
   per_page = 5
   offset = (page - 1) * per_page
   conn = get_db_connection()
   cur = conn.cursor()
   query = '''
       SELECT sr.id, sr.username, sr.reason, sr.report_time,
              al.ip, al.device, al.city, al.country, al.risk, al.login_time, u.locked
       FROM suspicious_reports sr
       JOIN access_logs al ON sr.log_id = al.id
       JOIN users u ON sr.username = u.username
       ORDER BY sr.report_time DESC
       LIMIT %s OFFSET %s
   '''
   cur.execute(query, (per_page, offset))
   reports = cur.fetchall()
   cur.execute('SELECT COUNT(*) FROM suspicious_reports')
   total = cur.fetchone()[0]
   has_next = (page * per_page) < total
   cur.close()
   conn.close()
   return render_template('admin_suspicious_reports.html', reports=reports, page=page, has_next=has_next,  role=session['role'])

# --- Lock User Account ---
@app.route('/block_ip/<ip>', methods=['POST'])
@login_required(role='admin')
def block_ip(ip):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO blocked_ips (ip) VALUES (%s) ON CONFLICT DO NOTHING', (ip,))
        cur.execute('''
            INSERT INTO admin_logs (admin_username, action, target_username)
            VALUES (%s, %s, %s)
        ''', (session['user'], 'Blocked IP', ip))
        conn.commit()
        status = 'success'
    except Exception as e:
        print("Error blocking IP:", e)
        conn.rollback()
        status = 'error'
    finally:
        cur.close()
        conn.close()
    return jsonify({'status': status})
 #--- Admin Users ---
@app.route('/admin_users', methods=['GET', 'POST'])

@login_required(role='admin')

def admin_users():

    message = None

    error = None
 
    conn = get_db_connection()

    cur = conn.cursor()
 
    try:

        # --- Handle Create User ---

        if request.method == 'POST' and 'create_user' in request.form:

            username = request.form['username']

            password = request.form['password']

            role = request.form['role']

            email = request.form['email']

            phone = request.form['phone']
 
            if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', password):

                error = '❌ Weak password. Must have letters, numbers, special characters, min 8 chars.'

            else:
                hashed_pw = hash_password(password)
     
                cur.execute("""

                INSERT INTO users (username, password, role, email, phone_number, status)

                VALUES (%s, %s, %s, %s, %s, 'active')

                """, (username, password, role, email, phone))

                cur.execute("""

                INSERT INTO admin_logs (admin_username, action, target_username)

                VALUES (%s, %s, %s)

                """, (session['user'], 'Created user', username))

                conn.commit()

                message = f'✅ User {username} created successfully!'
 
        # --- Handle Edit User ---

        if request.method == 'POST' and 'edit_user' in request.form:

            uid = request.form['user_id']

            email = request.form['email']

            phone = request.form['phone']

            role = request.form['role']

            password = request.form.get('password')
 
            cur.execute('SELECT username FROM users WHERE id = %s', (uid,))

            target_user = cur.fetchone()[0]
 
            if password:

                if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', password):

                    error = '❌ Weak password. Must have letters, numbers, special characters, min 8 chars.'

                else:

                    cur.execute('UPDATE users SET email=%s, phone_number=%s, role=%s, password=%s WHERE id=%s',

                                (email, phone, role, password, uid))

                    cur.execute("""

                    INSERT INTO admin_logs (admin_username, action, target_username)

                    VALUES (%s, %s, %s)

                    """, (session['user'], 'Edited user + password', target_user))

                    conn.commit()

                    message = f'✅ User ID {uid} updated with new password.'

            else:

                cur.execute('UPDATE users SET email=%s, phone_number=%s, role=%s WHERE id=%s',

                            (email, phone, role, uid))

                cur.execute("""

                INSERT INTO admin_logs (admin_username, action, target_username)

                VALUES (%s, %s, %s)

                """, (session['user'], 'Edited user', target_user))

                conn.commit()

                message = f'✅ User ID {uid} updated successfully.'
 
        # --- Handle Reset Password ---

        if request.method == 'POST' and 'reset_password' in request.form:

            uid = request.form['user_id']

            new_password = request.form['password']
 
            if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', new_password):

                error = '❌ Weak password. Must have letters, numbers, special characters, min 8 chars.'

            else:

                cur.execute('UPDATE users SET password=%s WHERE id=%s', (new_password, uid))

                cur.execute('SELECT username FROM users WHERE id = %s', (uid,))

                uname = cur.fetchone()[0]

                cur.execute("""

                INSERT INTO admin_logs (admin_username, action, target_username)

                VALUES (%s, %s, %s)

                """, (session['user'], 'Reset password', uname))

                conn.commit()

                message = f'✅ Password reset successfully for user ID {uid}.'
 
        # --- Handle Delete User ---

        if request.method == 'POST' and 'delete_user' in request.form:

            uid = request.form['user_id']

            cur.execute('UPDATE users SET status=%s WHERE id=%s', ('deleted', uid))

            cur.execute('SELECT username FROM users WHERE id = %s', (uid,))

            uname = cur.fetchone()[0]

            cur.execute("""

            INSERT INTO admin_logs (admin_username, action, target_username)

            VALUES (%s, %s, %s)

            """, (session['user'], 'Soft-deleted user', uname))

            conn.commit()

            message = f'✅ User ID {uid} soft-deleted.'
 
    except Exception as e:

        error = f'❌ Error: {str(e)}'

        conn.rollback()
 
    # Fetch users

    cur.execute('SELECT id, username, email, phone_number, role, status FROM users ORDER BY id')

    users = cur.fetchall()
 
    cur.close()

    conn.close()
 
    return make_response(render_template('admin_users.html', users=users, message=message, error=error,  role=session['role']))

 
# --- Active Users ---
 
@app.route('/active_users')
@login_required(role='admin')
def active_users():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT username, ip, device, login_time FROM active_sessions')
    users = cur.fetchall()
    cur.close()
    conn.close()
 
    return make_response(render_template('active_users.html', users=users,  role=session['role']))
 
# --- Force Logout Specific User ---
@app.route('/force_logout/<username>')
@login_required(role='admin')
def force_logout(username):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM active_sessions WHERE username = %s', (username,))
    conn.commit()
    cur.close()
    conn.close()
 
    return redirect('/active_users')

# --- Risk Panel ---
@app.route('/risk_panel')
@login_required(role='admin')
def risk_panel():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT risk, COUNT(*) FROM access_logs GROUP BY risk')
    data = cur.fetchall()
    cur.close()
    conn.close()
 
    # Prepare risk data for Chart.js
    risk_counts = {'low': 0, 'high': 0}
    for row in data:
        risk = row[0]
        count = row[1]
        risk_counts[risk] = count
 
    return make_response(render_template('risk_panel.html', risk_counts=risk_counts, role=session['role'] ))
# --- Heatmap ---
@app.route('/heatmap')

@login_required()

def heatmap():

    session['allowed_page'] = 'heatmap'

    conn = get_db_connection()

    cur = conn.cursor()
 
    page = request.args.get('page', 1, type=int)

    per_page = 5

    offset = (page - 1) * per_page
 
    date_filter = request.args.get('date')

    filters = []

    query = 'SELECT username, city, country, risk, login_time FROM access_logs WHERE 1=1'
 
    if date_filter:

        query += ' AND DATE(login_time) = %s'

        filters.append(date_filter)
 
    query += ' ORDER BY login_time DESC LIMIT %s OFFSET %s'

    filters.extend([per_page, offset])
 
    cur.execute(query, tuple(filters))

    logs = cur.fetchall()
 
    cur.execute('SELECT COUNT(*) FROM access_logs')

    total_logs = cur.fetchone()[0]

    has_next = (page * per_page) < total_logs
 
    conn.close()
 
    logins = []

    for log in logs:

        try:

            location = f"{log[1]},{log[2]}"

            response_geo = requests.get(f'https://nominatim.openstreetmap.org/search?q={location}&format=json')

            geo = response_geo.json()

            lat = float(geo[0]['lat'])

            lon = float(geo[0]['lon'])

        except:

            lat, lon = 33.8547, 35.8623
 
        logins.append({

            'username': log[0],

            'city': log[1],

            'country': log[2],

            'risk': log[3],

            'lat': lat,

            'lon': lon

        })
 
    return make_response(render_template('heatmap.html', logins=logins, page=page, has_next=has_next,role=session['role']))
# --- user work ---

@app.route('/user_work')
@login_required()
def user_work():
    if session.get('risk') == 'high':
        return render_template('user_blocked.html',
                               reason=session.get('risk_reason'),
                               role=session['role'],
                               user=session['user'])
    return render_template('user_work.html',
                           user=session['user'],
                           role=session['role'])
# --- submit report ---

@app.route('/submit_report', methods=['POST'])
@login_required()
def submit_report():
   if session.get('risk') == 'high':
       return 'Access denied: High risk.'
   report = request.form['report']
   # Optional: Save the report to the database
   print(f"Report from {session['user']}: {report}")  # or log it
   return '✅ Report submitted successfully.'
# --- Logout ---

@app.route('/logout')

@login_required()

def logout():

    username = session.get('user')

    conn = get_db_connection()

    cur = conn.cursor()

    cur.execute('DELETE FROM active_sessions WHERE username = %s', (username,))

    conn.commit()

    cur.close()

    conn.close()
 
    session.clear()

    return redirect('/')


# --- Main ---

if __name__ == '__main__':

    app.run(debug=True)

 