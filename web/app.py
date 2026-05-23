from flask import Flask, render_template, request, abort, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
import time

app = Flask(__name__)

# تأمين العمل خلف استضافات مثل Render/Heroku لجلب الـ IP الحقيقي
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# --- إعدادات الحماية ---
CONFIG = {
    "admin_pw": "admin1234",
    "max_fails": 10,         # حظر بعد 10 محاولات خاطئة
    "ban_time": 60,          # مدة الحظر (دقيقة)
}

# قاعدة بيانات المسارات المخفية
HIDDEN_PATHS = {
    "/admin": "Admin Panel - Please Login",
    "/config": "DB_HOST=localhost\nDB_USER=root\nDB_PASS=s3cur3_p@ss",
    "/.env": "SECRET_KEY=dh28d9238d\nDEBUG=False",
    "/backup": "Files: backup_2024.zip, database_dump.sql",
    "/api/v1/users": '[{"id": 1, "user": "admin", "role": "superuser"}]',
    "/dev": "Development portal is closed.",
    "/logs": "Access logs: 192.168.1.1 accessed /admin"
}

# سجل الزوار (في الذاكرة - يصفر عند إعادة تشغيل السيرفر)
firewall_logs = {} 

def get_client_ip():
    return request.remote_addr

# --- جدار الحماية (WAF) ---
@app.before_request
def waf_check():
    ip = get_client_ip()
    now = time.time()
    
    if ip in firewall_logs:
        # هل الـ IP محظور حالياً؟
        if now < firewall_logs[ip].get('banned_until', 0):
            remain = int(firewall_logs[ip]['banned_until'] - now)
            return make_response(f"⚠️ [WAF] Access Denied. IP Banned for {remain}s.", 403)

@app.after_request
def track_activity(response):
    # إذا كانت الاستجابة 404 أو 401، نعتبرها محاولة اختراق
    if response.status_code in [404, 401]:
        ip = get_client_ip()
        now = time.time()
        
        if ip not in firewall_logs:
            firewall_logs[ip] = {'fails': 0, 'banned_until': 0}
            
        firewall_logs[ip]['fails'] += 1
        
        # تفعيل الحظر عند تجاوز الحد
        if firewall_logs[ip]['fails'] >= CONFIG['max_attempts']:
            firewall_logs[ip]['banned_until'] = now + CONFIG['ban_time']
            firewall_logs[ip]['fails'] = 0 
            
    return response

# --- المسارات ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/<path:subpath>', methods=['GET', 'POST'])
def handle_paths(subpath):
    full_path = "/" + subpath
    
    # التحقق من المسارات المخفية
    if full_path in HIDDEN_PATHS:
        # إذا كان المسار هو أدمن، محاكاة تخمين باسورد
        if "admin" in full_path and request.method == 'POST':
            password = request.form.get('password')
            if password == CONFIG['admin_pw']:
                return "✅ Login Successful! Flag: {BINGO_YOU_GOT_IT}"
            return "❌ Invalid Password", 401
            
        elif "admin" in full_path:
            return f'''<h1>{HIDDEN_PATHS[full_path]}</h1>
                      <form method="POST"><input name="password" type="password"><input type="submit"></form>'''
        
        return f"<pre>{HIDDEN_PATHS[full_path]}</pre>"
    
    abort(404)

if __name__ == '__main__':
    app.run(debug=False)