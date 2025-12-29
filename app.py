import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from PIL import Image
from datetime import datetime, timedelta
from functools import wraps
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from flask_mail import Mail, Message
import uuid 


basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
os.makedirs(instance_path, exist_ok=True)


app = Flask(__name__, instance_path=instance_path)
app.config['SECRET_KEY'] = ':L0z63Iz2@BcrVM5^4q0J;E?Kmqj4wj82]wM6F]4s\'Yz%DN5Ve' 
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "database.db")}'
app.config['UPLOAD_FOLDER'] = os.path.join(instance_path, 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
app.config['ITEMS_PER_PAGE'] = 9


app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
mail = Mail(app)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def utility_processor():
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(recipient_id=current_user.id, is_read=False).count()
        return dict(unread_count=unread_count)
    return dict(unread_count=0)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_blocked = db.Column(db.Boolean, nullable=False, default=False)
    
    reset_token = db.Column(db.String(36), unique=True, nullable=True) 
    token_expiration = db.Column(db.DateTime, nullable=True)

    items = db.relationship('Item', backref='owner', lazy=True)
    reports_made = db.relationship('Report', foreign_keys='Report.reporter_id', backref='reporter', lazy=True)
    notifications_received = db.relationship('Notification', backref='recipient', lazy=True, foreign_keys='Notification.recipient_id')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    
    def generate_reset_token(self):
        self.reset_token = str(uuid.uuid4())
        self.token_expiration = datetime.utcnow() + timedelta(minutes=30) 
        db.session.commit()
        return self.reset_token
    
 
    @staticmethod
    def verify_reset_token(token):
        user = User.query.filter_by(reset_token=token).first()
        if user and user.token_expiration > datetime.utcnow():
            return user
        return None

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(300), nullable=False)
    location = db.Column(db.String(150), nullable=True)
    status = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(100), nullable=True)
    category = db.Column(db.String(50), nullable=True)
    is_resolved = db.Column(db.Boolean, default=False, nullable=False)
    date_reported = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    reports_received = db.relationship('Report', backref='reported_item', lazy=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('item_id', 'reporter_id', name='_item_reporter_uc'),)

# --- New Model: Notification ---
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reported_item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    matched_item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    score = db.Column(db.Float, nullable=False)
    reported_item = db.relationship('Item', foreign_keys=[reported_item_id])
    matched_item = db.relationship('Item', foreign_keys=[matched_item_id])


#  إنشاء قاعدة البيانات تلقائياً 
with app.app_context():
    db.create_all()

#  وظائف المساعدة (AI Matching, File Upload, Email Sender) 
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
THUMBNAIL_SIZE = (300, 200)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def find_matches_and_create_notification(new_item):
    """Finds matches and creates an in-app notification for the owner of the lost item."""
    if new_item.status == 'found': target_status = 'lost'; new_item_is_found = True
    else: target_status = 'found'; new_item_is_found = False
    candidates = Item.query.filter_by(category=new_item.category, status=target_status, is_resolved=False).all()
    if not candidates: return 0
    new_item_text = f"{new_item.name} {new_item.description}"
    candidate_texts = [f"{item.name} {item.description}" for item in candidates]
    vectorizer = TfidfVectorizer(stop_words='english')
    all_texts = [new_item_text] + candidate_texts
    tfidf_matrix = vectorizer.fit_transform(all_texts)
    cosine_similarities = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:]).flatten()
    matches_found = 0
    threshold = 0.5
    for i, score in enumerate(cosine_similarities):
        if score >= threshold:
            matched_item_candidate = candidates[i]
            if new_item_is_found:
                reported_item_id_for_notif = matched_item_candidate.id
                matched_item_id_for_notif = new_item.id
                recipient_user_id = matched_item_candidate.user_id
            else:
                reported_item_id_for_notif = new_item.id
                matched_item_id_for_notif = matched_item_candidate.id
                recipient_user_id = current_user.id
            existing_notif = Notification.query.filter_by(reported_item_id=reported_item_id_for_notif, matched_item_id=matched_item_id_for_notif).first()
            if not existing_notif:
                new_notification = Notification(recipient_id=recipient_user_id, reported_item_id=reported_item_id_for_notif, matched_item_id=matched_item_id_for_notif, score=score)
                db.session.add(new_notification); matches_found += 1
    db.session.commit(); return matches_found

def send_reset_email(user):
    """Function to send the reset email with the token."""
    token = user.generate_reset_token()
    msg = Message('Password Reset Request', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
    reset_url = url_for('reset_token', token=token, _external=True)
    msg.body = f'''To reset your password, visit the following link:
{reset_url}
If you did not make this request, simply ignore this email and no changes will be made to your account.
'''
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Mail failed to send: {e}")
        return False

# --- المسارات (Routes) ---
@app.route('/')
def home():
    page = request.args.get('page', 1, type=int); filter_status = request.args.get('filter'); search_query = request.args.get('search'); filter_category = request.args.get('category'); sort_by = request.args.get('sort', 'newest'); timeframe = request.args.get('timeframe')
    categories = db.session.query(Item.category).distinct().all(); categories = sorted([cat[0] for cat in categories if cat[0]])
    query = Item.query.filter_by(is_resolved=False)
    if filter_status in ['lost', 'found']: query = query.filter_by(status=filter_status)
    if filter_category: query = query.filter_by(category=filter_category)
    if search_query: query = query.filter(Item.name.contains(search_query) | Item.description.contains(search_query))
    now = datetime.utcnow()
    if timeframe == 'day': query = query.filter(Item.date_reported >= (now - timedelta(days=1)))
    elif timeframe == 'week': query = query.filter(Item.date_reported >= (now - timedelta(weeks=1)))
    elif timeframe == 'month': query = query.filter(Item.date_reported >= (now - timedelta(days=30)))
    if sort_by == 'oldest': query = query.order_by(Item.date_reported.asc())
    else: query = query.order_by(Item.date_reported.desc())
    items_pagination = query.paginate(page=page, per_page=app.config['ITEMS_PER_PAGE'], error_out=False); items = items_pagination.items
    return render_template('index.html',
                           items=items, pagination=items_pagination, categories=categories,
                           current_category=filter_category, current_status=filter_status,
                           current_sort=sort_by, current_timeframe=timeframe,
                           search_query=search_query)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('home'))
    if request.method == 'POST':
        user_by_username = User.query.filter_by(username=request.form.get('username')).first()
        if user_by_username: flash('This username is already taken.', 'danger'); return redirect(url_for('register'))
        user_by_email = User.query.filter_by(email=request.form.get('email')).first()
        if user_by_email: flash('This email is already registered.', 'danger'); return redirect(url_for('register'))
        hashed_password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        new_user = User(username=request.form['username'], email=request.form['email'], password_hash=hashed_password, is_admin=False, is_blocked=False)
        db.session.add(new_user); db.session.commit(); flash('Account created! You can now log in.', 'success'); return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('home'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            if user.is_blocked: flash('Your account has been blocked.', 'danger')
            else: login_user(user); return redirect(url_for('home'))
        else: flash('Login Unsuccessful. Check username and password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/report-found', methods=['GET', 'POST'])
@login_required
def report_found():
    if request.method == 'POST':
        file = request.files.get('item_file'); filename = None
        if file and file.filename != '' and allowed_file(file.filename):
            original_filename = secure_filename(file.filename); file_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
            file.save(file_path); filename = original_filename
            file_ext = original_filename.rsplit('.', 1)[1].lower()
            if file_ext in IMAGE_EXTENSIONS:
                try: img = Image.open(file_path); img.thumbnail(THUMBNAIL_SIZE); thumb_filename = original_filename.rsplit('.', 1)[0] + '_thumb.' + file_ext; thumb_path = os.path.join(app.config['UPLOAD_FOLDER'], thumb_filename); img.save(thumb_path)
                except Exception as e: flash(f'Could not create thumbnail: {e}', 'warning')
        
        new_item = Item(name=request.form['item_name'], description=request.form['item_description'], location=request.form['item_location'], category=request.form['item_category'], status='found', owner=current_user, filename=filename, is_resolved=False)
        db.session.add(new_item); 
        db.session.commit()
        
        matches_found = find_matches_and_create_notification(new_item)
        if matches_found > 0:
            flash(f'Item reported! We created {matches_found} potential match notification(s). Check your notifications!', 'success')
        else:
            flash('Item reported successfully! No immediate matches found.', 'success')
            
        return redirect(url_for('home'))
    return render_template('report-found.html')

@app.route('/report-lost', methods=['GET', 'POST'])
@login_required
def report_lost():
    if request.method == 'POST':
        file = request.files.get('item_file'); filename = None
        if file and file.filename != '' and allowed_file(file.filename):
            original_filename = secure_filename(file.filename); file_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
            file.save(file_path); filename = original_filename
            file_ext = original_filename.rsplit('.', 1)[1].lower()
            if file_ext in IMAGE_EXTENSIONS:
                try: img = Image.open(file_path); img.thumbnail(THUMBNAIL_SIZE); thumb_filename = original_filename.rsplit('.', 1)[0] + '_thumb.' + file_ext; thumb_path = os.path.join(app.config['UPLOAD_FOLDER'], thumb_filename); img.save(thumb_path)
                except Exception as e: flash(f'Could not create thumbnail: {e}', 'warning')
                
        new_item = Item(name=request.form['item_name'], description=request.form['item_description'], location=request.form['item_location'], category=request.form['item_category'], status='lost', owner=current_user, filename=filename, is_resolved=False)
        db.session.add(new_item); 
        db.session.commit()

        matches_found = find_matches_and_create_notification(new_item)
        if matches_found > 0:
            flash(f'Item reported! We created {matches_found} potential match notification(s). Check your notifications!', 'success')
        else:
            flash('Item reported successfully! We will notify you if a match is found.', 'success')

        return redirect(url_for('home'))
    return render_template('report-lost.html')

@app.route('/item/<int:item_id>')
def item_details(item_id):
    item = Item.query.get_or_404(item_id)
    already_reported = False
    if current_user.is_authenticated:
        already_reported = Report.query.filter_by(item_id=item.id, reporter_id=current_user.id).first() is not None
    return render_template('item-details.html', item=item, already_reported=already_reported)

@app.route('/notifications')
@login_required
def view_notifications():
    notifications = Notification.query.filter_by(recipient_id=current_user.id).order_by(Notification.timestamp.desc()).all()
    
    # Mark all notifications as read upon viewing them
    Notification.query.filter_by(recipient_id=current_user.id, is_read=False).update({Notification.is_read: True})
    db.session.commit()
    
    return render_template('notifications.html', notifications=notifications)

@app.route('/account')
@login_required
def account():
    items = Item.query.filter_by(owner=current_user).order_by(Item.date_reported.desc()).all()
    return render_template('account.html', items=items)

@app.route('/item/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.owner != current_user: abort(403)
    if request.method == 'POST':
        item.name = request.form['item_name']
        item.description = request.form['item_description']
        item.location = request.form['item_location']
        db.session.commit(); flash('Item updated!', 'success'); return redirect(url_for('account'))
    return render_template('edit_item.html', item=item)

@app.route('/item/<int:item_id>/delete', methods=['POST'])
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.owner != current_user: abort(403)
    db.session.delete(item); db.session.commit(); flash('Item deleted!', 'success'); return redirect(url_for('account'))

@app.route('/item/<int:item_id>/resolve', methods=['POST'])
@login_required
def resolve_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.owner != current_user: abort(403)
    item.is_resolved = True; db.session.commit(); flash('Item marked as resolved!', 'success'); return redirect(url_for('account'))

@app.route('/item/<int:item_id>/report', methods=['POST'])
@login_required
def report_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.owner == current_user: flash('You cannot report your own item.', 'warning'); return redirect(url_for('item_details', item_id=item_id))
    existing_report = Report.query.filter_by(item_id=item.id, reporter_id=current_user.id).first()
    if existing_report: flash('You have already reported this item.', 'info')
    else: new_report = Report(reported_item=item, reporter=current_user); db.session.add(new_report); db.session.commit(); flash('Item reported successfully. Thank you!', 'success')
    return redirect(url_for('item_details', item_id=item_id))
    
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users_count = User.query.count(); items_count = Item.query.count(); reports_count = Report.query.count()
    return render_template('admin/dashboard.html', users_count=users_count, items_count=items_count, reports_count=reports_count)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/<int:user_id>/block', methods=['POST'])
@login_required
@admin_required
def admin_block_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin: flash('Cannot block an administrator.', 'danger'); return redirect(url_for('admin_users'))
    else: user.is_blocked = True; db.session.commit(); flash(f'User {user.username} has been blocked.', 'success'); return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/unblock', methods=['POST'])
@login_required
@admin_required
def admin_unblock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_blocked = False; db.session.commit(); flash(f'User {user.username} has been unblocked.', 'success'); return redirect(url_for('admin_users'))

@app.route('/admin/items')
@login_required
@admin_required
def admin_items():
    items = Item.query.order_by(Item.date_reported.desc()).all()
    return render_template('admin/items.html', items=items)

@app.route('/admin/item/<int:item_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item); db.session.commit(); flash('Item deleted successfully by admin.', 'success'); return redirect(url_for('admin_items'))

@app.route('/admin/reports')
@login_required
@admin_required
def admin_reports():
    reports = db.session.query(Report, Item, User).join(Item, Report.item_id == Item.id).join(User, Report.reporter_id == User.id).order_by(Report.timestamp.desc()).all()
    return render_template('admin/reports.html', reports=reports)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- New Pages Routes ---
@app.route('/about')
def about():
    """Renders the About Us page."""
    return render_template('about.html')

@app.route('/contact')
def contact():
    """Renders the Contact Us page."""
    return render_template('contact.html')

# --- Password Reset Routes ---
def send_reset_email(user):
    """Function to send the reset email with the token."""
    token = user.generate_reset_token()
    
    msg = Message('Password Reset Request',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    
    # Build a secure, external URL for the email link
    reset_url = url_for('reset_token', token=token, _external=True)
    
    msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email and no changes will be made to your account.
'''
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Mail failed to send: {e}")
        return False

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated: return redirect(url_for('home'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            send_reset_email(user) # Will generate token and attempt to send email
            flash('An email has been sent with instructions to reset your password.', 'info')
        else:
            flash('If an account with that email exists, an email will be sent.', 'info')
        return redirect(url_for('login'))
        
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated: return redirect(url_for('home'))
        
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return render_template('reset_token.html', token=token) 

        # Update password and clear security token fields
        user.set_password(password)
        user.reset_token = None
        user.token_expiration = None
        
        db.session.commit()
        
        flash('Your password has been updated! You are now able to log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('reset_token.html', token=token)


# --- Main Run Block ---

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    