from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
import datetime as dt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta


from functools import wraps


app = Flask(__name__)
# Ensure instance directory exists and use absolute DB path inside it
os.makedirs(app.instance_path, exist_ok=True)
db_path = os.path.join(app.instance_path, 'shifts.db')
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "change-this-in-production"

# Email configuration (optional, for future features)
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "your-email@gmail.com")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "your-app-password")

db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)





class Shift(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, index=True)
    position = db.Column(db.String(80), nullable=False)
    hours = db.Column(db.Float, nullable=False)
    hourly_rate = db.Column(db.Float, nullable=False)
    tips = db.Column(db.Float, nullable=False, default=0.0)
    notes = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True, nullable=True)
    user = db.relationship('User', backref=db.backref('shifts', lazy=True))
    start_dt = db.Column(db.DateTime, nullable=True)
    end_dt = db.Column(db.DateTime, nullable=True)

    @property
    def wages(self) -> float:
        return round((self.hours or 0.0) * (self.hourly_rate or 0.0), 2)

    @property
    def total_pay(self) -> float:
        return round(self.wages + (self.tips or 0.0), 2)

def get_unique_positions() -> list[str]:
    query = db.session.query(Shift.position)
    if current_user.is_authenticated:
        query = query.filter(Shift.user_id == current_user.id)
    rows = query.distinct().order_by(Shift.position.asc()).all()
    return [r[0] for r in rows]

login_manager = LoginManager(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


def admin_required(f):
    """Decorator to require admin privileges for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
@login_required
def index():
    shifts = Shift.query.filter(Shift.user_id == current_user.id).order_by(Shift.date.desc(), Shift.id.desc()).all()
    totals = {
        "hours": round(sum(s.hours for s in shifts) or 0.0, 2),
        "wages": round(sum(s.wages for s in shifts) or 0.0, 2),
        "tips": round(sum(s.tips for s in shifts) or 0.0, 2),
    }
    totals["pay"] = round(totals["wages"] + totals["tips"], 2)
    effective_hr = round((totals["pay"] / totals["hours"]) if totals["hours"] else 0.0, 2)
    return render_template("index.html", shifts=shifts, totals=totals, effective_hr=effective_hr)


def parse_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def parse_datetime_local(value: str) -> datetime | None:
    # Expecting HTML datetime-local format: YYYY-MM-DDTHH:MM
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M")
    except ValueError:
        return None





@app.route("/shift/new", methods=["GET", "POST"])
@login_required
def add_shift():
    positions = get_unique_positions()
    if request.method == "POST":
        try:
            start_str = request.form.get("start_dt")
            end_str = request.form.get("end_dt")
            position = (request.form.get("position") or "").strip()
            start_dt = parse_datetime_local(start_str)
            end_dt = parse_datetime_local(end_str)
            total_salary = parse_float(request.form.get("total_salary"))
            tips = parse_float(request.form.get("tips"))
            notes = (request.form.get("notes") or "").strip()

            if not start_dt or not end_dt or not position:
                raise ValueError("Start, end, and position are required")
            if end_dt <= start_dt:
                raise ValueError("End datetime must be after start datetime")

            hours = round((end_dt - start_dt).total_seconds() / 3600.0, 2)
            date_obj = start_dt.date()
            # Derive hourly_rate from total_salary and hours (avoid division by zero)
            hourly_rate = round((total_salary / hours), 2) if hours else 0.0
            new_shift = Shift(
                date=date_obj,
                position=position,
                hours=hours,
                hourly_rate=hourly_rate,
                tips=tips,
                notes=notes,
                user_id=current_user.id,
                start_dt=start_dt,
                end_dt=end_dt,
            )
            db.session.add(new_shift)
            db.session.commit()
            flash("Shift added.", "success")
            return redirect(url_for("index"))
        except Exception as exc:
            db.session.rollback()
            flash(f"Error adding shift: {exc}", "danger")
    return render_template("add_edit.html", shift=None, positions=positions)


@app.route("/shift/<int:shift_id>/edit", methods=["GET", "POST"])
@login_required
def edit_shift(shift_id: int):
    shift = Shift.query.filter_by(id=shift_id, user_id=current_user.id).first_or_404()
    positions = get_unique_positions()
    if request.method == "POST":
        try:
            start_str = request.form.get("start_dt")
            end_str = request.form.get("end_dt")
            position = (request.form.get("position") or "").strip()
            start_dt = parse_datetime_local(start_str)
            end_dt = parse_datetime_local(end_str)
            total_salary = parse_float(request.form.get("total_salary"))
            tips = parse_float(request.form.get("tips"))
            notes = (request.form.get("notes") or "").strip()

            if not start_dt or not end_dt or not position:
                raise ValueError("Start, end, and position are required")
            if end_dt <= start_dt:
                raise ValueError("End datetime must be after start datetime")

            hours = round((end_dt - start_dt).total_seconds() / 3600.0, 2)
            shift.date = start_dt.date()
            shift.position = position
            shift.hours = hours
            shift.hourly_rate = round((total_salary / hours), 2) if hours else 0.0
            shift.tips = tips
            shift.notes = notes
            shift.start_dt = start_dt
            shift.end_dt = end_dt
            db.session.commit()
            flash("Shift updated.", "success")
            return redirect(url_for("index"))
        except Exception as exc:
            db.session.rollback()
            flash(f"Error updating shift: {exc}", "danger")
    return render_template("add_edit.html", shift=shift, positions=positions)


@app.route("/shift/<int:shift_id>/delete", methods=["POST"])
@login_required
def delete_shift(shift_id: int):
    shift = Shift.query.filter_by(id=shift_id, user_id=current_user.id).first_or_404()
    try:
        db.session.delete(shift)
        db.session.commit()
        flash("Shift deleted.", "info")
    except Exception as exc:
        db.session.rollback()
        flash(f"Error deleting shift: {exc}", "danger")
    return redirect(url_for("index"))


@app.route("/analytics")
@login_required
def analytics():
    # Filters
    start_str = (request.args.get("start") or "").strip()
    end_str = (request.args.get("end") or "").strip()
    pos = (request.args.get("position") or "").strip()

    query = Shift.query.filter(Shift.user_id == current_user.id)
    if start_str:
        try:
            start_date = dt.date.fromisoformat(start_str)
            query = query.filter(Shift.date >= start_date)
        except ValueError:
            start_str = ""
    if end_str:
        try:
            end_date = dt.date.fromisoformat(end_str)
            query = query.filter(Shift.date <= end_date)
        except ValueError:
            end_str = ""
    if pos:
        query = query.filter(Shift.position == pos)

    filtered_shifts = query.order_by(Shift.date.asc()).all()

    # Overall totals based on filtered dataset
    total_hours = round(sum(s.hours or 0.0 for s in filtered_shifts) or 0.0, 2)
    total_tips = round(sum(s.tips or 0.0 for s in filtered_shifts) or 0.0, 2)
    total_wages = round(sum(s.wages for s in filtered_shifts) or 0.0, 2)
    total_pay = round(total_wages + total_tips, 2)
    effective_hourly = round((total_pay / total_hours) if total_hours else 0.0, 2)

    # Monthly aggregates
    monthly_map = {}
    for s in filtered_shifts:
        ym = s.date.strftime("%Y-%m")
        entry = monthly_map.setdefault(ym, {"hours": 0.0, "wages": 0.0, "tips": 0.0, "pay": 0.0})
        entry["hours"] += s.hours or 0.0
        entry["wages"] += s.wages
        entry["tips"] += s.tips or 0.0
        entry["pay"] += s.total_pay

    monthly_labels = sorted(monthly_map.keys())
    monthly_hours = [round(monthly_map[m]["hours"], 2) for m in monthly_labels]
    monthly_wages = [round(monthly_map[m]["wages"], 2) for m in monthly_labels]
    monthly_tips = [round(monthly_map[m]["tips"], 2) for m in monthly_labels]
    monthly_pay = [round(monthly_map[m]["pay"], 2) for m in monthly_labels]

    # By position aggregates
    position_map = {}
    for s in filtered_shifts:
        p = s.position
        entry = position_map.setdefault(p, {"hours": 0.0, "wages": 0.0, "tips": 0.0, "pay": 0.0})
        entry["hours"] += s.hours or 0.0
        entry["wages"] += s.wages
        entry["tips"] += s.tips or 0.0
        entry["pay"] += s.total_pay

    position_labels = sorted(position_map.keys())
    position_hours = [round(position_map[p]["hours"], 2) for p in position_labels]
    position_wages = [round(position_map[p]["wages"], 2) for p in position_labels]
    position_tips = [round(position_map[p]["tips"], 2) for p in position_labels]
    position_pay = [round(position_map[p]["pay"], 2) for p in position_labels]

    # Daily trend (pay by day)
    daily_map = {}
    for s in filtered_shifts:
        ds = s.date.strftime("%Y-%m-%d")
        daily_map[ds] = daily_map.get(ds, 0.0) + s.total_pay
    daily_labels = sorted(daily_map.keys())
    daily_pay = [round(daily_map[d], 2) for d in daily_labels]

    return render_template(
        "analytics.html",
        total_hours=total_hours,
        total_wages=total_wages,
        total_tips=total_tips,
        total_pay=total_pay,
        effective_hourly=effective_hourly,
        monthly_labels=monthly_labels,
        monthly_hours=monthly_hours,
        monthly_wages=monthly_wages,
        monthly_tips=monthly_tips,
        monthly_pay=monthly_pay,
        position_labels=position_labels,
        position_hours=position_hours,
        position_wages=position_wages,
        position_tips=position_tips,
        position_pay=position_pay,
        daily_labels=daily_labels,
        daily_pay=daily_pay,
        positions=get_unique_positions(),
        filter_start=start_str,
        filter_end=end_str,
        filter_position=pos,
    )


# Settings
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        try:
            new_username = (request.form.get('username') or '').strip()
            new_email = (request.form.get('email') or '').strip()
            current_password = request.form.get('current_password') or ''
            new_password = request.form.get('new_password') or ''
            confirm_password = request.form.get('confirm_password') or ''

            if not current_password:
                raise ValueError('Current password is required')
            if not current_user.check_password(current_password):
                raise ValueError('Current password is incorrect')

            if new_username:
                existing = User.query.filter(User.username == new_username, User.id != current_user.id).first()
                if existing:
                    raise ValueError('Username already taken')
                current_user.username = new_username

            if new_email != current_user.email:
                if new_email:
                    existing = User.query.filter(User.email == new_email, User.id != current_user.id).first()
                    if existing:
                        raise ValueError('Email already registered')
                current_user.email = new_email if new_email else None

            if new_password or confirm_password:
                if new_password != confirm_password:
                    raise ValueError('New passwords do not match')
                if len(new_password) < 4:
                    raise ValueError('New password must be at least 4 characters')
                current_user.set_password(new_password)

            db.session.commit()
            flash('Settings updated.', 'success')
            return redirect(url_for('settings'))
        except Exception as exc:
            db.session.rollback()
            flash(str(exc), 'danger')
    return render_template('settings.html')


@app.route('/export')
@login_required
def export_data():
    fmt = (request.args.get('format') or 'csv').lower()
    user_shifts = Shift.query.filter(Shift.user_id == current_user.id).order_by(Shift.date.asc(), Shift.id.asc()).all()

    if fmt == 'json':
        data = [
            {
                'id': s.id,
                'date': s.date.isoformat() if s.date else None,
                'position': s.position,
                'hours': s.hours,
                'hourly_rate': s.hourly_rate,
                'tips': s.tips,
                'notes': s.notes,
                'wages': s.wages,
                'total_pay': s.total_pay,
                'start_dt': s.start_dt.isoformat() if s.start_dt else None,
                'end_dt': s.end_dt.isoformat() if s.end_dt else None,
            }
            for s in user_shifts
        ]
        response = make_response(jsonify(data))
        response.headers['Content-Disposition'] = 'attachment; filename=shifts.json'
        return response

    # default CSV
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['id','date','position','hours','hourly_rate','tips','notes','wages','total_pay','start_dt','end_dt'])
    for s in user_shifts:
        writer.writerow([
            s.id,
            s.date.isoformat() if s.date else '',
            s.position,
            s.hours,
            s.hourly_rate,
            s.tips,
            (s.notes or '').replace('\n',' ').strip(),
            s.wages,
            s.total_pay,
            s.start_dt.isoformat() if s.start_dt else '',
            s.end_dt.isoformat() if s.end_dt else '',
        ])
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=shifts.csv'
    return response


@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    try:
        password = request.form.get('confirm_password') or ''
        if not password:
            raise ValueError('Password confirmation is required')
        if not current_user.check_password(password):
            raise ValueError('Password is incorrect')

        # delete user-owned shifts first due to FK relationship
        Shift.query.filter(Shift.user_id == current_user.id).delete()
        # delete the user
        user = db.session.get(User, current_user.id)
        db.session.delete(user)
        db.session.commit()
        flash('Your account and data have been deleted.', 'info')
        return redirect(url_for('register'))
    except Exception as exc:
        db.session.rollback()
        flash(str(exc), 'danger')
        return redirect(url_for('settings'))


# Authentication routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip()
        password = request.form.get('password') or ''
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('register.html')
        if len(password) < 4:
            flash('Password must be at least 4 characters long', 'danger')
            return render_template('register.html')
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'danger')
            return render_template('register.html')
        if email and User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return render_template('register.html')
        user = User(username=username, email=email if email else None)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Account created. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        print(username)
        password = request.form.get('password') or ''
        print(password)
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            next_url = request.args.get('next')
            return redirect(next_url or url_for('index'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))





# Admin routes
@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard with system overview"""
    # Get system statistics
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    admin_users = User.query.filter_by(is_admin=True).count()
    
    # Get recent shifts (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_shifts = Shift.query.filter(Shift.start_dt >= week_ago).count()
    
    # Get shifts for today
    today = datetime.utcnow().date()
    today_shifts = Shift.query.filter(Shift.date == today).count()
    
    # Get recent users (last 7 days)
    recent_users = User.query.filter(User.created_at >= week_ago).count()
    
    # Get recent activity (last 10 shifts)
    recent_activity = db.session.query(Shift, User).join(User).order_by(Shift.id.desc()).limit(10).all()
    
    stats = {
        'total_users': total_users,
        'active_users': active_users,
        'admin_users': admin_users,
        'recent_shifts': recent_shifts,
        'today_shifts': today_shifts,
        'recent_users': recent_users
    }
    
    return render_template('admin/dashboard.html', stats=stats, recent_activity=recent_activity)


@app.route('/admin/users')
@admin_required
def admin_users():
    """List all users with admin controls"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', 'all')
    
    query = User.query
    
    # Apply search filter
    if search:
        query = query.filter(User.username.contains(search))
    
    # Apply status filter
    if status_filter == 'active':
        query = query.filter_by(is_active=True)
    elif status_filter == 'inactive':
        query = query.filter_by(is_active=False)
    elif status_filter == 'admin':
        query = query.filter_by(is_admin=True)
    
    # Paginate results
    users = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    return render_template('admin/users.html', users=users, search=search, status_filter=status_filter)


@app.route('/admin/users/new', methods=['GET', 'POST'])
@admin_required
def admin_users_new():
    """Create a new user"""
    if request.method == 'POST':
        try:
            username = (request.form.get('username') or '').strip()
            email = (request.form.get('email') or '').strip()
            password = request.form.get('password') or ''
            is_admin = 'is_admin' in request.form
            
            if not username or not password:
                raise ValueError('Username and password are required')
            
            if len(password) < 4:
                raise ValueError('Password must be at least 4 characters long')
            
            if User.query.filter_by(username=username).first():
                raise ValueError('Username already taken')
            
            if email and User.query.filter_by(email=email).first():
                raise ValueError('Email already registered')
            
            user = User(
                username=username,
                email=email if email else None,
                is_admin=is_admin
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            flash(f'User "{username}" created successfully.', 'success')
            return redirect(url_for('admin_users'))
            
        except Exception as exc:
            db.session.rollback()
            flash(str(exc), 'danger')
    
    return render_template('admin/user_form.html', user=None)


@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_users_edit(user_id):
    """Edit a user"""
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        try:
            username = (request.form.get('username') or '').strip()
            email = (request.form.get('email') or '').strip()
            password = request.form.get('password') or ''
            is_admin = 'is_admin' in request.form
            is_active = 'is_active' in request.form
            
            if not username:
                raise ValueError('Username is required')
            
            # Check username uniqueness (excluding current user)
            existing = User.query.filter(User.username == username, User.id != user.id).first()
            if existing:
                raise ValueError('Username already taken')
            
            # Check email uniqueness (excluding current user)
            if email:
                existing = User.query.filter(User.email == email, User.id != user.id).first()
                if existing:
                    raise ValueError('Email already registered')
            
            # Update user fields
            user.username = username
            user.email = email if email else None
            user.is_admin = is_admin
            user.is_active = is_active
            
            # Update password if provided
            if password:
                if len(password) < 4:
                    raise ValueError('Password must be at least 4 characters long')
                user.set_password(password)
            
            db.session.commit()
            flash(f'User "{username}" updated successfully.', 'success')
            return redirect(url_for('admin_users'))
            
        except Exception as exc:
            db.session.rollback()
            flash(str(exc), 'danger')
    
    return render_template('admin/user_form.html', user=user)


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_users_delete(user_id):
    """Delete a user"""
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting yourself
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_users'))
    
    try:
        username = user.username
        
        # Delete user's shifts first (due to foreign key constraint)
        Shift.query.filter_by(user_id=user.id).delete()
        
        # Delete the user
        db.session.delete(user)
        db.session.commit()
        
        flash(f'User "{username}" and all their data have been deleted.', 'success')
        
    except Exception as exc:
        db.session.rollback()
        flash(f'Error deleting user: {exc}', 'danger')
    
    return redirect(url_for('admin_users'))


@app.route('/admin/shifts')
@admin_required
def admin_shifts():
    """View all shifts across all users"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    user_filter = request.args.get('user', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    
    # Build query with joins
    query = db.session.query(Shift, User).join(User)
    
    # Apply filters
    if search:
        query = query.filter(Shift.position.contains(search))
    
    if user_filter:
        query = query.filter(User.username.contains(user_filter))
    
    if date_from:
        try:
            from_date = dt.date.fromisoformat(date_from)
            query = query.filter(Shift.date >= from_date)
        except ValueError:
            date_from = ""
    
    if date_to:
        try:
            to_date = dt.date.fromisoformat(date_to)
            query = query.filter(Shift.date <= to_date)
        except ValueError:
            date_to = ""
    
    # Paginate results
    shifts_data = query.order_by(Shift.date.desc(), Shift.id.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    # Get all users for filter dropdown
    all_users = User.query.order_by(User.username).all()
    
    return render_template('admin/shifts.html', 
                         shifts_data=shifts_data, 
                         search=search, 
                         user_filter=user_filter,
                         date_from=date_from,
                         date_to=date_to,
                         all_users=all_users)


@app.route('/admin/shifts/<int:shift_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_shifts_edit(shift_id):
    """Edit any shift (admin only)"""
    shift = Shift.query.get_or_404(shift_id)
    user = shift.user
    positions = get_unique_positions()
    
    if request.method == 'POST':
        try:
            start_str = request.form.get("start_dt")
            end_str = request.form.get("end_dt")
            position = (request.form.get("position") or "").strip()
            start_dt = parse_datetime_local(start_str)
            end_dt = parse_datetime_local(end_str)
            total_salary = parse_float(request.form.get("total_salary"))
            tips = parse_float(request.form.get("tips"))
            notes = (request.form.get("notes") or "").strip()

            if not start_dt or not end_dt or not position:
                raise ValueError("Start, end, and position are required")
            if end_dt <= start_dt:
                raise ValueError("End datetime must be after start datetime")

            hours = round((end_dt - start_dt).total_seconds() / 3600.0, 2)
            shift.date = start_dt.date()
            shift.position = position
            shift.hours = hours
            shift.hourly_rate = round((total_salary / hours), 2) if hours else 0.0
            shift.tips = tips
            shift.notes = notes
            shift.start_dt = start_dt
            shift.end_dt = end_dt
            
            db.session.commit()
            flash(f"Shift updated for {user.username}.", "success")
            return redirect(url_for('admin_shifts'))
            
        except Exception as exc:
            db.session.rollback()
            flash(f"Error updating shift: {exc}", "danger")
    
    return render_template("add_edit.html", shift=shift, positions=positions, admin_edit=True, user=user)


@app.route('/admin/shifts/<int:shift_id>/delete', methods=['POST'])
@admin_required
def admin_shifts_delete(shift_id):
    """Delete any shift (admin only)"""
    shift = Shift.query.get_or_404(shift_id)
    user = shift.user
    
    try:
        db.session.delete(shift)
        db.session.commit()
        flash(f"Shift deleted for {user.username}.", "info")
    except Exception as exc:
        db.session.rollback()
        flash(f"Error deleting shift: {exc}", "danger")
    
    return redirect(url_for('admin_shifts'))


def ensure_user_id_column():
    # Ensure user_id column exists on Shift for existing DBs
    try:
        info = db.session.execute(db.text("PRAGMA table_info(shift)")).fetchall()
        cols = {row[1] for row in info}
        if 'user_id' not in cols:
            db.session.execute(db.text('ALTER TABLE shift ADD COLUMN user_id INTEGER'))
            db.session.commit()
        if 'start_dt' not in cols:
            db.session.execute(db.text('ALTER TABLE shift ADD COLUMN start_dt DATETIME'))
            db.session.commit()
        if 'end_dt' not in cols:
            db.session.execute(db.text('ALTER TABLE shift ADD COLUMN end_dt DATETIME'))
            db.session.commit()
    except Exception:
        db.session.rollback()


def ensure_email_column():
    # Ensure email column exists on User for existing DBs
    try:
        info = db.session.execute(db.text("PRAGMA table_info(user)")).fetchall()
        cols = {row[1] for row in info}
        if 'email' not in cols:
            db.session.execute(db.text('ALTER TABLE user ADD COLUMN email VARCHAR(120)'))
            db.session.commit()
    except Exception:
        db.session.rollback()


def ensure_admin_columns():
    # Ensure admin-related columns exist on User for existing DBs
    try:
        info = db.session.execute(db.text("PRAGMA table_info(user)")).fetchall()
        cols = {row[1] for row in info}
        
        if 'is_admin' not in cols:
            db.session.execute(db.text('ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0'))
            db.session.commit()
        
        if 'created_at' not in cols:
            db.session.execute(db.text('ALTER TABLE user ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP'))
            db.session.commit()
        
        if 'is_active' not in cols:
            db.session.execute(db.text('ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1'))
            db.session.commit()
    except Exception:
        db.session.rollback()


def seed_mock_data() -> None:
    # Ensure demo user exists
    demo = User.query.filter_by(username='demo').first()
    if demo is None:
        demo = User(username='demo')
        demo.set_password('demo')
        db.session.add(demo)
        db.session.commit()
    
    # Ensure admin user exists
    admin = User.query.filter_by(username='admin').first()
    if admin is None:
        admin = User(username='admin', is_admin=True)
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()

    # Only seed shifts if none exist
    if Shift.query.first() is not None:
        return

    sample_shifts = [
        # Recent month
        {"date": dt.date.today().replace(day=1), "position": "Server", "hours": 6.5, "hourly_rate": 12.00, "tips": 85.00, "notes": "Lunch shift", "user_id": demo.id},
        {"date": dt.date.today().replace(day=3), "position": "Bartender", "hours": 8.0, "hourly_rate": 13.50, "tips": 140.00, "notes": "Friday night", "user_id": demo.id},
        {"date": dt.date.today().replace(day=6), "position": "Host", "hours": 5.0, "hourly_rate": 11.00, "tips": 20.00, "notes": "Slow evening", "user_id": demo.id},
        {"date": dt.date.today().replace(day=10), "position": "Server", "hours": 7.25, "hourly_rate": 12.00, "tips": 110.00, "notes": "Busy dinner", "user_id": demo.id},
        {"date": dt.date.today().replace(day=14), "position": "Barback", "hours": 7.5, "hourly_rate": 11.50, "tips": 60.00, "notes": "", "user_id": demo.id},
        # Previous month
        {"date": (dt.date.today().replace(day=1) - dt.timedelta(days=10)).replace(day=5), "position": "Server", "hours": 6.0, "hourly_rate": 12.00, "tips": 70.00, "notes": "", "user_id": demo.id},
        {"date": (dt.date.today().replace(day=1) - dt.timedelta(days=10)).replace(day=12), "position": "Bartender", "hours": 7.75, "hourly_rate": 13.50, "tips": 125.00, "notes": "Event night", "user_id": demo.id},
        {"date": (dt.date.today().replace(day=1) - dt.timedelta(days=10)).replace(day=18), "position": "Server", "hours": 6.25, "hourly_rate": 12.00, "tips": 95.00, "notes": "", "user_id": demo.id},
        {"date": (dt.date.today().replace(day=1) - dt.timedelta(days=10)).replace(day=22), "position": "Host", "hours": 4.5, "hourly_rate": 11.00, "tips": 15.00, "notes": "Matinee", "user_id": demo.id},
        {"date": (dt.date.today().replace(day=1) - dt.timedelta(days=10)).replace(day=27), "position": "Barback", "hours": 8.0, "hourly_rate": 11.50, "tips": 55.00, "notes": "Late close", "user_id": demo.id},
    ]
    for s in sample_shifts:
        # also set start/end datetimes for demo: start at 09:00
        start_dt = datetime.combine(s["date"], datetime.min.time()).replace(hour=9, minute=0)
        end_dt = start_dt + dt.timedelta(hours=s["hours"]) if s.get("hours") else None
        s["start_dt"] = start_dt
        s["end_dt"] = end_dt
        db.session.add(Shift(**s))
    db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_user_id_column()
        ensure_email_column()
        ensure_admin_columns()
        seed_mock_data()
    app.run(host="0.0.0.0", port=5000, debug=True)



