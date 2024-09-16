from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256
from functools import wraps
from datetime import datetime, date
from sqlalchemy import Date

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Integer, nullable=False)

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    niche = db.Column(db.String(50), nullable=False)
    budget = db.Column(db.Integer, nullable=False)
    deadline = db.Column(db.Date, nullable=False)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sponsor = db.relationship('User', backref=db.backref('campaigns', lazy=True))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template('index.html', username=session.get('user_name'))

@app.route('/sponser-registration', methods=['GET', 'POST'])
def sponser_registration():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists', 'error')
        else:
            hashed_password = pbkdf2_sha256.hash(password)
            new_user = User(name=name, email=email, password=hashed_password, role=2) 
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('sponser_registration.html')


@app.route('/influencer-registration', methods=['GET', 'POST'])
def influencer_registration():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists', 'error')
        else:
            hashed_password = pbkdf2_sha256.hash(password)
            new_user = User(name=name, email=email, password=hashed_password, role=1)  
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('influencer_registration.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and pbkdf2_sha256.verify(password, user.password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_role'] = user.role
            flash('Logged in successfully!', 'success')
            
            if user.role == 0:
                return redirect(url_for('admin_dashboard'))
            elif user.role == 1:
                return redirect(url_for('influencer_dashboard'))
            elif user.role == 2:
                return redirect(url_for('sponser_dashboard'))
            else:
                flash('Invalid user role', 'error')
                return redirect(url_for('login'))
        else:
            flash('Invalid email or password', 'error')
    return render_template('login.html')


@app.route('/campaigns')
@login_required
def campaigns_page():
    if session['user_role'] == 2:  # Sponsor role
        campaigns = Campaign.query.filter_by(sponsor_id=session['user_id']).all()
    else:
        campaigns = Campaign.query.all()  # For other roles, show all campaigns
    return render_template('campaigns.html', campaigns=campaigns, username=session.get('user_name'))


@app.route('/add_campaign', methods=['GET', 'POST'])
@login_required
def add_campaign():
    if request.method == 'POST':
        new_campaign = Campaign(
            name=request.form.get('name'),
            description=request.form.get('description'),
            niche=request.form.get('niche'),
            budget=int(request.form.get('budget')),
            deadline=datetime.strptime(request.form.get('deadline'), '%Y-%m-%d').date(),
            sponsor_id=session['user_id']  # Add the sponsor_id from the session
        )
        db.session.add(new_campaign)
        db.session.commit()
        flash('New campaign added successfully!', 'success')
        return redirect(url_for('campaigns_page'))
    return render_template('add_campaign.html', username=session.get('user_name'))

@app.route('/campaign/<int:campaign_id>')
@login_required
def campaign_details(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    return render_template('campaign_details.html', campaign=campaign, username=session.get('user_name'))

@app.route('/sponser-dashboard')
@login_required
def sponser_dashboard():
    campaigns = Campaign.query.filter_by(sponsor_id=session['user_id']).all()
    
    requests = [
        {"name": "Campaign 01", "influencer": "Influencer 01"},
        {"name": "Campaign 02", "influencer": "Influencer 01"},
        {"name": "Campaign 03", "influencer": "Company 03"}
    ]
    return render_template('sponser_dashboard.html', campaigns=campaigns, requests=requests, username=session.get('user_name'))

@app.route('/influencer-dashboard')
@login_required
def influencer_dashboard():
    campaigns = Campaign.query.all()  

    requests = [
        {"name": "Campaign 01", "company": "Company 01"},
        {"name": "Campaign 02", "company": "Company 02"},
        {"name": "Campaign 03", "company": "Company 03"}
    ]
    return render_template('influencer_dashboard.html', campaigns=campaigns, requests=requests, username=session.get('user_name'))










@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)