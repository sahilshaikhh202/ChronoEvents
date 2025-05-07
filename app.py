from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
import random
import string

app = Flask(__name__)
app.secret_key = 'your_secret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///event_registration.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Organizer Model
class Organizer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(12), unique=True, nullable=False)
    event_name = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(10), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    start_time = db.Column(db.String(10), nullable=False)
    end_time = db.Column(db.String(10), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    permission = db.Column(db.String(3), nullable=False)
    event_type = db.Column(db.String(10), nullable=False)
    description = db.Column(db.String(100), nullable=True)

# Registered Audience Model
class RegisteredAudience(db.Model):
    id = db.Column(db.String(12), primary_key=True)  
    event_id = db.Column(db.String(12), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(10), nullable=False)
    authenticated = db.Column(db.Boolean, default=False)  

# User model for login/signup
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Helper function to generate a random event ID or user ID
def generate_unique_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))

# Helper function to get an organizer by ID
def get_organizer_by_id(id):
    return Organizer.query.get(id)

# Route for user signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']

        # Check if the user already exists
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            return render_template('signup.html', error=True)

        # Create a new user
        new_user = User(full_name=full_name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please log in.', 'success')
        return redirect('/login')

    return render_template('signup.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Authenticate user
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            session['user_id'] = user.id
            session['email'] = user.email
            flash('Login successful!', 'success')
            return redirect('/')
        else:
            return render_template('login.html', error=True)
        
    return render_template('login.html')

# User Dashboard
@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session:
        flash('Please log in to access your dashboard.', 'danger')
        return redirect('/login')

    user_email = session['email']
    events = RegisteredAudience.query.filter_by(email=user_email).all()

    return render_template('user_dashboard.html', events=events)

# User logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('email', None)
    flash('You have been logged out.', 'success')
    return redirect('/login')

# Route for the home page
@app.route('/')
def index():
    ofa_events = Organizer.query.filter_by(event_type='ofa').all() 
    recent_event = Organizer.query.order_by(Organizer.id.desc()).first()  

    return render_template('index.html', ofa_events=ofa_events, recent_event=recent_event)



# Organizer Registration Page
@app.route('/register_organizer', methods=['GET', 'POST'])
def register_organizer():
    if request.method == 'POST':
        event_name = request.form['event-name']
        name = request.form['name']
        contact = request.form['contact']
        date = request.form['date']
        start_time = request.form['start-time']
        end_time = request.form['end-time']
        location = request.form['location']
        permission = request.form['permission']
        event_type = request.form['event-type']
        description = request.form.get('description', '')

        event_id = generate_unique_id()

        # Create new organizer entry
        new_organizer = Organizer(
            event_id=event_id,
            event_name=event_name,
            name=name,
            contact=contact,
            date=date,
            start_time=start_time,
            end_time=end_time,
            location=location,
            permission=permission,
            event_type=event_type,
            description=description
        )

        try:
            db.session.add(new_organizer)
            db.session.commit()
            flash('Organizer registered successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error occurred while registering the organizer: {str(e)}', 'danger')

        return redirect('/register_organizer')  

    # Check if the user is logged in
    user_logged_in = 'user_id' in session  
    return render_template('register_organizer.html', user_logged_in=user_logged_in)

# Audience Registration Page
@app.route('/register_audience', methods=['GET', 'POST'])
@app.route('/register_audience/<event_id>', methods=['GET', 'POST'])  
def register_audience(event_id=None):
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        contact = request.form['contact']
        form_event_id = request.form['event_id']

        # Check if the event exists
        organizer = Organizer.query.filter_by(event_id=form_event_id).first()

        if organizer:
            user_id = generate_unique_id()

            # Create new audience entry
            new_audience = RegisteredAudience(
                id=user_id,
                event_id=form_event_id,
                name=name,
                email=email,
                contact=contact
            )

            try:
                db.session.add(new_audience)
                db.session.commit()
                flash(f'Audience registered successfully! Your User ID: {user_id}', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error occurred while registering the audience: {str(e)}', 'danger')
        else:
            flash('Invalid Event ID. Please check and try again.', 'danger')

        return redirect('/register_audience')

    # Check if the user is logged in
    user_logged_in = 'user_id' in session

    return render_template('register_audience.html', event_id=event_id, user_logged_in=user_logged_in)

# Authentication Page
@app.route('/authentication', methods=['GET', 'POST'])
def authentication():
    if request.method == 'POST':
        event_id = request.form['event_id']
        user_id = request.form['user_id']

        # Check if event_id and user_id match in the RegisteredAudience model
        audience = RegisteredAudience.query.filter_by(event_id=event_id, id=user_id).first()

        if audience:
            # Update authenticated status
            audience.authenticated = True
            db.session.commit()
            flash('Authentication successful!', 'success')
        else:
            flash('Authentication failed. Invalid Event ID or User ID.', 'danger')

    # Check if the user is logged in
    user_logged_in = 'user_id' in session  

    return render_template('authentication.html', user_logged_in=user_logged_in)

# Admin Login Page
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == 'admin' and password == 'password':
            session['admin_logged_in'] = True
            return redirect('/admin')
        else:
            flash('Invalid username or password', 'danger')

    return render_template('admin_login.html')

# Admin Dashboard Page
@app.route('/admin')
def admin():
    if 'admin_logged_in' not in session:
        flash('Please log in to access the admin dashboard.', 'danger')
        return redirect('/admin_login')

    # Sorting organizers and audiences by event_id
    organizers = Organizer.query.order_by(Organizer.event_id).all()
    audiences = RegisteredAudience.query.order_by(RegisteredAudience.event_id).all()
    users = User.query.order_by(User.id).all()
    response = make_response(render_template('admin.html', organizers=organizers, audiences=audiences, users=users))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Delete Organizer Route
@app.route('/delete_organizer/<int:id>', methods=['POST'])
def delete_organizer(id):
    organizer = get_organizer_by_id(id)  
    
    if organizer:
        event_id = organizer.event_id  
        
        # Delete the organizer
        db.session.delete(organizer)
        db.session.commit()
        
        # Delete corresponding audience records
        RegisteredAudience.query.filter_by(event_id=event_id).delete()  
        db.session.commit()  
        
        flash('Organizer and corresponding audience records deleted successfully.', 'success')
    else:
        flash('Organizer not found!', 'danger')
    
    return redirect('/admin')  

@app.route('/delete_audience_by_event/<string:event_id>', methods=['POST'])
def delete_audience_by_event(event_id):
    try:
        deleted_count = RegisteredAudience.query.filter_by(event_id=event_id).delete()
        db.session.commit()

        if deleted_count > 0:
            flash(f'Successfully deleted {deleted_count} audience records for event ID: {event_id}', 'success')
        else:
            flash(f'No audience records found for event ID: {event_id}', 'info')

    except Exception as e:
        db.session.rollback()  
        flash(f'An error occurred while deleting audience records: {str(e)}', 'danger')

    return redirect(url_for('admin')) 

# Delete Audience Route by ID
@app.route('/delete_audience/<string:id>', methods=['POST'])  
def delete_audience(id):
    audience = RegisteredAudience.query.get(id)
    if audience:
        db.session.delete(audience)
        db.session.commit()
        flash('Audience deleted successfully!', 'success')
    else:
        flash('Audience not found!', 'danger')
    return redirect('/admin')  

@app.route('/delete_user/<int:id>', methods=['POST'])
def delete_user(id):
    user = User.query.get_or_404(id)  
    try:
        db.session.delete(user)  
        db.session.commit()
        flash('User deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    return redirect('/admin')

# Organizer Login Page
@app.route('/organizer_login', methods=['GET', 'POST'])
def organizer_login():
    if request.method == 'POST':
        event_id = request.form['event_id']
        contact_number = request.form['contact_number']

        
        organizer = Organizer.query.filter_by(event_id=event_id, contact=contact_number).first()

        if organizer:
            session['event_id'] = event_id 
            flash('Login successful!', 'success')
            return redirect('/organizer_dashboard')
        else:
            flash('Login failed. Invalid Event ID or Contact Number.', 'danger')

    # Check if the user is logged in
    user_logged_in = 'user_id' in session  

    return render_template('organizer_login.html', user_logged_in=user_logged_in)


# Organizer Dashboard Page
@app.route('/organizer_dashboard')
def organizer_dashboard():
    event_id = session.get('event_id')
    attendees = RegisteredAudience.query.filter_by(event_id=event_id).all() if event_id else []
    return render_template('organizer_dashboard.html', attendees=attendees)

# Logout route for Organizer
@app.route('/organizer_logout')
def organizer_logout():
    session.pop('event_id', None)  
    flash('You have been logged out successfully.', 'success')
    return redirect('/organizer_login')

# Admin Logout Route
@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)  # Clear the session
    flash('You have been logged out successfully.', 'success')
    return redirect('/admin_login')


# About page
@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  
    app.run(debug=True)