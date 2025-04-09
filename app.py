
from flask import Flask, render_template, request, redirect, url_for, flash, session,jsonify, current_app
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from gridfs import GridFS
import os
from flask import send_file, Response
import google.generativeai as genai
import logging
import re
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
import datetime
import jwt
from datetime import datetime, timedelta
from flask_mail import Mail, Message



# Configure logging
logging.getLogger("pymongo").setLevel(logging.WARNING)
logging.basicConfig(level=logging.DEBUG)  # Set to DEBUG for more detailed output
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Set Secret Key
app.secret_key = os.getenv("SECRET_KEY", "fallback-secret-key")

# CSRF Protection
csrf = CSRFProtect(app)
# ✅ Gmail SMTP settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'saviosunncom'          # Your Gmail address
app.config['MAIL_PASSWORD'] = 'fdm'  # App password
app.config['MAIL_DEFAULT_SENDER'] = 's@gmail.com'

mail = Mail(app)

# Configure file upload settings
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)  # Create upload directory

client = MongoClient("mongodb+srv://s0.0zmwv1l.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["HireSmart"]
recruiters_collection = db["Recruiters"]
jobs_collection = db["Jobs"]
signup_collection = db["Signup"] 
results_collection    = db["Results"] # Collection to store signup details

job_applicant_collection=db['Applicant'] # Collection for applicant details
fs = GridFS(db)  # GridFS for storing resume files

# Validate email format
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

# Validate password strength
def is_strong_password(password):
    return bool(re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password))

# Validate file uploads
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pdf', 'doc', 'docx'}

# JWT helper functions
def generate_jwt_token(user_id, role):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=1)  # token expires in 1 hour
    }
    token = jwt.encode(payload, app.secret_key, algorithm="HS256")
    return token

def verify_jwt_token(token):
    try:
        decoded = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        flash("Session expired. Please log in again.", "danger")
        return None
    except jwt.InvalidTokenError:
        flash("Invalid token. Please log in again.", "danger")
        return None

# Home Page
@app.route('/')
def home():
    return render_template('hiresmart.html')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Handle form data if needed
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        if name and email and message:
            flash("Thank you for reaching out! We'll get back to you soon.", "success")
        else:
            flash("All fields are required!", "danger")
        return redirect(url_for('contact'))

    return render_template('contact.html')

@app.route('/recruiter_signup', methods=['GET', 'POST'])
def recruiter_signup():
    if request.method == 'POST':
        full_name = request.form.get('fullName')
        email = request.form.get('email')
        password = request.form.get('password')
        role = "Recruiter"  # Static role for recruiters
        
        # Validate required fields
        if not full_name or not email or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for('recruiter_signup'))

        # Check if email is valid
        if not is_valid_email(email):
            flash("Please enter a valid email address.", "danger")
            return redirect(url_for('recruiter_signup'))
     
        # Check if email is already registered
        if signup_collection.find_one({'email': email}):
            flash("Email already registered!", "danger")
            return redirect(url_for('recruiter_signup'))

        # Check if password is strong
        if not is_strong_password(password):
            flash("Password is not strong enough. It must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one digit, and one special character (@$!%*?&).", "danger")
            return redirect(url_for('recruiter_signup'))

        # Debug statement
        logger.debug("Received valid recruiter signup data.")

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Insert details into the database
        try:
            result = signup_collection.insert_one({
                'full_name': full_name,
                'email': email,
                'password': hashed_password,
                'role': role
            })

            if result.inserted_id:
                logger.debug(f"Document inserted with ID: {result.inserted_id}")
            else:
                logger.debug("Insert operation failed.")

            total_documents = signup_collection.count_documents({})
            logger.debug(f"Total documents in Signup collection: {total_documents}")

            flash(f"Signup successful! Welcome, {full_name}", "success")
            return redirect(url_for('recruiter_login'))  # Redirect to login page

        except Exception as e:
            logger.error(f"Error inserting document into MongoDB: {str(e)}")
            flash("An error occurred while signing up. Please try again.", "danger")
            return redirect(url_for('recruiter_signup'))

    return render_template('recruiter_signup.html')

@app.route('/applicant_signup', methods=['GET', 'POST'])
def applicant_signup():
    if request.method == 'POST':
        full_name = request.form.get('fullName')
        email = request.form.get('email')
        password = request.form.get('password')
        role = "JobApplicant"  # Static role for applicants

        logger.debug(f"Received Signup Request: {full_name}, {email}")

        # Validate required fields
        if not full_name or not email or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for('applicant_signup'))

        # Check if email is valid
        if not is_valid_email(email):
            flash("Please enter a valid email address.", "danger")
            return redirect(url_for('applicant_signup'))

        # Check if email is already registered
        if signup_collection.find_one({'email': email}):
            flash("Email already registered!", "danger")
            return redirect(url_for('applicant_signup'))

        # Check if password is strong
        if not is_strong_password(password):
            flash("Password must be strong (at least 8 characters, with uppercase, lowercase, number, and special character).", "danger")
            return redirect(url_for('applicant_signup'))

        try:
            hashed_password = generate_password_hash(password)
        except Exception as e:
            logger.error(f"Error hashing password: {e}")
            flash("Error processing password!", "danger")
            return redirect(url_for('applicant_signup'))

        try:
            result = signup_collection.insert_one({
                'full_name': full_name,
                'email': email,
                'password': hashed_password,
                'role': role
            })

            logger.debug(f"Signup successful! Inserted ID: {result.inserted_id}")
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for('applicant_login'))  # Redirect to login page
        except Exception as e:
            logger.error(f"Database Error: {e}")
            flash("Error saving data! Try again later.", "danger")
            return redirect(url_for('applicant_signup'))

    return render_template('applicant_signup.html')

# Recruiter Login with JWT
@app.route('/recruiter/login', methods=['GET', 'POST'])
def recruiter_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Find recruiter in the database
        recruiter = signup_collection.find_one({'email': email, 'role': 'Recruiter'})

        if recruiter and check_password_hash(recruiter['password'], password):
            # Generate JWT token
            token = generate_jwt_token(str(recruiter['_id']), recruiter['role'])
            session['jwt_token'] = token
            session['user_id'] = str(recruiter['_id'])
            session['user_name'] = recruiter['full_name']
            session['user_email'] = recruiter['email']  # Store email in session
            session['role'] = recruiter['role']
            return redirect(url_for('recruiter_dashboard'))
        else:
            flash("Invalid email or password!", "danger")
            return redirect(url_for('recruiter_login'))
    return render_template('recruiter_login.html')

# Applicant Login with JWT
@app.route('/applicant/login', methods=['GET', 'POST'])
def applicant_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        logger.debug(f"Email: {email}, Password: {password}")

        applicant = signup_collection.find_one({'email': email, 'role': "JobApplicant"})
        logger.debug(f"Applicant: {applicant}")

        if applicant and check_password_hash(applicant['password'], password):
            token = generate_jwt_token(str(applicant['_id']), applicant['role'])
            session['jwt_token'] = token
            session['user_id'] = str(applicant['_id'])
            session['user_name'] = applicant['full_name']
            session['user_email'] = applicant['email']  # Optionally store email for applicants too
            session['role'] = applicant['role']
            flash(f"Welcome {session['user_name']}!", "success")
            return redirect(url_for('applicant_dashboard'))
        else:
            flash("Invalid credentials!", "danger")
            return redirect(url_for('applicant_login'))
    return render_template('applicant_login.html')

# Recruiter Dashboard (JWT Protected)
@app.route('/recruiter/dashboard', methods=['GET', 'POST'])
def recruiter_dashboard():
    print('savio')
    # Check if user is logged in as Recruiter
    token = session.get('jwt_token')
    if not token:
        flash("Please log in.", "danger")
        return redirect(url_for('recruiter_login'))
    decoded = verify_jwt_token(token)
    if not (decoded and decoded.get('role') == 'Recruiter'):
        session.clear()
        return redirect(url_for('recruiter_login'))
    
    if request.method == 'POST':
        print('savio sunny')
        try:
            # Handle file upload for the company logo
            logo = request.files.get("companyLogo")
            if logo and logo.filename != "":
                if not logo.filename.lower().endswith(('.jpg', '.jpeg', '.png')):
                    flash("Invalid file type for company logo. Only JPG or PNG files are allowed.", "danger")
                    return redirect(url_for('recruiter_dashboard'))
                logo_file_id = fs.put(
                    logo,
                    filename=secure_filename(f"{session['user_id']}_{logo.filename}"),
                    content_type=logo.content_type
                )
            else:
                flash("Company logo is required.", "danger")
                return redirect(url_for('recruiter_dashboard'))
            
            # Build job data from the form fields including job role
            job_data = {
                "companyName": request.form.get("companyName"),
                "companyLogo": str(logo_file_id),
                "companyLocation": request.form.get("companyLocation"),
                "jobRole": request.form.get("jobRole"),
                "jobDescription": request.form.get("jobDescription"),
                
                "noOfCandidates": int(request.form.get("noOfCandidates", 0)),
                "deadline": request.form.get("deadline"),
                "posted_by": ObjectId(session['user_id']),
                "posted_at": datetime.now()
            }
            logger.debug("Form Data: %s", request.form.to_dict())
            logger.debug("Files Data: %s", request.files.to_dict())
            
            result = jobs_collection.insert_one(job_data)
            logger.info(f"Job posted successfully with ID: {result.inserted_id}")
            flash("Job posted successfully!", "success")
            # Redirect to the job success page
            return redirect(url_for("job_su"))
        
        except KeyError as e:
            logger.error(f"Missing form field: {e}")
            flash(f"Error: Missing required field {e}", "danger")
            return redirect(url_for("recruiter_dashboard"))
        except Exception as e:
            logger.error(f"Error posting job: {e}")
            flash(f"Error posting job: {str(e)}", "danger")
            return redirect(url_for("recruiter_dashboard"))
   
    recruiter_id = ObjectId(session['user_id'])
# Get jobs posted by this recruiter in the last 3 days
    three_days_ago = datetime.now() - timedelta(days=3)
    print(three_days_ago)

    recent_jobs = list(jobs_collection.find({
        "posted_by": recruiter_id,
        "posted_at": {"$gte": three_days_ago}
    }))
    job_ids = [str(job["_id"]) for job in recent_jobs]
    print(job_ids)
    total_applications = results_collection.count_documents({
        "job_id": {"$in": job_ids}
    })



# Prepare job info with extra fields
    job_list = []
    for job in recent_jobs:
        job_id = job["_id"]
        
        
        deadline_date = datetime.strptime(job.get("deadline", ""), "%Y-%m-%d")  # assuming YYYY-MM-DD format
        days_left = (deadline_date - datetime.now()).days
        

        job_list.append({
            "job_title": job["jobRole"],
            "company": job["companyName"],
            "posted_on": job["posted_at"].strftime("%Y-%m-%d"),
            
            "days_left": days_left+1,
            "deadline": job["deadline"],
            "candidates": job["noOfCandidates"]
        })
    print(job_list)
    print(total_applications)
    active_jobs_count = jobs_collection.count_documents({"posted_by": recruiter_id})
    count = results_collection.count_documents({"mail": True})


    return render_template('recruiter_dashboard.html', 
        recruiter_name=session['user_name'],
        recruiter_email=session['user_email'],
        active_jobs_count=active_jobs_count,
        recent_jobs=job_list,
        total_applications=total_applications,
        count=count
    )

@app.route('/modify_job_description', methods=['POST'])
def modify_job_description():
    try:
        data = request.get_json()
        original_text = data.get("jobDescription", "")
        if not original_text:
            return {"error": "No job description provided."}, 400

        # Instantiate the Gemini client using your API key
        genai.configure(api_key="AIzaSyBYVUgqT3Q274") 
        
        # Prepare a system prompt to instruct Gemini
        system_prompt = (
            "Improve the following job description by correcting grammar, spelling mistakes, "
            "and making it clear, formal, and professional:"
        )
        
        # Combine system prompt and original text into the contents
        contents = f"{system_prompt}\n\n{original_text}"
        
        # Call Gemini using the provided model (adjust the model name if needed)
        
        model = genai.GenerativeModel("gemini-1.5-flash-8b")
        contents = f"{system_prompt}\n\n{original_text}"
        response = model.generate_content(contents)
        modified_text = response.text
        if not modified_text:
            logger.error("Gemini API returned no modified text.")
            return {"error": "No modified text returned from Gemini."}, 500

        return {"modifiedText": modified_text}, 200

    except Exception as e:
        logger.error(f"Error in modify_job_description: {e}")
        return {"error": "Internal server error."}, 500
@app.route('/job_success')
def job_success():
    # You can pass additional data if necessary
    return render_template('job_success.html')


@app.route("/post_success")
def job_suc():
     return render_template('postjob.html')
# Applicant Dashboard (JWT Protected)
# Applicant Dashboard
@app.route('/applicant/dashboard')
def applicant_dashboard():
    if 'user_id' in session and session.get('role') == 'JobApplicant':
        # The template can optionally receive job data if needed,
        # but the frontend will fetch data from /api/jobs.
        return render_template('applicant_dashboard.html', 
                               user_name=session.get('user_name', 'User'))
    else:
        flash("Unauthorized access. Please log in as a Job Applicant.", "danger")
        return redirect(url_for('applicant_login'))
@app.route('/resume/<file_id>')
def get_resume(file_id):
    try:
        file_id_obj = ObjectId(file_id)
        grid_out = fs.get(file_id_obj)
        return Response(grid_out.read(), mimetype=grid_out.content_type)
    except Exception as e:
        return "Resume not found", 404


@app.route('/api/jobs')
def api_jobs():
    if 'user_id' in session and session.get('role') == 'JobApplicant':
        # Fetch job listings from the MongoDB collection stored in jobs_collection
        jobs = list(jobs_collection.find({}))
        
        # Convert ObjectId and datetime objects to strings for JSON serialization
        for job in jobs:
            job['_id'] = str(job['_id'])
            job['posted_by'] = str(job['posted_by'])
            if job.get('posted_at'):
                job['posted_at'] = job['posted_at'].isoformat()
            if job.get('deadline') and isinstance(job['deadline'], datetime):
                job['deadline'] = job['deadline'].isoformat()
            
            # Convert companyLogo to a URL that points to the get_logo route if available
            if job.get('companyLogo'):
                job['companyLogo'] = url_for('get_logo', file_id=job['companyLogo'], _external=True)
        
        return jsonify(jobs)
    else:
        return jsonify({'error': 'Unauthorized access'}), 401



    

@app.route('/instructions')
def instructions():
    return render_template('instructions.html')

@app.route('/logout')
def logout():
    if 'role' in session:
        role = session['role']
        session.clear()
        flash("Logged out successfully.", "info")
        if role == 'Recruiter':
            return redirect(url_for('recruiter_login'))
        elif role == 'JobApplicant':
            return redirect(url_for('applicant_login'))
    return redirect(url_for('home'))

# Personal Information Route
@app.route('/profile_settings', methods=['GET', 'POST'])
def profile_settings():
    if 'user_id' not in session or session['role'] != 'JobApplicant':
        logger.error("Unauthorized access to profile_settings")
        flash("Please login as an applicant first", "danger")
        return redirect(url_for('applicant_login'))

    applicant_id = ObjectId(session['user_id'])
    logger.debug(f"Profile settings accessed by applicant_id: {applicant_id}")

    if request.method == 'POST':
        logger.debug(f"Received POST request to /profile_settings: {request.form}")
        try:
            personal_info = {
                'firstName': request.form.get('firstName', ''),
                'lastName': request.form.get('lastName', ''),
                'fullName': request.form.get('fullName', ''),
                'phone': request.form.get('phone', ''),
                'nationality': request.form.get('nationality', ''),
                'gender': request.form.get('gender', ''),
                'dob': request.form.get('dob', ''),
                'address': {
                    'line1': request.form.get('addressLine1', ''),
                    'line2': request.form.get('addressLine2', ''),
                    'country': request.form.get('country', ''),
                    'city': request.form.get('city', ''),
                    'state': request.form.get('state', ''),
                    'zipCode': request.form.get('zipCode', '')
                }
            }
            
            logger.debug(f"Personal info to save: {personal_info}")
            result = job_applicant_collection.update_one(
                {"_id": applicant_id},
                {"$set": {"personal_info": personal_info}},
                upsert=True
            )

            if result.modified_count > 0:
                logger.info(f"Personal details updated for applicant_id: {applicant_id}")
                flash("Personal details updated successfully!", "success")
            elif result.upserted_id:
                logger.info(f"Personal details inserted for applicant_id: {applicant_id}, upserted_id: {result.upserted_id}")
                flash("Personal details saved successfully!", "success")
            else:
                logger.info(f"No changes detected for applicant_id: {applicant_id}")
                flash("No changes detected in personal details", "info")

            return redirect(url_for('education_qualifications'))
        
        except Exception as e:
            logger.error(f"Personal info save error: {str(e)}", exc_info=True)
            flash(f"Error saving personal details: {str(e)}", "danger")
            return redirect(url_for('profile_settings'))

    existing_data = job_applicant_collection.find_one({"_id": applicant_id})
    logger.debug(f"Existing data for applicant_id {applicant_id}: {existing_data}")
    return render_template('profile_settings.html', 
                           data=existing_data.get('personal_info', {}) if existing_data else {})



# Education Qualifications
@app.route('/education_qualifications', methods=['GET', 'POST'])
def education_qualifications():
    if 'user_id' not in session or session['role'] != 'JobApplicant':
        logger.error("Unauthorized access to education_qualifications")
        flash("Please login as applicant first", "danger")
        return redirect(url_for('applicant_login'))

    applicant_id = ObjectId(session['user_id'])
    logger.debug(f"Education qualifications accessed by applicant_id: {applicant_id}")

    if request.method == 'POST':
        logger.debug(f"Received POST request to /education_qualifications: {request.form}")
        try:
            resume = request.files.get('resume')
            resume_filename = None
            
            if resume and resume.filename != '':
                if not allowed_file(resume.filename):
                    logger.error(f"Invalid file type for resume: {resume.filename}")
                    flash("Invalid file type for resume", "danger")
                    return redirect(url_for('education_qualifications'))
                
                resume_file_id = fs.put(
                    resume,
                    filename=secure_filename(f"{applicant_id}_{resume.filename}"),
                    content_type=resume.content_type
                )
                logger.debug(f"Resume uploaded to GridFS with file_id: {resume_file_id}")

            try:
                active_backlogs = int(request.form.get('activeBacklogs', 0))
            except ValueError:
                active_backlogs = 0

            education_data = {
                "applying_for": request.form.get('applyingFor', ''),
                "highest_qualification": request.form.get('highestQualification', ''),
                "completion_year": request.form.get('completionYear', ''),
                "ug_course_type": request.form.get('ugCourseType', ''),
                "tenth_marks": request.form.get('tenthMarks', ''),
                "tenth_year": request.form.get('tenthYear', ''),
                "higher_secondary": request.form.get('higherSecondary', ''),
                "ug_degree": request.form.get('ugDegree', ''),
                "ug_specialization": request.form.get('ugSpecialization', ''),
                "ug_marks": request.form.get('ugMarks', ''),
                "active_backlogs": active_backlogs,
                "pg_college": request.form.get('pgCollege', ''),
                "pg_year": request.form.get('pgYear', ''),
                "work_experience": request.form.get('workExperience', ''),
                "semester_exams": request.form.get('semesterExams', ''),
                "resume_file_id": str(resume_file_id) if resume_file_id else None
            }
            
            logger.debug(f"Education data to save: {education_data}")

            result = job_applicant_collection.update_one(
                {"_id": applicant_id},
                {"$set": {"education": education_data}},
                upsert=True
            )

            if result.modified_count > 0:
                logger.info(f"Education details updated for applicant_id: {applicant_id}")
                flash("Education details updated successfully!", "success")
            elif result.upserted_id:
                logger.info(f"Education details inserted for applicant_id: {applicant_id}, upserted_id: {result.upserted_id}")
                flash("Education details saved successfully!", "success")
            elif resume_file_id:
                logger.info(f"Resume updated for applicant_id: {applicant_id}")
                flash("Resume updated successfully!", "success")
            else:
                logger.info(f"No changes detected for applicant_id: {applicant_id}")
                flash("No changes detected", "info")

            return redirect(url_for('applicant_dashboard'))
        
        except Exception as e:
            logger.error(f"Education save error: {str(e)}", exc_info=True)
            flash(f"Error saving education details: {str(e)}", "danger")
            return redirect(url_for('education_qualifications'))

    existing_data = job_applicant_collection.find_one({"_id": applicant_id})
    logger.debug(f"Existing data for applicant_id {applicant_id}: {existing_data}")
    return render_template('education_qualifications.html', 
                           data=existing_data.get('education', {}) if existing_data else {})

@app.route("/job_openings")
def job_openings():
    if 'user_id' not in session or session['role'] != 'JobApplicant':
        flash("Unauthorized access. Please log in as a job applicant.", "danger")
        return redirect(url_for('applicant_login'))
    
    jobs = list(jobs_collection.find())
    return render_template("job_openings.html", jobs=jobs)

import requests

@app.route('/job/<job_id>')
def job_detail(job_id):
    try:
        job = jobs_collection.find_one({"_id": ObjectId(job_id)})
        if not job:
            return "Job not found", 404

        logo_url = url_for('get_logo', file_id=job['companyLogo'])

        # Get applicant data from job_applicant_collection (modify query as needed)
        user_id = session['user_id']
        print(user_id)
        applicant = job_applicant_collection.find_one({"_id": ObjectId(user_id)})
        print(applicant)


        if not applicant:
            return render_template('new.html')

        personal_info = applicant.get("personal_info", {})
        education_data = applicant.get("education", {})

        return render_template(
            'job.html',
            job=job,
            logo_url=logo_url,
            personal_info=personal_info,
            education_data=education_data
        )

    except Exception as e:
        return f"An error occurred: {str(e)}", 500
    
@app.route('/apply_job/<job_id>', methods=['POST'])
@csrf.exempt
def apply_job(job_id):
    user_id = session.get('user_id')
    applicant = job_applicant_collection.find_one({"_id": ObjectId(user_id)})
    personal_info = applicant.get("personal_info", {})
    education_data = applicant.get("education", {})
    external_url = 'http://127.0.0.1:5002/process'

    # Prepare data to send
    data_to_send = {
        'job_id': job_id,
        'user_id': user_id,
        'personal_info': personal_info,
        'education_data': education_data,
        
        
    }

    try:
        response = requests.post(external_url, json=data_to_send)
        response.raise_for_status()  # Raise error for bad response
    except requests.exceptions.RequestException as e:
        # Log or handle the failure gracefully
        print("Error sending data to external link:", e)

   
    return render_template('job_success.html', job_id=job_id)

@app.route("/candidates")
def candidates():
    # 1. Auth check
    if 'user_id' not in session or session.get('role') != 'Recruiter':
        flash("Unauthorized access. Please log in as a recruiter.", "danger")
        return redirect(url_for('recruiter_login'))

    recruiter_id = ObjectId(session['user_id'])

    # 2. Fetch all jobs by this recruiter
    job_postings = list(jobs_collection.find({"posted_by": recruiter_id}))
    if not job_postings:
        flash("You haven’t posted any jobs yet.", "info")
        return render_template("candidates.html",
                               candidate_list=[],
                               current_company=None,
                               company_idx=0,
                               total_companies=0,
                               recommended_limit=0)

    # 3. Build a list of unique companies
    companies = []
    for job in job_postings:
        name = job.get("companyName", "N/A")
        if name not in companies:
            companies.append(name)
    total = len(companies)

    # 4. Figure out which company to show
    try:
        idx = int(request.args.get("company_idx", 0))
    except ValueError:
        idx = 0
    idx = max(0, min(idx, total - 1))
    current_company = companies[idx]

    # 5. Jobs for this company
    jobs_for_company = [j for j in job_postings if j.get("companyName") == current_company]

    # 5a. Sum up “number of candidates needed” across these jobs
    #    (assumes your job doc has `noOfCandidates`—rename if needed)
    total_needed = sum(j.get("noOfCandidates", 0) for j in jobs_for_company)
    recommended_limit = total_needed + 10

    # 6. Fetch all applicants for those job_ids
    job_ids = [str(j["_id"]) for j in jobs_for_company]
    applicants = list(results_collection.find({"job_id": {"$in": job_ids}}))

    # 7. Build & sort candidate_list
    candidate_list = []
    for appl in applicants:
        uid = appl["user_id"]
        job = next((j for j in jobs_for_company if str(j["_id"]) == appl["job_id"]), None)
        if not job:
            continue
        user_obj = job_applicant_collection.find_one({"_id": ObjectId(appl["user_id"])})
        if not user_obj:
            continue

        resume_file_id = user_obj.get("education", {}).get("resume_file_id")
        resume_link = url_for('get_resume', file_id=resume_file_id) if resume_file_id else None

        candidate_list.append({
            "applicant_id":    uid,
            "full_name": user_obj.get("personal_info", {}).get("fullName", "N/A"),
            "job_role": job.get("jobRole", "N/A"),
            "qualification": user_obj.get("education", {}).get("highest_qualification", "N/A"),
            "skills": appl.get("resume_skill_entities", []),
            "total_score": appl.get("total_score", 0),
            "resume_link": resume_link,
            "mail": appl.get("mail", False)
        })

    candidate_list.sort(key=lambda c: c["total_score"], reverse=True)

    # 8. Tag top N as “AI Recommended”
    for i, cand in enumerate(candidate_list):
        cand["is_recommended"] = (i < recommended_limit)

    return render_template("candidates.html",
                           candidate_list=candidate_list,
                           current_company=current_company,
                           company_idx=idx,
                           total_companies=total,
                           recommended_limit=recommended_limit)



@app.route("/send_email")
def send_email():
    selected_ids = request.args.getlist("selected_ids")
    company_idx  = request.args.get("company_idx", 0, type=int)

    if not selected_ids:
        flash("⚠️ No candidates selected!", "warning")
        return redirect(url_for('candidates', company_idx=company_idx))

    job_ids     = set()
    emails_sent = 0
    emails      = []

    # 1. Collect email info & job_ids
    for uid in selected_ids:
        appl = results_collection.find_one({"user_id": uid})
        if not appl:
            current_app.logger.warning(f"No application found for user_id={uid}")
            continue

        job_ids.add(appl["job_id"])
        user = signup_collection.find_one({"_id": ObjectId(uid)})
        if not user or "email" not in user:
            continue

        emails.append({
            "email": user["email"],
            "name": user.get("personal_info", {}).get("fullName", "Candidate"),
            "job_id": appl["job_id"]
        })

    if not emails:
        flash("❌ No valid candidates/emails found.", "danger")
        return redirect(url_for('candidates', company_idx=company_idx))

    # 2. Compute test date
    test_date = (datetime.utcnow() + timedelta(days=3)).strftime("%A, %B %d, %Y")

    # 3. Send each email
    for info in emails:
        # Get job info
        job = jobs_collection.find_one({"_id": ObjectId(info["job_id"])})
        job_role = job.get("jobRole", "N/A")
        company_name = job.get("companyName", "our company")

        try:
            msg = Message(
                subject="📬 You’re Shortlisted! Next Steps",
                recipients=[info["email"]],
                body=f"""Dear {info['name']},

Congratulations! You’ve been shortlisted for the position of
“{job_role}” at {company_name}.

📅 Proctoring test scheduled on: {test_date}

The test link is given below,instructions will be given shortly in the next mail

http://localhost:3000

Best of luck!  
Recruitment Team
"""
            )
            mail.send(msg)
            emails_sent += 1
        except Exception as e:
            current_app.logger.error(f"Failed sending to {info['email']}: {e}")
            flash(f"Failed to send email to {info['email']}.", "danger")

    if emails_sent == 0:
        flash("❌ No emails were sent.", "danger")
        return redirect(url_for('candidates', company_idx=company_idx))

    # 4. Update mail flags
    results_collection.update_many(
        {"job_id": {"$in": list(job_ids)}},
        {"$set": {"mail": False}}
    )
    results_collection.update_many(
        {"user_id": {"$in": selected_ids}},
        {"$set": {"mail": True}}
    )

    flash(f"✅ Emails sent to {emails_sent} candidate(s). Proctoring test is on {test_date}.", "success")
    return redirect(url_for('candidates', company_idx=company_idx))

@app.route('/logo/<file_id>')
def get_logo(file_id):
    try:
        file_id_obj = ObjectId(file_id)
        grid_out = fs.get(file_id_obj)
        return Response(grid_out.read(), mimetype=grid_out.content_type)
    except Exception as e:
        # Handle file not found or any error
        return "Logo not found", 404



@app.route("/upload_resume", methods=["GET", "POST"])
def upload_resume():
    if 'user_id' not in session or session['role'] != 'JobApplicant':
        flash("Please log in as an applicant first.", "danger")
        return redirect(url_for('applicant_login'))

    applicant_id = ObjectId(session['user_id'])

    if request.method == "POST":
        resume = request.files.get("resume")
        photo = request.files.get("photo")

        try:
            if resume and allowed_file(resume.filename):
                resume_file_id = fs.put(
                    resume,
                    filename=secure_filename(f"{applicant_id}_{resume.filename}"),
                    content_type=resume.content_type
                )
                job_applicant_collection.update_one(
                    {"_id": applicant_id},
                    {"$set": {"resume_file_id": str(resume_file_id)}},
                    upsert=True
                )
            else:
                flash("Please upload a valid resume file (PDF, DOC, DOCX).", "danger")
                return redirect(url_for("upload_resume"))

            if photo and photo.filename.endswith((".jpg", ".png", ".jpeg")):
                photo_file_id = fs.put(
                    photo,
                    filename=secure_filename(f"{applicant_id}_{photo.filename}"),
                    content_type=photo.content_type
                )
                job_applicant_collection.update_one(
                    {"_id": applicant_id},
                    {"$set": {"photo_file_id": str(photo_file_id)}},
                    upsert=True
                )
            elif photo:
                flash("Please upload a valid photo file (JPG, PNG, JPEG).", "danger")
                return redirect(url_for("upload_resume"))

            flash("Files uploaded successfully!", "success")
            return redirect(url_for("upload_resume"))

        except Exception as e:
            logger.error(f"Error uploading files: {str(e)}")
            flash(f"Error uploading files: {str(e)}", "danger")
            return redirect(url_for("upload_resume"))

    return render_template("upload_resume.html")

@app.route("/resumes")
def resumes():
    candidates_list = job_applicant_collection.find({}, {"_id": 0, "name": 1, "resume": 1})
    return render_template("resumes.html", candidates=candidates_list)

if __name__ == '__main__':
    app.run(debug=True)
