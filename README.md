# HealthSecure v3

## **Overview**

HealthSecure v3 is a secure healthcare management web application designed to manage patient records, user roles, and audit logs with a focus on security best practices.

## **Features**

* User authentication (login system)
* Role-based access control (admin, staff, etc.)
* Patient record management (create, edit, view)
* Audit logging for tracking system activity
* Basic security implementations for sensitive data handling

## **Tech Stack**

* Python (Flask)
* MySQL
* HTML, CSS
* Jinja Templates

## **Setup Instructions**

1. Clone the repository
2. Install dependencies:
   pip install -r requirements.txt
3. Set up the database using the provided SQL file
4. Run the application:
   python app.py

**Live Demo**

* Live URL (Railway): https://healthsecurev3-production.up.railway.app/login

## **Demo Credentials**

Use the following accounts to test different roles:

**Admin**

  * Username: Fawad
  * Password: admin123

**Staff**

  * Username: Rohan
  * Password: raj

## **Environment Setup (.env)**
This project uses a `.env` file for database configuration. Since `.env` is included in `.gitignore`, it is not uploaded to GitHub.
After cloning the repository, create a file named `.env` in the root directory and add your own database credentials like this:

```
DB_HOST=your_db_host
DB_USER=your_username
DB_PASSWORD=your_password
DB_NAME=railway
DB_PORT=your_db_port_number
SECRET_KEY=your_secret_key
```

> Without this file, the application will fail to connect to the database and will not start.

> For Railway deployment, these variables should be configured in the Railway environment settings instead of a local `.env` file.

## **Security Note**

This project implements **HIPAA-inspired security practices**, including:

* Password hashing
* Role-based access control
* Audit logging

⚠️ This application is **not HIPAA compliant** and is intended for educational purposes only.

## Learning Purpose

This project was developed as part of a software engineering learning experience to understand secure application design principles in healthcare systems.
