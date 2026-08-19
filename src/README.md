# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Sign up for activities

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Run the application:

   ```
   python app.py
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Sign up for an activity                                             |

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.

## Authentication configuration

Activity mutations require a teacher or administrator bearer token. Configure
users with the `AUTH_USERS_JSON` environment variable. Passwords must be stored
as PBKDF2 records generated with `auth.hash_password`, never as plaintext. Each
record has `password_hash`, `role`, and `tenant_id` fields:

```json
{
   "teacher@mergington.edu": {
      "password_hash": "pbkdf2_sha256$...$...",
      "role": "staff",
      "tenant_id": "mergington-high-school"
   }
}
```

Use `POST /auth/login` with a JSON body containing `username` and `password`,
then send the returned token as `Authorization: Bearer <token>`. Tokens expire
after one hour and are stored only in memory.
