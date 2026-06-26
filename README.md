# KBCA Backend API

This is the FastAPI backend for the KBCA application. It provides authentication, OTP verification via email, and secure JWT-based sessions.

## Prerequisites
- Python 3.11+
- PostgreSQL (or SQLite for local development)

## Setup

1. **Clone the repository and enter the directory.**

2. **Create a virtual environment and activate it:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Variables:**
   Copy `.env.template` to `.env` and fill in your details:
   ```bash
   cp .env.template .env
   ```

5. **Database Migrations:**
   Initialize the database using Alembic:
   ```bash
   alembic upgrade head
   ```

## Running the Application

Start the development server:
```bash
uvicorn main:app --reload
```
The API will be available at `http://localhost:8000`. You can view the interactive documentation at `http://localhost:8000/docs`.

## Running Tests

Run the test suite using pytest:
```bash
pytest
```
