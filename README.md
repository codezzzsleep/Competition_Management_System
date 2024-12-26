

# **College Competition Management System**

## **Project Overview**

The College Competition Management System is designed to help colleges efficiently manage student participation in various competitions. The system supports the creation and management of competitions, management and statistics of student participation, teacher guidance records, judge scoring, performance analysis, and data export functionality. The system provides multi-role access to meet the needs of administrators, teachers, and students.

---

## **Features**

### **1. User Roles**
- **Administrator**:
  - Add, edit, and delete competitions.
  - Manage student, teacher, and user accounts.
  - Generate statistical reports and visualized charts.
- **Teacher**:
  - View the competition records and achievements of guided students.
  - Manage the competition status of guided students.
- **Student**:
  - View their own competition records and achievements.
- **Visitor**:
  - Browse public competition information and award lists.

### **2. System Features**
- **User Management**:
  - User registration, login, and role assignment.
  - Logical deletion of users (`is_delete` flag).
- **Competition Management**:
  - Add, edit, and delete competitions.
  - Bulk import competition data (Excel files).
- **Participation Management**:
  - Add and manage student participation information, including advisors and results.
- **Data Statistics & Analysis**:
  - Statistics for the number of participants, advisors, competition levels, and score distributions.
  - Provide charts (pie charts, bar charts) to display statistical results.
- **Report Export**:
  - Export competition data in Excel or PDF format.
- **Judge Scoring**:
  - Allow judges to score students’ work and record comments.

---

## **Technology Stack**

### **Frontend**
- **Framework**: Vue 3
- **State Management**: Vuex/Pinia
- **Routing**: Vue Router
- **HTTP Requests**: Axios
- **UI Framework** (optional): Element Plus / Ant Design Vue / Tailwind CSS

### **Backend**
- **Framework**: Flask
- **Database**: MySQL / SQLite (development environment)
- **ORM**: Flask-SQLAlchemy
- **Authentication**: Flask-JWT-Extended (JWT-based user authentication)
- **Others**: Flask-CORS, Flask-Bcrypt (password encryption)

### **Deployment**
- **Frontend**: Nginx
- **Backend**: Gunicorn + Nginx
- **Database**: MySQL

---

## **Project Directory Structure**

```
competition-management-system/
│
├── backend/                      # Backend directory
│   ├── app.py                    # Main application file
│   ├── models.py                 # Database models
│   ├── routes.py                 # API routes
│   ├── config.py                 # Configuration file (database, JWT, etc.)
│   ├── requirements.txt          # Backend dependencies
│   └── migrations/               # Database migration files
│
├── frontend/                     # Frontend directory
│   ├── public/                   # Static files
│   ├── src/                      # Source code
│   │   ├── assets/               # Static assets
│   │   ├── components/           # Vue components
│   │   ├── pages/                # Pages
│   │   ├── router/               # Routing
│   │   ├── store/                # State management
│   │   ├── App.vue               # Main Vue component
│   │   └── main.js               # Vue entry point
│   └── package.json              # Frontend dependencies
│
├── README.md                     # Project documentation
└── .gitignore                    # Git ignore file
```

---

## **Getting Started**

### **1. Clone the Repository**
```bash
git clone https://github.com/your-repository/competition-management-system.git
cd competition-management-system
```

### **2. Backend Setup**

#### **Install Python Dependencies**
Ensure Python version is 3.8 or higher:
```bash
cd backend
pip install -r requirements.txt
```

#### **Configure the Database**
Edit `backend/config.py` to set up the database connection:
```python
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://username:password@localhost/competition_db'
```

#### **Initialize the Database**
Run the following commands to create database tables:
```bash
flask db init
flask db migrate
flask db upgrade
```

#### **Run the Backend**
```bash
python app.py
```
The backend will start on `http://127.0.0.1:5000`.

---

### **3. Frontend Setup**

#### **Install Dependencies**
```bash
cd frontend
npm install
```

#### **Run the Development Server**
```bash
npm run serve
```
The frontend will start on `http://localhost:8080`.

---

### **4. Enable Cross-Origin Resource Sharing**
In `backend/app.py`, enable CORS:
```python
from flask_cors import CORS
CORS(app)
```

---

## **API Examples**

### **User Registration**
- **Endpoint**: `POST /api/register`
- **Request Body**:
  ```json
  {
    "username": "user1",
    "password": "password123",
    "role": "student",
    "name": "John Doe",
    "email": "user1@example.com"
  }
  ```
- **Response**:
  ```json
  {"message": "User registered successfully"}
  ```

### **User Login**
- **Endpoint**: `POST /api/login`
- **Request Body**:
  ```json
  {
    "username": "user1",
    "password": "password123"
  }
  ```
- **Response**:
  ```json
  {
    "message": "Login successful",
    "access_token": "jwt-token"
  }
  ```

### **Fetch Competitions**
- **Endpoint**: `GET /api/contests`
- **Response**:
  ```json
  [
    {
      "id": 1,
      "name": "Mathematics Modeling Competition",
      "category": "National",
      "start_time": "2024-01-01T00:00:00",
      "end_time": "2024-01-05T23:59:59"
    }
  ]
  ```

---

## **System Features for Expansion**

1. **Data Import and Export**:
   - Support bulk import of student and competition data via Excel files.
   - Export competition data as Excel or PDF reports.

2. **Data Visualization**:
   - Use ECharts or Chart.js to provide visualized data insights (e.g., performance distribution, participation statistics).

3. **Real-Time Updates**:
   - Use WebSocket for real-time updates on competition progress (e.g., ranking, scoring updates).

4. **Notification System**:
   - Integrate email notification for competition status updates or reminders.

---

## **Common Issues**

1. **How to Modify Database Configuration?**
   - Update the `SQLALCHEMY_DATABASE_URI` field in `backend/config.py`.

2. **How to Deploy to Production?**
   - Deploy Flask backend using Gunicorn:
     ```bash
     gunicorn -w 4 -b 0.0.0.0:5000 app:app
     ```
   - Build and deploy the Vue frontend:
     ```bash
     npm run build
     ```
   - Serve the built files using Nginx.

3. **How to Add New Features?**
   - Backend: Add new API routes in `routes.py` and define models in `models.py`.
   - Frontend: Add new components in `src/components/` and update `router/index.js`.

---

## **Contributing**

- Author: **alpha-409: CiNie**
- Contributions are welcome! Feel free to submit issues or pull requests.

---

## **License**

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

