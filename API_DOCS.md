# Task Tracker & Dashboard API Documentation

This document provides complete technical specifications for the RESTful API service built with Express.js, Sequelize, and PostgreSQL.

---

## 1. Overview & Base URL

- **Base URL**: `http://localhost:3000` (or your production domain)
- **Protocol**: HTTP/HTTPS
- **Data Format**: `application/json`
- **Authentication**: JWT (Bearer Token) via HTTP `Authorization` header

---

## 2. Authentication & Authorization

All protected routes require a JSON Web Token (JWT) provided in the request headers:

```http
Authorization: Bearer <your_jwt_token>
```

### Authentication Errors

| Status Code | Error Message | Description |
|:---|:---|:---|
| `401 Unauthorized` | `{"error": "No token"}` | The `Authorization` header is missing or empty. |
| `401 Unauthorized` | `{"error": "Invalid token"}` | The token is expired, corrupted, or signed with an invalid key. |

---

## 3. Data Models Reference

### User
| Field | Type | Description | Constraints |
|:---|:---|:---|:---|
| `id` | Integer | Unique identifier | Primary Key, Auto Increment |
| `name` | String | User's full name | Required |
| `email` | String | User's email address | Required, Unique |
| `password` | String | Bcrypt-hashed password | Required |
| `emoji` | String | User avatar/profile emoji | Optional |

### Task
| Field | Type | Description | Constraints |
|:---|:---|:---|:---|
| `id` | Integer | Unique identifier | Primary Key, Auto Increment |
| `name` | String | Title or description of the task | Required |
| `weeklyTarget`| Integer | Target number of completions per week | Required |
| `enabled` | Boolean | Whether task is active | Default: `true` |
| `UserId` | Integer | Owner ID | Foreign Key (User) |

### Completion
| Field | Type | Description | Constraints |
|:---|:---|:---|:---|
| `id` | Integer | Unique identifier | Primary Key, Auto Increment |
| `date` | Date (YYYY-MM-DD) | Date of completion | Required, Format: `YYYY-MM-DD` |
| `completed` | Boolean | Completion status | Default: `false` |
| `UserId` | Integer | User ID | Foreign Key (User) |
| `TaskId` | Integer | Task ID | Foreign Key (Task) |

> **Unique Index**: Composite unique key on `(UserId, TaskId, date)` ensures only one completion record exists per user/task/day.

---

## 4. Endpoints Summary

| Method | Endpoint | Auth Required | Description |
|:---|:---|:---:|:---|
| `POST` | `/auth/register` | No | Register a new user and obtain JWT token |
| `POST` | `/auth/login` | No | Authenticate user and obtain JWT token |
| `GET` | `/api/dashboard` | Yes | Retrieve user profile, all tasks, and completion history |
| `POST` | `/api/tasks` | Yes | Create a new task |
| `PATCH`| `/api/tasks/:id/toggle` | Yes | Enable or disable a task |
| `POST` | `/api/completions` | Yes | Record or toggle task completion status for a date |

---

## 5. Endpoints Detail

### 5.1 Register User

Creates a new user account, securely hashes the password using bcrypt, and returns an access token.

- **Method**: `POST`
- **URL**: `/auth/register`
- **Auth**: None

#### Request Body
```json
{
  "name": "Jane Doe",
  "email": "jane@example.com",
  "password": "SecurePassword123!",
  "emoji": "🚀"
}
```

#### Response (`200 OK`)
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### 5.2 Login User

Authenticates user credentials against the database and returns a JWT token.

- **Method**: `POST`
- **URL**: `/auth/login`
- **Auth**: None

#### Request Body
```json
{
  "email": "jane@example.com",
  "password": "SecurePassword123!"
}
```

#### Response (`200 OK`)
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Error Response (`401 Unauthorized`)
```json
{
  "error": "Invalid login"
}
```

---

### 5.3 Fetch Dashboard Data

Retrieves current authenticated user profile details, list of all associated tasks, and all completion entries.

- **Method**: `GET`
- **URL**: `/api/dashboard`
- **Auth**: Bearer Token required

#### Request Headers
```http
Authorization: Bearer <token>
```

#### Response (`200 OK`)
```json
{
  "user": {
    "id": 1,
    "name": "Jane Doe",
    "email": "jane@example.com",
    "emoji": "🚀"
  },
  "tasks": [
    {
      "id": 10,
      "name": "Morning Workout",
      "weeklyTarget": 5,
      "enabled": true,
      "createdAt": "2026-08-20T10:00:00.000Z",
      "updatedAt": "2026-08-20T10:00:00.000Z",
      "UserId": 1
    }
  ],
  "completions": [
    {
      "taskId": 10,
      "date": "2026-08-23",
      "completed": true
    }
  ]
}
```

---

### 5.4 Create Task

Creates a new habit/task assigned to the authenticated user.

- **Method**: `POST`
- **URL**: `/api/tasks`
- **Auth**: Bearer Token required

#### Request Headers
```http
Authorization: Bearer <token>
Content-Type: application/json
```

#### Request Body
```json
{
  "name": "Read 20 pages",
  "weeklyTarget": 7
}
```

#### Response (`200 OK`)
```json
{
  "id": 11,
  "name": "Read 20 pages",
  "weeklyTarget": 7,
  "enabled": true,
  "UserId": 1,
  "createdAt": "2026-08-23T11:20:00.000Z",
  "updatedAt": "2026-08-23T11:20:00.000Z"
}
```

---

### 5.5 Enable / Disable Task

Toggles the active (`enabled`) state of a task. When disabled, completions cannot be logged for it.

- **Method**: `PATCH`
- **URL**: `/api/tasks/:id/toggle`
- **Auth**: Bearer Token required
- **URL Parameters**:
  - `id` *(Integer, Required)*: ID of the task to toggle.

#### Request Headers
```http
Authorization: Bearer <token>
```

#### Response (`200 OK`)
```json
{
  "id": 10,
  "name": "Morning Workout",
  "weeklyTarget": 5,
  "enabled": false,
  "UserId": 1,
  "createdAt": "2026-08-20T10:00:00.000Z",
  "updatedAt": "2026-08-23T11:25:00.000Z"
}
```

#### Error Response (`404 Not Found`)
```json
{
  "error": "Task not found"
}
```

---

### 5.6 Record / Toggle Completion

Creates or updates a task completion record for a specific date. If the task is disabled or does not belong to the user, the operation is rejected.

- **Method**: `POST`
- **URL**: `/api/completions`
- **Auth**: Bearer Token required

#### Request Headers
```http
Authorization: Bearer <token>
Content-Type: application/json
```

#### Request Body
```json
{
  "taskId": 10,
  "date": "2026-08-23",
  "completed": true
}
```

#### Response (`200 OK`)
```json
{
  "success": true,
  "completion": {
    "taskId": 10,
    "date": "2026-08-23",
    "completed": true
  }
}
```

#### Error Responses

- **`403 Forbidden`** (Task disabled or not owned by user):
  ```json
  {
    "error": "Task disabled or not found"
  }
  ```

- **`500 Internal Server Error`**:
  ```json
  {
    "error": "Completion error"
  }
  ```

---

## 6. Setup & Environment Variables

Make sure the following environment variable is set in your `.env` file before starting the application:

```env
DATABASE_URL=postgres://<user>:<password>@<neon_host>/<database>?sslmode=require
```

### Running the Server
```bash
# Install dependencies
npm install express cors jsonwebtoken bcryptjs sequelize pg pg-hstore dotenv

# Run application
node server.js
```