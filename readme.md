# Library Management System

This project is a web-based library management system developed using Flask for the backend and HTML/CSS/JavaScript for the frontend. It allows administrators to manage users, books, and book borrowings efficiently. The system includes features for user authentication, book borrowing, and comprehensive management of library resources.

## Features

- **User Management**: Administrators can view active users, disable users, and update user information.
  
- **Book Management**: Administrators can add new books, update book details, disable books, and view active books.
  
- **Borrow Management**: Administrators can track borrows, manage return dates, and view overdue returns.
  
- **Authentication**: Users and administrators have separate login portals with authentication handled securely.
  
- **User Accounts**: Users can log in and borrow an existing book from the list of active books.
  
- **Responsive Design**: The frontend is designed to be responsive, ensuring a good user experience across devices.

## Technologies Used

- **Backend**: Flask (Python)
  
- **Frontend**: HTML, CSS, JavaScript
  
- **Database**: SQLite (for simplicity in this example; can be replaced with more robust databases like PostgreSQL or MySQL for production)
  
- **External Libraries**: Axios (for API requests), Bootstrap (for styling)

## Setup Instructions

1. **Clone the Repository**: `git clone <repository-url>`
  
2. **Install Dependencies**: `pip install -r requirements.txt`
  
3. **Run the Flask Application**: Start the backend server and launch the frontend with a live server.

## Project Structure

- **`/static`**: Contains static assets like CSS and JavaScript files.
  
- **`/templates`**: HTML templates used by Flask for rendering pages.
  
- **`app.py`**: Flask application script containing the backend logic.
  
- **`database.db`**: SQLite database file storing user, book, and borrow information.

