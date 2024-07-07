from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from flask_cors import CORS

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
CORS(app, supports_credentials=True)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    city = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    disabled = db.Column(db.Boolean, default=False, nullable=False)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    type = db.Column(db.Integer, nullable=False)
    disabled = db.Column(db.Boolean, default=False, nullable=False)

class Borrow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    borrow_date = db.Column(db.Date, nullable=False, default=datetime.date.today)
    return_date = db.Column(db.Date, nullable=False)
    returned_date = db.Column(db.Date)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256', salt_length=8)
    
    new_user = User(name=data['name'], email=data['email'], city=data['city'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'New user registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    name = data.get('name')
    password = data.get('password')

    user = User.query.filter_by(name=name).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Login failed! Check name and password'}), 401
    
    if user.disabled:
        return jsonify({'message': 'User account is disabled'}), 403
    
    token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({'token': token})

@app.route('/disable_user/<int:user_id>', methods=['POST'])
def disable_user(user_id):
    token = request.headers.get('x-access-token')
    
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.get(data['user_id'])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # Check if user has borrowed any books
    borrowed_books = Borrow.query.filter_by(user_id=user_id).all()
    if borrowed_books:
        return jsonify({'message': 'User cannot be disabled while borrowing books'}), 400
    
    user.disabled = True
    db.session.commit()
    
    return jsonify({'message': 'User account has been disabled'})


@app.route('/edit_user/<int:user_id>', methods=['PUT'])
def edit_user(user_id):
    token = request.headers.get('x-access-token')
    
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.get(data['user_id'])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    data = request.get_json()
    user.name = data.get('name', user.name)
    user.email = data.get('email', user.email)
    user.city = data.get('city', user.city)
    if 'password' in data:
        user.password = generate_password_hash(data['password'], method='pbkdf2:sha256', salt_length=8)
    
    db.session.commit()
    
    return jsonify({'message': 'User details have been updated'})

@app.route('/add_book_admin', methods=['POST'])
def add_book_admin():
    token = request.headers.get('x-access-token')
    
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.get(data['user_id'])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401
    
    if current_user.name != 'admin':
        return jsonify({'message': 'Unauthorized access! Admin access required.'}), 403
    
    data = request.get_json()
    new_book = Book(name=data['name'], author=data['author'], type=data['type'])
    db.session.add(new_book)
    db.session.commit()
    
    return jsonify({'message': 'New book added successfully'}), 201

@app.route('/edit_book/<int:book_id>', methods=['PUT'])
def edit_book(book_id):
    token = request.headers.get('x-access-token')
    
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.get(data['user_id'])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401
    
    book = Book.query.get(book_id)
    if not book:
        return jsonify({'message': 'Book not found'}), 404
    
    data = request.get_json()
    book.name = data.get('name', book.name)
    book.author = data.get('author', book.author)
    book.type = data.get('type', book.type)
    if 'disabled' in data:
        book.disabled = data['disabled']
    
    db.session.commit()
    
    return jsonify({'message': 'Book details have been updated'})

@app.route('/disable_book/<int:book_id>', methods=['POST'])
def disable_book(book_id):
    token = request.headers.get('x-access-token')
    
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.get(data['user_id'])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401
    
    book = Book.query.get(book_id)
    if not book:
        return jsonify({'message': 'Book not found'}), 404
    
    book.disabled = True
    db.session.commit()
    
    return jsonify({'message': 'Book has been disabled'})

@app.route('/borrow_book/<int:book_id>', methods=['POST'])
def borrow_book(book_id):
    token = request.headers.get('x-access-token')
    
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.get(data['user_id'])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401
    
    book = Book.query.get(book_id)
    if not book:
        return jsonify({'message': 'Book not found'}), 404
    
    if book.disabled:
        return jsonify({'message': 'Book is disabled'}), 403
    
    borrow_date = datetime.date.today()
    if book.type == 1:
        return_date = borrow_date + datetime.timedelta(days=10)
    elif book.type == 2:
        return_date = borrow_date + datetime.timedelta(days=5)
    elif book.type == 3:
        return_date = borrow_date + datetime.timedelta(days=2)
    else:
        return jsonify({'message': 'Invalid book type'}), 400
    
    new_borrow = Borrow(book_id=book.id, user_id=current_user.id, borrow_date=borrow_date, return_date=return_date)
    db.session.add(new_borrow)
    db.session.commit()
    
    return jsonify({'message': 'Book borrowed successfully', 'return_date': return_date})

@app.route('/return_book/<int:borrow_id>', methods=['POST'])
def return_book(borrow_id):
    token = request.headers.get('x-access-token')
    
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.get(data['user_id'])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401
    
    borrow = Borrow.query.get(borrow_id)
    if not borrow:
        return jsonify({'message': 'Borrow record not found'}), 404
    
    if borrow.user_id != current_user.id:
        return jsonify({'message': 'You are not authorized to return this book'}), 403
    
    if borrow.returned_date:
        return jsonify({'message': 'Book has already been returned'}), 400
    
    borrow.returned_date = datetime.date.today()
    db.session.commit()
    
    return jsonify({'message': 'Book returned successfully'})

@app.route('/not_disabled_customers', methods=['GET'])
def not_disabled_customers():
    customers = User.query.filter_by(disabled=False).all()
    result = [{'id': customer.id, 'name': customer.name, 'email': customer.email, 'city': customer.city} for customer in customers]
    return jsonify(result)

@app.route('/not_disabled_books_admin', methods=['GET'])
def not_disabled_books_admin():
    books = Book.query.filter_by(disabled=False).all()
    result = [{'id': book.id, 'name': book.name, 'author': book.author, 'type': book.type} for book in books]
    return jsonify(result)

@app.route('/not_returned_borrows', methods=['GET'])
def not_returned_borrows():
    borrows = Borrow.query.filter(Borrow.returned_date == None).all()
    result = [{'id': borrow.id, 'book_id': borrow.book_id, 'user_id': borrow.user_id, 'borrow_date': borrow.borrow_date.strftime('%Y-%m-%d'), 'return_date': borrow.return_date.strftime('%Y-%m-%d'), 'returned_date': borrow.returned_date.strftime('%Y-%m-%d') if borrow.returned_date else None} for borrow in borrows]
    return jsonify(result)

@app.route('/late_returns_admin', methods=['GET'])
def late_returns_admin():
    today = datetime.date.today()
    late_borrows = Borrow.query.filter(Borrow.returned_date > Borrow.return_date).all()
    result = [{'id': borrow.id, 'book_id': borrow.book_id, 'user_id': borrow.user_id, 'borrow_date': borrow.borrow_date.strftime('%Y-%m-%d'), 'return_date': borrow.return_date.strftime('%Y-%m-%d'), 'returned_date': borrow.returned_date.strftime('%Y-%m-%d') if borrow.returned_date else None} for borrow in late_borrows]
    return jsonify(result)

@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('x-access-token')
    
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.get(data['user_id'])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401
    
    if current_user.disabled:
        return jsonify({'message': 'User account is disabled'}), 403
    
    return jsonify({'message': f'Hello, {current_user.name} from {current_user.city}'})

@app.route('/all_users', methods=['GET'])
def all_users():
    token = request.headers.get('x-access-token')
    
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.get(data['user_id'])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401
    
    if current_user.name != 'admin':
        return jsonify({'message': 'Unauthorized access! Admin access required.'}), 403
    
    # Fetch only non-disabled users
    users = User.query.filter_by(disabled=False).all()
    result = [{'id': user.id, 'name': user.name, 'email': user.email, 'city': user.city} for user in users]
    return jsonify(result)


@app.route('/edit_book_admin/<int:book_id>', methods=['PUT'])
def edit_book_admin(book_id):
    token = request.headers.get('x-access-token')
    
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = db.session.get(User, data['user_id'])  # Use db.session.get() here
    except:
        return jsonify({'message': 'Token is invalid!'}), 401
    
    if current_user.name != 'admin':
        return jsonify({'message': 'Unauthorized access! Admin access required.'}), 403
    
    book = db.session.get(Book, book_id)  # Use db.session.get() here
    if not book:
        return jsonify({'message': 'Book not found'}), 404
    
    data = request.get_json()
    
    # Check if there are active borrows for this book
    active_borrows = Borrow.query.filter_by(book_id=book_id, returned_date=None).all()
    if active_borrows:
        return jsonify({'message': 'Cannot edit book with active borrows!'}), 400
    
    # Assuming you have fields in your Book model like name, author, etc.
    book.name = data.get('name', book.name)
    book.author = data.get('author', book.author)
    book.disabled = data.get('disabled', book.disabled)
    
    db.session.commit()
    
    return jsonify({'message': 'Book updated successfully'})

    
    # Update book details if provided
    book.name = data.get('name', book.name)
    book.author = data.get('author', book.author)
    book.type = data.get('type', book.type)
    
    if 'disabled' in data:
        book.disabled = data['disabled']
    
    db.session.commit()
    
    return jsonify({'message': 'Book details have been updated'})


@app.route('/available_books', methods=['GET'])
def available_books():
    available_books = Book.query.filter_by(disabled=False).all()
    active_borrows = Borrow.query.filter(Borrow.returned_date == None).all()
    available_books_ids = [book.id for book in available_books]
    active_borrows_books_ids = [borrow.book_id for borrow in active_borrows]

    result = [{'id': book.id, 'name': book.name, 'author': book.author, 'type': book.type} for book in available_books if book.id not in active_borrows_books_ids]
    return jsonify(result)

@app.route('/active_borrows', methods=['GET'])
def active_borrows():
    token = request.headers.get('x-access-token')
    
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.get(data['user_id'])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401
    
    borrows = Borrow.query.filter_by(user_id=current_user.id, returned_date=None).all()
    
    result = []
    for borrow in borrows:
        book = Book.query.get(borrow.book_id)
        if book:
            result.append({
                'id': borrow.id,
                'book_id': borrow.book_id,
                'book_name': book.name,
                'book_author': book.author,
                'borrow_date': borrow.borrow_date.strftime('%Y-%m-%d'),
                'return_date': borrow.return_date.strftime('%Y-%m-%d') if borrow.return_date else None
            })
    
    return jsonify(result)


@app.route('/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    token = request.headers.get('x-access-token')

    if not token:
        return jsonify({'message': 'Token is missing!'}), 401

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        admin_user = User.query.get(data['user_id'])
        if admin_user.name != 'admin':
            return jsonify({'message': 'Only admin can delete users!'}), 403
    except:
        return jsonify({'message': 'Token is invalid or user not found!'}), 401

    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        return jsonify({'message': 'User not found!'}), 404

    db.session.delete(user_to_delete)
    db.session.commit()

    return jsonify({'message': 'User deleted successfully!'})

@app.route('/all_books', methods=['GET'])
def all_books():
    token = request.headers.get('x-access-token')
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.get(data['user_id'])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401

    if current_user.name != 'admin':
        return jsonify({'message': 'Unauthorized access! Admin access required.'}), 403

    books = Book.query.all()
    result = [{'id': book.id, 'name': book.name, 'author': book.author, 'type': book.type, 'disabled': book.disabled} for book in books]

    return jsonify(result)

@app.route('/all_borrows', methods=['GET'])
def all_borrows():
    token = request.headers.get('x-access-token')
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.get(data['user_id'])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401

    if current_user.name != 'admin':
        return jsonify({'message': 'Unauthorized access! Admin access required.'}), 403

    borrows = Borrow.query.all()
    result = [{'id': borrow.id, 'user_id': borrow.user_id, 'book_id': borrow.book_id, 'borrow_date': borrow.borrow_date.strftime('%Y-%m-%d'), 'return_date': borrow.return_date.strftime('%Y-%m-%d') if borrow.return_date else None, 'returned_date': borrow.returned_date.strftime('%Y-%m-%d') if borrow.returned_date else None} for borrow in borrows]

    return jsonify(result)

@app.route('/history', methods=['GET'])
def history():
    token = request.headers.get('x-access-token')
    
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.get(data['user_id'])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401
    
    if current_user.name != 'admin':
        return jsonify({'message': 'Unauthorized access! Admin access required.'}), 403
    
    # Fetch all users with their disable status
    users = User.query.all()
    users_data = [{'id': user.id, 'name': user.name, 'email': user.email, 'disabled': user.disabled} for user in users]
    
    # Fetch all books with their disable status
    books = Book.query.all()
    books_data = [{'id': book.id, 'name': book.name, 'author': book.author, 'disabled': book.disabled} for book in books]
    
    # Fetch all borrows with actual return date
    borrows = Borrow.query.all()
    borrows_data = [{'id': borrow.id, 'user_id': borrow.user_id, 'book_id': borrow.book_id,
                     'borrow_date': borrow.borrow_date.strftime('%Y-%m-%d'),
                     'return_date': borrow.return_date.strftime('%Y-%m-%d') if borrow.return_date else None,
                     'returned_date': borrow.returned_date.strftime('%Y-%m-%d') if borrow.returned_date else None} for borrow in borrows]
    
    result = {
        'users': users_data,
        'books': books_data,
        'borrows': borrows_data
    }
    
    return jsonify(result)



with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
