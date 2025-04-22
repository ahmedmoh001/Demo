# app.py
from flask import render_template, redirect, request, session, url_for, Flask, jsonify
from flask import send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime
import os
import random
import string
from werkzeug.utils import secure_filename

from models import init_app, db
from models.user import User
from models.book_type import BookType
from models.product import Product
from models.order import Order
from models.order_item import OrderItem
from models.review import Review

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['SESSION_KEY_PREFIX'] = 'helloo'
app.config['SESSION_COOKIE_NAME'] = 'Bookstorevsession'
app.secret_key = "Kc5c3zTk'-3<&BdL:P92O{_(:-NkY+K"

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
init_app(app)


def get_random_numbers(string_length=3):
    return ''.join(random.choice(string.digits) for x in range(string_length))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')

        if password != confirm_password:
            return "Passwords do not match", 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return "User already exists", 400

        user = User(
            username=username,
            email=email,
            password=password,  # In production, hash the password!
            role=role,
            created_at=datetime.now()
        )
        try:
            db.session.add(user)
            db.session.commit()
            return redirect('/login')
        except Exception as e:
            db.session.rollback()
            return f"Registration failed: {str(e)}", 500

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email, password=password).first()
        if user:
            session['user_id'] = user.id
            session['role'] = user.role
            if user.role == 'admin':
                return redirect('/admin/dashboard')
            else:
                return redirect('/user/dashboard')
        else:
            return "Invalid email or password", 401

    return render_template('login.html')


@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' not in session or session.get('role') != 'customer':
        return redirect('/login')
    return render_template('user/dashboard.html')


@app.route('/get_products')
def get_products():
    products = Product.query.all()
    book_types = {t.id: t.type_name for t in BookType.query.all()}

    result = []
    for p in products:
        result.append({
            'id': p.id,
            'title': p.title,
            'author': p.author,
            'description': p.description,
            'price': p.price,
            'stock': p.stock,
            'image_url': p.image_url,
            'book_type': book_types.get(p.book_type_id, 'Unknown')
        })

    return jsonify(result)


@app.route('/add_product', methods=['POST'])
def add_product():
    title = request.form.get('title')
    author = request.form.get('author')
    description = request.form.get('description')
    price = request.form.get('price')
    book_type_id = request.form.get('book_type_id')
    stock = request.form.get('stock')
    created_by = request.form.get('created_by')
    file = request.files.get('image_url')

    image_url = None
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        image_url = filepath

    product = Product(
        title=title,
        author=author,
        description=description,
        price=price,
        book_type_id=book_type_id,
        stock=stock,
        image_url=image_url,
        created_by=created_by,
        created_at=datetime.now()
    )
    try:
        db.session.add(product)
        db.session.commit()
        db.session.close()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error creating product", "error": str(e)}), 400
    return jsonify({"message": "Product added successfully."}), 201


@app.route('/add_book_type', methods=['POST'])
def add_book_type():
    type_name = request.form.get('type_name')
    description = request.form.get('description')

    book_type = BookType(
        type_name=type_name,
        description=description
    )
    try:
        db.session.add(book_type)
        db.session.commit()
        db.session.close()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error creating book type", "error": str(e)}), 400
    return jsonify({"message": "Book type added successfully."}), 201


@app.route('/get_book_types', methods=['GET'])
def get_book_types():
    types = BookType.query.all()
    return jsonify([{k: v for k, v in t.__dict__.items() if not k.startswith('_')} for t in types])


@app.route('/product_details/<int:product_id>')
def product_details(product_id):
    product = Product.query.get_or_404(product_id)
    book_type = BookType.query.get(product.book_type_id)
    reviews = Review.query.filter_by(product_id=product_id).all()

    # Check if the user is admin from the session
    is_admin = session.get('role') == 'admin'

    return render_template('user/product_details.html',
                           product=product,
                           book_type=book_type,
                           reviews=reviews,
                           is_admin=is_admin)


@app.route('/add_review', methods=['POST'])
def add_review():
    user_id = request.form.get('user_id')
    product_id = request.form.get('product_id')
    rating = request.form.get('rating')
    comment = request.form.get('comment')

    review = Review(
        user_id=user_id,
        product_id=product_id,
        rating=rating,
        comment=comment,
        review_date=datetime.now()
    )
    try:
        db.session.add(review)
        db.session.commit()
        db.session.close()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error adding review", "error": str(e)}), 400
    return jsonify({"message": "Review added successfully."}), 201


@app.route('/get_reviews', methods=['GET'])
def get_reviews():
    reviews = Review.query.all()
    return jsonify([{k: v for k, v in r.__dict__.items() if not k.startswith('_')} for r in reviews])


@app.route('/add_order', methods=['POST'])
def add_order():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 403

    user_id = request.form.get('user_id')
    total_amount = request.form.get('total_amount')
    status = request.form.get('status')

    new_order = Order(
        user_id=user_id,
        total_amount=total_amount,
        status=status,
        order_date=datetime.now()
    )
    try:
        db.session.add(new_order)
        db.session.commit()
        return jsonify({'message': 'Order created', 'order_id': new_order.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error creating order: {str(e)}'}), 500


@app.route('/add_order_items', methods=['POST'])
def add_order_items():
    data = request.get_json()
    order_id = data.get('order_id')
    items = data.get('items')

    try:
        for item in items:
            product = Product.query.get(item['product_id'])

            if product.stock < item['quantity']:
                return jsonify({'error': f'Insufficient stock for {product.title}'}), 400

            order_item = OrderItem(
                order_id=order_id,
                product_id=item['product_id'],
                quantity=item['quantity'],
                price=product.price
            )
            product.stock -= item['quantity']
            db.session.add(order_item)

        db.session.commit()
        return jsonify({'message': 'Order items added'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error adding order items: {str(e)}'}), 500


@app.route('/cart')
def cart():
    if 'user_id' not in session or session.get('role') != 'customer':
        return redirect('/login')
    return render_template('user/cart.html')


@app.route('/orders')
def orders():
    if 'user_id' not in session or session.get('role') != 'customer':
        return redirect('/login')
    return render_template('user/orders.html')


# @app.route('/get_orders')
# def get_orders():
#     if 'user_id' not in session or session.get('role') != 'customer':
#         return jsonify([]), 403
#
#     user_id = session['user_id']
#     orders = Order.query.filter_by(user_id=user_id).order_by(Order.order_date.desc()).all()
#     return jsonify([{k: v for k, v in o.__dict__.items() if not k.startswith('_')} for o in orders])
#

# @app.route('/get_order_details/<int:order_id>')
# def get_order_details(order_id):
#     if 'user_id' not in session:
#         return redirect('/login')
#
#     order = Order.query.filter_by(id=order_id, user_id=session['user_id']).first()
#     if not order:
#         return "Order not found or access denied", 404
#
#     order_items = OrderItem.query.filter_by(order_id=order.id).all()
#     products = {p.id: p for p in Product.query.all()}
#
#     detailed_items = []
#     for item in order_items:
#         product = products.get(item.product_id)
#         if product:
#             detailed_items.append({
#                 'id': product.id,
#                 'title': product.title,
#                 'image_url': product.image_url,
#                 'quantity': item.quantity,
#                 'price': item.price
#             })
#
#     return render_template('user/order_details.html', order=order, items=detailed_items)


@app.route('/get_order_details/<int:order_id>')
def view_order_details(order_id):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    role = session.get('role')

    if role == 'admin':
        order = Order.query.get(order_id)
    else:
        order = Order.query.filter_by(id=order_id, user_id=user_id).first()

    if not order:
        return "Order not found or access denied", 404

    order_items_raw = OrderItem.query.filter_by(order_id=order.id).all()
    products = {p.id: p for p in Product.query.all()}

    order_items = []
    for item in order_items_raw:
        product = products.get(item.product_id)
        if product:
            order_items.append({
                'id': product.id,
                'name': product.title,
                'image_url': product.image_url,
                'quantity': item.quantity,
                'price': item.price
            })

    return render_template(
        'user/order_details.html',
        order=order,
        items=order_items
    )


@app.route('/cancel_order', methods=['POST'])
def cancel_order():
    if 'user_id' not in session:
        return redirect('/login')

    order_id = request.form.get('order_id')
    user_id = session['user_id']

    order = Order.query.filter_by(id=order_id, user_id=user_id).first()
    if not order:
        return "Order not found or access denied", 404

    if order.status.lower() != 'pending':
        return "Only pending orders can be cancelled.", 400

    # Restore stock
    order_items = OrderItem.query.filter_by(order_id=order.id).all()
    for item in order_items:
        product = Product.query.get(item.product_id)
        if product:
            product.stock += item.quantity

    order.status = 'Cancelled'
    db.session.commit()

    return redirect(f'/get_order_details/{order_id}')


@app.route('/submit_review', methods=['POST'])
def submit_review():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    product_id = request.form.get('product_id')
    rating = int(request.form.get('rating'))
    comment = request.form.get('comment')
    order_id = request.form.get('order_id')

    # Ensure the order is delivered and belongs to the user
    order = Order.query.filter_by(id=order_id, user_id=user_id, status='Delivered').first()
    if not order:
        return "You can only review delivered orders.", 403

    review = Review(
        user_id=user_id,
        product_id=product_id,
        rating=rating,
        comment=comment,
        review_date=datetime.now()
    )

    try:
        db.session.add(review)
        db.session.commit()
        return redirect(f'/get_order_details/{order_id}')
    except Exception as e:
        db.session.rollback()
        return f"Failed to submit review: {str(e)}", 500


@app.route('/set_order_delivered', methods=['POST'])
def set_order_delivered():
    order_id = request.form.get('order_id')
    order = Order.query.get(order_id)

    if not order:
        return jsonify({'error': 'Order not found'}), 404

    order.status = 'Delivered'
    db.session.commit()
    return jsonify({'message': f'Order #{order.id} marked as Delivered'})


@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect('/login')
    return render_template('admin/dashboard.html')


@app.route('/get_orders')
def get_orders():
    if 'user_id' not in session:
        return redirect('/login')

    if session.get('role') == 'admin':
        orders = Order.query.all()
    else:
        orders = Order.query.filter_by(user_id=session['user_id']).all()

    return jsonify([
        {
            "id": order.id,
            "total_amount": order.total_amount,
            "status": order.status,
            "user_id": order.user_id,
            "order_date": order.order_date.strftime('%Y-%m-%d %H:%M')
        } for order in orders
    ])


@app.route('/get_users')
def get_users():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify([])

    users = User.query.all()
    return jsonify([
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "created_at": user.created_at.strftime('%Y-%m-%d')
        } for user in users
    ])


@app.route('/admin/products')
def admin_products():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect('/login')

    products = Product.query.all()
    book_types = {bt.id: bt.type_name for bt in BookType.query.all()}

    # Merge type name into each product
    enriched_products = []
    for p in products:
        enriched_products.append({
            'id': p.id,
            'title': p.title,
            'author': p.author,
            'price': p.price,
            'stock': p.stock,
            'image_url': p.image_url,
            'type_name': book_types.get(p.book_type_id, 'Unknown')
        })

    return render_template('admin/products.html', products=enriched_products)


@app.route('/admin/delete_product', methods=['POST'])
def delete_product():
    product_id = request.form.get('product_id')
    try:
        product = Product.query.get(product_id)
        if product:
            db.session.delete(product)
            db.session.commit()
        else:
            return render_template('admin/products.html', products=Product.query.all(),
                                   error_message="Product not found.")
    except Exception as e:
        db.session.rollback()
        return render_template('admin/products.html', products=Product.query.all(),
                               error_message="Error deleting product.")

    return redirect('/admin/products')


@app.route('/update_stock', methods=['POST'])
def update_stock():
    if 'role' not in session or session['role'] != 'admin':
        return redirect('/login')

    product_id = request.form.get('product_id')
    new_stock = request.form.get('stock')

    try:
        product = Product.query.get(product_id)
        if product:
            product.stock = int(new_stock)
            db.session.commit()
        return redirect(f'/product_details/{product_id}')
    except Exception as e:
        db.session.rollback()
        return f"Error updating stock: {str(e)}", 500


@app.route('/admin/add_product', methods=['GET', 'POST'])
def admin_add_product():
    if 'role' not in session or session['role'] != 'admin':
        return redirect('/login')

    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        description = request.form.get('description')
        price = request.form.get('price')
        stock = request.form.get('stock')
        book_type_id = request.form.get('book_type_id')
        created_by = session.get('user_id')

        file = request.files.get('image')
        image_url = None

        if file and file.filename != '':
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            image_url = filepath

        product = Product(
            title=title,
            author=author,
            description=description,
            price=price,
            stock=stock,
            book_type_id=book_type_id,
            image_url=image_url,
            created_by=created_by
        )

        try:
            db.session.add(product)
            db.session.commit()
            return redirect('/admin/products')
        except Exception as e:
            db.session.rollback()
            return render_template('admin/add_product.html', book_types=BookType.query.all(), error=str(e))

    book_types = BookType.query.all()
    return render_template('admin/add_product.html', book_types=book_types)


@app.route('/admin/users')
def admin_users():
    if 'role' not in session or session['role'] != 'admin':
        return redirect('/login')

    users = User.query.all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/delete_user', methods=['POST'])
def admin_delete_user():
    if 'role' not in session or session['role'] != 'admin':
        return redirect('/login')

    user_id = request.form.get('user_id')
    user = User.query.get(user_id)

    if not user:
        return "User not found", 404

    try:
        db.session.delete(user)
        db.session.commit()
        return redirect('/admin/users')
    except Exception as e:
        db.session.rollback()
        return f"Error deleting user: {str(e)}", 500


@app.route('/admin/orders')
def admin_orders():
    if 'role' not in session or session['role'] != 'admin':
        return redirect('/login')

    orders = Order.query.order_by(Order.order_date.desc()).all()
    return render_template('admin/orders.html', orders=orders)


@app.route('/admin/mark_delivered', methods=['POST'])
def mark_delivered():
    order_id = request.form.get('order_id')
    order = Order.query.get(order_id)

    if order and order.status != 'Delivered':
        order.status = 'Delivered'
        db.session.commit()

    return redirect('/admin/orders')


@app.route('/admin/cancel_order', methods=['POST'])
def cancel_order_admin():
    order_id = request.form.get('order_id')
    order = Order.query.get(order_id)

    if order and order.status not in ['Cancelled', 'Delivered']:
        items = OrderItem.query.filter_by(order_id=order.id).all()
        for item in items:
            product = Product.query.get(item.product_id)
            if product:
                product.stock += item.quantity
        order.status = 'Cancelled'
        db.session.commit()

    return redirect('/admin/orders')


# @app.route('/get_order_items', methods=['POST'])
# def get_order_items():
#     order_id = request.form.get('order_id')
#
#     if not order_id:
#         return jsonify({"error": "order_id is required"}), 400
#
#     items = OrderItem.query.filter_by(order_id=order_id).all()
#     item_list = [
#         {
#             "id": item.id,
#             "order_id": item.order_id,
#             "product_id": item.product_id,
#             "quantity": item.quantity,
#             "price": item.price
#         } for item in items
#     ]
#     return jsonify(item_list), 200


@app.route('/admin/delete_book_type', methods=['POST'])
def delete_book_type():
    if 'role' not in session or session['role'] != 'admin':
        return redirect('/login')

    book_type_id = request.form.get('book_type_id')
    book_type = BookType.query.get(book_type_id)

    if not book_type:
        return render_template('admin/book_types.html', book_types=BookType.query.all(),
                               error_message="Book type not found.")

    try:
        db.session.delete(book_type)
        db.session.commit()
        return redirect('/admin/book_types')
    except Exception as e:
        db.session.rollback()
        return render_template('admin/book_types.html', book_types=BookType.query.all(),
                               error_message="Error deleting book type.")


@app.route('/admin/book_types', methods=['GET', 'POST'])
def manage_book_types():
    if 'role' not in session or session['role'] != 'admin':
        return redirect('/login')

    if request.method == 'POST':
        type_name = request.form.get('type_name')
        description = request.form.get('description')

        if not type_name:
            return render_template('admin/book_types.html', book_types=BookType.query.all(),
                                   error_message="Type name is required.")

        new_type = BookType(type_name=type_name, description=description)
        try:
            db.session.add(new_type)
            db.session.commit()
            return redirect('/admin/book_types')
        except Exception as e:
            db.session.rollback()
            return render_template('admin/book_types.html', book_types=BookType.query.all(),
                                   error_message="Error adding book type.")

    return render_template('admin/book_types.html', book_types=BookType.query.all())


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
