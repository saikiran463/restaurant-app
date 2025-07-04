from flask import Blueprint, render_template, session, redirect, url_for, flash, request, jsonify
import uuid
import boto3
import os
from datetime import datetime

# --- AWS Config and Table Setup ---
AWS_REGION = 'ap-south-1'  # Change as needed
MENU_TABLE = 'Menu'

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
menu_table = dynamodb.Table(MENU_TABLE)
s3 = boto3.client('s3', region_name=AWS_REGION)

routes = Blueprint('routes', __name__)

@routes.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Username and password required', 'danger')
            return redirect(url_for('routes.admin_login'))
        users_table = get_table('Users')
        resp = users_table.get_item(Key={'username': username})
        user = resp.get('Item')
        if not user or user['password'] != hash_password(password):
            flash('Invalid credentials', 'danger')
            return redirect(url_for('routes.admin_login'))
        flash('Login successful!', 'success')
        session['admin_logged_in'] = True
        return redirect(url_for('routes.admin_panel'))
    return render_template('admin_login.html')


# --- Admin Order Status Update Route ---
@routes.route('/admin/order_status/<order_id>', methods=['POST'])
def admin_order_status(order_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('routes.admin_login'))
    new_status = request.form.get('status', 'closed')
    orders_table = boto3.resource('dynamodb', region_name=AWS_REGION).Table('Orders')
    # Update the order status
    orders_table.update_item(
        Key={'order_id': order_id},
        UpdateExpression='SET #s = :s',
        ExpressionAttributeNames={'#s': 'status'},
        ExpressionAttributeValues={':s': new_status}
    )
    flash('Order status updated!', 'success')
    return redirect(url_for('routes.admin_panel'))


@routes.route('/admin', methods=['GET'])
def admin_panel():
    if not session.get('admin_logged_in'):
        return redirect(url_for('routes.admin_login'))
    # Fetch menu items
    menu_items = menu_table.scan().get('Items', [])
    # Fetch all orders
    orders_table = boto3.resource('dynamodb', region_name=AWS_REGION).Table('Orders')
    orders = orders_table.scan().get('Items', [])
    # Sort orders by order_time descending
    orders.sort(key=lambda o: o.get('order_time', ''), reverse=True)
    return render_template('admin.html', menu_items=menu_items, orders=orders)

# --- Place Order Route (AJAX from menu.html) ---
@routes.route('/place_order', methods=['POST'])
def place_order():

    data = request.get_json()
    print('DEBUG: Received order data:', data)
    items = data.get('items', [])
    total = data.get('total', 0)
    order_id = str(uuid.uuid4())[:8]
    order_time = datetime.utcnow().isoformat()
    username = session.get('username')
    print('DEBUG: Session username at order placement:', username)
    if not username:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401
    try:
        orders_table = boto3.resource('dynamodb', region_name=AWS_REGION).Table('Orders')
        orders_table.put_item(Item={
            'order_id': order_id,
            'username': username,
            'items': items,
            'total': total,
            'order_time': order_time,
            'status': 'received'
        })
        print(f'DEBUG: Order placed for user {username}, order_id={order_id}')
        # --- Production: Send order notification (email/SNS) ---
        try:
            item_lines = "\n".join([f"- {i['name']} x{i['qty']} (₹{i['price']})" for i in items])
            message = f"New Order Received!\nOrder ID: {order_id}\nUser: {username}\nItems:\n{item_lines}\nTotal: ₹{total}\nTime: {order_time}"
            publish_sns_message(message)
            print('Order notification sent via SNS/email.')
        except Exception as notify_err:
            print('Order notification failed:', repr(notify_err))

        return jsonify({'success': True, 'order_id': order_id})
    except Exception as e:
        print('Order placement failed:', repr(e))
        return jsonify({'success': False, 'error': str(e)}), 500

# --- Delete Menu Item ---
@routes.route('/admin/delete/<item_id>', methods=['POST'])
def admin_delete(item_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    # Get the item to find the image_url
    response = menu_table.get_item(Key={'item_id': item_id})
    item = response.get('Item')
    if item and 'image_url' in item:
        # Extract the S3 key from the image_url
        image_url = item['image_url']
        # Example: https://bucket-name.s3.amazonaws.com/menu/uuid.jpg
        # S3 key is everything after the bucket domain
        s3_key = image_url.split('.amazonaws.com/')[-1]
        try:
            s3.delete_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
        except Exception as e:
            flash(f'Image delete failed: {e}', 'warning')
    menu_table.delete_item(Key={'item_id': item_id})
    flash('Menu item deleted!', 'success')
    return redirect(url_for('routes.admin_panel'))


import hashlib
from app.aws_utils import get_table, S3_BUCKET_NAME


@routes.route('/')
def home():
    return redirect(url_for('routes.register'))

# Helper to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()



@routes.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Username and password required
        if not username or not password:
            flash('Username and password required', 'danger')
            return redirect(url_for('routes.register'))
        # Username uniqueness check
        users_table = get_table('Users')
        resp = users_table.get_item(Key={'username': username})
        if resp.get('Item'):
            flash('Username already exists. Please choose another.', 'danger_username')
            return redirect(url_for('routes.register'))
        # Password criteria: min 8 chars, at least 1 uppercase, 1 lowercase, 1 digit, 1 special char
        import re
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger_password')
            return redirect(url_for('routes.register'))
        if not re.search(r'[A-Z]', password):
            flash('Password must contain at least one uppercase letter.', 'danger_password')
            return redirect(url_for('routes.register'))
        if not re.search(r'[a-z]', password):
            flash('Password must contain at least one lowercase letter.', 'danger_password')
            return redirect(url_for('routes.register'))
        if not re.search(r'\d', password):
            flash('Password must contain at least one digit.', 'danger_password')
            return redirect(url_for('routes.register'))
        if not re.search(r'[^A-Za-z0-9]', password):
            flash('Password must contain at least one special character.', 'danger_password')
            return redirect(url_for('routes.register'))
        # All checks passed, register user
        users_table.put_item(Item={
            'username': username,
            'password': hash_password(password)
        })
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('routes.login'))
    return render_template('register.html')




@routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Username and password required', 'danger')
            return redirect(url_for('routes.login'))
        users_table = get_table('Users')
        resp = users_table.get_item(Key={'username': username})
        user = resp.get('Item')
        if not user or user['password'] != hash_password(password):
            flash('Invalid credentials', 'danger')
            return redirect(url_for('routes.login'))
        flash('Login successful!', 'success')
        session['username'] = username
        return redirect(url_for('routes.menu'))
    return render_template('login.html')




# --- Menu Page ---
@routes.route('/menu')
def menu():
    try:
        response = menu_table.scan()
        menu_items = response.get('Items', [])
        return render_template('menu.html', menu_items=menu_items)
    except Exception as e:
        flash(f'Error loading menu: {e}', 'danger')
        return render_template('menu.html', menu_items=[])

# --- User Order History (AJAX) ---
@routes.route('/order_history')
def order_history():
    try:
        username = session.get('username')
        if not username:
            return jsonify({'orders': []})
        orders_table = boto3.resource('dynamodb', region_name=AWS_REGION).Table('Orders')
        resp = orders_table.scan()
        orders = resp.get('Items', [])
        user_orders = [o for o in orders if o.get('username') == username]
        user_orders.sort(key=lambda o: o.get('order_time', ''), reverse=True)
        return jsonify({'orders': user_orders})
    except Exception as e:
        print('Failed to fetch user order history:', repr(e))
        return jsonify({'orders': []})

# --- User Details (AJAX) ---
@routes.route('/user_details')
def user_details():
    try:
        username = session.get('username')
        if username:
            return jsonify({'success': True, 'username': username})
        else:
            return jsonify({'success': False}), 401
    except Exception as e:
        print('Failed to fetch user details:', repr(e))
        return jsonify({'success': False}), 500
