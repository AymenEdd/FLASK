from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, EmailField, IntegerField, DecimalField
from wtforms.validators import DataRequired, Email, Length, NumberRange, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.Text, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    orders = db.relationship('Order', backref='user', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(200), default='https://via.placeholder.com/300x200')
    stock = db.Column(db.Integer, default=0)
    category = db.Column(db.String(50), nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[
        DataRequired(), 
        Regexp(r'^\+?[\d\s\-\(\)]{10,20}$', message="Please enter a valid phone number")
    ])
    address = TextAreaField('Address', validators=[DataRequired(), Length(min=10, max=500)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Register')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send Message')

class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired(), NumberRange(min=0)])
    stock = IntegerField('Stock', validators=[DataRequired(), NumberRange(min=0)])
    category = StringField('Category', validators=[DataRequired()])
    image_url = StringField('Image URL')
    submit = SubmitField('Add Product')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes principales
@app.route('/')
def home():
    products = Product.query.limit(8).all()
    return render_template('home.html', products=products)

@app.route('/products')
def products():
    page = request.args.get('page', 1, type=int)
    category = request.args.get('category', '')
    
    query = Product.query
    if category:
        query = query.filter_by(category=category)
    
    products = query.paginate(page=page, per_page=12, error_out=False)
    categories = db.session.query(Product.category.distinct()).all()
    
    return render_template('products.html', products=products, categories=categories)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        flash('Thank you for your message! We will get back to you soon.', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html', form=form)

# Routes d'authentification
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        flash('Invalid username or password', 'error')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter(
            (User.username == form.username.data) | 
            (User.email == form.email.data)
        ).first()
        
        if existing_user:
            flash('Username or email already exists', 'error')
            return render_template('register.html', form=form)
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            phone=form.phone.data,
            address=form.address.data,
            password_hash=generate_password_hash(form.password.data)
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Routes utilisateur (avec isolation des commandes)
@app.route('/dashboard')
@login_required
def dashboard():
    # ISOLATION: Chaque utilisateur ne voit que SES commandes
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('dashboard.html', orders=orders)

@app.route('/order/<int:order_id>')
@login_required
def order_detail(order_id):
    # ISOLATION: Un utilisateur ne peut voir que SES propres commandes
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()
    
    # Récupérer les items de la commande
    order_items = db.session.query(OrderItem, Product)\
        .join(Product, OrderItem.product_id == Product.id)\
        .filter(OrderItem.order_id == order_id)\
        .all()
    
    return render_template('order_detail.html', order=order, order_items=order_items)

# Routes panier et checkout
@app.route('/add_to_cart/<int:product_id>')
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Vérifier le stock disponible
    if product.stock <= 0:
        flash(f'Sorry, {product.name} is out of stock!', 'error')
        return redirect(request.referrer or url_for('products'))
    
    if 'cart' not in session:
        session['cart'] = {}
    
    cart = session['cart']
    current_quantity = cart.get(str(product_id), 0)
    
    # Vérifier si on peut ajouter un de plus
    if current_quantity >= product.stock:
        flash(f'Cannot add more {product.name}. Only {product.stock} in stock!', 'error')
        return redirect(request.referrer or url_for('products'))
    
    if str(product_id) in cart:
        cart[str(product_id)] += 1
    else:
        cart[str(product_id)] = 1
    
    session['cart'] = cart
    flash(f'{product.name} added to cart!', 'success')
    return redirect(request.referrer or url_for('home'))

@app.route('/cart')
@login_required
def cart():
    if 'cart' not in session or not session['cart']:
        return render_template('cart.html', cart_items=[], total=0)
    
    cart_items = []
    total = 0
    
    for product_id, quantity in session['cart'].items():
        product = Product.query.get(int(product_id))
        if product:
            cart_items.append({
                'product': product,
                'quantity': quantity,
                'subtotal': product.price * quantity
            })
            total += product.price * quantity
    
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/cart/remove/<int:product_id>')
@login_required
def remove_from_cart(product_id):
    if 'cart' in session and str(product_id) in session['cart']:
        del session['cart'][str(product_id)]
        session.modified = True
        flash('Product removed from cart!', 'success')
    return redirect(url_for('cart'))

@app.route('/cart/update', methods=['POST'])
@login_required
def update_cart():
    if 'cart' not in session:
        return redirect(url_for('cart'))
    
    for product_id, quantity in request.form.items():
        if product_id.startswith('quantity_'):
            actual_product_id = product_id.replace('quantity_', '')
            try:
                new_quantity = int(quantity)
                if new_quantity <= 0:
                    # Supprimer l'item si quantité = 0
                    if actual_product_id in session['cart']:
                        del session['cart'][actual_product_id]
                else:
                    # Vérifier le stock disponible
                    product = Product.query.get(int(actual_product_id))
                    if product and new_quantity <= product.stock:
                        session['cart'][actual_product_id] = new_quantity
                    else:
                        flash(f'Cannot update quantity. Only {product.stock if product else 0} in stock!', 'error')
            except ValueError:
                continue
    
    session.modified = True
    flash('Cart updated!', 'success')
    return redirect(url_for('cart'))

@app.route('/checkout')
@login_required
def checkout():
    if 'cart' not in session or not session['cart']:
        flash('Your cart is empty!', 'error')
        return redirect(url_for('cart'))
    
    # Calculer le total et valider le stock
    total = 0
    cart_products = []
    
    for product_id, quantity in session['cart'].items():
        product = Product.query.get(int(product_id))
        if product:
            if product.stock >= quantity:
                cart_products.append((product, quantity))
                total += product.price * quantity
            else:
                flash(f'Insufficient stock for {product.name}. Available: {product.stock}', 'error')
                return redirect(url_for('cart'))
    
    if not cart_products:
        flash('No valid products in cart', 'error')
        return redirect(url_for('cart'))
    
    # Créer la commande (ISOLATION: liée à l'utilisateur connecté uniquement)
    order = Order(
        user_id=current_user.id,  # IMPORTANT: Isolation par utilisateur
        total=total,
        status='pending'
    )
    db.session.add(order)
    db.session.flush()  # Obtenir l'ID de la commande
    
    # Créer les items de commande et mettre à jour le stock
    for product, quantity in cart_products:
        order_item = OrderItem(
            order_id=order.id,
            product_id=product.id,
            quantity=quantity,
            price=product.price
        )
        db.session.add(order_item)
        
        # Décrémenter le stock
        product.stock -= quantity
    
    db.session.commit()
    session['cart'] = {}  # Vider le panier
    
    flash(f'Order #{order.id} placed successfully! Total: ${total:.2f}', 'success')
    return redirect(url_for('order_detail', order_id=order.id))

# Routes admin - Gestion des produits
@app.route('/admin/products', methods=['GET', 'POST'])
@login_required
def admin_products():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    
    form = ProductForm()
    if form.validate_on_submit():
        product = Product(
            name=form.name.data,
            description=form.description.data,
            price=form.price.data,
            stock=form.stock.data,
            category=form.category.data,
            image_url=form.image_url.data or 'https://via.placeholder.com/300x200'
        )
        db.session.add(product)
        db.session.commit()
        flash('Product added successfully!', 'success')
        return redirect(url_for('admin_products'))
    
    products = Product.query.all()
    return render_template('admin_products.html', form=form, products=products)

@app.route('/admin/products/<int:product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    
    product = Product.query.get_or_404(product_id)
    form = ProductForm(obj=product)
    
    if form.validate_on_submit():
        product.name = form.name.data
        product.description = form.description.data
        product.price = form.price.data
        product.stock = form.stock.data
        product.category = form.category.data
        product.image_url = form.image_url.data or 'https://via.placeholder.com/300x200'
        
        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('admin_products'))
    
    return render_template('edit_product.html', form=form, product=product)

@app.route('/admin/products/<int:product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('admin_products'))

# Updated admin_orders route - replace your existing one
@app.route('/admin/orders')
@login_required
def admin_orders():
    if not current_user.is_admin:
        flash('Access denied - Admin privileges required', 'error')
        return redirect(url_for('home'))
    
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    
    # Admin sees ALL orders (no user filter)
    query = Order.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    orders = query.order_by(Order.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    # Calculate statistics
    stats = {
        'total_orders': Order.query.count(),
        'pending_orders': Order.query.filter_by(status='pending').count(),
        'processing_orders': Order.query.filter_by(status='processing').count(),
        'shipped_orders': Order.query.filter_by(status='shipped').count(),
        'delivered_orders': Order.query.filter_by(status='delivered').count(),
        'completed_orders': Order.query.filter_by(status='completed').count(),
        'cancelled_orders': Order.query.filter_by(status='cancelled').count(),
        'total_revenue': db.session.query(db.func.sum(Order.total))\
            .filter_by(status='completed').scalar() or 0
    }
    
    return render_template('admin_orders.html', 
                         orders=orders, 
                         stats=stats, 
                         status_filter=status_filter)

@app.route('/admin/orders/<int:order_id>')
@login_required
def admin_order_detail(order_id):
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    
    # Admin can view ANY order - fetch with better error handling
    order = Order.query.get(order_id)
    if not order:
        flash(f'Order #{order_id} not found', 'error')
        return redirect(url_for('admin_orders'))
    
    # Fetch order items with products
    order_items = db.session.query(OrderItem, Product)\
        .join(Product, OrderItem.product_id == Product.id)\
        .filter(OrderItem.order_id == order_id)\
        .all()
    
    # Debug information (remove in production)
    print(f"DEBUG: Order ID: {order_id}")
    print(f"DEBUG: Order found: {order is not None}")
    print(f"DEBUG: Order items count: {len(order_items) if order_items else 0}")
    
    return render_template('admin_order_detail.html', 
                         order=order, 
                         order_items=order_items) 

@app.route('/admin/orders/<int:order_id>/update_status', methods=['POST'])
@login_required
def update_order_status(order_id):
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status')
    
    valid_statuses = ['pending', 'processing', 'shipped', 'delivered', 'completed', 'cancelled']
    
    if new_status in valid_statuses:
        old_status = order.status
        order.status = new_status
        db.session.commit()
        
        status_messages = {
            'pending': 'Order set to pending',
            'processing': 'Order is being processed',
            'shipped': 'Order has been shipped',
            'delivered': 'Order has been delivered',
            'completed': 'Order completed',
            'cancelled': 'Order cancelled'
        }
        
        flash(f'{status_messages.get(new_status, "Status updated")} (from {old_status} to {new_status})', 'success')
    else:
        flash('Invalid status', 'error')
    
    return redirect(url_for('admin_order_detail', order_id=order_id))

@app.route('/admin/orders/<int:order_id>/delete', methods=['POST'])
@login_required
def delete_order(order_id):
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    
    order = Order.query.get_or_404(order_id)
    
    # Restaurer le stock avant de supprimer
    order_items = OrderItem.query.filter_by(order_id=order_id).all()
    for item in order_items:
        product = Product.query.get(item.product_id)
        if product:
            product.stock += item.quantity
    
    # Supprimer les items puis la commande
    OrderItem.query.filter_by(order_id=order_id).delete()
    db.session.delete(order)
    db.session.commit()
    
    flash(f'Order #{order_id} deleted successfully', 'success')
    return redirect(url_for('admin_orders'))

# Route utilitaire pour créer des données de test
@app.route('/admin/create_test_order')
@login_required
def create_test_order():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    
    # Créer un utilisateur de test s'il n'existe pas
    test_user = User.query.filter_by(username='testuser').first()
    if not test_user:
        test_user = User(
            username='testuser',
            email='test@example.com',
            phone='+1234567890',
            address='123 Test Street, Test City, TC 12345',
            password_hash=generate_password_hash('test123')
        )
        db.session.add(test_user)
        db.session.commit()
    
    # Créer une commande de test
    test_order = Order(
        user_id=test_user.id,
        total=299.97,
        status='pending'
    )
    db.session.add(test_order)
    db.session.flush()
    
    # Ajouter quelques produits à la commande
    products = Product.query.limit(3).all()
    for i, product in enumerate(products):
        if product:
            order_item = OrderItem(
                order_id=test_order.id,
                product_id=product.id,
                quantity=i + 1,
                price=product.price
            )
            db.session.add(order_item)
    
    db.session.commit()
    flash(f'Test order #{test_order.id} created successfully!', 'success')
    return redirect(url_for('admin_orders'))
@app.route('/admin/debug/orders/<int:order_id>')
@login_required  
def debug_order_detail(order_id):
    if not current_user.is_admin:
        return "Access denied"
    
    order = Order.query.get(order_id)
    if not order:
        return f"Order #{order_id} not found in database"
    
    order_items = db.session.query(OrderItem, Product)\
        .join(Product, OrderItem.product_id == Product.id)\
        .filter(OrderItem.order_id == order_id)\
        .all()
    
    # Use the debug template we created
    return render_template('debug_order_detail.html', 
                         order=order, 
                         order_items=order_items,
                         debug_info={
                             'order_id_requested': order_id,
                             'order_found': True,
                             'order_items_count': len(order_items)
                         })
@app.route('/admin/debug/orders')
@login_required
def debug_list_orders():
    if not current_user.is_admin:
        return "Access denied"
    
    orders = Order.query.all()
    order_info = []
    
    for order in orders:
        order_info.append({
            'id': order.id,
            'user': order.user.username,
            'total': order.total,
            'status': order.status,
            'created_at': order.created_at
        })
    
    return f"""
    <h2>Debug: All Orders in Database</h2>
    <p>Found {len(orders)} orders:</p>
    <ul>
    {''.join([f'<li><a href="/admin/orders/{o["id"]}">Order #{o["id"]}</a> - {o["user"]} - ${o["total"]} - {o["status"]}</li>' for o in order_info])}
    </ul>
    <p><a href="/admin/create_test_order">Create Test Order</a></p>
    <p><a href="/admin/orders">Back to Admin Orders</a></p>
    """


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Créer l'utilisateur admin_order_detail s'il n'existe pas
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                phone='+1234567890',
                address='Admin Office, 456 Admin Street, Admin City, AC 67890',
                password_hash=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
        
        # Ajouter des produits d'exemple s'ils n'existent pas
        if Product.query.count() == 0:
            sample_products = [
                Product(name='Laptop', description='High-performance laptop with latest processor and graphics card', price=999.99, stock=10, category='Electronics', image_url='https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=300&h=200&fit=crop'),
                Product(name='Smartphone', description='Latest smartphone model with advanced camera system', price=699.99, stock=15, category='Electronics', image_url='https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=300&h=200&fit=crop'),
                Product(name='Headphones', description='Wireless noise-canceling headphones with premium sound quality', price=199.99, stock=20, category='Electronics', image_url='https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=300&h=200&fit=crop'),
                Product(name='T-Shirt', description='Comfortable cotton t-shirt in various colors and sizes', price=29.99, stock=50, category='Clothing', image_url='https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=300&h=200&fit=crop'),
                Product(name='Jeans', description='Classic blue jeans with perfect fit and comfort', price=79.99, stock=30, category='Clothing', image_url='https://images.unsplash.com/photo-1542272604-787c3835535d?w=300&h=200&fit=crop'),
                Product(name='Sneakers', description='Comfortable running shoes with advanced cushioning', price=129.99, stock=25, category='Shoes', image_url='https://images.unsplash.com/photo-1549298916-b41d501d3772?w=300&h=200&fit=crop'),
                Product(name='Watch', description='Elegant wristwatch with premium materials and craftsmanship', price=299.99, stock=12, category='Accessories', image_url='https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=300&h=200&fit=crop'),
                Product(name='Backpack', description='Durable travel backpack with multiple compartments', price=89.99, stock=18, category='Accessories', image_url='https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=300&h=200&fit=crop'),
            ]
            for product in sample_products:
                db.session.add(product)
        
        db.session.commit()
    
    app.run(debug=True)