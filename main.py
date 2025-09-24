from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, EmailField, IntegerField, DecimalField
from wtforms.validators import DataRequired, Email, Length, NumberRange, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask import send_from_directory
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///ecommerce.db')
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

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    # Relationships
    user = db.relationship('User', backref=db.backref('cart_items', lazy=True, cascade='all, delete-orphan'))
    product = db.relationship('Product', backref=db.backref('cart_items', lazy=True))
    
    # Ensure unique constraint: one user can't have duplicate products in cart
    __table_args__ = (db.UniqueConstraint('user_id', 'product_id', name='unique_user_product_cart'),)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    is_read = db.Column(db.Boolean, default=False)
    admin_response = db.Column(db.Text, nullable=True)
    response_date = db.Column(db.DateTime, nullable=True)
    responded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class ContactResponseForm(FlaskForm):
    admin_response = TextAreaField('Réponse', validators=[DataRequired()])
    submit = SubmitField('Envoyer la réponse')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def inject_toast_messages():
    """Make toast messages available to all templates and clear them"""
    toast_message = session.pop('toast_message', None)
    toast_type = session.pop('toast_type', None)
    
    return {
        'toast_message': toast_message,
        'toast_type': toast_type or 'info'
    }

def redirect_with_toast(endpoint, message, toast_type='info', **values):
    """Redirect to a route with a toast message stored in session"""
    session['toast_message'] = message
    session['toast_type'] = toast_type
    return redirect(url_for(endpoint, **values))

def render_with_toast(template, message, toast_type='info', **kwargs):
    """Render template with toast message"""
    # Store in session so it persists through redirects if needed
    session['toast_message'] = message
    session['toast_type'] = toast_type
    return render_template(template, **kwargs)

@app.route('/clear-session')
def clear_session():
    """Utility route to clear session - useful for debugging"""
    session.clear()
    return redirect_with_toast('home', 'Session cleared!', 'info')
# Routes principales
@app.route('/')
def home():
    products = Product.query.limit(8).all()
    # Remove these lines - the context processor handles toasts now:
    # toast_message = session.pop('toast_message', None)
    # toast_type = session.pop('toast_type', None)
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
            session['toast_message'] = f'Bienvenue {user.username}!'
            session['toast_type'] = 'success'
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        return render_with_toast('login.html', 'Nom d\'utilisateur ou mot de passe incorrect', 'error', form=form)
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
            return render_with_toast('register.html', 'Nom d\'utilisateur ou email déjà existant', 'error', form=form)
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            phone=form.phone.data,
            address=form.address.data,
            password_hash=generate_password_hash(form.password.data)
        )
        db.session.add(user)
        db.session.commit()
        return redirect_with_toast('login', 'Inscription réussie! Veuillez vous connecter.', 'success')
    
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    return redirect_with_toast('home', f'Au revoir {username}!', 'info')

# Routes utilisateur (avec isolation des commandes)
@app.route('/dashboard')
@login_required
def dashboard():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    # Remove manual toast handling:
    # toast_message = session.pop('toast_message', None)
    # toast_type = session.pop('toast_type', None)
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
    
    if product.stock <= 0:
        return redirect_with_toast('products', f'Désolé, {product.name} est en rupture de stock!', 'error')
    
    cart_item = Cart.query.filter_by(
        user_id=current_user.id,
        product_id=product_id
    ).first()
    
    if cart_item:
        if cart_item.quantity >= product.stock:
            return redirect_with_toast('products', f'Impossible d\'ajouter plus de {product.name}. Seulement {product.stock} en stock!', 'error')
        
        cart_item.quantity += 1
        db.session.commit()
        return redirect_with_toast('products', f'Quantité de {product.name} augmentée à {cart_item.quantity}!', 'success')
    else:
        new_cart_item = Cart(
            user_id=current_user.id,
            product_id=product_id,
            quantity=1
        )
        db.session.add(new_cart_item)
        db.session.commit()
        return redirect_with_toast('products', f'{product.name} ajouté au panier!', 'success')



@app.route('/cart')
@login_required
def cart():
    # Get user's cart items from database
    cart_items_query = db.session.query(Cart, Product)\
        .join(Product, Cart.product_id == Product.id)\
        .filter(Cart.user_id == current_user.id)\
        .order_by(Cart.created_at.desc())\
        .all()
    
    cart_items = []
    total = 0
    
    for cart_item, product in cart_items_query:
        # Check if product is still available and adjust quantity if needed
        if product.stock <= 0:
            # Remove item if product is no longer available
            db.session.delete(cart_item)
            continue
        
        # Adjust quantity if stock is less than cart quantity
        if cart_item.quantity > product.stock:
            cart_item.quantity = product.stock
            db.session.commit()
        
        subtotal = product.price * cart_item.quantity
        cart_items.append({
            'cart_item': cart_item,
            'product': product,
            'quantity': cart_item.quantity,
            'subtotal': subtotal
        })
        total += subtotal
    
    # Commit any changes made during stock validation
    db.session.commit()
    
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/cart/remove/<int:product_id>')
@login_required
def remove_from_cart(product_id):
    cart_item = Cart.query.filter_by(
        user_id=current_user.id,
        product_id=product_id
    ).first()
    
    if cart_item:
        product_name = cart_item.product.name
        db.session.delete(cart_item)
        db.session.commit()
        return redirect_with_toast('cart', f'{product_name} retiré du panier!', 'success')
    
    return redirect(url_for('cart'))

@app.route('/cart/update', methods=['POST'])
@login_required
def update_cart():
    error_messages = []
    
    for field_name, new_quantity in request.form.items():
        if field_name.startswith('quantity_'):
            try:
                product_id = int(field_name.replace('quantity_', ''))
                new_quantity = int(new_quantity)
                
                cart_item = Cart.query.filter_by(
                    user_id=current_user.id,
                    product_id=product_id
                ).first()
                
                if cart_item:
                    if new_quantity <= 0:
                        db.session.delete(cart_item)
                    else:
                        product = cart_item.product
                        if new_quantity <= product.stock:
                            cart_item.quantity = new_quantity
                        else:
                            error_messages.append(f'Stock insuffisant pour {product.name}. Seulement {product.stock} disponible!')
                            
            except (ValueError, TypeError):
                continue
    
    db.session.commit()
    
    if error_messages:
        return redirect_with_toast('cart', ' '.join(error_messages), 'warning')
    else:
        return redirect_with_toast('cart', 'Panier mis à jour!', 'success')

@app.route('/cart/clear')
@login_required
def clear_cart():
    Cart.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    return redirect_with_toast('cart', 'Panier vidé!', 'success')


@app.route('/checkout')
@login_required
def checkout():
    cart_items_query = db.session.query(Cart, Product)\
        .join(Product, Cart.product_id == Product.id)\
        .filter(Cart.user_id == current_user.id)\
        .all()
    
    if not cart_items_query:
        return redirect_with_toast('cart', 'Votre panier est vide!', 'error')
    
    subtotal = 0
    cart_products = []
    
    for cart_item, product in cart_items_query:
        if product.stock >= cart_item.quantity:
            cart_products.append((product, cart_item.quantity))
            subtotal += product.price * cart_item.quantity
        else:
            return redirect_with_toast('cart', f'Stock insuffisant pour {product.name}. Disponible: {product.stock}', 'error')
    
    if not cart_products:
        return redirect_with_toast('cart', 'Aucun produit valide dans le panier', 'error')
    
    order_calculation = calculate_order_total(subtotal)
    
    order = Order(
        user_id=current_user.id,
        total=order_calculation['total'],
        status='pending'
    )
    db.session.add(order)
    db.session.flush()
    
    for product, quantity in cart_products:
        order_item = OrderItem(
            order_id=order.id,
            product_id=product.id,
            quantity=quantity,
            price=product.price
        )
        db.session.add(order_item)
        product.stock -= quantity
    
    db.session.commit()
    Cart.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    
    return redirect_with_toast('order_detail', 
                             f'Commande #{order.id} passée avec succès! Total: {order_calculation["total"]:.2f} {order_calculation["currency"]}', 
                             'success', 
                             order_id=order.id)
# Routes admin - Gestion des produits
@app.route('/admin/products', methods=['GET', 'POST'])
@login_required
def admin_products():
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
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
        return redirect_with_toast('admin_products', 'Produit ajouté avec succès!', 'success')
    
    products = Product.query.all()
    # Remove manual toast handling - context processor handles it
    return render_template('admin_products.html', form=form, products=products)

@app.route('/admin/products/<int:product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
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
        return redirect_with_toast('admin_products', 'Produit mis à jour avec succès!', 'success')
    
    return render_template('edit_product.html', form=form, product=product)

@app.route('/admin/products/<int:product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    product = Product.query.get_or_404(product_id)
    product_name = product.name
    db.session.delete(product)
    db.session.commit()
    return redirect_with_toast('admin_products', f'Produit {product_name} supprimé avec succès!', 'success')


# Updated admin_orders route - replace your existing one
@app.route('/admin/orders')
@login_required
def admin_orders():
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    
    query = Order.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    orders = query.order_by(Order.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
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
    
    # Remove manual toast handling
    return render_template('admin_orders.html', orders=orders, stats=stats, status_filter=status_filter)


@app.route('/admin/orders/<int:order_id>')
@login_required
def admin_order_detail(order_id):
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    # Admin can view ANY order - fetch with better error handling
    order = Order.query.get(order_id)
    if not order:
        flash(f'Commande #{order_id} introuvable', 'error')
        return redirect(url_for('admin_orders'))
    
    # Fetch order items with products
    order_items = db.session.query(OrderItem, Product)\
        .join(Product, OrderItem.product_id == Product.id)\
        .filter(OrderItem.order_id == order_id)\
        .all()
    
    # Get shipping settings for calculations
    settings = get_shipping_settings()
    
    # Calculate order breakdown (for display purposes)
    # Note: This is for display only, the actual order.total remains unchanged
    items_subtotal = sum(item.price * item.quantity for item, product in order_items)
    
    # Calculate what the breakdown would be with current settings
    subtotal = items_subtotal / (1 + settings.tax_rate)  # Remove tax to get base price
    tax = subtotal * settings.tax_rate
    
    # Determine shipping cost based on order total
    if order.total >= settings.free_shipping_threshold:
        shipping_cost = 0
        free_shipping = True
    else:
        shipping_cost = settings.standard_shipping_cost
        free_shipping = False
    
    order_breakdown = {
        'subtotal': subtotal,
        'tax': tax,
        'shipping_cost': shipping_cost,
        'free_shipping': free_shipping,
        'currency': settings.currency
    }
    
    return render_template('admin_order_detail.html', 
                         order=order, 
                         order_items=order_items,
                         order_breakdown=order_breakdown,
                         settings=settings)

@app.route('/admin/orders/<int:order_id>/update_status', methods=['POST'])
@login_required
def update_order_status(order_id):
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status')
    
    valid_statuses = ['pending', 'processing', 'shipped', 'delivered', 'completed', 'cancelled']
    
    if new_status in valid_statuses:
        old_status = order.status
        order.status = new_status
        db.session.commit()
        
        status_messages = {
            'pending': 'Commande en attente',
            'processing': 'Commande en cours de traitement',
            'shipped': 'Commande expédiée',
            'delivered': 'Commande livrée',
            'completed': 'Commande terminée',
            'cancelled': 'Commande annulée'
        }
        
        return redirect_with_toast('admin_order_detail', 
                                 f'{status_messages.get(new_status, "Statut mis à jour")} (de {old_status} à {new_status})', 
                                 'success', 
                                 order_id=order_id)
    else:
        return redirect_with_toast('admin_order_detail', 'Statut invalide', 'error', order_id=order_id)


@app.route('/admin/orders/<int:order_id>/delete', methods=['POST'])
@login_required
def delete_order(order_id):
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    order = Order.query.get_or_404(order_id)
    
    # Restore stock before deleting
    order_items = OrderItem.query.filter_by(order_id=order_id).all()
    for item in order_items:
        product = Product.query.get(item.product_id)
        if product:
            product.stock += item.quantity
    
    OrderItem.query.filter_by(order_id=order_id).delete()
    db.session.delete(order)
    db.session.commit()
    
    return redirect_with_toast('admin_orders', f'Commande #{order_id} supprimée avec succès', 'success')


# Route utilitaire pour créer des données de test
@app.route('/admin/create_test_order')
@login_required
def create_test_order():
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
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
    
    test_order = Order(
        user_id=test_user.id,
        total=299.97,
        status='pending'
    )
    db.session.add(test_order)
    db.session.flush()
    
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
    return redirect_with_toast('admin_orders', f'Commande de test #{test_order.id} créée avec succès!', 'success')

@app.route('/admin/debug/orders/<int:order_id>')
@login_required  
def debug_order_detail(order_id):
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
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
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
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
# Add this context processor function to your app.py file
# Place it after your models and before your routes

@app.context_processor
def inject_cart_count():
    """Make cart count available to all templates"""
    if current_user.is_authenticated:
        try:
            # Only query if Cart table exists
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            if 'cart' in inspector.get_table_names():
                cart_count = Cart.query.filter_by(user_id=current_user.id).count()
                cart_total_quantity = db.session.query(db.func.sum(Cart.quantity))\
                    .filter_by(user_id=current_user.id).scalar() or 0
                return {
                    'cart_count': cart_count,
                    'cart_total_quantity': int(cart_total_quantity)
                }
        except Exception:
            pass
    
    return {'cart_count': 0, 'cart_total_quantity': 0}
# Alternative: You can also create a simple template helper function
# Add this after your context processor

@app.template_filter('cart_count')
def get_cart_count(user_id=None):
    """Template filter to get cart count for specific user"""
    if not user_id and current_user.is_authenticated:
        user_id = current_user.id
    
    if user_id:
        try:
            return Cart.query.filter_by(user_id=user_id).count()
        except:
            return 0
    return 0

class ShippingSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    free_shipping_threshold = db.Column(db.Float, nullable=False, default=500.0)  # 500 DH
    standard_shipping_cost = db.Column(db.Float, nullable=False, default=30.0)  # 30 DH
    express_shipping_cost = db.Column(db.Float, nullable=False, default=60.0)  # 60 DH
    tax_rate = db.Column(db.Float, nullable=False, default=0.2)  # 20% VAT
    currency = db.Column(db.String(5), nullable=False, default='DH')
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp())

# Add form for shipping settings
class ShippingSettingsForm(FlaskForm):
    free_shipping_threshold = DecimalField('Seuil livraison gratuite (DH)', 
                                         validators=[DataRequired(), NumberRange(min=0)], 
                                         default=500)
    standard_shipping_cost = DecimalField('Coût livraison standard (DH)', 
                                        validators=[DataRequired(), NumberRange(min=0)], 
                                        default=30)
    express_shipping_cost = DecimalField('Coût livraison express (DH)', 
                                       validators=[DataRequired(), NumberRange(min=0)], 
                                       default=60)
    tax_rate = DecimalField('Taux de TVA (%)', 
                          validators=[DataRequired(), NumberRange(min=0, max=100)], 
                          default=20)
    submit = SubmitField('Sauvegarder les paramètres')

# Helper function to get current shipping settings
def get_shipping_settings():
    settings = ShippingSettings.query.first()
    if not settings:
        # Create default settings
        settings = ShippingSettings(
            free_shipping_threshold=500.0,
            standard_shipping_cost=30.0,
            express_shipping_cost=60.0,
            tax_rate=0.2,
            currency='DH'
        )
        db.session.add(settings)
        db.session.commit()
    return settings

# Add context processor to make shipping settings available globally
@app.context_processor
def inject_shipping_settings():
    """Make shipping settings available to all templates"""
    try:
        settings = get_shipping_settings()
        return {
            'shipping_settings': settings,
            'free_shipping_threshold': settings.free_shipping_threshold,
            'standard_shipping_cost': settings.standard_shipping_cost,
            'tax_rate': settings.tax_rate,
            'currency': settings.currency
        }
    except:
        return {
            'shipping_settings': None,
            'free_shipping_threshold': 500,
            'standard_shipping_cost': 30,
            'tax_rate': 0.2,
            'currency': 'DH'
        }

# Admin route to manage shipping settings
@app.route('/admin/shipping-settings', methods=['GET', 'POST'])
@login_required
def admin_shipping_settings():
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    settings = get_shipping_settings()
    form = ShippingSettingsForm(obj=settings)
    
    if form.tax_rate.data:
        form.tax_rate.data = settings.tax_rate * 100
    
    if form.validate_on_submit():
        settings.free_shipping_threshold = form.free_shipping_threshold.data
        settings.standard_shipping_cost = form.standard_shipping_cost.data
        settings.express_shipping_cost = form.express_shipping_cost.data
        settings.tax_rate = form.tax_rate.data / 100
        settings.updated_by = current_user.id
        settings.updated_at = db.func.current_timestamp()
        
        db.session.commit()
        return redirect_with_toast('admin_shipping_settings', 'Paramètres de livraison mis à jour avec succès!', 'success')
    
    # Remove manual toast handling
    return render_template('admin_shipping_settings.html', form=form, settings=settings)

# Helper function to calculate order totals with dynamic settings
def calculate_order_total(subtotal, shipping_type='standard'):
    """Calculate order total with current shipping settings"""
    settings = get_shipping_settings()
    
    # Calculate tax
    tax = subtotal * settings.tax_rate
    
    # Calculate shipping
    total_before_shipping = subtotal + tax
    
    if total_before_shipping >= settings.free_shipping_threshold:
        shipping_cost = 0
    else:
        if shipping_type == 'express':
            shipping_cost = settings.express_shipping_cost
        else:
            shipping_cost = settings.standard_shipping_cost
    
    total = total_before_shipping + shipping_cost
    
    return {
        'subtotal': subtotal,
        'tax': tax,
        'shipping_cost': shipping_cost,
        'total': total,
        'free_shipping': shipping_cost == 0,
        'currency': settings.currency
    }

# Ajoutez ce formulaire à vos autres formulaires dans app.py

class EditProfileForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired(), Length(min=4, max=20)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Numéro de téléphone', validators=[
        DataRequired(), 
        Regexp(r'^\+?[\d\s\-\(\)]{10,20}$', message="Veuillez entrer un numéro de téléphone valide")
    ])
    address = TextAreaField('Adresse', validators=[DataRequired(), Length(min=10, max=500)])
    current_password = PasswordField('Mot de passe actuel')
    new_password = PasswordField('Nouveau mot de passe', validators=[Length(min=0, max=128)])
    confirm_password = PasswordField('Confirmer le nouveau mot de passe')
    submit = SubmitField('Mettre à jour le profil')
    
    def validate_confirm_password(self, field):
        if self.new_password.data and self.new_password.data != field.data:
            raise ValidationError('Les mots de passe ne correspondent pas.')

# Ajoutez ces routes à votre app.py

@app.route('/profile')
@login_required
def profile():
    """Afficher le profil de l'utilisateur"""
    orders_count = Order.query.filter_by(user_id=current_user.id).count()
    recent_orders = Order.query.filter_by(user_id=current_user.id)\
        .order_by(Order.created_at.desc()).limit(5).all()
    
    return render_template('profile.html', 
                         user=current_user, 
                         orders_count=orders_count,
                         recent_orders=recent_orders)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(obj=current_user)
    
    if form.validate_on_submit():
        existing_user = User.query.filter(
            (User.username == form.username.data) | (User.email == form.email.data)
        ).filter(User.id != current_user.id).first()
        
        if existing_user:
            if existing_user.username == form.username.data:
                return render_with_toast('edit_profile.html', 'Ce nom d\'utilisateur est déjà utilisé par un autre compte.', 'error', form=form)
            if existing_user.email == form.email.data:
                return render_with_toast('edit_profile.html', 'Cette adresse email est déjà utilisée par un autre compte.', 'error', form=form)
        
        if form.new_password.data:
            if not form.current_password.data:
                return render_with_toast('edit_profile.html', 'Veuillez entrer votre mot de passe actuel pour le changer.', 'error', form=form)
            
            if not check_password_hash(current_user.password_hash, form.current_password.data):
                return render_with_toast('edit_profile.html', 'Mot de passe actuel incorrect.', 'error', form=form)
            
            current_user.password_hash = generate_password_hash(form.new_password.data)
        
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.phone = form.phone.data
        current_user.address = form.address.data
        
        try:
            db.session.commit()
            return redirect_with_toast('profile', 'Profil mis à jour avec succès!', 'success')
        except Exception as e:
            db.session.rollback()
            return render_with_toast('edit_profile.html', 'Erreur lors de la mise à jour du profil. Veuillez réessayer.', 'error', form=form)
    
    return render_template('edit_profile.html', form=form)

@app.route('/profile/delete', methods=['POST'])
@login_required
def delete_account():
    password = request.form.get('password')
    
    if not password:
        return redirect_with_toast('profile', 'Mot de passe requis pour supprimer le compte.', 'error')
    
    if not check_password_hash(current_user.password_hash, password):
        return redirect_with_toast('profile', 'Mot de passe incorrect.', 'error')
    
    try:
        Cart.query.filter_by(user_id=current_user.id).delete()
        
        orders = Order.query.filter_by(user_id=current_user.id).all()
        for order in orders:
            order.status = 'user_deleted'
        
        user_id = current_user.id
        db.session.delete(current_user)
        db.session.commit()
        
        return redirect_with_toast('home', 'Votre compte a été supprimé avec succès.', 'info')
        
    except Exception as e:
        db.session.rollback()
        return redirect_with_toast('profile', 'Erreur lors de la suppression du compte. Veuillez réessayer.', 'error')

        
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        contact_message = Contact(
            name=form.name.data,
            email=form.email.data,
            message=form.message.data
        )
        db.session.add(contact_message)
        db.session.commit()
        
        return render_with_toast('contact.html', 'Merci pour votre message ! Nous vous répondrons dans les plus brefs délais.', 'success', form=ContactForm())
    return render_template('contact.html', form=form)

# Add these new admin routes for contact management
@app.route('/admin/contacts')
@login_required
def admin_contacts():
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error') 
    
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    
    # Build query based on filter
    query = Contact.query
    if status_filter == 'unread':
        query = query.filter_by(is_read=False)
    elif status_filter == 'read':
        query = query.filter_by(is_read=True)
    elif status_filter == 'responded':
        query = query.filter(Contact.admin_response.isnot(None))
    elif status_filter == 'pending':
        query = query.filter(Contact.admin_response.is_(None))
    
    contacts = query.order_by(Contact.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    # Calculate statistics
    stats = {
        'total_contacts': Contact.query.count(),
        'unread_contacts': Contact.query.filter_by(is_read=False).count(),
        'pending_responses': Contact.query.filter(Contact.admin_response.is_(None)).count(),
        'responded_contacts': Contact.query.filter(Contact.admin_response.isnot(None)).count()
    }
    
    return render_template('admin_contacts.html', 
                         contacts=contacts, 
                         stats=stats, 
                         status_filter=status_filter)

@app.route('/admin/contacts/<int:contact_id>')
@login_required
def admin_contact_detail(contact_id):
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    contact = Contact.query.get_or_404(contact_id)
    
    # Mark as read when viewed
    if not contact.is_read:
        contact.is_read = True
        db.session.commit()
    
    response_form = ContactResponseForm()
    
    return render_template('admin_contact_detail.html', 
                         contact=contact, 
                         response_form=response_form)

@app.route('/admin/contacts/<int:contact_id>/respond', methods=['POST'])
@login_required
def respond_to_contact(contact_id):
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    contact = Contact.query.get_or_404(contact_id)
    form = ContactResponseForm()
    
    if form.validate_on_submit():
        contact.admin_response = form.admin_response.data
        contact.response_date = db.func.current_timestamp()
        contact.responded_by = current_user.id
        contact.is_read = True
        
        db.session.commit()
        
        return redirect_with_toast('admin_contact_detail', f'Réponse envoyée à {contact.name} avec succès !', 'success', contact_id=contact_id)
    
    # If form validation fails, show errors
    error_messages = []
    for field, errors in form.errors.items():
        for error in errors:
            error_messages.append(f'Erreur dans {field}: {error}')
    
    if error_messages:
        return redirect_with_toast('admin_contact_detail', ' '.join(error_messages), 'error', contact_id=contact_id)
    
    return redirect(url_for('admin_contact_detail', contact_id=contact_id))


@app.route('/admin/contacts/<int:contact_id>/mark_read', methods=['POST'])
@login_required
def mark_contact_read(contact_id):
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    contact = Contact.query.get_or_404(contact_id)
    contact.is_read = True
    db.session.commit()
    
    return redirect_with_toast('admin_contacts', 'Message marqué comme lu', 'success')

@app.route('/admin/contacts/<int:contact_id>/delete', methods=['POST'])
@login_required
def delete_contact(contact_id):
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    contact = Contact.query.get_or_404(contact_id)
    contact_name = contact.name
    db.session.delete(contact)
    db.session.commit()
    
    return redirect_with_toast('admin_contacts', f'Message de {contact_name} supprimé avec succès', 'success')

@app.template_filter('field_label')
def get_field_label_filter(field_name):
    """Template filter to get French field labels"""
    labels = {
        'username': 'Nom d\'utilisateur',
        'email': 'Email', 
        'phone': 'Téléphone',
        'address': 'Adresse',
        'current_password': 'Mot de passe actuel',
        'new_password': 'Nouveau mot de passe',
        'confirm_password': 'Confirmation du mot de passe'
    }
    return labels.get(field_name, field_name)
# Add this to your context processor to show unread contacts count
@app.context_processor
def inject_admin_stats():
    """Make admin statistics available to all templates"""
    if current_user.is_authenticated and current_user.is_admin:
        try:
            # Check if Contact table exists
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            if 'contact' in inspector.get_table_names():
                unread_contacts = Contact.query.filter_by(is_read=False).count()
                pending_responses = Contact.query.filter(Contact.admin_response.is_(None)).count()
                return {
                    'unread_contacts_count': unread_contacts,
                    'pending_responses_count': pending_responses
                }
        except Exception:
            pass
    
    return {'unread_contacts_count': 0, 'pending_responses_count': 0}
@app.route('/static/<path:filename>')
def custom_static(filename):
    return send_from_directory('static', filename, cache_timeout=60*60*24*7)  
    # Ici cache_timeout = 7 jours
if __name__ == '__main__':
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Create default admin user if doesn't exist
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
        
        # Create default shipping settings if they don't exist
        shipping_settings = ShippingSettings.query.first()
        if not shipping_settings:
            shipping_settings = ShippingSettings(
                free_shipping_threshold=500.0,
                standard_shipping_cost=30.0,
                express_shipping_cost=60.0,
                tax_rate=0.2,
                currency='DH'
            )
            db.session.add(shipping_settings)
        
        # Add sample products if none exist
        if Product.query.count() == 0:
            sample_products = [
                Product(name='Laptop HP Pavilion', description='Ordinateur portable haute performance avec processeur Intel i7, 16GB RAM, SSD 512GB', price=8999.99, stock=10, category='Électronique', image_url='https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=300&h=200&fit=crop'),
                Product(name='iPhone 15 Pro', description='Dernier modèle iPhone avec système de caméra avancé et puce A17', price=12999.99, stock=15, category='Électronique', image_url='https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=300&h=200&fit=crop'),
                Product(name='AirPods Pro', description='Écouteurs sans fil avec réduction de bruit active et son de qualité premium', price=2499.99, stock=20, category='Électronique', image_url='https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=300&h=200&fit=crop'),
                Product(name='T-Shirt Premium', description='T-shirt en coton bio confortable, disponible en plusieurs couleurs et tailles', price=299.99, stock=50, category='Vêtements', image_url='https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=300&h=200&fit=crop'),
                Product(name='Jean Levi\'s 501', description='Jean classique bleu avec coupe parfaite et confort optimal', price=899.99, stock=30, category='Vêtements', image_url='https://images.unsplash.com/photo-1542272604-787c3835535d?w=300&h=200&fit=crop'),
                Product(name='Nike Air Max', description='Chaussures de course confortables avec amorti avancé', price=1299.99, stock=25, category='Chaussures', image_url='https://images.unsplash.com/photo-1549298916-b41d501d3772?w=300&h=200&fit=crop'),
                Product(name='Montre Casio', description='Montre-bracelet élégante avec matériaux premium et artisanat de qualité', price=2999.99, stock=12, category='Accessoires', image_url='https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=300&h=200&fit=crop'),
                Product(name='Sac à Dos North Face', description='Sac de voyage durable avec multiples compartements', price=899.99, stock=18, category='Accessoires', image_url='https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=300&h=200&fit=crop'),
            ]
            for product in sample_products:
                db.session.add(product)
        
        # Add some sample contact messages for testing (optional)
        if Contact.query.count() == 0:
            sample_contacts = [
                Contact(
                    name='Ahmed Benali',
                    email='ahmed.benali@email.com',
                    message='Bonjour,\n\nJ\'aimerais savoir si vous avez des promotions en cours sur les laptops ? Je suis intéressé par l\'achat d\'un ordinateur portable pour mes études.\n\nMerci d\'avance pour votre réponse.\n\nCordialement,\nAhmed'
                ),
                Contact(
                    name='Fatima Zahra',
                    email='fatima.zahra@email.com',
                    message='Salut,\n\nJ\'ai commandé un iPhone la semaine dernière (commande #123) mais je n\'ai pas encore reçu de confirmation d\'expédition. Pouvez-vous me donner des nouvelles ?\n\nMerci !',
                    is_read=True
                ),
                Contact(
                    name='Youssef Alami',
                    email='youssef.alami@email.com',
                    message='Bonsoir,\n\nEst-ce que vous livrez à Agadir ? Et quels sont les délais de livraison pour cette région ?\n\nMerci pour vos informations.'
                )
            ]
            for contact in sample_contacts:
                db.session.add(contact)
        
        # Commit all changes
        db.session.commit()
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)