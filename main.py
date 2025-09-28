from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, EmailField, IntegerField, DecimalField
from wtforms.validators import DataRequired, Email, Length, NumberRange, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid 
from flask import send_from_directory
from flask_wtf.file import FileField, FileAllowed
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
    ville = db.Column(db.String(100), nullable=True)  # NEW FIELD
    code_postal = db.Column(db.String(10), nullable=True)  # NEW FIELD
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
    
    @property
    def title(self):
        """Generate a display title based on date and ID"""
        if self.created_at:
            date_str = self.created_at.strftime('%y%m%d')
            return f"CMD-{date_str}-{str(self.id).zfill(4)}"
        return f"CMD-{str(self.id).zfill(4)}"
    
    @property 
    def display_id(self):
        """Alternative display format"""
        return f"#{str(self.id).zfill(6)}"

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

class OrderDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False, unique=True)
    customer_name = db.Column(db.String(100), nullable=False)
    customer_email = db.Column(db.String(120), nullable=False)
    customer_phone = db.Column(db.String(20), nullable=False)
    shipping_address = db.Column(db.Text, nullable=False)
    shipping_city = db.Column(db.String(50), nullable=False)
    shipping_postal = db.Column(db.String(10), nullable=True)
    payment_method = db.Column(db.String(20), nullable=False, default='card')  # 'card' or 'cash_on_delivery'
    delivery_method = db.Column(db.String(20), nullable=False, default='home_delivery')  # 'home_delivery' or 'express_delivery'
    special_instructions = db.Column(db.Text, nullable=True)
    shipping_cost = db.Column(db.Float, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    # Relationship
    order = db.relationship('Order', backref=db.backref('details', uselist=False, cascade='all, delete-orphan'))
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
    ville = StringField('Ville', validators=[DataRequired(), Length(min=2, max=100)])  # NEW FIELD
    code_postal = StringField('Code Postal', validators=[
        DataRequired(), 
        Regexp(r'^\d{5}$', message="Le code postal doit contenir 5 chiffres")
    ])  # NEW FIELD
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
    image_file = FileField('Image File', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')
    ])
    # Keep image_url as fallback
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
    
    # Get related products from the same category, excluding current product
    related_products = Product.query.filter(
        Product.category == product.category,
        Product.id != product.id,
        Product.stock > 0  # Only show products in stock
    ).limit(4).all()
    
    return render_template('product_detail.html', product=product, related_products=related_products)


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
            return redirect_with_toast(
                next_page.split('/')[-1] if next_page else 'dashboard', 
                f'Bienvenue {user.username}!', 
                'success'
            )
        else:
            return render_with_toast(
                'login.html', 
                'Nom d\'utilisateur ou mot de passe incorrect', 
                'error', 
                form=form
            )
    
    # Handle form validation errors
    if form.errors:
        error_messages = []
        for field, errors in form.errors.items():
            for error in errors:
                error_messages.append(f'{error}')
        
        if error_messages:
            return render_with_toast(
                'login.html', 
                ' • '.join(error_messages), 
                'error', 
                form=form
            )
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        # Check for existing user
        existing_user = User.query.filter(
            (User.username == form.username.data) | 
            (User.email == form.email.data)
        ).first()
        
        if existing_user:
            if existing_user.username == form.username.data:
                return render_with_toast(
                    'register.html', 
                    'Ce nom d\'utilisateur est déjà utilisé', 
                    'error', 
                    form=form
                )
            else:
                return render_with_toast(
                    'register.html', 
                    'Cette adresse email est déjà utilisée', 
                    'error', 
                    form=form
                )
        
        try:
            # Create new user
            user = User(
                username=form.username.data,
                email=form.email.data,
                phone=form.phone.data,
                address=form.address.data,
                ville=form.ville.data,
                code_postal=form.code_postal.data,
                password_hash=generate_password_hash(form.password.data)
            )
            db.session.add(user)
            db.session.commit()
            
            return redirect_with_toast(
                'login', 
                f'Compte créé avec succès pour {user.username}! Veuillez vous connecter.', 
                'success'
            )
            
        except Exception as e:
            db.session.rollback()
            return render_with_toast(
                'register.html', 
                'Erreur lors de la création du compte. Veuillez réessayer.', 
                'error', 
                form=form
            )
    
    # Handle form validation errors
    if form.errors:
        error_messages = []
        for field, errors in form.errors.items():
            field_name = {
                'username': 'Nom d\'utilisateur',
                'email': 'Email',
                'phone': 'Téléphone',
                'address': 'Adresse',
                'ville': 'Ville',
                'code_postal': 'Code postal',
                'password': 'Mot de passe'
            }.get(field, field)
            
            for error in errors:
                error_messages.append(f'{field_name}: {error}')
        
        if error_messages:
            return render_with_toast(
                'register.html', 
                ' • '.join(error_messages), 
                'error', 
                form=form
            )
    
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


def extract_city_from_address(address):
    """Try to extract city name from address string"""
    if not address:
        return ""
    
    # Common Moroccan cities for smart detection
    moroccan_cities = [
        'Casablanca', 'Rabat', 'Fès', 'Marrakech', 'Agadir', 'Tangier', 'Meknès', 
        'Oujda', 'Kenitra', 'Tétouan', 'Safi', 'Mohammedia', 'Khouribga', 
        'El Jadida', 'Béni Mellal', 'Nador', 'Taza', 'Settat', 'Larache'
    ]
    
    address_upper = address.upper()
    for city in moroccan_cities:
        if city.upper() in address_upper:
            return city
    
    # Fallback: try to get last part of address (often the city)
    parts = address.split(',')
    if len(parts) >= 2:
        return parts[-1].strip()
    
    return ""
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
    
    # Get shipping settings for template
    settings = get_shipping_settings()
    
    # Calculate tax amount and other values needed by template
    subtotal_ht = total / (1 + settings.tax_rate)
    tax_amount = total - subtotal_ht
    
    # Calculate shipping
    shipping_amount = 0 if total >= settings.free_shipping_threshold else settings.standard_shipping_cost
    grand_total = total + shipping_amount
    
    return render_template('cart.html', 
                         cart_items=cart_items, 
                         total=total,
                         tax_amount=tax_amount,
                         subtotal_ht=subtotal_ht,
                         shipping_amount=shipping_amount,
                         grand_total=grand_total,
                         free_shipping_threshold=settings.free_shipping_threshold,
                         standard_shipping_cost=settings.standard_shipping_cost,
                         tax_rate=settings.tax_rate)

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


@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if request.method == 'GET':
        # Handle GET request - show cart page with modal
        cart_items_query = db.session.query(Cart, Product)\
            .join(Product, Cart.product_id == Product.id)\
            .filter(Cart.user_id == current_user.id)\
            .all()
        
        if not cart_items_query:
            return redirect_with_toast('cart', 'Votre panier est vide!', 'error')
        
        cart_items = []
        total = 0
        
        for cart_item, product in cart_items_query:
            # Check stock availability
            if product.stock <= 0:
                db.session.delete(cart_item)
                continue
            
            # Adjust quantity if stock is insufficient
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
        
        db.session.commit()
        
        # Get shipping settings for the modal
        settings = get_shipping_settings()
        
        # Pass customer info from user profile and session for pre-filling form
        customer_info = {
            'customer_name': session.get('customer_name', current_user.username),
            'customer_email': session.get('customer_email', current_user.email),
            'customer_phone': session.get('customer_phone', current_user.phone or ''),
            'shipping_address': session.get('shipping_address', current_user.address or ''),
            'shipping_city': session.get('shipping_city', current_user.ville),
            'shipping_postal': session.get('shipping_postal', current_user.code_postal)
        }
        
        return render_template('cart.html', 
                             cart_items=cart_items, 
                             total=total,
                             free_shipping_threshold=settings.free_shipping_threshold,
                             standard_shipping_cost=settings.standard_shipping_cost,
                             tax_rate=settings.tax_rate,
                             customer_info=customer_info)
    
    # Handle POST request - process the modal form submission
    if request.method == 'POST':
        # Validate required fields
        required_fields = ['customer_name', 'customer_email', 'customer_phone', 'shipping_address', 'shipping_city']
        missing_fields = []
        
        for field in required_fields:
            if not request.form.get(field, '').strip():
                missing_fields.append(field)
        
        if missing_fields:
            return redirect_with_toast('cart', 'Veuillez remplir tous les champs obligatoires', 'error')
        
        # Check terms acceptance
        if not request.form.get('accept_terms'):
            return redirect_with_toast('cart', 'Vous devez accepter les conditions générales', 'error')
        
        # Get form data
        customer_data = {
            'customer_name': request.form.get('customer_name').strip(),
            'customer_email': request.form.get('customer_email').strip(),
            'customer_phone': request.form.get('customer_phone').strip(),
            'shipping_address': request.form.get('shipping_address').strip(),
            'shipping_city': request.form.get('shipping_city').strip(),
            'shipping_postal': request.form.get('shipping_postal', '').strip(),
            'payment_method': request.form.get('payment_method', 'card'),
            'delivery_method': request.form.get('delivery_method', 'home_delivery'),
            'special_instructions': request.form.get('special_instructions', '').strip()
        }
        
        # Save customer data to session for future use
        for key, value in customer_data.items():
            if key.startswith(('customer_', 'shipping_')):
                session[key] = value
        
        # Validate cart items
        cart_items_query = db.session.query(Cart, Product)\
            .join(Product, Cart.product_id == Product.id)\
            .filter(Cart.user_id == current_user.id)\
            .all()
        
        if not cart_items_query:
            return redirect_with_toast('cart', 'Votre panier est vide!', 'error')
        
        # Calculate totals
        subtotal = 0
        cart_products = []
        
        for cart_item, product in cart_items_query:
            if product.stock >= cart_item.quantity:
                cart_products.append((product, cart_item.quantity))
                subtotal += product.price * cart_item.quantity
            else:
                return redirect_with_toast('cart', 
                                         f'Stock insuffisant pour {product.name}. Disponible: {product.stock}', 
                                         'error')
        
        if not cart_products:
            return redirect_with_toast('cart', 'Aucun produit valide dans le panier', 'error')
        
        # Calculate shipping cost based on delivery method
        settings = get_shipping_settings()
        shipping_cost = 0
        
        if subtotal < settings.free_shipping_threshold:
            shipping_cost = settings.standard_shipping_cost
        
        # Add express delivery fee if selected
        if customer_data['delivery_method'] == 'express_delivery':
            shipping_cost += 50  # Express delivery surcharge
        
        # Calculate final total
        total_with_shipping = subtotal + shipping_cost
        
        try:
            # Create order
            order = Order(
                user_id=current_user.id,
                total=total_with_shipping,
                status='pending'
            )
            db.session.add(order)
            db.session.flush()  # Get order ID
            
            # Add order items
            for product, quantity in cart_products:
                order_item = OrderItem(
                    order_id=order.id,
                    product_id=product.id,
                    quantity=quantity,
                    price=product.price
                )
                db.session.add(order_item)
                
                # Update product stock
                product.stock -= quantity
            
            # Create order details record for additional info
            order_details = OrderDetails(
                order_id=order.id,
                customer_name=customer_data['customer_name'],
                customer_email=customer_data['customer_email'],
                customer_phone=customer_data['customer_phone'],
                shipping_address=customer_data['shipping_address'],
                shipping_city=customer_data['shipping_city'],
                shipping_postal=customer_data['shipping_postal'],
                payment_method=customer_data['payment_method'],
                delivery_method=customer_data['delivery_method'],
                special_instructions=customer_data['special_instructions'],
                shipping_cost=shipping_cost
            )
            db.session.add(order_details)
            
            # Clear cart
            Cart.query.filter_by(user_id=current_user.id).delete()
            
            # Commit all changes
            db.session.commit()
            
            # Prepare success message
            payment_method_text = 'carte bancaire' if customer_data['payment_method'] == 'card' else 'paiement à la livraison'
            delivery_method_text = 'livraison express' if customer_data['delivery_method'] == 'express_delivery' else 'livraison standard'
            
            success_message = f'Commande #{order.id} confirmée! Paiement: {payment_method_text}, {delivery_method_text}. Total: {total_with_shipping:.2f} DH'
            
            return redirect_with_toast('order_detail', success_message, 'success', order_id=order.id)
            
        except Exception as e:
            db.session.rollback()
            print(f"Checkout error: {e}")
            return redirect_with_toast('cart', 'Erreur lors du traitement de votre commande. Veuillez réessayer.', 'error')

# Routes admin - Gestion des produits
@app.route('/admin/products', methods=['GET', 'POST'])
@login_required
def admin_products():
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    form = ProductForm()
    if form.validate_on_submit():
        image_url = 'https://via.placeholder.com/300x200'
        
        # Handle file upload
        if form.image_file.data:
            file = form.image_file.data
            filename = secure_filename(file.filename)
            # Create unique filename
            import uuid
            filename = f"{uuid.uuid4().hex}_{filename}"
            
            # Create upload directory if it doesn't exist
            upload_dir = os.path.join(app.root_path, 'static', 'uploads')
            os.makedirs(upload_dir, exist_ok=True)
            
            file_path = os.path.join(upload_dir, filename)
            file.save(file_path)
            
            image_url = url_for('static', filename=f'uploads/{filename}')
        
        # Use URL if provided and no file uploaded
        elif form.image_url.data:
            image_url = form.image_url.data
        
        product = Product(
            name=form.name.data,
            description=form.description.data,
            price=form.price.data,
            stock=form.stock.data,
            category=form.category.data,
            image_url=image_url
        )
        db.session.add(product)
        db.session.commit()
        return redirect_with_toast('admin_products', 'Produit ajouté avec succès!', 'success')
    
    products = Product.query.all()
    return render_template('admin_products.html', form=form, products=products)

@app.route('/admin/products/<int:product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    product = Product.query.get_or_404(product_id)
    form = ProductForm(obj=product)
    
    if form.validate_on_submit():
        # Handle image update
        image_url = product.image_url  # Keep current image by default
        
        # Handle file upload (takes priority)
        if form.image_file.data:
            file = form.image_file.data
            filename = secure_filename(file.filename)
            filename = f"{uuid.uuid4().hex}_{filename}"
            
            # Create upload directory
            upload_dir = os.path.join(app.root_path, 'static', 'uploads')
            os.makedirs(upload_dir, exist_ok=True)
            
            # Delete old uploaded file if it exists in uploads folder
            if product.image_url and '/uploads/' in product.image_url:
                try:
                    old_filename = os.path.basename(product.image_url)
                    old_file_path = os.path.join(upload_dir, old_filename)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)
                except:
                    pass  # Continue if file deletion fails
            
            # Save new file
            file_path = os.path.join(upload_dir, filename)
            file.save(file_path)
            image_url = url_for('static', filename=f'uploads/{filename}')
        
        # Handle URL input (if no file uploaded)
        elif form.image_url.data and form.image_url.data != product.image_url:
            image_url = form.image_url.data
        
        # Update product
        product.name = form.name.data
        product.description = form.description.data
        product.price = form.price.data
        product.stock = form.stock.data
        product.category = form.category.data
        product.image_url = image_url
        
        db.session.commit()
        return redirect_with_toast('admin_products', f'Produit "{product.name}" mis à jour avec succès!', 'success')
    
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
    old_status = order.status
    
    valid_statuses = ['pending', 'processing', 'shipped', 'delivered', 'completed', 'cancelled']
    
    if new_status in valid_statuses:
        # Handle stock restoration when order is cancelled
        if new_status == 'cancelled' and old_status != 'cancelled':
            # Restore stock for all items in this order
            order_items = OrderItem.query.filter_by(order_id=order_id).all()
            for item in order_items:
                product = Product.query.get(item.product_id)
                if product:
                    product.stock += item.quantity
                    print(f"Restored {item.quantity} units to product {product.name}. New stock: {product.stock}")
        
        # Handle stock deduction when order is uncancelled (moved from cancelled to another status)
        elif old_status == 'cancelled' and new_status != 'cancelled':
            # Check if we have enough stock to fulfill the order
            order_items = OrderItem.query.filter_by(order_id=order_id).all()
            insufficient_stock = []
            
            for item in order_items:
                product = Product.query.get(item.product_id)
                if product and product.stock < item.quantity:
                    insufficient_stock.append(f"{product.name} (besoin: {item.quantity}, disponible: {product.stock})")
            
            if insufficient_stock:
                return redirect_with_toast('admin_order_detail', 
                                         f'Stock insuffisant pour réactiver cette commande: {", ".join(insufficient_stock)}', 
                                         'error', 
                                         order_id=order_id)
            
            # Deduct stock if we have enough
            for item in order_items:
                product = Product.query.get(item.product_id)
                if product:
                    product.stock -= item.quantity
                    print(f"Deducted {item.quantity} units from product {product.name}. New stock: {product.stock}")
        
        # Update order status
        order.status = new_status
        db.session.commit()
        
        status_messages = {
            'pending': 'Commande en attente',
            'processing': 'Commande en cours de traitement',
            'shipped': 'Commande expédiée',
            'delivered': 'Commande livrée',
            'completed': 'Commande terminée',
            'cancelled': 'Commande annulée - stock restauré'
        }
        
        message = status_messages.get(new_status, "Statut mis à jour")
        if old_status == 'cancelled' and new_status != 'cancelled':
            message += " - stock déduit"
        
        return redirect_with_toast('admin_order_detail', 
                                 f'{message} (de {old_status} à {new_status})', 
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
    
    def validate_new_password(self, field):
        """Validate new password strength"""
        if field.data and len(field.data) < 8:
            raise ValidationError('Le mot de passe doit contenir au moins 8 caractères.')
    
    def validate_confirm_password(self, field):
        """Validate password confirmation"""
        if self.new_password.data and self.new_password.data != field.data:
            raise ValidationError('Les mots de passe ne correspondent pas.')
    
    def validate_current_password(self, field):
        """Validate current password is provided when changing password"""
        if self.new_password.data and not field.data:
            raise ValidationError('Mot de passe actuel requis pour changer le mot de passe.')


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
    
    if request.method == 'POST':
        print("=== FORM SUBMISSION DEBUG ===")
        print(f"Form data received: {dict(request.form)}")
        print(f"Form validate_on_submit(): {form.validate_on_submit()}")
        print(f"Form errors: {form.errors}")
        
        if not form.validate_on_submit():
            print("Form validation failed!")
            print(f"Detailed form errors: {form.errors}")
            # Don't redirect - just render template with errors
            return render_template('edit_profile.html', form=form)
        
        # Form is valid, continue with processing...
        existing_user = User.query.filter(
            (User.username == form.username.data) | (User.email == form.email.data)
        ).filter(User.id != current_user.id).first()
        
        if existing_user:
            if existing_user.username == form.username.data:
                form.username.errors.append('Ce nom d\'utilisateur est déjà utilisé.')
            if existing_user.email == form.email.data:
                form.email.errors.append('Cette adresse email est déjà utilisée.')
            print(f"Existing user errors: {form.errors}")
            return render_template('edit_profile.html', form=form)
        
        # Validate current password if changing password
        if form.new_password.data:
            if not form.current_password.data:
                form.current_password.errors.append('Mot de passe actuel requis.')
                print(f"Current password required: {form.errors}")
                return render_template('edit_profile.html', form=form)
            
            if not check_password_hash(current_user.password_hash, form.current_password.data):
                form.current_password.errors.append('Mot de passe actuel incorrect.')
                print(f"Current password incorrect: {form.errors}")
                return render_template('edit_profile.html', form=form)
            
            current_user.password_hash = generate_password_hash(form.new_password.data)
        
        # Update user information
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.phone = form.phone.data
        current_user.address = form.address.data
        
        try:
            db.session.commit()
            return redirect_with_toast('profile', 'Profil mis à jour avec succès!', 'success')
        except Exception as e:
            db.session.rollback()
            print(f"Database error: {e}")
            return render_with_toast('edit_profile.html', 'Erreur lors de la mise à jour.', 'error', form=form)
    
    # GET request
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
        # Create all database tables first
        db.create_all()
        
        # Add database migration for new columns BEFORE any User queries
        from sqlalchemy import text
        try:
            # Try to add new columns if they don't exist
            db.session.execute(text('ALTER TABLE user ADD COLUMN ville VARCHAR(100)'))
            db.session.execute(text('ALTER TABLE user ADD COLUMN code_postal VARCHAR(10)'))
            db.session.commit()
            print("New columns (ville, code_postal) added successfully")
        except Exception as e:
            print(f"Columns may already exist: {e}")
            # Rollback in case of error
            db.session.rollback()
        
        # Now it's safe to query User model after columns are added
        try:
            # Create default admin user if doesn't exist
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    email='admin@example.com',
                    phone='+1234567890',
                    address='Admin Office, 456 Admin Street, Admin City, AC 67890',
                    ville='Admin City',  # Add the new field
                    code_postal='67890',  # Add the new field
                    password_hash=generate_password_hash('admin123'),
                    is_admin=True
                )
                db.session.add(admin)
                print("Default admin user created")
        except Exception as e:
            print(f"Error creating admin user: {e}")
        
        # Create default shipping settings if they don't exist
        try:
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
                print("Default shipping settings created")
        except Exception as e:
            print(f"Error creating shipping settings: {e}")
        
        # Add sample products if none exist
        try:
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
                print("Sample products added")
        except Exception as e:
            print(f"Error creating sample products: {e}")
        
        # Add some sample contact messages for testing (optional)
        try:
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
                print("Sample contact messages added")
        except Exception as e:
            print(f"Error creating sample contacts: {e}")
        
        # Commit all changes
        try:
            db.session.commit()
            print("Database initialization completed successfully")
        except Exception as e:
            print(f"Error committing to database: {e}")
            db.session.rollback()
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)