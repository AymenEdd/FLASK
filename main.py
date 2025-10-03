from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, EmailField, IntegerField, DecimalField
from wtforms.validators import DataRequired, Email, Length, NumberRange, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
import uuid 
from flask import send_from_directory
from flask_wtf.file import FileField, FileAllowed
import requests
from PIL import Image
from dotenv import load_dotenv
from openai import OpenAI, APIConnectionError, RateLimitError, APIError
import base64
import httpx
import ssl
import certifi
from datetime import datetime, timedelta
load_dotenv()


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("SECRET_KEY environment variable must be set")# Get database URL from environment
# Get database URL from environment - Railway compatible
database_url = os.getenv('DATABASE_URL') or \
               os.getenv('DATABASE_PRIVATE_URL') or \
               os.getenv('PGDATABASE')

if not database_url:
    # Fallback to SQLite only for local development
    database_url = 'sqlite:///ecommerce.db'
    print("⚠️  WARNING: Using SQLite (development only)")
else:
    # Fix Railway's postgres:// to postgresql://
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    print(f"✓ Using PostgreSQL database")

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# PostgreSQL optimizations
if 'postgresql://' in database_url:
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
        'max_overflow': 20
    }
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['STABILITY_API_KEY'] = os.getenv('STABILITY_API_KEY', '')
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['ENHANCED_FOLDER'] = os.path.join(app.root_path, 'static', 'enhanced')


# Create custom SSL context
ssl_context = ssl.create_default_context(cafile=certifi.where())

# Initialize OpenAI client with SSL context
try:
    openai_client = OpenAI(
        api_key=os.getenv('OPENAI_API_KEY'),
        timeout=httpx.Timeout(60.0, connect=10.0),
        max_retries=3,
        http_client=httpx.Client(
            timeout=httpx.Timeout(60.0, connect=10.0),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            verify=ssl_context  # Add SSL context
        )
    )
    print("OpenAI client initialized successfully")
except Exception as e:
    print(f"OpenAI client initialization failed: {e}")
    openai_client = None
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['ENHANCED_FOLDER'], exist_ok=True)

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
    description = TextAreaField('Description', render_kw={'required': False})
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


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Overall ratings
    overall_rating = db.Column(db.Integer, nullable=False)  # 1-5
    delivery_rating = db.Column(db.Integer, nullable=True)  # 1-5
    customer_service_rating = db.Column(db.Integer, nullable=True)  # 1-5
    
    # Comments
    general_comment = db.Column(db.Text, nullable=True)
    
    # Recommendation
    recommend = db.Column(db.String(10), nullable=True)  # 'yes', 'no', 'maybe'
    
    # Privacy
    is_anonymous = db.Column(db.Boolean, default=False)
    
    # Status
    is_published = db.Column(db.Boolean, default=True)
    is_verified_purchase = db.Column(db.Boolean, default=True)
    
    # Admin moderation
    is_approved = db.Column(db.Boolean, default=True)
    admin_notes = db.Column(db.Text, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    
    # Relationships
    user = db.relationship('User', backref=db.backref('reviews', lazy=True))
    order = db.relationship('Order', backref=db.backref('review', uselist=False, cascade='all, delete-orphan'))
    product_reviews = db.relationship('ProductReview', backref='review', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Review {self.id} for Order {self.order_id}>'
    
    @property
    def reviewer_name(self):
        """Return reviewer name or 'Anonymous' if anonymous"""
        if self.is_anonymous:
            return 'Client Anonyme'
        return self.user.username if self.user else 'Utilisateur Supprimé'


class ProductReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    review_id = db.Column(db.Integer, db.ForeignKey('review.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    
    # Product-specific rating and comment
    rating = db.Column(db.Integer, nullable=False)  # 1-5
    comment = db.Column(db.Text, nullable=True)
    
    # Helpfulness votes (optional feature for future)
    helpful_count = db.Column(db.Integer, default=0)
    not_helpful_count = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    # Relationships
    product = db.relationship('Product', backref=db.backref('reviews', lazy=True))
    
    def __repr__(self):
        return f'<ProductReview {self.id} for Product {self.product_id}>'

# Add these imports to your app.py
from datetime import datetime, timedelta

# ============================================
# DATABASE MODELS - Add to your models section
# ============================================

class Return(db.Model):
    """Model for product returns"""
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Return details
    reason = db.Column(db.String(50), nullable=False)  # wrong_size, wrong_item, defective, etc.
    description = db.Column(db.Text, nullable=True)
    
    # Status tracking
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected, completed
    
    # Return method
    return_method = db.Column(db.String(20), default='pickup')  # pickup, ship_back
    
    # Refund details
    refund_amount = db.Column(db.Float, nullable=True)
    refund_method = db.Column(db.String(20), nullable=True)  # original_payment, store_credit
    refund_status = db.Column(db.String(20), default='pending')  # pending, processed, completed
    
    # Admin notes
    admin_notes = db.Column(db.Text, nullable=True)
    processed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    processed_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    order = db.relationship('Order', backref=db.backref('returns', lazy=True))
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('returns', lazy=True))
    processor = db.relationship('User', foreign_keys=[processed_by])
    items = db.relationship('ReturnItem', backref='return_request', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Return {self.id} for Order {self.order_id}>'
    
    @property
    def can_be_created(self):
        """Check if return can be created (within 30 days)"""
        if not self.order.created_at:
            return False
        days_since_order = (datetime.utcnow() - self.order.created_at).days
        return days_since_order <= 30


class ReturnItem(db.Model):
    """Items included in a return request"""
    id = db.Column(db.Integer, primary_key=True)
    return_id = db.Column(db.Integer, db.ForeignKey('return.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    
    # Item condition
    condition = db.Column(db.String(20), nullable=True)  # unopened, opened, defective
    
    # Relationships
    product = db.relationship('Product', backref=db.backref('return_items', lazy=True))
    
    def __repr__(self):
        return f'<ReturnItem {self.id} - Product {self.product_id}>'


# ============================================
# FORMS - Add to your forms section
# ============================================

class ReturnForm(FlaskForm):
    """Form for creating a return request"""
    order_id = IntegerField('Order ID', validators=[DataRequired()])
    reason = StringField('Reason', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Length(max=1000)])
    return_method = StringField('Return Method', validators=[DataRequired()])
    
    # Dynamic fields for items will be handled in JavaScript
    submit = SubmitField('Submit Return Request')


# ============================================
# ROUTES - Add these to your app.py
# ============================================

@app.route('/returns/create', methods=['POST'])
@login_required
def create_return():
    """Create a new return request"""
    try:
        order_id = request.form.get('order_id')
        reason = request.form.get('reason')
        description = request.form.get('description', '').strip()
        return_method = request.form.get('return_method', 'pickup')
        
        # Validate required fields
        if not order_id or not reason:
            return jsonify({
                'success': False,
                'message': 'Commande et raison sont obligatoires'
            }), 400
        
        # Get order and verify ownership
        order = Order.query.filter_by(
            id=int(order_id),
            user_id=current_user.id
        ).first()
        
        if not order:
            return jsonify({
                'success': False,
                'message': 'Commande introuvable'
            }), 404
        
        # Check if order is eligible for return
        if order.status not in ['delivered', 'completed']:
            return jsonify({
                'success': False,
                'message': 'Seules les commandes livrées peuvent être retournées'
            }), 400
        
        # Check if return already exists
        existing_return = Return.query.filter_by(order_id=order.id).first()
        if existing_return:
            return jsonify({
                'success': False,
                'message': 'Une demande de retour existe déjà pour cette commande'
            }), 400
        
        # Check 30-day return window
        days_since_order = (datetime.utcnow() - order.created_at).days
        if days_since_order > 30:
            return jsonify({
                'success': False,
                'message': f'La période de retour (30 jours) est expirée. Commande passée il y a {days_since_order} jours.'
            }), 400
        
        # Create return request
        new_return = Return(
            order_id=order.id,
            user_id=current_user.id,
            reason=reason,
            description=description,
            return_method=return_method,
            status='pending',
            refund_amount=order.total,  # Full refund by default
            refund_method='original_payment'
        )
        db.session.add(new_return)
        db.session.flush()  # Get return ID
        
        # Add all order items to return
        order_items = OrderItem.query.filter_by(order_id=order.id).all()
        for order_item in order_items:
            return_item = ReturnItem(
                return_id=new_return.id,
                product_id=order_item.product_id,
                quantity=order_item.quantity,
                condition='unopened'  # Default condition
            )
            db.session.add(return_item)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Demande de retour créée avec succès! Vous recevrez un email de confirmation.',
            'return_id': new_return.id
        })
        
    except ValueError:
        return jsonify({
            'success': False,
            'message': 'ID de commande invalide'
        }), 400
    except Exception as e:
        db.session.rollback()
        print(f"Error creating return: {e}")
        return jsonify({
            'success': False,
            'message': 'Erreur lors de la création de la demande de retour'
        }), 500


@app.route('/returns/my-returns')
@login_required
def my_returns():
    """View user's return requests"""
    returns = Return.query.filter_by(user_id=current_user.id)\
        .order_by(Return.created_at.desc()).all()
    
    return render_template('my_returns.html', returns=returns)


@app.route('/returns/<int:return_id>')
@login_required
def return_detail(return_id):
    """View return request details"""
    return_request = Return.query.filter_by(
        id=return_id,
        user_id=current_user.id
    ).first_or_404()
    
    return render_template('return_detail.html', return_request=return_request)


@app.route('/returns/<int:return_id>/cancel', methods=['POST'])
@login_required
def cancel_return(return_id):
    """Cancel a pending return request"""
    return_request = Return.query.filter_by(
        id=return_id,
        user_id=current_user.id
    ).first_or_404()
    
    if return_request.status != 'pending':
        return redirect_with_toast('my_returns', 
                                  'Seules les demandes en attente peuvent être annulées', 
                                  'error')
    
    db.session.delete(return_request)
    db.session.commit()
    
    return redirect_with_toast('my_returns', 
                              'Demande de retour annulée avec succès', 
                              'success')


# ============================================
# ADMIN ROUTES - For managing returns
# ============================================

@app.route('/admin/returns')
@login_required
def admin_returns():
    """Admin view of all return requests"""
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    
    query = Return.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    returns = query.order_by(Return.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    stats = {
        'total_returns': Return.query.count(),
        'pending_returns': Return.query.filter_by(status='pending').count(),
        'approved_returns': Return.query.filter_by(status='approved').count(),
        'completed_returns': Return.query.filter_by(status='completed').count(),
        'rejected_returns': Return.query.filter_by(status='rejected').count()
    }
    
    return render_template('admin_returns.html', returns=returns, stats=stats, status_filter=status_filter)


@app.route('/admin/returns/<int:return_id>')
@login_required
def admin_return_detail(return_id):
    """Admin view of return request details"""
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    return_request = Return.query.get_or_404(return_id)
    return render_template('admin_return_detail.html', return_request=return_request)


@app.route('/admin/returns/<int:return_id>/update-status', methods=['POST'])
@login_required
def update_return_status(return_id):
    """Update return request status"""
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    return_request = Return.query.get_or_404(return_id)
    new_status = request.form.get('status')
    admin_notes = request.form.get('admin_notes', '').strip()
    
    valid_statuses = ['pending', 'approved', 'rejected', 'completed']
    
    if new_status not in valid_statuses:
        return redirect_with_toast('admin_return_detail', 
                                  'Statut invalide', 
                                  'error', 
                                  return_id=return_id)
    
    old_status = return_request.status
    return_request.status = new_status
    return_request.processed_by = current_user.id
    return_request.processed_at = datetime.utcnow()
    
    if admin_notes:
        return_request.admin_notes = admin_notes
    
    # If approved, process refund
    if new_status == 'approved' and old_status != 'approved':
        return_request.refund_status = 'processed'
        
        # Restore stock for returned items
        for return_item in return_request.items:
            product = Product.query.get(return_item.product_id)
            if product:
                product.stock += return_item.quantity
    
    # If completed, mark refund as completed
    if new_status == 'completed':
        return_request.refund_status = 'completed'
    
    db.session.commit()
    
    status_messages = {
        'pending': 'Retour en attente',
        'approved': 'Retour approuvé - Remboursement en cours',
        'rejected': 'Retour rejeté',
        'completed': 'Retour terminé - Remboursement effectué'
    }
    
    message = status_messages.get(new_status, "Statut mis à jour")
    
    return redirect_with_toast('admin_return_detail', 
                              f'{message} (de {old_status} à {new_status})', 
                              'success', 
                              return_id=return_id)


@app.route('/admin/returns/<int:return_id>/delete', methods=['POST'])
@login_required
def delete_return(return_id):
    """Delete a return request"""
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    return_request = Return.query.get_or_404(return_id)
    db.session.delete(return_request)
    db.session.commit()
    
    return redirect_with_toast('admin_returns', 
                              f'Demande de retour #{return_id} supprimée', 
                              'success')


# ============================================
# HELPER FUNCTIONS
# ============================================

def get_eligible_orders_for_return(user_id):
    """Get orders eligible for return (delivered/completed within 30 days)"""
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    
    eligible_orders = Order.query.filter(
        Order.user_id == user_id,
        Order.status.in_(['delivered', 'completed']),
        Order.created_at >= thirty_days_ago
    ).all()
    
    # Filter out orders that already have returns
    orders_with_returns = db.session.query(Return.order_id).filter_by(user_id=user_id).all()
    order_ids_with_returns = [r[0] for r in orders_with_returns]
    
    return [order for order in eligible_orders if order.id not in order_ids_with_returns]


# ============================================
# CONTEXT PROCESSOR
# ============================================

@app.context_processor
def inject_return_stats():
    """Make return statistics available to templates"""
    if current_user.is_authenticated:
        if current_user.is_admin:
            pending_returns = Return.query.filter_by(status='pending').count()
            return {'pending_returns_count': pending_returns}
    return {'pending_returns_count': 0}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
# Context processor for product review stats - MUST be after models
@app.context_processor
def inject_product_review_stats():
    """Make product review statistics available to all templates"""
    def get_product_review_stats(product_id):
        try:
            # EAGER LOAD the Review relationship
            product_reviews = db.session.query(ProductReview)\
                .join(Review)\
                .options(db.joinedload(ProductReview.review))\
                .filter(ProductReview.product_id == product_id)\
                .filter(Review.is_approved == True)\
                .filter(Review.is_published == True)\
                .all()
            
            if not product_reviews:
                return {
                    'count': 0,
                    'avg_rating': 0,
                    'rating_distribution': {5: 0, 4: 0, 3: 0, 2: 0, 1: 0},
                    'reviews': []  # Add this
                }
            
            # Calculate stats...
            total_rating = sum(pr.rating for pr in product_reviews)
            avg_rating = total_rating / len(product_reviews)
            
            rating_distribution = {5: 0, 4: 0, 3: 0, 2: 0, 1: 0}
            for review in product_reviews:
                rating_distribution[review.rating] += 1
            
            return {
                'count': len(product_reviews),
                'avg_rating': round(avg_rating, 1),
                'rating_distribution': rating_distribution,
                'reviews': product_reviews  # Add the actual reviews
            }
        except Exception as e:
            print(f"Error in get_product_review_stats: {e}")
            import traceback
            traceback.print_exc()
            return {
                'count': 0,
                'avg_rating': 0,
                'rating_distribution': {5: 0, 4: 0, 3: 0, 2: 0, 1: 0},
                'reviews': []
            }
    
    return dict(get_product_review_stats=get_product_review_stats)
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
@app.route('/debug/check-reviews/<int:product_id>')
@login_required
def debug_check_reviews(product_id):
    if not current_user.is_admin:
        return "Access denied", 403
    
    # Check all reviews without filtering
    all_reviews = db.session.query(ProductReview)\
        .filter(ProductReview.product_id == product_id)\
        .all()
    
    # Check filtered reviews
    filtered_reviews = db.session.query(ProductReview)\
        .join(Review)\
        .filter(ProductReview.product_id == product_id)\
        .filter(Review.is_approved == True)\
        .filter(Review.is_published == True)\
        .all()
    
    debug_data = {
        'product_id': product_id,
        'total_all_reviews': len(all_reviews),
        'total_filtered_reviews': len(filtered_reviews),
        'all_reviews': [
            {
                'id': pr.id,
                'rating': pr.rating,
                'comment': pr.comment,
                'review_id': pr.review_id,
                'is_approved': pr.review.is_approved if pr.review else None,
                'is_published': pr.review.is_published if pr.review else None
            }
            for pr in all_reviews
        ]
    }
    
    return f"<pre>{json.dumps(debug_data, indent=2)}</pre>"
@app.route('/clear-session')
def clear_session():
    """Utility route to clear session - useful for debugging"""
    session.clear()
    return redirect_with_toast('home', 'Session cleared!', 'info')
# Routes principales
@app.route('/')
def home():
    products = Product.query.limit(8).all()
    return render_template('home.html', products=products)

@app.route('/products/api')
def products_api():
    """API endpoint for AJAX product loading"""
    page = request.args.get('page', 1, type=int)
    category = request.args.get('category', 'all')
    search = request.args.get('search', '')
    in_stock = request.args.get('in_stock', 'false')
    sort_by = request.args.get('sort', 'name')
    sort_order = request.args.get('order', 'asc')
    
    # Base query
    query = Product.query
    
    # Apply category filter
    if category and category != 'all':
        query = query.filter_by(category=category)
    
    # Apply search filter
    if search:
        query = query.filter(Product.name.ilike(f'%{search}%'))
    
    # Apply stock filter
    if in_stock == 'true':
        query = query.filter(Product.stock > 0)
    
    # Apply sorting
    if sort_by == 'price':
        query = query.order_by(Product.price.desc() if sort_order == 'desc' else Product.price.asc())
    elif sort_by == 'name':
        query = query.order_by(Product.name.desc() if sort_order == 'desc' else Product.name.asc())
    elif sort_by == 'rating':
        # For rating, we'll do a simple order by id for now
        # You can implement a more complex rating sort if needed
        query = query.order_by(Product.id.desc() if sort_order == 'desc' else Product.id.asc())
    else:
        query = query.order_by(Product.name.asc())
    
    # Get total count before pagination
    total = query.count()
    
    # Paginate results
    products = query.paginate(page=page, per_page=12, error_out=False)
    
    # Render product cards HTML
    products_html = render_template('partials/product_cards.html', products=products.items)
    
    # Render pagination HTML
    pagination_html = render_template('partials/pagination.html', 
                                     products=products,
                                     current_category=category,
                                     current_search=search,
                                     current_in_stock=in_stock,
                                     current_sort=sort_by,
                                     current_order=sort_order)
    
    return jsonify({
        'html': products_html,
        'pagination': pagination_html,
        'count': len(products.items),
        'total': total,
        'page': page,
        'pages': products.pages
    })
    
@app.route('/products')
def products():
    page = request.args.get('page', 1, type=int)
    category = request.args.get('category', 'all')
    search = request.args.get('search', '')
    in_stock = request.args.get('in_stock', 'false')
    sort_by = request.args.get('sort', 'name-asc')
    
    # Base query
    query = Product.query
    
    # Apply category filter
    if category and category != 'all':
        query = query.filter_by(category=category)
    
    # Apply search filter
    if search:
        query = query.filter(Product.name.ilike(f'%{search}%'))
    
    # Apply stock filter
    if in_stock == 'true':
        query = query.filter(Product.stock > 0)
    
    # Apply sorting
    if sort_by == 'price-asc':
        query = query.order_by(Product.price.asc())
    elif sort_by == 'price-desc':
        query = query.order_by(Product.price.desc())
    elif sort_by == 'name-asc':
        query = query.order_by(Product.name.asc())
    elif sort_by == 'name-desc':
        query = query.order_by(Product.name.desc())
    else:
        query = query.order_by(Product.name.asc())
    
    # Paginate results
    products = query.paginate(page=page, per_page=12, error_out=False)
    
    # Get categories for filter buttons
    categories = db.session.query(Product.category).distinct().all()
    
    return render_template('products.html', 
                         products=products, 
                         categories=categories,
                         current_category=category,
                         current_search=search,
                         current_in_stock=in_stock,
                         current_sort=sort_by)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Get related products from the same category, excluding current product
    related_products = Product.query.filter(
        Product.category == product.category,
        Product.id != product.id,
        Product.stock > 0
    ).limit(4).all()
    
    # CRITICAL FIX: Get reviews with proper eager loading
    product_reviews_query = db.session.query(ProductReview)\
        .join(Review)\
        .filter(ProductReview.product_id == product_id)\
        .filter(Review.is_approved == True)\
        .filter(Review.is_published == True)\
        .order_by(ProductReview.created_at.desc())\
        .all()
    
    return render_template('product_detail.html', 
                         product=product, 
                         related_products=related_products,
                         product_reviews_direct=product_reviews_query)


# Routes d'authentification
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect_with_toast(
                next_page if next_page else 'home', 
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
    
    # Get reviews for all products in this order
    product_ids = [product.id for _, product in order_items]
    
    # Create a map of product reviews
    product_reviews_map = {}
    for product_id in product_ids:
        reviews = db.session.query(ProductReview)\
            .join(Review)\
            .options(db.joinedload(ProductReview.review))\
            .filter(ProductReview.product_id == product_id)\
            .filter(Review.is_approved == True)\
            .filter(Review.is_published == True)\
            .order_by(ProductReview.created_at.desc())\
            .all()
        product_reviews_map[product_id] = reviews
    
    return render_template('order_detail.html', 
                         order=order, 
                         order_items=order_items,
                         product_reviews_map=product_reviews_map)

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

# Ajoutez cette route dans votre app.py après la route order_detail

@app.route('/track/<int:order_id>')
@login_required
def track_order(order_id):
    """Page de suivi de commande pour l'utilisateur"""
    # ISOLATION: Un utilisateur ne peut suivre que SES propres commandes
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()
    
    if not order:
        return redirect_with_toast('dashboard', 'Commande introuvable', 'error')
    
    # Récupérer les items de la commande
    order_items = db.session.query(OrderItem, Product)\
        .join(Product, OrderItem.product_id == Product.id)\
        .filter(OrderItem.order_id == order_id)\
        .all()
    
    # Définir les étapes de suivi avec leur statut
    tracking_steps = [
        {
            'status': 'pending',
            'title': 'Commande reçue',
            'description': 'Votre commande a été enregistrée avec succès',
            'icon': 'fa-receipt',
            'completed': order.status in ['pending', 'processing', 'shipped', 'delivered', 'completed']
        },
        {
            'status': 'processing',
            'title': 'En préparation',
            'description': 'Votre commande est en cours de préparation',
            'icon': 'fa-box',
            'completed': order.status in ['processing', 'shipped', 'delivered', 'completed']
        },
        {
            'status': 'shipped',
            'title': 'Expédiée',
            'description': 'Votre commande a été expédiée',
            'icon': 'fa-truck',
            'completed': order.status in ['shipped', 'delivered', 'completed']
        },
        {
            'status': 'delivered',
            'title': 'Livrée',
            'description': 'Votre commande a été livrée',
            'icon': 'fa-check-circle',
            'completed': order.status in ['delivered', 'completed']
        }
    ]
    
    # Calculer le pourcentage de progression
    completed_steps = sum(1 for step in tracking_steps if step['completed'])
    progress_percentage = (completed_steps / len(tracking_steps)) * 100
    
    # Obtenir les détails de livraison si disponibles
    try:
        order_details = OrderDetails.query.filter_by(order_id=order_id).first()
    except:
        order_details = None
    
    return render_template('track_order.html', 
                         order=order, 
                         order_items=order_items,
                         order_details=order_details,
                         tracking_steps=tracking_steps,
                         progress_percentage=progress_percentage)
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
def enhance_image_with_stability_ai(image_path):
    """
    Enhance image using Stability AI's latest API
    Version corrigée avec meilleure gestion d'erreurs
    """
    try:
        api_key = app.config.get('STABILITY_API_KEY', '').strip()
        
        # Vérification de la clé API
        if not api_key:
            print("❌ ERREUR: STABILITY_API_KEY non configurée dans .env")
            return None
        
        print(f"🔑 API Key trouvée: {api_key[:10]}...")
        
        # Vérifier que le fichier existe
        if not os.path.exists(image_path):
            print(f"❌ ERREUR: Fichier introuvable: {image_path}")
            return None
        
        # Optimiser l'image avant envoi (max 1024x1024 pour éviter erreurs)
        img = Image.open(image_path)
        img.thumbnail((1024, 1024), Image.Resampling.LANCZOS)
        
        # Convertir en bytes
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()
        
        print(f"📤 Envoi de l'image ({len(img_byte_arr)} bytes)...")
        
        # Nouvel endpoint recommandé par Stability AI
        url = "https://api.stability.ai/v2beta/stable-image/upscale/conservative"
        
        headers = {
            "authorization": f"Bearer {api_key}",
            "accept": "image/*"
        }
        
        files = {
            "image": ("image.png", img_byte_arr, "image/png")
        }
        
        data = {
            "output_format": "png"
        }
        
        # Faire la requête avec timeout
        response = requests.post(
            url, 
            headers=headers, 
            files=files, 
            data=data,
            timeout=60
        )
        
        print(f"📡 Réponse API: Status {response.status_code}")
        
        # Gestion détaillée des erreurs
        if response.status_code == 200:
            # Sauvegarder l'image améliorée
            filename = os.path.basename(image_path)
            name, ext = os.path.splitext(filename)
            enhanced_filename = f"enhanced_{name}.png"
            enhanced_path = os.path.join(app.config['ENHANCED_FOLDER'], enhanced_filename)
            
            with open(enhanced_path, 'wb') as f:
                f.write(response.content)
            
            print(f"✅ Image améliorée sauvegardée: {enhanced_path}")
            return enhanced_path
            
        elif response.status_code == 401:
            print("❌ ERREUR 401: Clé API invalide ou expirée")
            print(f"Vérifiez votre clé sur https://platform.stability.ai/account/keys")
            
        elif response.status_code == 402:
            print("❌ ERREUR 402: Crédits insuffisants sur votre compte Stability AI")
            print("Rechargez vos crédits sur https://platform.stability.ai/account/credits")
            
        elif response.status_code == 429:
            print("❌ ERREUR 429: Trop de requêtes, attendez quelques secondes")
            
        else:
            print(f"❌ ERREUR {response.status_code}: {response.text}")
        
        return None
        
    except requests.exceptions.Timeout:
        print("❌ ERREUR: Timeout - L'API a mis trop de temps à répondre")
        return None
        
    except requests.exceptions.RequestException as e:
        print(f"❌ ERREUR de connexion: {e}")
        return None
        
    except Exception as e:
        print(f"❌ ERREUR inattendue: {e}")
        import traceback
        traceback.print_exc()
        return None

def enhance_image_creative(image_path, prompt="professional product photography, high quality"):
    """
    Creative upscale - Plus cher mais meilleure qualité
    """
    try:
        api_key = app.config.get('STABILITY_API_KEY', '').strip()
        
        if not api_key:
            print("❌ STABILITY_API_KEY non configurée")
            return None
        
        # Lire l'image
        with open(image_path, 'rb') as f:
            img_bytes = f.read()
        
        url = "https://api.stability.ai/v2beta/stable-image/upscale/creative"
        
        headers = {
            "authorization": f"Bearer {api_key}",
            "accept": "image/*"
        }
        
        files = {
            "image": ("image.png", img_bytes, "image/png")
        }
        
        data = {
            "prompt": prompt,
            "output_format": "png",
            "creativity": 0.2  # 0-0.35, plus bas = plus fidèle à l'original
        }
        
        print(f"🎨 Amélioration créative avec prompt: '{prompt}'")
        
        response = requests.post(url, headers=headers, files=files, data=data, timeout=90)
        
        if response.status_code == 200:
            filename = os.path.basename(image_path)
            name, ext = os.path.splitext(filename)
            enhanced_filename = f"creative_{name}.png"
            enhanced_path = os.path.join(app.config['ENHANCED_FOLDER'], enhanced_filename)
            
            with open(enhanced_path, 'wb') as f:
                f.write(response.content)
            
            print(f"✅ Image créative sauvegardée: {enhanced_path}")
            return enhanced_path
        else:
            print(f"❌ Erreur {response.status_code}: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return None

def optimize_image(image_path, max_size=(1200, 1200)):
    """Basic image optimization before AI enhancement"""
    try:
        img = Image.open(image_path)
        
        # Convert to RGB
        if img.mode in ('RGBA', 'P'):
            img = img.convert('RGB')
        
        # Resize if too large
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        
        # Save optimized
        optimized_path = image_path.replace('.', '_opt.')
        img.save(optimized_path, 'JPEG', quality=90, optimize=True)
        
        return optimized_path
    except Exception as e:
        print(f"Optimization error: {e}")
        return image_path

# Update your admin_products route
# Ajoutez ces imports en haut de app.py


# Ajoutez cette fonction helper avant les routes
def generate_product_description_from_image(image_path, product_name=None):
    """Generate description with better error handling"""
    if not openai_client:
        print("❌ OpenAI client not initialized")
        return None
    
    try:
        # Read and encode image
        with open(image_path, 'rb') as image_file:
            image_data = base64.b64encode(image_file.read()).decode('utf-8')
        
        # Prepare the prompt - UPDATED to request bullet points
        prompt = f"""Analysez cette image de produit et générez une description marketing professionnelle en français.

La description doit:
- Être organisée en 2-3 points principaux avec des tirets (-)
- Chaque point doit être une ligne courte (max 15 mots)
- Total: 6-8 lignes maximum
- Décrire visuellement ce que vous voyez dans l'image
- Mettre en avant les caractéristiques visibles
- Utiliser un langage persuasif adapté au e-commerce
- Être adaptée pour un public marocain

Format attendu:
- Premier point clé du produit
- Deuxième point clé du produit  
- Troisième point clé du produit

PAS de paragraphe, UNIQUEMENT des bullet points avec tirets."""

        # Make API call with vision
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{image_data}"
                            }
                        }
                    ]
                }
            ],
            max_tokens=200,  # Reduced since we want shorter output
            temperature=0.6,
            timeout=60
        )
        
        description = response.choices[0].message.content.strip()
        print(f"✅ Description générée par AI (vision): {description[:100]}...")
        return description
        
    except APIConnectionError as e:
        print(f"❌ OpenAI Connection Error: {e}")
        return None
    except RateLimitError as e:
        print(f"❌ OpenAI Rate Limit: {e}")
        return None
    except APIError as e:
        print(f"❌ OpenAI API Error: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {type(e).__name__}: {e}")
        return None

def generate_description_from_name(product_name, category=None):
    """Generate product description from name only (fallback when no image)"""
    if not openai_client:
        print("❌ OpenAI client not initialized")
        return None
    
    try:
        prompt = f"""Générez une description marketing professionnelle en français pour ce produit:

Produit: {product_name}
{f'Catégorie: {category}' if category else ''}

La description doit:
- Être organisée en 2-3 points principaux avec des tirets (-)
- Chaque point doit être une ligne courte (max 15 mots)
- Total: 6-8 lignes maximum
- Mettre en avant les caractéristiques probables du produit
- Utiliser un langage persuasif adapté au e-commerce
- Être adaptée pour un public marocain

Format attendu:
- Premier point clé du produit
- Deuxième point clé du produit  
- Troisième point clé du produit

PAS de paragraphe, UNIQUEMENT des bullet points avec tirets."""

        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "user", "content": prompt}
            ],
            max_tokens=200,
            temperature=0.7,
            timeout=60
        )
        
        description = response.choices[0].message.content.strip()
        print(f"✅ Description générée par AI (nom): {description[:100]}...")
        return description
        
    except APIConnectionError as e:
        print(f"❌ OpenAI Connection Error: {e}")
        return None
    except RateLimitError as e:
        print(f"❌ OpenAI Rate Limit: {e}")
        return None
    except APIError as e:
        print(f"❌ OpenAI API Error: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {type(e).__name__}: {e}")
        return None

# MODIFIEZ la route admin_products comme suit:
@app.route('/admin/products', methods=['GET', 'POST'])
@login_required
def admin_products():
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    form = ProductForm()
    if form.validate_on_submit():
        image_url = 'https://via.placeholder.com/300x200'
        file_path = None
        ai_description = None
        
        if form.image_file.data:
            file = form.image_file.data
            filename = secure_filename(file.filename)
            filename = f"{uuid.uuid4().hex}_{filename}"
            
            upload_dir = app.config['UPLOAD_FOLDER']
            file_path = os.path.join(upload_dir, filename)
            file.save(file_path)
            
            optimized_path = optimize_image(file_path)
            enhanced_path = enhance_image_with_stability_ai(optimized_path)
            
            if enhanced_path:
                enhanced_filename = os.path.basename(enhanced_path)
                image_url = url_for('static', filename=f'enhanced/{enhanced_filename}')
                file_path = enhanced_path
                flash('Image améliorée avec Stability AI!', 'success')
            else:
                image_url = url_for('static', filename=f'uploads/{filename}')
            
            # Génération basée UNIQUEMENT sur l'image (pas de nom)
            if not form.description.data or form.description.data.strip() == '':
                print(f"📝 Génération de description AI depuis l'image...")
                ai_description = generate_product_description_from_image(file_path)  # Pas de product_name
                
                if ai_description:
                    flash('✨ Description générée automatiquement par IA depuis l\'image!', 'info')
        
        elif form.image_url.data:
            image_url = form.image_url.data
        
        # Fallback si pas d'image mais description vide
        if not ai_description and (not form.description.data or form.description.data.strip() == ''):
            ai_description = generate_description_from_name(
                form.name.data,
                category=form.category.data
            )
            if ai_description:
                flash('✨ Description générée par IA (basée sur le nom - pas d\'image fournie)!', 'info')
        
        final_description = ai_description or form.description.data or f"Produit de qualité: {form.name.data}"
        
        product = Product(
            name=form.name.data,
            description=final_description,
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


# MODIFIEZ également la route edit_product:
@app.route('/admin/products/<int:product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    product = Product.query.get_or_404(product_id)
    form = ProductForm(obj=product)
    
    if form.validate_on_submit():
        image_url = product.image_url
        file_path = None
        ai_description = None
        
        if form.image_file.data:
            file = form.image_file.data
            filename = secure_filename(file.filename)
            filename = f"{uuid.uuid4().hex}_{filename}"
            
            # Delete old image if exists
            if product.image_url and '/uploads/' in product.image_url:
                try:
                    old_filename = os.path.basename(product.image_url)
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_filename)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                except:
                    pass
            
            # Save and enhance new image
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            optimized_path = optimize_image(file_path)
            enhanced_path = enhance_image_with_stability_ai(optimized_path)
            
            if enhanced_path:
                enhanced_filename = os.path.basename(enhanced_path)
                image_url = url_for('static', filename=f'enhanced/{enhanced_filename}')
                file_path = enhanced_path
                flash('Image améliorée avec Stability AI!', 'success')
            else:
                image_url = url_for('static', filename=f'uploads/{filename}')
            
            # 🎯 Générer description si vide
            if not form.description.data or form.description.data.strip() == '':
                ai_description = generate_product_description_from_image(
                    file_path,
                )
                if ai_description:
                    flash('✨ Description régénérée automatiquement par IA!', 'info')
        
        elif form.image_url.data and form.image_url.data != product.image_url:
            image_url = form.image_url.data
        
        # Fallback: génération par nom si pas d'image
        if not ai_description and (not form.description.data or form.description.data.strip() == ''):
            ai_description = generate_description_from_name(
                form.name.data,
                category=form.category.data
            )
            if ai_description:
                flash('✨ Description générée par IA (basée sur le nom)!', 'info')
        
        product.name = form.name.data
        product.description = ai_description or form.description.data or product.description
        product.price = form.price.data
        product.stock = form.stock.data
        product.category = form.category.data
        product.image_url = image_url
        
        db.session.commit()
        return redirect_with_toast('admin_products', f'Produit "{product.name}" mis à jour!', 'success')
    
    return render_template('edit_product.html', form=form, product=product)
# Bulk enhancement route
@app.route('/admin/enhance-all-products', methods=['POST'])
@login_required
def enhance_all_products():
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    products = Product.query.filter(Product.image_url.like('%/uploads/%')).all()
    enhanced_count = 0
    failed_count = 0
    
    for product in products:
        try:
            filename = os.path.basename(product.image_url)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            if os.path.exists(file_path):
                enhanced_path = enhance_image_with_stability_ai(file_path)
                
                if enhanced_path:
                    enhanced_filename = os.path.basename(enhanced_path)
                    product.image_url = url_for('static', filename=f'enhanced/{enhanced_filename}')
                    enhanced_count += 1
                else:
                    failed_count += 1
        except Exception as e:
            print(f"Error enhancing product {product.id}: {e}")
            failed_count += 1
    
    db.session.commit()
    
    message = f'{enhanced_count} images améliorées'
    if failed_count > 0:
        message += f', {failed_count} échecs'
    
    return redirect_with_toast('admin_products', message, 'success' if enhanced_count > 0 else 'warning')

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

@app.route('/submit-review', methods=['POST'])
@login_required
def submit_review():
    try:
        data = request.get_json()
        order_id = data.get('order_id')
        
        # Verify order belongs to user and is completed
        order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()
        if not order:
            return jsonify({'success': False, 'message': 'Commande non trouvée'})
        
        if order.status != 'completed':
            return jsonify({'success': False, 'message': 'Seules les commandes terminées peuvent être évaluées'})
        
        # Check if review already exists
        existing_review = Review.query.filter_by(order_id=order_id, user_id=current_user.id).first()
        if existing_review:
            return jsonify({'success': False, 'message': 'Vous avez déjà évalué cette commande'})
        
        # Validate overall rating
        overall_rating = data.get('overall_rating')
        if not overall_rating or int(overall_rating) < 1 or int(overall_rating) > 5:
            return jsonify({'success': False, 'message': 'Note générale invalide'})
        
        # Create main review - EXPLICITLY SET is_approved and is_published
        review = Review(
            order_id=order_id,
            user_id=current_user.id,
            overall_rating=int(overall_rating),
            delivery_rating=int(data.get('delivery_rating')) if data.get('delivery_rating') else None,
            customer_service_rating=int(data.get('customer_service_rating')) if data.get('customer_service_rating') else None,
            general_comment=data.get('general_comment', '').strip() or None,
            recommend=data.get('recommend'),
            is_anonymous=data.get('anonymous', False),
            is_verified_purchase=True,
            is_approved=True,  # ADD THIS LINE
            is_published=True   # ADD THIS LINE
        )
        db.session.add(review)
        db.session.flush()  # Get review ID
        
        # Create product reviews
        products = data.get('products', [])
        for product_data in products:
            product_id = product_data.get('product_id')
            product_rating = product_data.get('rating')
            
            if product_id and product_rating:
                # Verify product was in the order
                order_item = OrderItem.query.filter_by(
                    order_id=order_id, 
                    product_id=product_id
                ).first()
                
                if order_item:
                    product_review = ProductReview(
                        review_id=review.id,
                        product_id=product_id,
                        rating=int(product_rating),
                        comment=product_data.get('comment', '').strip() or None
                    )
                    db.session.add(product_review)
        
        db.session.commit()
        
        # Log for debugging
        print(f"✅ Review created: ID={review.id}, approved={review.is_approved}, published={review.is_published}")
        
        return jsonify({
            'success': True, 
            'message': 'Merci pour votre avis ! Il a été enregistré avec succès.',
            'review_id': review.id
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error submitting review: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Erreur lors de l\'enregistrement de votre avis'})

@app.route('/debug/product-reviews/<int:product_id>')
def debug_product_reviews(product_id):
    """Debug route to see all reviews for a product"""
    if not current_user.is_authenticated or not current_user.is_admin:
        return "Access denied", 403
    
    product = Product.query.get_or_404(product_id)
    
    # Get ALL product reviews without filtering
    all_reviews = db.session.query(ProductReview, Review)\
        .join(Review)\
        .filter(ProductReview.product_id == product_id)\
        .all()
    
    debug_info = {
        'product_name': product.name,
        'total_product_reviews': len(all_reviews),
        'reviews': []
    }
    
    for pr, r in all_reviews:
        debug_info['reviews'].append({
            'id': pr.id,
            'rating': pr.rating,
            'comment': pr.comment,
            'created_at': pr.created_at.strftime('%Y-%m-%d %H:%M:%S') if pr.created_at else 'N/A',
            'review_id': r.id,
            'is_approved': r.is_approved,
            'is_published': r.is_published,
            'user_id': r.user_id,
            'order_id': r.order_id
        })
    
    return f"<pre>{json.dumps(debug_info, indent=2)}</pre>"
# Route to view user's reviews
@app.route('/my-reviews')
@login_required
def my_reviews():
    reviews = Review.query.filter_by(user_id=current_user.id)\
        .order_by(Review.created_at.desc()).all()
    return render_template('my_reviews.html', reviews=reviews)

@app.route('/admin/fix-reviews')
@login_required
def fix_reviews():
    if not current_user.is_admin:
        return "Access denied", 403
    
    # Get all reviews and set them to approved/published
    reviews = Review.query.all()
    fixed = 0
    
    for review in reviews:
        if not review.is_approved or not review.is_published:
            review.is_approved = True
            review.is_published = True
            fixed += 1
    
    db.session.commit()
    
    return f"Fixed {fixed} reviews. Total reviews: {len(reviews)}"
# Route to view all reviews for a product (public)
@app.route('/product/<int:product_id>/reviews')
def product_reviews(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Get all approved product reviews
    product_reviews = db.session.query(ProductReview, Review, User)\
        .join(Review, ProductReview.review_id == Review.id)\
        .join(User, Review.user_id == User.id)\
        .filter(ProductReview.product_id == product_id)\
        .filter(Review.is_approved == True)\
        .filter(Review.is_published == True)\
        .order_by(ProductReview.created_at.desc())\
        .all()
    
    # Calculate average rating
    if product_reviews:
        avg_rating = sum(pr.rating for pr, r, u in product_reviews) / len(product_reviews)
    else:
        avg_rating = 0
    
    return render_template('product_reviews.html', 
                         product=product, 
                         product_reviews=product_reviews,
                         avg_rating=avg_rating)


# Admin route to manage reviews
@app.route('/admin/reviews')
@login_required
def admin_reviews():
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    page = request.args.get('page', 1, type=int)
    filter_type = request.args.get('filter', 'all')
    
    query = Review.query
    
    if filter_type == 'pending':
        query = query.filter_by(is_approved=False)
    elif filter_type == 'approved':
        query = query.filter_by(is_approved=True)
    elif filter_type == 'high_rated':
        query = query.filter(Review.overall_rating >= 4)
    elif filter_type == 'low_rated':
        query = query.filter(Review.overall_rating <= 2)
    
    reviews = query.order_by(Review.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    stats = {
        'total_reviews': Review.query.count(),
        'pending_reviews': Review.query.filter_by(is_approved=False).count(),
        'approved_reviews': Review.query.filter_by(is_approved=True).count(),
        'avg_overall_rating': db.session.query(db.func.avg(Review.overall_rating)).scalar() or 0,
        'five_star_reviews': Review.query.filter_by(overall_rating=5).count(),
        'one_star_reviews': Review.query.filter_by(overall_rating=1).count()
    }
    
    return render_template('admin_reviews.html', reviews=reviews, stats=stats, filter_type=filter_type)


# Admin route to approve/reject review
@app.route('/admin/reviews/<int:review_id>/toggle-approval', methods=['POST'])
@login_required
def toggle_review_approval(review_id):
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    review = Review.query.get_or_404(review_id)
    review.is_approved = not review.is_approved
    
    admin_note = request.form.get('admin_note')
    if admin_note:
        review.admin_notes = admin_note
    
    db.session.commit()
    
    status = 'approuvé' if review.is_approved else 'rejeté'
    return redirect_with_toast('admin_reviews', f'Avis #{review_id} {status} avec succès', 'success')


# Admin route to delete review
@app.route('/admin/reviews/<int:review_id>/delete', methods=['POST'])
@login_required
def delete_review(review_id):
    if not current_user.is_admin:
        return redirect_with_toast('home', 'Accès refusé', 'error')
    
    review = Review.query.get_or_404(review_id)
    db.session.delete(review)
    db.session.commit()
    
    return redirect_with_toast('admin_reviews', f'Avis #{review_id} supprimé avec succès', 'success')

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
    # Pre-fill form with user data if logged in
    if current_user.is_authenticated and request.method == 'GET':
        form = ContactForm(
            name=current_user.username,
            email=current_user.email
        )
    else:
        form = ContactForm()
    
    if form.validate_on_submit():
        contact_message = Contact(
            name=form.name.data,
            email=form.email.data,
            message=form.message.data
        )
        db.session.add(contact_message)
        db.session.commit()
        
        return redirect_with_toast('contact', 
                                  'Merci pour votre message ! Nous vous répondrons dans les plus brefs délais.', 
                                  'success')
    
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

@app.route('/admin/test-openai')
@login_required
def test_openai():
    if not current_user.is_admin:
        return "Access denied"
    
    import socket
    
    result = {
        'openai_client_exists': openai_client is not None,
        'api_key_set': bool(os.getenv('OPENAI_API_KEY')),
        'api_key_preview': os.getenv('OPENAI_API_KEY', '')[:20] + '...',
        'network_test': 'Testing...'
    }
    
    # Test network connectivity
    try:
        socket.create_connection(('api.openai.com', 443), timeout=5)
        result['network_test'] = 'SUCCESS: Can reach api.openai.com'
    except Exception as e:
        result['network_test'] = f'FAILED: {e}'
    
    # Test OpenAI API
    if openai_client:
        try:
            response = openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "Say OK"}],
                max_tokens=5,
                timeout=30
            )
            result['api_test'] = 'SUCCESS: ' + response.choices[0].message.content
        except Exception as e:
            result['api_test'] = f'ERROR: {type(e).__name__}: {str(e)}'
    
    return f"<pre>{result}</pre>"

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
            db.session.rollback()
        
        # Create default admin user if doesn't exist
        try:
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    email='admin@example.com',
                    phone='+1234567890',
                    address='Admin Office, 456 Admin Street, Admin City, AC 67890',
                    ville='Admin City',
                    code_postal='67890',
                    password_hash=generate_password_hash('admin123'),
                    is_admin=True
                )
                db.session.add(admin)
                db.session.flush()
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
                db.session.flush()
                print("Sample products added")
        except Exception as e:
            print(f"Error creating sample products: {e}")
        
        # Add sample contact messages
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
        
        # Create comprehensive sample reviews
        try:
            all_products = Product.query.all()
            
            # Define reviewers with their review data
            reviewers_data = [
                {
                    'username': 'testuser',
                    'email': 'test@example.com',
                    'phone': '+212612345678',
                    'address': '123 Test Street',
                    'ville': 'Casablanca',
                    'code_postal': '20000',
                    'products': [0, 1, 2],  # Laptop, iPhone, AirPods
                    'ratings': [5, 4, 5],
                    'comments': [
                        'Laptop incroyable ! Très rapide et parfait pour le travail.',
                        'iPhone magnifique, la qualité photo est exceptionnelle.',
                        'AirPods confortables avec une excellente qualité sonore.'
                    ],
                    'overall': 5,
                    'delivery': 5,
                    'service': 4,
                    'general': 'Excellente expérience ! Les produits sont arrivés rapidement et en parfait état. Je recommande vivement cette boutique.',
                    'recommend': 'yes',
                    'anonymous': False
                },
                {
                    'username': 'reviewer2',
                    'email': 'reviewer2@example.com',
                    'phone': '+212612345679',
                    'address': '456 Review Street',
                    'ville': 'Rabat',
                    'code_postal': '10000',
                    'products': [3, 4],  # T-Shirt, Jeans
                    'ratings': [3, 3],
                    'comments': [
                        'Qualité acceptable pour le prix.',
                        'Taille un peu grande, attention au guide des tailles.'
                    ],
                    'overall': 3,
                    'delivery': 2,
                    'service': 3,
                    'general': 'Produits corrects mais la livraison a pris plus de temps que prévu.',
                    'recommend': 'maybe',
                    'anonymous': True
                },
                {
                    'username': 'sarah_m',
                    'email': 'sarah.m@example.com',
                    'phone': '+212612345680',
                    'address': '789 Street',
                    'ville': 'Marrakech',
                    'code_postal': '40000',
                    'products': [0, 1],  # Laptop, iPhone
                    'ratings': [5, 5],
                    'comments': [
                        'Produit excellent ! Livraison rapide et emballage soigné.',
                        'Très satisfaite de mon achat, fonctionne parfaitement.'
                    ],
                    'overall': 5,
                    'delivery': 5,
                    'service': 5,
                    'general': 'Service impeccable du début à la fin. Je recommande à 100%!',
                    'recommend': 'yes',
                    'anonymous': False
                },
                {
                    'username': 'karim_b',
                    'email': 'karim.b@example.com',
                    'phone': '+212612345681',
                    'address': '321 Avenue',
                    'ville': 'Fès',
                    'code_postal': '30000',
                    'products': [2],  # AirPods
                    'ratings': [4],
                    'comments': ['Bon produit mais le prix est un peu élevé.'],
                    'overall': 4,
                    'delivery': 4,
                    'service': 4,
                    'general': 'Bon achat dans l\'ensemble. Qualité au rendez-vous.',
                    'recommend': 'yes',
                    'anonymous': False
                },
                {
                    'username': 'nadia_k',
                    'email': 'nadia.k@example.com',
                    'phone': '+212612345682',
                    'address': '654 Rue',
                    'ville': 'Tanger',
                    'code_postal': '90000',
                    'products': [3, 4],  # T-Shirt, Jeans
                    'ratings': [5, 4],
                    'comments': [
                        'Excellent rapport qualité-prix, très confortable.',
                        'Bonne qualité mais la taille est légèrement grande.'
                    ],
                    'overall': 4,
                    'delivery': 5,
                    'service': 4,
                    'general': 'Très contente de mes achats. Livraison rapide!',
                    'recommend': 'yes',
                    'anonymous': False
                },
                {
                    'username': 'omar_h',
                    'email': 'omar.h@example.com',
                    'phone': '+212612345683',
                    'address': '987 Boulevard',
                    'ville': 'Agadir',
                    'code_postal': '80000',
                    'products': [5, 6],  # Nike Air Max, Montre
                    'ratings': [3, 4],
                    'comments': [
                        'Chaussures correctes mais pas très confortables pour la course.',
                        'Belle montre, fonctionne bien.'
                    ],
                    'overall': 3,
                    'delivery': 3,
                    'service': 4,
                    'general': 'Produits acceptables. Service client réactif.',
                    'recommend': 'maybe',
                    'anonymous': False
                },
                {
                    'username': 'fatima_z',
                    'email': 'fatima.z@example.com',
                    'phone': '+212612345684',
                    'address': '159 Place',
                    'ville': 'Oujda',
                    'code_postal': '60000',
                    'products': [7],  # Sac à Dos
                    'ratings': [5],
                    'comments': ['Sac très résistant et pratique, je recommande !'],
                    'overall': 5,
                    'delivery': 5,
                    'service': 5,
                    'general': 'Excellent produit et service. Totalement satisfaite!',
                    'recommend': 'yes',
                    'anonymous': False
                }
            ]
            
            for reviewer_data in reviewers_data:
                # Check if user exists
                reviewer = User.query.filter_by(username=reviewer_data['username']).first()
                if not reviewer:
                    reviewer = User(
                        username=reviewer_data['username'],
                        email=reviewer_data['email'],
                        phone=reviewer_data['phone'],
                        address=reviewer_data['address'],
                        ville=reviewer_data['ville'],
                        code_postal=reviewer_data['code_postal'],
                        password_hash=generate_password_hash('test123')
                    )
                    db.session.add(reviewer)
                    db.session.flush()
                    
                    # Create order
                    selected_products = [all_products[i] for i in reviewer_data['products']]
                    order_total = sum(p.price * (i + 1) for i, p in enumerate(selected_products))
                    
                    new_order = Order(
                        user_id=reviewer.id,
                        total=order_total,
                        status='completed'
                    )
                    db.session.add(new_order)
                    db.session.flush()
                    
                    # Add order items
                    for i, product in enumerate(selected_products):
                        order_item = OrderItem(
                            order_id=new_order.id,
                            product_id=product.id,
                            quantity=i + 1,
                            price=product.price
                        )
                        db.session.add(order_item)
                    
                    # Add order details
                    order_details = OrderDetails(
                        order_id=new_order.id,
                        customer_name=reviewer_data['username'],
                        customer_email=reviewer_data['email'],
                        customer_phone=reviewer_data['phone'],
                        shipping_address=reviewer_data['address'],
                        shipping_city=reviewer_data['ville'],
                        shipping_postal=reviewer_data['code_postal'],
                        payment_method='card',
                        delivery_method='home_delivery',
                        shipping_cost=0
                    )
                    db.session.add(order_details)
                    db.session.flush()
                    
                    # Create review
                    new_review = Review(
                        order_id=new_order.id,
                        user_id=reviewer.id,
                        overall_rating=reviewer_data['overall'],
                        delivery_rating=reviewer_data['delivery'],
                        customer_service_rating=reviewer_data['service'],
                        general_comment=reviewer_data['general'],
                        recommend=reviewer_data['recommend'],
                        is_anonymous=reviewer_data['anonymous'],
                        is_verified_purchase=True,
                        is_approved=True,
                        is_published=True
                    )
                    db.session.add(new_review)
                    db.session.flush()
                    
                    # Add product reviews
                    for i, product_index in enumerate(reviewer_data['products']):
                        product = all_products[product_index]
                        product_review = ProductReview(
                            review_id=new_review.id,
                            product_id=product.id,
                            rating=reviewer_data['ratings'][i],
                            comment=reviewer_data['comments'][i]
                        )
                        db.session.add(product_review)
                    
                    print(f"Created review for user {reviewer_data['username']}")
            
        except Exception as e:
            print(f"Error creating sample reviews: {e}")
            db.session.rollback()
        
        # Commit all changes
        try:
            db.session.commit()
            print("\n=== Database initialization completed successfully ===")
            print(f"Users: {User.query.count()}")
            print(f"Products: {Product.query.count()}")
            print(f"Orders: {Order.query.count()}")
            print(f"Reviews: {Review.query.count()}")
            print(f"Product Reviews: {ProductReview.query.count()}")
            print(f"Contacts: {Contact.query.count()}")
            print("\nLogin credentials:")
            print("Admin: admin / admin123")
            print("Test User: testuser / test123")
            print("All reviewers: password is 'test123'")
        except Exception as e:
            print(f"Error committing to database: {e}")
            db.session.rollback()
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)