from main import app, db, User, Product, ShippingSettings, Order, OrderItem, OrderDetails, Review, ProductReview
from werkzeug.security import generate_password_hash

with app.app_context():
    
    db.create_all()
    print("✓ Database tables created")
    
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
            db.session.commit()
            print("✓ Default admin user created")
    except Exception as e:
        print(f"⚠ Error creating admin user: {e}")
        db.session.rollback()
    
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
            db.session.commit()
            print("✓ Default shipping settings created")
    except Exception as e:
        print(f"⚠ Error creating shipping settings: {e}")
        db.session.rollback()
    
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
            db.session.commit()
            print("✓ Sample products added")
    except Exception as e:
        print(f"⚠ Error creating sample products: {e}")
        db.session.rollback()
    
    print("\n=== Database initialization completed ===")
    print(f"Users: {User.query.count()}")
    print(f"Products: {Product.query.count()}")
    print("\nLogin: admin / admin123")