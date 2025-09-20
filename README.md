# E-Commerce Flask Application

A complete e-commerce web application built with Flask, featuring user authentication, product management, shopping cart, and admin panel.

## Features

### 🏠 **Pages**

- **Home Page**: Featured products showcase with hero section
- **Products Page**: Browse all products with category filtering and pagination
- **Product Details**: Individual product pages with detailed information
- **About Page**: Company information, team, and values
- **Contact Page**: Contact form with FAQ section
- **Dashboard**: User account management and order history
- **Shopping Cart**: Cart management and checkout process

### 🔐 **Authentication System**

- User registration and login
- Password hashing with Werkzeug
- Session management with Flask-Login
- Protected routes and user roles
- Admin panel access control

### 🛒 **E-Commerce Features**

- Product catalog with categories
- Shopping cart functionality
- Order management system
- Stock tracking
- Admin product management

### 🎨 **Modern UI/UX**

- Responsive Bootstrap 5 design
- Font Awesome icons
- Custom CSS animations
- Mobile-friendly interface
- Dark mode toggle (bonus feature)

## Installation

1. **Clone or download the project files**

2. **Install Python dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**

   ```bash
   python app.py
   ```

4. **Open your browser and visit:**
   ```
   http://localhost:5000
   ```

## Default Accounts

### Admin Account

- **Username:** `admin`
- **Password:** `admin123`
- **Access:** Full admin panel with product management

### Regular User

- Register a new account through the registration page

## Project Structure

```
flask/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── templates/            # HTML templates
│   ├── base.html         # Base template
│   ├── home.html         # Home page
│   ├── products.html     # Products listing
│   ├── product_detail.html # Product details
│   ├── about.html        # About page
│   ├── contact.html      # Contact page
│   ├── login.html        # Login page
│   ├── register.html     # Registration page
│   ├── dashboard.html    # User dashboard
│   ├── cart.html         # Shopping cart
│   └── admin_products.html # Admin panel
└── static/               # Static files
    ├── css/
    │   └── style.css     # Custom styles
    └── js/
        └── main.js       # JavaScript functionality
```

## Database Models

- **User**: User accounts with authentication
- **Product**: Product catalog with categories and stock
- **Order**: Customer orders
- **OrderItem**: Individual items within orders

## Key Features Explained

### Authentication

- Secure password hashing
- Session management
- Role-based access (admin vs regular users)
- Protected routes

### Shopping Cart

- Session-based cart storage
- Add/remove products
- Quantity management
- Checkout process

### Admin Panel

- Add new products
- Manage existing products
- View all products in table format
- Product CRUD operations

### Responsive Design

- Mobile-first approach
- Bootstrap 5 components
- Custom CSS animations
- Modern UI elements

## Customization

### Adding New Features

1. **New Pages**: Create new templates in `templates/` and add routes in `app.py`
2. **New Models**: Add database models in `app.py` and run the app to create tables
3. **Styling**: Modify `static/css/style.css` for custom styling
4. **JavaScript**: Add functionality in `static/js/main.js`

### Database

- Uses SQLite by default (file: `ecommerce.db`)
- To use PostgreSQL/MySQL, change the database URI in `app.py`
- Database tables are created automatically on first run

## Sample Data

The application includes sample products in various categories:

- Electronics (Laptop, Smartphone, Headphones)
- Clothing (T-Shirt, Jeans)
- Shoes (Sneakers)
- Accessories (Watch, Backpack)

## Security Features

- Password hashing with Werkzeug
- CSRF protection with Flask-WTF
- Input validation and sanitization
- Secure session management

## Browser Compatibility

- Chrome (recommended)
- Firefox
- Safari
- Edge
- Mobile browsers

## Troubleshooting

### Common Issues

1. **Port already in use:**

   - Change the port in `app.py`: `app.run(debug=True, port=5001)`

2. **Database errors:**

   - Delete `ecommerce.db` file and restart the application

3. **Static files not loading:**

   - Ensure the `static/` folder structure is correct
   - Check file permissions

4. **Template errors:**
   - Verify all template files are in the `templates/` folder
   - Check for syntax errors in HTML

## Development

### Running in Development Mode

```bash
export FLASK_ENV=development
python app.py
```

### Debugging

- Set `debug=True` in `app.run()` for development
- Check console output for error messages
- Use browser developer tools for frontend debugging

## Production Deployment

For production deployment, consider:

- Using a production WSGI server (Gunicorn)
- Setting up a proper database (PostgreSQL)
- Configuring environment variables for secrets
- Setting up SSL/HTTPS
- Using a reverse proxy (Nginx)

## License

This project is open source and available under the MIT License.

## Support

For questions or issues:

1. Check the troubleshooting section
2. Review the code comments
3. Check Flask documentation for specific features

---

**Happy Shopping! 🛒**
# FLASK
# FLASK
# FLASK
# FLASK
