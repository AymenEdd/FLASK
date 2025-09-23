// Main JavaScript for E-Commerce Store

document.addEventListener("DOMContentLoaded", function () {
  // Initialize tooltips
  var tooltipTriggerList = [].slice.call(
    document.querySelectorAll('[data-bs-toggle="tooltip"]')
  );
  var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl);
  });

  // Initialize popovers
  var popoverTriggerList = [].slice.call(
    document.querySelectorAll('[data-bs-toggle="popover"]')
  );
  var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
    return new bootstrap.Popover(popoverTriggerEl);
  });

  // Add fade-in animation to cards
  const cards = document.querySelectorAll(".card");
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add("fade-in");
      }
    });
  });

  cards.forEach((card) => {
    observer.observe(card);
  });

  // Smooth scrolling for anchor links
  document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener("click", function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute("href"));
      if (target) {
        target.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      }
    });
  });

  // Add loading state to forms
  const forms = document.querySelectorAll("form");
  forms.forEach((form) => {
    form.addEventListener("submit", function () {
      const submitBtn = this.querySelector(
        'button[type="submit"], input[type="submit"]'
      );
      if (submitBtn) {
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<span class="spinner"></span> Processing...';
        submitBtn.disabled = true;

        // Re-enable after 3 seconds (in case of errors)
        setTimeout(() => {
          submitBtn.innerHTML = originalText;
          submitBtn.disabled = false;
        }, 3000);
      }
    });
  });

  // Cart functionality
  const addToCartButtons = document.querySelectorAll(".add-to-cart");
  addToCartButtons.forEach((button) => {
    button.addEventListener("click", function (e) {
      e.preventDefault();
      const productId = this.dataset.productId;
      const productName = this.dataset.productName;

      // Show success message
      showNotification(`${productName} added to cart!`, "success");

      // Update cart count in navbar
      updateCartCount();
    });
  });

  // Search functionality
  const searchInput = document.getElementById("searchInput");
  if (searchInput) {
    searchInput.addEventListener("input", function () {
      const searchTerm = this.value.toLowerCase();
      const products = document.querySelectorAll(".product-card");

      products.forEach((product) => {
        const productName = product
          .querySelector(".card-title")
          .textContent.toLowerCase();
        const productDescription = product
          .querySelector(".card-text")
          .textContent.toLowerCase();

        if (
          productName.includes(searchTerm) ||
          productDescription.includes(searchTerm)
        ) {
          product.style.display = "block";
        } else {
          product.style.display = "none";
        }
      });
    });
  }

  // Quantity selector for cart
  const quantityInputs = document.querySelectorAll(".quantity-input");
  quantityInputs.forEach((input) => {
    input.addEventListener("change", function () {
      const productId = this.dataset.productId;
      const newQuantity = parseInt(this.value);

      if (newQuantity < 1) {
        this.value = 1;
        return;
      }

      // Update cart via AJAX (would be implemented in a real app)
      updateCartQuantity(productId, newQuantity);
    });
  });

  // Image lazy loading
  const images = document.querySelectorAll("img[data-src]");
  const imageObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        const img = entry.target;
        img.src = img.dataset.src;
        img.classList.remove("lazy");
        imageObserver.unobserve(img);
      }
    });
  });

  images.forEach((img) => {
    imageObserver.observe(img);
  });

  // Auto-hide alerts after 5 seconds
  const alerts = document.querySelectorAll(".alert");
  alerts.forEach((alert) => {
    setTimeout(() => {
      const bsAlert = new bootstrap.Alert(alert);
      bsAlert.close();
    }, 5000);
  });
});

// Utility functions
function showNotification(message, type = "info") {
  const notification = document.createElement("div");
  notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
  notification.style.cssText = `
        top: 20px;
        right: 20px;
        z-index: 1050;
        min-width: 300px;
    `;

  notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;

  document.body.appendChild(notification);

  // Auto-remove after 3 seconds
  setTimeout(() => {
    if (notification.parentNode) {
      notification.remove();
    }
  }, 3000);
}

function updateCartCount() {
  // This would typically make an AJAX call to get the current cart count
  const cartBadge = document.querySelector(".navbar .badge");
  if (cartBadge) {
    const currentCount = parseInt(cartBadge.textContent) || 0;
    cartBadge.textContent = currentCount + 1;
  }
}

function updateCartQuantity(productId, quantity) {
  // This would make an AJAX call to update the cart
  console.log(`Updating product ${productId} quantity to ${quantity}`);
}

// Product image zoom functionality
function initImageZoom() {
  const productImages = document.querySelectorAll(".product-image");
  productImages.forEach((img) => {
    img.addEventListener("click", function () {
      const modal = document.createElement("div");
      modal.className = "modal fade";
      modal.innerHTML = `
                <div class="modal-dialog modal-lg modal-dialog-centered">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Product Image</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body text-center">
                            <img src="${this.src}" class="img-fluid" alt="Product Image">
                        </div>
                    </div>
                </div>
            `;

      document.body.appendChild(modal);
      const bsModal = new bootstrap.Modal(modal);
      bsModal.show();

      modal.addEventListener("hidden.bs.modal", function () {
        modal.remove();
      });
    });
  });
}

// Initialize image zoom when DOM is loaded
document.addEventListener("DOMContentLoaded", initImageZoom);

// Form validation enhancement
function enhanceFormValidation() {
  const forms = document.querySelectorAll("form");
  forms.forEach((form) => {
    const inputs = form.querySelectorAll("input, textarea, select");
    inputs.forEach((input) => {
      input.addEventListener("blur", function () {
        validateField(this);
      });

      input.addEventListener("input", function () {
        if (this.classList.contains("is-invalid")) {
          validateField(this);
        }
      });
    });
  });
}

function validateField(field) {
  const value = field.value.trim();
  const type = field.type;
  const required = field.hasAttribute("required");

  // Remove existing validation classes
  field.classList.remove("is-valid", "is-invalid");

  // Check if field is required and empty
  if (required && !value) {
    field.classList.add("is-invalid");
    return false;
  }

  // Email validation
  if (type === "email" && value) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(value)) {
      field.classList.add("is-invalid");
      return false;
    }
  }

  // Password validation
  if (type === "password" && value) {
    if (value.length < 6) {
      field.classList.add("is-invalid");
      return false;
    }
  }

  // If we get here, field is valid
  if (value) {
    field.classList.add("is-valid");
  }

  return true;
}
// Ultra responsive navbar scroll effect
let lastScrollTop = 0;
const navbar = document.querySelector('.navbar');
let ticking = false;

function updateNavbar() {
  const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
  
  // Add/remove scrolled class based on scroll position
  if (scrollTop > 20) {
    navbar.classList.add('scrolled');
  } else {
    navbar.classList.remove('scrolled');
  }
  
  lastScrollTop = scrollTop <= 0 ? 0 : scrollTop;
  ticking = false;
}

function requestTick() {
  if (!ticking) {
    requestAnimationFrame(updateNavbar);
    ticking = true;
  }
}

// Optimized scroll listener
window.addEventListener('scroll', requestTick, { passive: true });

// Initial check
document.addEventListener('DOMContentLoaded', function() {
  if (window.pageYOffset > 20) {
    navbar.classList.add('scrolled');
  }
});
// Initialize form validation
document.addEventListener("DOMContentLoaded", enhanceFormValidation);

// Dark mode toggle (bonus feature)


// Initialize dark mode
document.addEventListener("DOMContentLoaded", initDarkMode);
