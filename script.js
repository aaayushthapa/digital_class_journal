// Main application JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Notification bell click event
    const notificationBell = document.querySelector('.notifications');
    if (notificationBell) {
        notificationBell.addEventListener('click', function() {
            alert('Notifications panel would open here.');
        });
    }
    
    // Search functionality
    const searchInput = document.querySelector('.search-bar input');
    const searchButton = document.querySelector('.search-bar button');
    
    if (searchInput && searchButton) {
        searchButton.addEventListener('click', function() {
            performSearch(searchInput.value);
        });
        
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                performSearch(searchInput.value);
            }
        });
    }
    
    // Active menu item highlighting
    const currentPath = window.location.pathname;
    const menuItems = document.querySelectorAll('.nav-menu li a');
    
    menuItems.forEach(item => {
        if (item.getAttribute('href') === currentPath) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });
});

function performSearch(query) {
    if (query.trim() !== '') {
        alert(`Searching for: ${query}`);
        // In a real application, this would trigger an AJAX search or page navigation
    }
}

// Function to show a toast notification
function showToast(message, type = 'success') {
    const toastContainer = document.createElement('div');
    toastContainer.className = `toast show align-items-center text-white bg-${type} border-0`;
    toastContainer.setAttribute('role', 'alert');
    toastContainer.setAttribute('aria-live', 'assertive');
    toastContainer.setAttribute('aria-atomic', 'true');
    
    toastContainer.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    const toastWrapper = document.getElementById('toastWrapper') || createToastWrapper();
    toastWrapper.appendChild(toastContainer);
    
    // Auto-remove toast after 5 seconds
    setTimeout(() => {
        toastContainer.classList.remove('show');
        setTimeout(() => toastContainer.remove(), 300);
    }, 5000);
}

function createToastWrapper() {
    const wrapper = document.createElement('div');
    wrapper.id = 'toastWrapper';
    wrapper.style.position = 'fixed';
    wrapper.style.top = '20px';
    wrapper.style.right = '20px';
    wrapper.style.zIndex = '1100';
    document.body.appendChild(wrapper);
    return wrapper;
}