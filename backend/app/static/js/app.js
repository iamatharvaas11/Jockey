const API_BASE_URL = '/api/v1';

window.appState = {
  token: localStorage.getItem('jocky_token'),
  user: JSON.parse(localStorage.getItem('jocky_user') || 'null'),
  
  init() {
    // Check auth on protected pages
    const path = window.location.pathname;
    const publicPages = ['/login', '/register'];
    
    if (!this.token && !publicPages.includes(path)) {
      window.location.href = '/login';
    } else if (this.token && publicPages.includes(path)) {
      window.location.href = '/dashboard';
    }
  },

  logout() {
    localStorage.removeItem('jocky_token');
    localStorage.removeItem('jocky_user');
    window.location.href = '/login';
  }
};

window.apiClient = {
  getHeaders() {
    const headers = { 'Content-Type': 'application/json' };
    const token = localStorage.getItem('jocky_token');
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
  },
  
  async handleResponse(response) {
    if (response.status === 401) {
      window.appState.logout();
      return null;
    }
    
    const data = await response.json().catch(() => ({}));
    
    if (!response.ok) {
      throw new Error(data.detail || data.message || 'API request failed');
    }
    
    return data;
  },

  async get(endpoint) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'GET',
      headers: this.getHeaders()
    });
    return this.handleResponse(response);
  },

  async post(endpoint, data) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(data)
    });
    return this.handleResponse(response);
  },
  
  async put(endpoint, data) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'PUT',
      headers: this.getHeaders(),
      body: JSON.stringify(data)
    });
    return this.handleResponse(response);
  },

  async delete(endpoint) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'DELETE',
      headers: this.getHeaders()
    });
    return this.handleResponse(response);
  },
  
  async upload(endpoint, formData) {
    const headers = { ...this.getHeaders() };
    delete headers['Content-Type']; // Let browser set multipart with boundary
    
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: headers,
      body: formData
    });
    return this.handleResponse(response);
  }
};

window.utils = {
  formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    const date = new Date(dateStr);
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  },
  
  formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
  },
  
  async copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      window.dispatchEvent(new CustomEvent('toast', { 
        detail: { message: 'Copied to clipboard!', type: 'success' }
      }));
    } catch (err) {
      window.dispatchEvent(new CustomEvent('toast', { 
        detail: { message: 'Failed to copy text', type: 'error' }
      }));
    }
  },
  
  logout() {
    localStorage.removeItem('jocky_token');
    localStorage.removeItem('jocky_user');
    window.location.href = '/login';
  },

  getSeverityBadge(severity) {
    const classes = {
      'LOW': 'badge-blue',
      'MEDIUM': 'badge-yellow',
      'HIGH': 'badge-orange',
      'CRITICAL': 'badge-red'
    };
    return classes[severity?.toUpperCase()] || 'badge-gray';
  },

  getStatusBadge(status) {
    const classes = {
      'OPEN': 'badge-blue',
      'ACTIVE': 'badge-green',
      'CONTAINED': 'badge-yellow',
      'CLOSED': 'badge-gray'
    };
    return classes[status?.toUpperCase()] || 'badge-gray';
  }
};

// Initialize auth check
document.addEventListener('DOMContentLoaded', () => {
  window.appState.init();
});
