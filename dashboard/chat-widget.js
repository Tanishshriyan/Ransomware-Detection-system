class RansomGuardChat {
    constructor() {
        this.isOpen = false;
        this.messages = [];
        this.init();
    }

    init() {
        this.createChatWidget();
        this.attachEventListeners();
    }

    createChatWidget() {
        const chatHTML = `
            <div id="chat-widget" class="chat-widget">
                <!-- Chat Toggle Button -->
                <button id="chat-toggle" class="chat-toggle">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" 
                              stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    <span class="chat-badge" id="chat-badge" style="display: none;">1</span>
                </button>

                <!-- Chat Window -->
                <div id="chat-window" class="chat-window" style="display: none;">
                    <div class="chat-header">
                        <div class="chat-header-info">
                            <h3>🛡️ RansomGuard AI</h3>
                            <span class="chat-status">● Online</span>
                        </div>
                        <button id="chat-close" class="chat-close-btn">×</button>
                    </div>

                    <div id="chat-messages" class="chat-messages">
                        <div class="chat-message assistant">
                            <div class="message-content">
                                👋 Hi! I'm your RansomGuard AI assistant. Ask me about:
                                <ul>
                                    <li>Current threats and detections</li>
                                    <li>ML score explanations</li>
                                    <li>Ransomware behavior analysis</li>
                                    <li>Remediation guidance</li>
                                </ul>
                            </div>
                            <div class="message-time">${new Date().toLocaleTimeString()}</div>
                        </div>
                    </div>

                    <div class="chat-input-container">
                        <input 
                            type="text" 
                            id="chat-input" 
                            class="chat-input" 
                            placeholder="Ask about threats, ML scores, or ransomware..."
                            autocomplete="off"
                        />
                        <button id="chat-send" class="chat-send-btn">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                                <path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z" 
                                      stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </button>
                    </div>

                    <div class="quick-actions">
                        <button class="quick-btn" data-query="Show me current threats">Current Threats</button>
                        <button class="quick-btn" data-query="Explain ML detection scores">ML Scores</button>
                        <button class="quick-btn" data-query="What are common ransomware behaviors?">Ransomware Info</button>
                    </div>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', chatHTML);
    }

    attachEventListeners() {
        const toggle = document.getElementById('chat-toggle');
        const close = document.getElementById('chat-close');
        const send = document.getElementById('chat-send');
        const input = document.getElementById('chat-input');
        const quickBtns = document.querySelectorAll('.quick-btn');

        toggle.addEventListener('click', () => this.toggleChat());
        close.addEventListener('click', () => this.toggleChat());
        send.addEventListener('click', () => this.sendMessage());
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.sendMessage();
        });

        quickBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const query = btn.getAttribute('data-query');
                input.value = query;
                this.sendMessage();
            });
        });
    }

    toggleChat() {
        this.isOpen = !this.isOpen;
        const window = document.getElementById('chat-window');
        const badge = document.getElementById('chat-badge');
        
        window.style.display = this.isOpen ? 'flex' : 'none';
        if (this.isOpen) badge.style.display = 'none';
    }

    async sendMessage() {
        const input = document.getElementById('chat-input');
        const message = input.value.trim();
        
        if (!message) return;

        // Add user message to UI
        this.addMessage(message, 'user');
        input.value = '';

        // Show typing indicator
        this.showTypingIndicator();

        try {
            // Send to backend
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message })
            });

            const data = await response.json();

            // Remove typing indicator
            this.removeTypingIndicator();

            if (data.success) {
                const suffix = data.fallback ? '\n\n[Running in local fallback mode]' : '';
                this.addMessage(`${data.response}${suffix}`, 'assistant');
            } else {
                this.addMessage('Sorry, I encountered an error. Please try again.', 'assistant');
            }

        } catch (error) {
            this.removeTypingIndicator();
            this.addMessage('Connection error. Please check your backend.', 'assistant');
        }
    }

    addMessage(content, role) {
        const container = document.getElementById('chat-messages');
        const messageDiv = document.createElement('div');
        messageDiv.className = `chat-message ${role}`;
        
        messageDiv.innerHTML = `
            <div class="message-content">${this.formatMessage(content)}</div>
            <div class="message-time">${new Date().toLocaleTimeString()}</div>
        `;

        container.appendChild(messageDiv);
        container.scrollTop = container.scrollHeight;
    }

    formatMessage(content) {
        // Basic markdown-like formatting
        return this.escapeHtml(content)
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\n/g, '<br>');
    }

    escapeHtml(content) {
        const div = document.createElement('div');
        div.textContent = content;
        return div.innerHTML;
    }

    showTypingIndicator() {
        const container = document.getElementById('chat-messages');
        const indicator = document.createElement('div');
        indicator.id = 'typing-indicator';
        indicator.className = 'chat-message assistant typing';
        indicator.innerHTML = `
            <div class="message-content">
                <div class="typing-dots">
                    <span></span><span></span><span></span>
                </div>
            </div>
        `;
        container.appendChild(indicator);
        container.scrollTop = container.scrollHeight;
    }

    removeTypingIndicator() {
        const indicator = document.getElementById('typing-indicator');
        if (indicator) indicator.remove();
    }
}

// Initialize chat when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.ransomGuardChat = new RansomGuardChat();
});
