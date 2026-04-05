/* ===================================
   RANSOMGUARD DASHBOARD JAVASCRIPT
   Real-time WebSocket monitoring
   =================================== */

/* ===================================
   CINEMATIC INTRO SEQUENCE
   =================================== */

// Intro animation controller
class IntroSequence {

    constructor() {
        this.overlay = document.getElementById('intro-overlay');
        this.progress = document.getElementById('loading-progress');
        this.status = document.getElementById('system-status');
        this.particles = document.getElementById('particles');
        
        this.statusMessages = [
            'Initializing systems...',
            'Loading detection engine...',
            'Connecting to backend...',
            'Starting real-time monitoring...',
            'System ready!'
        ];
        
        this.currentStep = 0;
    }

    async start() {
        // Generate particles
        this.createParticles();
        
        // Run loading sequence
        await this.runSequence();
        
        // Hide intro
        setTimeout(() => {
            this.overlay.classList.add('hidden');
        }, 500);
    }

    createParticles() {
        for (let i = 0; i < 30; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.left = `${Math.random() * 100}%`;
            particle.style.animationDelay = `${Math.random() * 8}s`;
            particle.style.animationDuration = `${5 + Math.random() * 5}s`;
            this.particles.appendChild(particle);
        }
    }

    async runSequence() {
        for (let i = 0; i < this.statusMessages.length; i++) {
            this.status.textContent = this.statusMessages[i];
            const targetProgress = ((i + 1) / this.statusMessages.length) * 100;
            this.progress.style.width = `${targetProgress}%`;
            await this.sleep(600);
        }
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize intro on page load
document.addEventListener('DOMContentLoaded', () => {
    const intro = new IntroSequence();
    intro.start();
});

/* ===================================
   CUSTOM CURSOR CONTROLLER
   =================================== */

class CustomCursor {
    constructor() {
        this.cursor = document.getElementById('cursor');
        this.follower = document.getElementById('cursor-follower');
        this.cursorX = 0;
        this.cursorY = 0;
        this.followerX = 0;
        this.followerY = 0;
        
        this.init();
    }

    init() {
        // Track mouse movement
        document.addEventListener('mousemove', (e) => {
            this.cursorX = e.clientX;
            this.cursorY = e.clientY;
        });

        // Hide cursor when leaving window
        document.addEventListener('mouseleave', () => {
            this.cursor.classList.add('hidden');
            this.follower.classList.add('hidden');
        });

        // Show cursor when entering window
        document.addEventListener('mouseenter', () => {
            this.cursor.classList.remove('hidden');
            this.follower.classList.remove('hidden');
        });

        // Mouse down effect
        document.addEventListener('mousedown', () => {
            document.body.classList.add('cursor-active');
        });

        // Mouse up effect
        document.addEventListener('mouseup', () => {
            document.body.classList.remove('cursor-active');
        });

        // Add hover effects for interactive elements
        this.addHoverEffects();

        // Start animation loop
        this.animate();
    }

    addHoverEffects() {
        // Select all interactive elements
        const hoverElements = document.querySelectorAll('a, button, .nav-link, .stat-card, .feature-card, input, textarea');
        
        hoverElements.forEach(element => {
            element.addEventListener('mouseenter', () => {
                document.body.classList.add('cursor-hover');
                
                // Special effect for buttons
                if (element.tagName === 'BUTTON' || element.classList.contains('btn')) {
                    document.body.classList.add('cursor-button');
                }
            });

            element.addEventListener('mouseleave', () => {
                document.body.classList.remove('cursor-hover');
                document.body.classList.remove('cursor-button');
            });
        });

        // Text selection effect
        const textElements = document.querySelectorAll('p, h1, h2, h3, h4, h5, h6, span');
        textElements.forEach(element => {
            element.addEventListener('mouseenter', () => {
                document.body.classList.add('cursor-text');
            });
            element.addEventListener('mouseleave', () => {
                document.body.classList.remove('cursor-text');
            });
        });
    }

    animate() {
        // Smooth cursor movement with easing
        const speed = 0.2; // Lower = smoother/slower

        // Update cursor position (instant)
        this.cursor.style.left = this.cursorX + 'px';
        this.cursor.style.top = this.cursorY + 'px';

        // Update follower with delay (creates trailing effect)
        this.followerX += (this.cursorX - this.followerX) * speed;
        this.followerY += (this.cursorY - this.followerY) * speed;

        this.follower.style.left = (this.followerX - 20) + 'px'; // Center the follower
        this.follower.style.top = (this.followerY - 20) + 'px';

        // Continue animation loop
        requestAnimationFrame(() => this.animate());
    }
}

// Initialize custom cursor after intro
document.addEventListener('DOMContentLoaded', () => {
    // Wait for intro to finish before enabling cursor
    setTimeout(() => {
        const customCursor = new CustomCursor();
    }, 3000); // Match intro duration
});


/* ===================================
   SCROLL ANIMATIONS CONTROLLER
   =================================== */

class ScrollAnimations {
    constructor() {
        this.observerOptions = {
            root: null,
            rootMargin: '0px',
            threshold: 0.15
        };
        
        this.init();
    }

    init() {
        // Add scroll-reveal class to elements
        this.setupScrollReveal();
        
        // Create Intersection Observer
        this.observer = new IntersectionObserver(
            this.handleIntersection.bind(this),
            this.observerOptions
        );

        // Observe all elements with scroll-reveal class
        const elements = document.querySelectorAll('.scroll-reveal');
        elements.forEach(element => this.observer.observe(element));

        // Add parallax effect to hero
        this.setupParallax();

        // Add dynamic stat counter
        this.setupStatCounters();
    }

    setupScrollReveal() {
        // Auto-add scroll-reveal class to key elements
        const selectors = [
            '.stat-card',
            '.feature-card',
            '.engine-card',
            '.pipeline-stage',
            '.section-title',
            '.section-subtitle'
        ];

        selectors.forEach(selector => {
            document.querySelectorAll(selector).forEach(element => {
                if (!element.classList.contains('scroll-reveal')) {
                    element.classList.add('scroll-reveal');
                }
            });
        });
    }

    handleIntersection(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('revealed');
                
                // Unobserve after revealing (performance optimization)
                this.observer.unobserve(entry.target);
            }
        });
    }

    setupParallax() {
        const hero = document.querySelector('.hero');
        if (!hero) return;

        window.addEventListener('scroll', () => {
            const scrolled = window.pageYOffset;
            const parallaxSpeed = 0.5;
            
            if (hero && scrolled < hero.offsetHeight) {
                hero.style.transform = `translateY(${scrolled * parallaxSpeed}px)`;
                hero.style.opacity = 1 - (scrolled / hero.offsetHeight) * 0.5;
            }
        });
    }

    setupStatCounters() {
        // Animate numbers when they come into view
        const statValues = document.querySelectorAll('.stat-value');
        
        statValues.forEach(element => {
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        this.animateValue(element);
                        observer.unobserve(entry.target);
                    }
                });
            });
            
            observer.observe(element);
        });
    }

    animateValue(element) {
        const text = element.textContent;
        const hasPercent = text.includes('%');
        const number = parseInt(text.replace(/[^0-9]/g, ''));
        
        if (isNaN(number)) return;

        const duration = 1000;
        const steps = 30;
        const stepValue = number / steps;
        const stepDuration = duration / steps;
        let current = 0;

        const timer = setInterval(() => {
            current += stepValue;
            if (current >= number) {
                current = number;
                clearInterval(timer);
            }
            element.textContent = hasPercent ? `${Math.floor(current)}%` : Math.floor(current);
        }, stepDuration);
    }
}

// Initialize scroll animations after intro
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        const scrollAnimations = new ScrollAnimations();
    }, 3000); // Match intro duration
});



/* ===================================
   DASHBOARD CODE 
   =================================== */


class RansomGuardDashboard {
        setupScrollHeader() {
        const header = document.querySelector('header');
        if (!header) return;

        window.addEventListener('scroll', () => {
            if (window.scrollY > 10) {
                header.classList.add('scrolled');
            } else {
                header.classList.remove('scrolled');
            }
        });
    }
    constructor() {
        this.ws = null;
        this.reconnectInterval = 3000;
        this.maxReconnectAttempts = 10;
        this.reconnectAttempts = 0;
        this.reconnectTimer = null;
        this.heartbeatTimer = null;
        this.heartbeatInterval = 15000;
        this.manualClose = false;
        this.activityBuffer = [];
        this.maxActivityItems = 40;
        this.activityByPid = new Map();
        this.threatHistory = new Map();
        this.promptedAlerts = new Set();
        this.eventKeys = new Set();
        this.eventKeyOrder = [];
        
        this.init();
    }

    init() {
        console.log('ðŸš€ Initializing RansomGuard Dashboard...');
        this.setupScrollHeader(); 
        this.connectWebSocket();
        this.fetchInitialStats();
        this.syncPendingAlerts();
        this.pollDemoStatus();
        this.setupEventListeners();
    }

/* ===================================
   WEBSOCKET CONNECTION & MESSAGE HANDLING
   =================================== */

connectWebSocket() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
        return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    console.log('ðŸ”Œ Connecting to WebSocket:', wsUrl);

    this.manualClose = false;
    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
        console.log('âœ… WebSocket connected successfully');
        this.reconnectAttempts = 0;
        this.clearReconnectTimer();
        this.startHeartbeat();
        this.updateConnectionStatus(true);
        this.fetchInitialStats();
        this.syncPendingAlerts();
        this.updateDemoStatus();
    };

    this.ws.onmessage = (event) => {
        try {
            const message = JSON.parse(event.data);
            console.log('ðŸ“¨ Received:', message);
            this.handleWebSocketMessage(message);
        } catch (error) {
            console.error('âŒ Failed to parse message:', error, event.data);
        }
    };
    
    this.ws.onerror = (error) => {
        console.error('âŒ WebSocket error:', error);
        this.updateConnectionStatus(false);
    };

    this.ws.onclose = () => {
        console.log('ðŸ”Œ WebSocket disconnected');
        this.stopHeartbeat();
        this.updateConnectionStatus(false);
        if (!this.manualClose) {
            this.scheduleReconnect();
        }
    };
}

clearReconnectTimer() {
    if (this.reconnectTimer) {
        clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
    }
}

scheduleReconnect() {
    if (this.reconnectTimer) {
        return;
    }

    const attempt = Math.min(this.reconnectAttempts, this.maxReconnectAttempts);
    const delay = Math.min(this.reconnectInterval * Math.max(1, attempt + 1), 15000);
    this.reconnectAttempts += 1;
    console.log(`ðŸ” Reconnecting WebSocket in ${delay}ms (attempt ${this.reconnectAttempts})`);
    this.reconnectTimer = setTimeout(() => {
        this.reconnectTimer = null;
        this.connectWebSocket();
    }, delay);
}

startHeartbeat() {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            return;
        }

        try {
            this.ws.send(JSON.stringify({ type: 'ping', ts: Date.now() }));
        } catch (error) {
            console.error('Heartbeat send failed:', error);
        }
    }, this.heartbeatInterval);
}

stopHeartbeat() {
    if (this.heartbeatTimer) {
        clearInterval(this.heartbeatTimer);
        this.heartbeatTimer = null;
    }
}

makeEventKey(event) {
    if (!event || typeof event !== 'object') {
        return '';
    }

    return [
        event.event_id || event.alert_id || '',
        event.timestamp || '',
        event.pid || event.process_id || '',
        event.event_type || event.type || '',
        event.file_path || event.path || '',
        event.process_name || event.process || event.name || '',
        event.suspicion_score || event.score || event.threat_score || 0,
    ].join('|');
}

rememberEventKey(key) {
    if (!key) {
        return true;
    }
    if (this.eventKeys.has(key)) {
        return false;
    }

    this.eventKeys.add(key);
    this.eventKeyOrder.push(key);
    while (this.eventKeyOrder.length > 500) {
        const oldest = this.eventKeyOrder.shift();
        if (oldest) {
            this.eventKeys.delete(oldest);
        }
    }
    return true;
}

async syncPendingAlerts() {
    try {
        const response = await fetch('/api/pending_alerts');
        if (!response.ok) {
            return;
        }

        const alerts = await response.json();
        if (!Array.isArray(alerts)) {
            return;
        }

        alerts.forEach(alert => this.handleThreatAlert({ alert_id: alert.alert_id, data: alert }));
    } catch (error) {
        console.debug('Pending alert sync skipped:', error);
    }
}

handleWebSocketMessage(message) {
    const type = message.type;
    console.log('ðŸ”§ Processing message type:', type);
    
    switch(type) {
        case 'bulk':
            // Handle bulk events - THIS IS THE KEY ONE
            console.log('ðŸ“¦ Processing bulk events:', message.data);
            if (message.data && Array.isArray(message.data)) {
                message.data.forEach(event => {
                    this.processEvent(event);
                });
            }
            break;

        case 'stats':
            // Handle stats messages (same as system)
            console.log('ðŸ“Š Updating stats:', message.data);
            this.updateStats(message.data);
            break;

        case 'system':
            // Handle system stats
            console.log(' Updating system stats:', message.data);
            this.updateStats(message.data);
            break; 
            
        case 'activity':
            this.processEvent(message.data);
            break;
        case 'event':
            // Single event
            console.log('ðŸ“ Processing single event:', message.data);
            this.processEvent(message.data);
            break;

        case 'alert':
            this.handleThreatAlert(message.data || {});
            break;

        case 'threat_alert':
            this.handleThreatAlert(message);
            break;

        case 'decision_result':
            this.handleDecisionResult(message);
            break;

        case 'protection_action':
            this.handleProtectionAction(message.data || {});
            break;

        case 'threat_update':
            this.processEvent(message.data);
            break;

        case 'pending_alerts':
            if (Array.isArray(message.data)) {
                message.data.forEach(alert => this.handleThreatAlert({ alert_id: alert.alert_id, data: alert }));
            }
            break;
            
        case 'ping':
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
            }
            break;

        case 'pong':
            break;
            
        default:
            console.warn('âš ï¸ Unknown message type:', type, message);
            break;
    }
}

processEvent(event) {
    if (!event) return;

    const eventKey = this.makeEventKey(event);
    if (!this.rememberEventKey(eventKey)) {
        return;
    }
    
    console.log('âš™ï¸ Processing event:', event);
    
    // Extract normalized event fields from supported payload shapes
    const processName = event.process_name || event.process || event.name || 'Unknown Process';
    const eventType = event.status || event.event_type || event.type || 'unknown';
    const score = parseInt(event.suspicion_score || event.score || event.threat_score || 0);
    const timestamp = event.timestamp || new Date().toISOString();
    const pid = event.pid || event.process_id || 'N/A';
    const filePath = event.file_path || event.last_file_path || event.path || event.status || 'N/A';
    
    // Add to activity feed
    this.addToActivityFeed(processName, eventType, score, timestamp, pid, filePath);

    if (event.pid !== undefined && event.status) {
        this.upsertThreatHistoryEntry(event);
    }
}

addToActivityFeed(processName, eventType, score, timestamp, pid, path = 'N/A') {
    // Determine severity
    let severity = 'low';
    let icon = '\u{1F6E1}';
    let color = '#10b981';
    
    if (score >= 85) {
        severity = 'critical';
        icon = '\u{1F6A8}';
        color = '#ef4444';
    } else if (score >= 60) {
        severity = 'high';
        icon = '\u26A0\uFE0F';
        color = '#f59e0b';
    } else if (score >= 30) {
        severity = 'medium';
        icon = '\u{1F4CC}';
        color = '#3b82f6';
    }

    const normalizedPid = String(pid);
    const nextItem = {
        pid: normalizedPid,
        process: processName,
        operation: eventType,
        path: path,
        score: score,
        timestamp: timestamp,
        risk: severity,
        icon: icon,
        color: color,
    };

    const existingIndex = this.activityBuffer.findIndex(item => String(item.pid) === normalizedPid);
    if (existingIndex >= 0) {
        this.activityBuffer.splice(existingIndex, 1);
    }
    this.activityBuffer.unshift(nextItem);
    this.activityByPid.set(normalizedPid, nextItem);

    if (this.activityBuffer.length > this.maxActivityItems) {
        this.activityBuffer = this.activityBuffer.slice(0, this.maxActivityItems);
    }

    this.renderActivityFeed();
    console.log('âœ… Feed row upserted:', processName, pid);
}

updateStats(data) {
    console.log('Stats update:', data);

    if (!data || typeof data !== 'object') {
        return;
    }

    if (data.active_threats !== undefined) {
        this.updateStat('stat-threats', data.active_threats);
    }
    if (data.blocked_threats !== undefined || data.blocked_today !== undefined) {
        this.updateStat('stat-blocked', data.blocked_threats ?? data.blocked_today);
    }
    if (data.total_threats !== undefined) {
        this.updateStat('stat-total-threats', data.total_threats);
    }
    if (data.files_monitored !== undefined) {
        this.updateStat('stat-files', data.files_monitored);
    }
    if (data.protection_rate !== undefined) {
        this.updateStat('stat-protection', `${data.protection_rate}%`);
    }
    if (Array.isArray(data.threats)) {
        this.replaceThreatHistory(data.threats);
    }
}

normalizeThreat(threat) {
    if (!threat || typeof threat !== 'object') {
        return null;
    }

    const normalizedPid = Number.parseInt(threat.pid ?? threat.process_id ?? 0, 10);
    if (!Number.isFinite(normalizedPid) || normalizedPid <= 0) {
        return null;
    }

    const rawStatus = String(threat.status || '').toUpperCase();
    const normalizedStatus = rawStatus === 'DETECTED' || rawStatus === 'ANALYZING'
        ? 'ACTIVE'
        : (rawStatus || 'ACTIVE');

    return {
        pid: normalizedPid,
        process_name: threat.process_name || threat.process || threat.name || 'Unknown Process',
        status: normalizedStatus,
        score: Number.parseInt(threat.score ?? threat.suspicion_score ?? threat.threat_score ?? 0, 10) || 0,
        files_affected: Number.parseInt(threat.files_affected ?? 0, 10) || 0,
        first_seen: Number(threat.first_seen ?? threat.timestamp ?? 0) || 0,
        last_seen: Number(threat.last_seen ?? threat.timestamp ?? 0) || 0,
        was_blocked: Boolean(threat.was_blocked),
    };
}

replaceThreatHistory(threats) {
    this.threatHistory.clear();
    threats.forEach(threat => {
        const normalized = this.normalizeThreat(threat);
        if (normalized) {
            this.threatHistory.set(String(normalized.pid), normalized);
        }
    });
    this.renderThreatHistory();
}

upsertThreatHistoryEntry(threat) {
    const normalized = this.normalizeThreat(threat);
    if (!normalized) {
        return;
    }

    const key = String(normalized.pid);
    const existing = this.threatHistory.get(key) || {};
    this.threatHistory.set(key, {
        ...existing,
        ...normalized,
        process_name: normalized.process_name || existing.process_name || 'Unknown Process',
        first_seen: normalized.first_seen || existing.first_seen || 0,
        last_seen: normalized.last_seen || existing.last_seen || normalized.first_seen || 0,
        was_blocked: Boolean(normalized.was_blocked || existing.was_blocked),
    });
    this.renderThreatHistory();
}

getThreatStatusMeta(status) {
    const normalized = String(status || 'CLOSED').toUpperCase();
    if (normalized === 'ACTIVE') {
        return { className: 'history-status-active', icon: '\u26A0\uFE0F', label: 'ACTIVE' };
    }
    if (normalized === 'BLOCKED') {
        return { className: 'history-status-blocked', icon: '\u26D4', label: 'BLOCKED' };
    }
    return { className: 'history-status-closed', icon: '\u25CF', label: 'CLOSED' };
}

renderThreatHistory() {
    const tableBody = document.getElementById('threat-history-body');
    if (!tableBody) {
        return;
    }

    const rows = Array.from(this.threatHistory.values()).sort((left, right) => {
        const priority = { ACTIVE: 0, BLOCKED: 1, CLOSED: 2 };
        const leftPriority = priority[left.status] ?? 3;
        const rightPriority = priority[right.status] ?? 3;
        if (leftPriority !== rightPriority) {
            return leftPriority - rightPriority;
        }
        if ((right.first_seen || 0) !== (left.first_seen || 0)) {
            return (right.first_seen || 0) - (left.first_seen || 0);
        }
        return (right.score || 0) - (left.score || 0);
    });

    if (rows.length === 0) {
        tableBody.innerHTML = `
            <tr class="process-empty-row">
                <td colspan="6">No threats detected yet.</td>
            </tr>
        `;
        return;
    }

    tableBody.innerHTML = rows.map(item => {
        const statusMeta = this.getThreatStatusMeta(item.status);
        return `
            <tr>
                <td>${this.escapeHtml(String(item.pid))}</td>
                <td class="history-process">${this.escapeHtml(item.process_name)}</td>
                <td class="status-cell">
                    <span class="history-status ${statusMeta.className}">
                        <span class="history-status-icon">${statusMeta.icon}</span>
                        <span>${statusMeta.label}</span>
                    </span>
                </td>
                <td class="history-score ${this.getScoreClass(item.score)}">${this.escapeHtml(String(item.score))}</td>
                <td>${this.escapeHtml(String(item.files_affected))}</td>
                <td class="history-time">${this.escapeHtml(this.formatProcessTime(item.first_seen))}</td>
            </tr>
        `;
    }).join('');
}

formatTimestamp(timestamp) {
    try {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = Math.floor((now - date) / 1000); // seconds ago
        
        if (diff < 60) return 'Just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        
        return date.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit'
        });
    } catch (e) {
        return 'Just now';
    }
}

updateConnectionStatus(connected) {
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.querySelector('.status-text');
    const footerStatus = document.getElementById('footer-ws-status');
    
    if (statusDot) {
        statusDot.className = connected ? 'status-dot connected' : 'status-dot disconnected';
        statusDot.style.background = connected ? '#10b981' : '#ef4444';
    }
    
    if (statusText) {
        statusText.textContent = connected ? 'Connected' : 'Disconnected';
    }

    if (footerStatus) {
        footerStatus.textContent = connected ? 'Connected' : 'Disconnected';
    }
}


    // === Event Handlers ===
    handleThreatAlert(message) {
        const data = message && message.data ? message.data : message;
        const alertId = message && message.alert_id ? message.alert_id : data.alert_id;
        if (alertId) {
            if (this.promptedAlerts.has(alertId)) {
                return;
            }
            this.promptedAlerts.add(alertId);
        }
        console.warn('ðŸš¨ THREAT ALERT:', data);
        const process = data.process || 'Unknown Process';
        const score = data.threat_score || data.score || data.suspicion_score || 90;
        const timestamp = data.timestamp || (Date.now() / 1000);
        const pid = data.pid || 'N/A';

        // Add to visible feed immediately
        this.addToActivityFeed(process, data.status || 'threat_alert', score, timestamp, pid, data.file_path || 'Threat detected');
        this.upsertThreatHistoryEntry({
            pid: data.pid,
            process_name: process,
            status: data.status || 'ACTIVE',
            score: score,
            files_affected: data.files_affected || 0,
            first_seen: timestamp,
            last_seen: timestamp,
            was_blocked: Boolean(data.was_blocked),
        });

        this.showNotification('Threat Detected', {
            body: `${process} (PID ${pid}) scored ${score}`,
            icon: '\u{1F6A8}'
        });
    }

    handleDecisionResult(message) {
        const decision = message.decision || 'UNKNOWN';
        const result = message.result || {};
        const statusText = result.message || (result.success ? 'Action completed' : 'Action failed');
        this.addToActivityFeed(
            `Decision: ${decision}`,
            'decision_result',
            result.success ? 10 : 80,
            Date.now() / 1000,
            message.alert_id || 'N/A',
            statusText
        );
        this.showNotification('Threat Decision Applied', {
            body: `${decision}: ${statusText}`,
            icon: result.success ? '\u2705' : '\u26A0\uFE0F'
        });
    }

    handleProtectionAction(action) {
        const process = action.process || 'Unknown Process';
        const pid = action.pid ?? 'N/A';
        const score = Number.parseInt(action.score || 0, 10) || 0;
        const ts = action.timestamp || (Date.now() / 1000);
        const label = action.status || action.action || 'monitor_only';
        this.addToActivityFeed(process, label, score, ts, pid, action.reason || label);
        this.upsertThreatHistoryEntry({
            pid: action.pid,
            process_name: process,
            status: action.status || (label === 'terminated' ? 'BLOCKED' : 'ACTIVE'),
            score: score,
            files_affected: action.files_affected || 0,
            first_seen: ts,
            last_seen: ts,
            was_blocked: Boolean(action.was_blocked || action.status === 'BLOCKED' || label === 'terminated'),
        });

        if (action.active_threats !== undefined || action.blocked_threats !== undefined) {
            this.updateStats({
                active_threats: action.active_threats ?? 0,
                blocked_today: action.blocked_threats ?? 0,
                blocked_threats: action.blocked_threats ?? 0,
                total_threats: action.total_threats ?? 0,
            });
        }

        if (label === 'terminated') {
            this.showNotification('Threat Blocked', {
                body: `${process} (PID ${pid}) terminated at score ${score}`,
                icon: '\u2705'
            });
        } else if (label === 'termination_failed') {
            this.showNotification('Termination Failed', {
                body: `${process} (PID ${pid}) could not be terminated`,
                icon: '\u26A0\uFE0F'
            });
        }
    }
    handleActivityUpdate(data) {
        this.addActivityItem({
            timestamp: data.timestamp || new Date().toISOString(),
            process: data.process || 'Unknown',
            operation: data.operation || 'file operation',
            path: data.path || 'N/A',
            score: data.suspicion_score || data.score || 0,
            risk: this.calculateRiskLevel(data.suspicion_score || data.score || 0)
        });
    }

    handleStatsUpdate(data) {
        this.updateStats(data);
    }

    handleStatusUpdate(data) {
        // Handle general status updates from backend
        const stats = data.statistics || data.stats;
            if (stats) {
                this.handleStatsUpdate(stats);
            }
    }

    // === Activity Feed Management ===
    addActivityItem(item) {
        this.activityBuffer.unshift(item);
        
        // Keep only last N items
        if (this.activityBuffer.length > this.maxActivityItems) {
            this.activityBuffer = this.activityBuffer.slice(0, this.maxActivityItems);
        }

        this.renderActivityFeed();
    }

    renderActivityFeed() {
        const feedElement = document.getElementById('activity-feed');
        if (!feedElement) return;

        if (this.activityBuffer.length === 0) {
            feedElement.innerHTML = `
                <div class="activity-placeholder">
                    <div class="placeholder-icon">\u{1F4E1}</div>
                    <p class="placeholder-text">Waiting for events...</p>
                    <p class="placeholder-subtext">Last ${this.maxActivityItems} events from the defense engine</p>
                </div>
            `;
            return;
        }

        feedElement.innerHTML = this.activityBuffer.map(item => `
            <div class="activity-item ${item.risk}-risk">
                <div class="activity-timestamp">${this.formatTimestamp(item.timestamp)}</div>
                <div class="activity-details">
                    <div class="activity-process">${this.escapeHtml(item.process)}</div>
                    <div class="activity-path">
                        <strong>${this.escapeHtml(item.operation)}</strong> -> ${this.escapeHtml(item.path)}
                    </div>
                </div>
                <div class="activity-score ${this.getScoreClass(item.score)}">
                    ${item.score}
                </div>
            </div>
        `).join('');
    }

    // === API Calls ===
    async fetchInitialStats() {
        try {
            const response = await fetch('/api/status');
            if (!response.ok) throw new Error('Failed to fetch status');
            
            const data = await response.json();
            console.log('ðŸ“Š Initial stats:', data);

            const stats = data.statistics || data.stats || {};
            const threatSummary = data.threat_summary || {};
            this.updateStats({
                ...threatSummary,
                ...stats,
                threats: Array.isArray(stats.threats) ? stats.threats : (threatSummary.threats || []),
                blocked_threats: stats.blocked_threats ?? threatSummary.blocked_threats,
                total_threats: stats.total_threats ?? threatSummary.total_threats,
                active_threats: stats.active_threats ?? threatSummary.active_threats,
            });
        } catch (error) {
            console.error('âŒ Failed to fetch initial stats:', error);
        }
    }

    async updateDemoStatus() {
        const statusEl = document.getElementById('demo-status');
        const tableBodyEl = document.getElementById('demo-process-table-body');
        if (!statusEl || !tableBodyEl) return;

        try {
            const resp = await fetch('/api/demo/status');
            const data = await resp.json();
            if (!resp.ok || !data.success) {
                statusEl.textContent = `Demo status: unavailable`;
                this.renderDemoProcessTable(tableBodyEl, null);
                return;
            }

            this.updateStats(data);

            const demo = data.demo || {};
            const state = demo.state || 'idle';
            const phase = demo.phase || '-';
            const elapsed = demo.elapsed_seconds || 0;
            statusEl.textContent = `Demo status: ${state} | Phase ${phase} | Elapsed ${elapsed}s`;
            if (demo.error) {
                statusEl.textContent += ` | Error: ${demo.error}`;
            }
            this.renderDemoProcessTable(tableBodyEl, demo);
        } catch (error) {
            console.error('âŒ updateDemoStatus failed:', error);
            statusEl.textContent = `Demo status: error`;
            this.renderDemoProcessTable(tableBodyEl, null);
        }
    }

    pollDemoStatus() {
        this.updateDemoStatus();
        this.demoStatusTimer = setInterval(() => this.updateDemoStatus(), 3000);
    }

    async startDemo() {
        const messageEl = document.getElementById('demo-status');
        if (messageEl) messageEl.textContent = 'Demo status: starting...';

        try {
            const response = await fetch('/api/demo/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ duration: 30, batch_size: 30, rename_ext: '.lockbit', create_ransom_note: true }),
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.detail || 'Failed to start demo');
            }

            if (messageEl) messageEl.textContent = `Demo status: ${data.demo?.state || 'starting'}`;
            this.updateDemoStatus();
        } catch (error) {
            console.error('âŒ startDemo failed:', error);
            if (messageEl) messageEl.textContent = `Demo status: start failed: ${error.message}`;
        }
    }

    async stopDemo() {
        const messageEl = document.getElementById('demo-status');
        if (messageEl) messageEl.textContent = 'Demo status: stopping...';

        try {
            const response = await fetch('/api/demo/stop', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.detail || 'Failed to stop demo');
            }

            if (messageEl) messageEl.textContent = `Demo status: ${data.demo?.state || 'stopped'}`;
            this.updateDemoStatus();
        } catch (error) {
            console.error('âŒ stopDemo failed:', error);
            if (messageEl) messageEl.textContent = `Demo status: stop failed: ${error.message}`;
        }
    }

    renderDemoProcessTable(tableBodyEl, demo) {
        const pid = demo && demo.pid ? Number(demo.pid) : 0;
        const processName = demo && demo.process_name ? String(demo.process_name) : '';
        const startedAt = demo && demo.started_at ? demo.started_at : null;

        if (!pid) {
            tableBodyEl.innerHTML = `
                <tr class="process-empty-row">
                    <td colspan="3">No ransomware demo process running.</td>
                </tr>
            `;
            return;
        }

        tableBodyEl.innerHTML = `
            <tr>
                <td>${this.escapeHtml(String(pid))}</td>
                <td>${this.escapeHtml(processName || 'safe_file_churn_simulator')}</td>
                <td>${this.escapeHtml(this.formatProcessTime(startedAt))}</td>
            </tr>
        `;
    }

    formatProcessTime(timestamp) {
        if (!timestamp) {
            return '-';
        }
        const asNumber = Number(timestamp);
        if (!Number.isFinite(asNumber)) {
            return '-';
        }
        const date = new Date(asNumber * 1000);
        if (isNaN(date.getTime())) {
            return '-';
        }
        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
        });
    }
    // === Utility Functions ===
    calculateRiskLevel(score) {
        if (score >= 60) return 'high';
        if (score >= 45) return 'medium';
        return 'low';
    }

    getScoreClass(score) {
        if (score >= 60) return 'high';
        if (score >= 45) return 'medium';
        return 'low';
    }

    formatTimestamp(timestamp) {
        const date = (typeof timestamp === 'number')
            ? new Date(timestamp * 1000)
            : new Date(timestamp);
        if (isNaN(date.getTime())) {
            return 'Just now';
        }
        const now = new Date();
        const diffMs = now - date;
        const diffSecs = Math.floor(diffMs / 1000);
        const diffMins = Math.floor(diffSecs / 60);
        const diffHours = Math.floor(diffMins / 60);

        if (diffSecs < 60) return `${diffSecs}s ago`;
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        
        return date.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    updateStat(elementId, value) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = value;
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showNotification(title, options) {
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, options);
        }
    }

    // === Event Listeners ===
    setupEventListeners() {
    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }

    // Enhanced smooth scroll for navigation links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            const href = link.getAttribute('href');
            if (href.startsWith('#')) {
                e.preventDefault();
                const target = document.querySelector(href);
                if (target) {
                    const offsetTop = target.offsetTop - 80; // Account for header
                    window.scrollTo({
                        top: offsetTop,
                        behavior: 'smooth'
                    });
                    
                    // Add active class animation
                    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                    link.classList.add('active');
                }
            }
        });
    });

    const demoStartBtn = document.getElementById('demo-start-btn');
    if (demoStartBtn) {
        demoStartBtn.addEventListener('click', () => this.startDemo());
    }

    const demoStopBtn = document.getElementById('demo-stop-btn');
    if (demoStopBtn) {
        demoStopBtn.addEventListener('click', () => this.stopDemo());
    }

    window.addEventListener('online', () => this.connectWebSocket());
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) {
            this.connectWebSocket();
            this.fetchInitialStats();
            this.syncPendingAlerts();
        }
    });
    window.addEventListener('beforeunload', () => {
        this.manualClose = true;
        this.clearReconnectTimer();
        this.stopHeartbeat();
        if (this.ws) {
            this.ws.close();
        }
    });

        // Highlight active section on scroll
        window.addEventListener('scroll', () => {
            const sections = document.querySelectorAll('section[id]');
            const scrollPosition = window.scrollY + 100;

            sections.forEach(section => {
                const sectionTop = section.offsetTop;
                const sectionHeight = section.offsetHeight;
                const sectionId = section.getAttribute('id');

                if (scrollPosition >= sectionTop && scrollPosition < sectionTop + sectionHeight) {
                    document.querySelectorAll('.nav-link').forEach(link => {
                        link.classList.remove('active');
                        if (link.getAttribute('href') === `#${sectionId}`) {
                            link.classList.add('active');
                        }
                    });
                }
            });
        });
    }
}

/* ===================================
   INITIALIZATION
   =================================== */

let dashboardInstance = null;

// Initialize everything when DOM loads
document.addEventListener('DOMContentLoaded', () => {
    console.log('========================================');
    console.log('ðŸš€ RansomGuard Dashboard Loading...');
    console.log('========================================');
    
    // 1. Start intro animation
    const intro = new IntroSequence();
    intro.start().then(() => {
        console.log('âœ… Intro complete');
    });
    
    // 2. Initialize dashboard after intro (3 seconds)
    setTimeout(() => {
        console.log('ðŸŽ›ï¸ Initializing main dashboard...');
        
        try {
            // Create dashboard instance (adjust class name if needed)
            dashboardInstance = new RansomGuardDashboard();
            window.dashboard = dashboardInstance; // Make globally accessible
            
            console.log('âœ… Dashboard initialized successfully');
            console.log('Dashboard instance:', window.dashboard);
        } catch (error) {
            console.error('âŒ Dashboard initialization failed:', error);
        }
    }, 3000);
    
    // 3. Initialize custom cursor
    setTimeout(() => {
        console.log('ðŸ–±ï¸ Initializing custom cursor...');
        try {
            const cursor = new CustomCursor();
            console.log('âœ… Custom cursor initialized');
        } catch (error) {
            console.error('âŒ Cursor initialization failed:', error);
        }
    }, 3000);
    
    // 4. Initialize scroll animations
    setTimeout(() => {
        console.log('ðŸ“œ Initializing scroll animations...');
        try {
            const scrollAnims = new ScrollAnimations();
            console.log('âœ… Scroll animations initialized');
        } catch (error) {
            console.error('âŒ Scroll animations failed:', error);
        }
    }, 3000);
});

console.log('ðŸ“„ dashboard.js loaded');


