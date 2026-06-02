function dashboard() {
    return {
        snapshot: {
            scan_id: null,
            target: null,
            is_active: false,
            progress: { current_phase: 'idle', phases_completed: [], percentage: 0 },
            severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            exploitation_counts: { pending: 0, exploited: 0, potential: 0, false_positive: 0, skipped: 0 },
            agents: [],
            top_findings: [],
            total_findings: 0,
            last_updated: new Date().toISOString(),
        },
        events: [],
        connected: false,
        eventSource: null,
        maxEvents: 100,

        connect() {
            this.setupSSE();
        },

        setupSSE() {
            if (this.eventSource) {
                this.eventSource.close();
            }

            const params = new URLSearchParams(window.location.search);
            const scanId = params.get('scan_id') || '';
            const url = scanId ? `/api/events?scan_id=${scanId}` : '/api/events';

            this.eventSource = new EventSource(url);
            this.connected = true;

            this.eventSource.addEventListener('snapshot', (e) => {
                try {
                    this.snapshot = JSON.parse(e.data);
                } catch (err) {
                    console.error('Failed to parse snapshot:', err);
                }
            });

            this.eventSource.addEventListener('bus', (e) => {
                try {
                    const event = JSON.parse(e.data);
                    this.events.unshift(event);
                    if (this.events.length > this.maxEvents) {
                        this.events = this.events.slice(0, this.maxEvents);
                    }
                } catch (err) {
                    console.error('Failed to parse bus event:', err);
                }
            });

            this.eventSource.onerror = () => {
                this.connected = false;
                this.eventSource.close();
                // Reconnect after 3 seconds
                setTimeout(() => this.setupSSE(), 3000);
            };

            this.eventSource.onopen = () => {
                this.connected = true;
            };
        },

        agentIcon(state) {
            const icons = { idle: '⏸️', running: '🔄', completed: '✅', failed: '❌' };
            return icons[state] || '?';
        },

        formatTime(ts) {
            if (!ts) return '—';
            try {
                const d = new Date(ts);
                return d.toLocaleTimeString();
            } catch {
                return String(ts).slice(11, 19);
            }
        },
    };
}
