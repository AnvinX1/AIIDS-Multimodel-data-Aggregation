"""
Web Dashboard for AI-Powered Intrusion Detection System
Provides a web interface for monitoring and managing the IDS
"""

from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS
import json
import os
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import threading
import time
from real_time_detector import RealTimeDetector, create_sample_flow
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Global detector instance
detector = None
monitoring_data = {
    'is_monitoring': False,
    'start_time': None,
    'total_flows_processed': 0,
    'alerts': []
}

class WebDashboard:
    """Web dashboard for the intrusion detection system"""
    
    def __init__(self):
        self.detector = None
        self.monitoring_thread = None
        self.sample_flows = []
        
    def initialize_detector(self):
        """Initialize the real-time detector"""
        try:
            self.detector = RealTimeDetector()
            logger.info("Detector initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Error initializing detector: {e}")
            return False
    
    def generate_sample_flows(self, count=10):
        """Generate sample flows for demonstration"""
        flows = []
        for i in range(count):
            flow = create_sample_flow()
            # Add some variation
            flow['Flow Duration'] += np.random.randint(-100, 100)
            flow['Total Fwd Packets'] += np.random.randint(-2, 2)
            flows.append(flow)
        return flows

# Initialize dashboard
dashboard = WebDashboard()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/status')
def get_status():
    """Get system status"""
    global detector, monitoring_data
    
    if detector is None:
        try:
            detector = RealTimeDetector()
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    stats = detector.get_detection_stats()
    
    status = {
        'system_status': 'online',
        'detector_loaded': detector is not None,
        'monitoring': monitoring_data['is_monitoring'],
        'monitoring_start_time': monitoring_data['start_time'],
        'total_flows_processed': monitoring_data['total_flows_processed'],
        'detection_stats': stats,
        'timestamp': datetime.now().isoformat()
    }
    
    return jsonify(status)

@app.route('/api/detect', methods=['POST'])
def detect_anomaly():
    """Detect anomaly in a single flow"""
    global detector
    
    if detector is None:
        try:
            detector = RealTimeDetector()
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    try:
        flow_data = request.json
        
        if not flow_data:
            return jsonify({'error': 'No flow data provided'}), 400
        
        # Detect anomaly
        label, confidence, details = detector.detect_anomaly(flow_data)
        
        # Add to monitoring data if high risk
        if details.get('risk_level') in ['HIGH', 'CRITICAL']:
            monitoring_data['alerts'].append({
                'timestamp': details['timestamp'],
                'label': label,
                'confidence': confidence,
                'risk_level': details['risk_level']
            })
            
            # Keep only last 100 alerts
            if len(monitoring_data['alerts']) > 100:
                monitoring_data['alerts'] = monitoring_data['alerts'][-100:]
        
        return jsonify({
            'predicted_label': label,
            'confidence': confidence,
            'details': details
        })
        
    except Exception as e:
        logger.error(f"Error in detection: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/batch_detect', methods=['POST'])
def batch_detect():
    """Detect anomalies in multiple flows"""
    global detector
    
    if detector is None:
        try:
            detector = RealTimeDetector()
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    try:
        flows_data = request.json
        
        if not flows_data or not isinstance(flows_data, list):
            return jsonify({'error': 'No flows data provided'}), 400
        
        # Detect anomalies
        results = detector.batch_detect(flows_data)
        
        # Update monitoring data
        monitoring_data['total_flows_processed'] += len(flows_data)
        
        # Add high-risk alerts
        for result in results:
            if result.get('risk_level') in ['HIGH', 'CRITICAL']:
                monitoring_data['alerts'].append({
                    'timestamp': result['timestamp'],
                    'label': result['predicted_label'],
                    'confidence': result['confidence'],
                    'risk_level': result['risk_level']
                })
        
        # Keep only last 100 alerts
        if len(monitoring_data['alerts']) > 100:
            monitoring_data['alerts'] = monitoring_data['alerts'][-100:]
        
        return jsonify({
            'results': results,
            'total_processed': len(flows_data)
        })
        
    except Exception as e:
        logger.error(f"Error in batch detection: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/start_monitoring', methods=['POST'])
def start_monitoring():
    """Start real-time monitoring"""
    global detector, monitoring_data
    
    if detector is None:
        try:
            detector = RealTimeDetector()
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    if monitoring_data['is_monitoring']:
        return jsonify({'message': 'Monitoring already active'})
    
    try:
        # Start monitoring with sample data generator
        def sample_flow_generator():
            """Generate sample flows for demonstration"""
            while monitoring_data['is_monitoring']:
                flows = dashboard.generate_sample_flows(5)
                yield flows
                time.sleep(2)  # Generate flows every 2 seconds
        
        monitoring_data['is_monitoring'] = True
        monitoring_data['start_time'] = datetime.now().isoformat()
        
        # Start monitoring in separate thread
        def monitoring_loop():
            flow_gen = sample_flow_generator()
            while monitoring_data['is_monitoring']:
                try:
                    flows = next(flow_gen)
                    results = detector.batch_detect(flows)
                    monitoring_data['total_flows_processed'] += len(flows)
                    
                    # Log high-risk detections
                    for result in results:
                        if result.get('risk_level') in ['HIGH', 'CRITICAL']:
                            monitoring_data['alerts'].append({
                                'timestamp': result['timestamp'],
                                'label': result['predicted_label'],
                                'confidence': result['confidence'],
                                'risk_level': result['risk_level']
                            })
                    
                    time.sleep(2)
                    
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}")
                    time.sleep(2)
        
        monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitoring_thread.start()
        
        return jsonify({'message': 'Monitoring started successfully'})
        
    except Exception as e:
        monitoring_data['is_monitoring'] = False
        logger.error(f"Error starting monitoring: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop_monitoring', methods=['POST'])
def stop_monitoring():
    """Stop real-time monitoring"""
    global monitoring_data
    
    monitoring_data['is_monitoring'] = False
    monitoring_data['start_time'] = None
    
    return jsonify({'message': 'Monitoring stopped successfully'})

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    global monitoring_data
    
    # Return last 50 alerts
    recent_alerts = monitoring_data['alerts'][-50:] if monitoring_data['alerts'] else []
    
    return jsonify({
        'alerts': recent_alerts,
        'total_alerts': len(monitoring_data['alerts'])
    })

@app.route('/api/detection_history')
def get_detection_history():
    """Get detection history"""
    global detector
    
    if detector is None:
        return jsonify({'error': 'Detector not initialized'}), 500
    
    try:
        history = detector.detection_history[-100:]  # Last 100 detections
        return jsonify({'history': history})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export_history')
def export_history():
    """Export detection history"""
    global detector
    
    if detector is None:
        return jsonify({'error': 'Detector not initialized'}), 500
    
    try:
        filename = f"detection_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        detector.export_detection_history(filename)
        
        return send_file(filename, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sample_flow')
def get_sample_flow():
    """Get a sample flow for testing"""
    sample_flow = create_sample_flow()
    return jsonify(sample_flow)

@app.route('/api/model_info')
def get_model_info():
    """Get information about the trained models"""
    global detector
    
    if detector is None:
        return jsonify({'error': 'Detector not initialized'}), 500
    
    try:
        model_info = {
            'label_classes': detector.label_encoder.classes_.tolist(),
            'feature_count': len(detector.scaler.feature_names_in_) if hasattr(detector.scaler, 'feature_names_in_') else 'Unknown',
            'model_type': 'Ensemble (RandomForest + XGBoost + LightGBM)',
            'last_updated': datetime.now().isoformat()
        }
        
        return jsonify(model_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Create templates directory and HTML template
def create_templates():
    """Create HTML templates for the dashboard"""
    os.makedirs('templates', exist_ok=True)
    
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI-Powered Intrusion Detection System</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .card h3 {
            margin-top: 0;
            color: #333;
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-online { background-color: #4CAF50; }
        .status-offline { background-color: #f44336; }
        .status-warning { background-color: #ff9800; }
        .btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 5px;
        }
        .btn:hover { background: #5a6fd8; }
        .btn-danger { background: #f44336; }
        .btn-danger:hover { background: #da190b; }
        .alert {
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid;
        }
        .alert-high { background: #fff3cd; border-color: #ff9800; }
        .alert-critical { background: #f8d7da; border-color: #f44336; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            margin: 20px 0;
        }
        .stat-item {
            text-align: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        #detectionChart {
            max-height: 300px;
        }
        .flow-input {
            width: 100%;
            height: 200px;
            font-family: monospace;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AI-Powered Intrusion Detection System</h1>
            <p>Real-time Network Security Monitoring Dashboard</p>
        </div>

        <div class="dashboard-grid">
            <!-- System Status Card -->
            <div class="card">
                <h3>System Status</h3>
                <div id="systemStatus">
                    <p><span class="status-indicator status-offline"></span>Loading...</p>
                </div>
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-value" id="totalFlows">0</div>
                        <div class="stat-label">Total Flows</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="anomalyRate">0%</div>
                        <div class="stat-label">Anomaly Rate</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="alertsCount">0</div>
                        <div class="stat-label">Active Alerts</div>
                    </div>
                </div>
            </div>

            <!-- Monitoring Controls Card -->
            <div class="card">
                <h3>Monitoring Controls</h3>
                <button class="btn" onclick="startMonitoring()">Start Monitoring</button>
                <button class="btn btn-danger" onclick="stopMonitoring()">Stop Monitoring</button>
                <button class="btn" onclick="testDetection()">Test Detection</button>
                <button class="btn" onclick="exportHistory()">Export History</button>
                <div id="monitoringStatus" style="margin-top: 15px;">
                    <p>Monitoring: <span id="monitoringIndicator">Stopped</span></p>
                </div>
            </div>

            <!-- Detection Chart Card -->
            <div class="card">
                <h3>Detection Trends</h3>
                <canvas id="detectionChart"></canvas>
            </div>

            <!-- Recent Alerts Card -->
            <div class="card">
                <h3>Recent Alerts</h3>
                <div id="alertsList">
                    <p>No alerts yet</p>
                </div>
            </div>
        </div>

        <!-- Flow Testing Card -->
        <div class="card">
            <h3>Flow Testing</h3>
            <p>Test the detection system with custom flow data:</p>
            <button class="btn" onclick="loadSampleFlow()">Load Sample Flow</button>
            <button class="btn" onclick="detectFlow()">Detect Anomaly</button>
            <textarea id="flowInput" class="flow-input" placeholder="Paste flow data in JSON format here..."></textarea>
            <div id="detectionResult" style="margin-top: 15px;"></div>
        </div>
    </div>

    <script>
        let detectionChart;
        let updateInterval;

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            initializeChart();
            updateStatus();
            updateInterval = setInterval(updateStatus, 5000); // Update every 5 seconds
        });

        function initializeChart() {
            const ctx = document.getElementById('detectionChart').getContext('2d');
            detectionChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Anomaly Rate',
                        data: [],
                        borderColor: '#667eea',
                        backgroundColor: 'rgba(102, 126, 234, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 1
                        }
                    }
                }
            });
        }

        async function updateStatus() {
            try {
                const response = await fetch('/api/status');
                const status = await response.json();
                
                // Update system status
                const statusElement = document.getElementById('systemStatus');
                const indicator = status.detector_loaded ? 'status-online' : 'status-offline';
                statusElement.innerHTML = `<p><span class="status-indicator ${indicator}"></span>System ${status.detector_loaded ? 'Online' : 'Offline'}</p>`;
                
                // Update monitoring status
                const monitoringIndicator = document.getElementById('monitoringIndicator');
                monitoringIndicator.textContent = status.monitoring ? 'Active' : 'Stopped';
                monitoringIndicator.style.color = status.monitoring ? '#4CAF50' : '#f44336';
                
                // Update stats
                document.getElementById('totalFlows').textContent = status.detection_stats.total_detections || 0;
                document.getElementById('anomalyRate').textContent = 
                    ((status.detection_stats.anomaly_rate || 0) * 100).toFixed(1) + '%';
                
                // Update chart
                updateChart(status.detection_stats);
                
                // Update alerts
                updateAlerts();
                
            } catch (error) {
                console.error('Error updating status:', error);
            }
        }

        function updateChart(stats) {
            const now = new Date().toLocaleTimeString();
            detectionChart.data.labels.push(now);
            detectionChart.data.datasets[0].data.push(stats.anomaly_rate || 0);
            
            // Keep only last 20 data points
            if (detectionChart.data.labels.length > 20) {
                detectionChart.data.labels.shift();
                detectionChart.data.datasets[0].data.shift();
            }
            
            detectionChart.update();
        }

        async function updateAlerts() {
            try {
                const response = await fetch('/api/alerts');
                const data = await response.json();
                
                const alertsList = document.getElementById('alertsList');
                document.getElementById('alertsCount').textContent = data.total_alerts;
                
                if (data.alerts.length === 0) {
                    alertsList.innerHTML = '<p>No alerts yet</p>';
                    return;
                }
                
                let alertsHtml = '';
                data.alerts.slice(-10).reverse().forEach(alert => {
                    const alertClass = alert.risk_level === 'CRITICAL' ? 'alert-critical' : 'alert-high';
                    alertsHtml += `
                        <div class="alert ${alertClass}">
                            <strong>${alert.label}</strong> - ${alert.risk_level}
                            <br><small>Confidence: ${(alert.confidence * 100).toFixed(1)}% - ${new Date(alert.timestamp).toLocaleString()}</small>
                        </div>
                    `;
                });
                
                alertsList.innerHTML = alertsHtml;
                
            } catch (error) {
                console.error('Error updating alerts:', error);
            }
        }

        async function startMonitoring() {
            try {
                const response = await fetch('/api/start_monitoring', { method: 'POST' });
                const result = await response.json();
                alert(result.message);
            } catch (error) {
                alert('Error starting monitoring: ' + error.message);
            }
        }

        async function stopMonitoring() {
            try {
                const response = await fetch('/api/stop_monitoring', { method: 'POST' });
                const result = await response.json();
                alert(result.message);
            } catch (error) {
                alert('Error stopping monitoring: ' + error.message);
            }
        }

        async function testDetection() {
            try {
                const response = await fetch('/api/sample_flow');
                const sampleFlow = await response.json();
                
                const detectResponse = await fetch('/api/detect', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(sampleFlow)
                });
                
                const result = await detectResponse.json();
                alert(`Detection Result: ${result.predicted_label} (Confidence: ${(result.confidence * 100).toFixed(1)}%)`);
                
            } catch (error) {
                alert('Error testing detection: ' + error.message);
            }
        }

        async function loadSampleFlow() {
            try {
                const response = await fetch('/api/sample_flow');
                const sampleFlow = await response.json();
                document.getElementById('flowInput').value = JSON.stringify(sampleFlow, null, 2);
            } catch (error) {
                alert('Error loading sample flow: ' + error.message);
            }
        }

        async function detectFlow() {
            const flowInput = document.getElementById('flowInput').value;
            if (!flowInput.trim()) {
                alert('Please enter flow data');
                return;
            }
            
            try {
                const flowData = JSON.parse(flowInput);
                const response = await fetch('/api/detect', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(flowData)
                });
                
                const result = await response.json();
                const resultDiv = document.getElementById('detectionResult');
                
                if (result.error) {
                    resultDiv.innerHTML = `<div class="alert alert-critical">Error: ${result.error}</div>`;
                } else {
                    const riskClass = result.details.risk_level === 'CRITICAL' ? 'alert-critical' : 
                                    result.details.risk_level === 'HIGH' ? 'alert-high' : 'alert';
                    resultDiv.innerHTML = `
                        <div class="alert ${riskClass}">
                            <strong>Prediction:</strong> ${result.predicted_label}<br>
                            <strong>Confidence:</strong> ${(result.confidence * 100).toFixed(1)}%<br>
                            <strong>Risk Level:</strong> ${result.details.risk_level}
                        </div>
                    `;
                }
                
            } catch (error) {
                alert('Error detecting flow: ' + error.message);
            }
        }

        async function exportHistory() {
            try {
                const response = await fetch('/api/export_history');
                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'detection_history.json';
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                } else {
                    alert('Error exporting history');
                }
            } catch (error) {
                alert('Error exporting history: ' + error.message);
            }
        }
    </script>
</body>
</html>
    """
    
    with open('templates/dashboard.html', 'w') as f:
        f.write(html_template)

def main():
    """Main function to run the web dashboard"""
    print("Starting AI-Powered Intrusion Detection System Web Dashboard")
    print("="*60)
    
    # Create templates
    create_templates()
    
    # Initialize dashboard
    if not dashboard.initialize_detector():
        print("Warning: Could not initialize detector. Some features may not work.")
    
    print("Dashboard will be available at: http://localhost:5000")
    print("Press Ctrl+C to stop the server")
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == "__main__":
    main()
