import os
import time
import pandas as pd
import numpy as np
import subprocess
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
import threading
import json
from datetime import datetime
import logging
import argparse

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ids_comparison.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("IDS_Comparison")

class LiveIDSComparison:
    def __init__(self, model_path, open_source_ids_cmd, cicflowmeter_path, interface="eth0"):
        # 
        # Initialize the Live IDS Comparison system
        
        # Args:
        #     model_path: Path to your saved TensorFlow model
        #     open_source_ids_cmd: Command to run the open source IDS
        #     cicflowmeter_path: Path to CICFlowMeter installation
        #     interface: Network interface to monitor
        # 
        self.interface = interface
        self.model_path = model_path
        self.open_source_ids_cmd = open_source_ids_cmd
        self.cicflowmeter_path = cicflowmeter_path
        self.flow_output_dir = "flow_output"
        self.last_processed_file = None
        self.stop_threads = False
        
        # Create output directory if it doesn't exist
        os.makedirs(self.flow_output_dir, exist_ok=True)
        
        # Load the model
        logger.info(f"Loading model from {model_path}")
        self.model = tf.keras.models.load_model(model_path)
        
        # Initialize scaler - load from file if available
        if os.path.exists("scaler.pkl"):
            import pickle
            with open("scaler.pkl", "rb") as f:
                self.scaler = pickle.load(f)
        else:
            self.scaler = StandardScaler()
            logger.warning("No scaler.pkl found. Will use a new StandardScaler")
        
        # Results storage
        self.results = {
            "timestamp": [],
            "flow_id": [],
            "my_model_prediction": [],
            "my_model_confidence": [],
            "open_source_ids_alert": [],
            "agreement": []
        }

    def start_cicflowmeter(self):
        # Start CICFlowMeter to capture network flows
        cmd = (f"java -jar {self.cicflowmeter_path}/CICFlowMeter.jar "
               f"capture {self.interface} {self.flow_output_dir}")
        
        logger.info(f"Starting CICFlowMeter with command: {cmd}")
        
        # Start CICFlowMeter in a subprocess
        self.cicflowmeter_process = subprocess.Popen(
            cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        logger.info("CICFlowMeter started successfully")

    def start_open_source_ids(self):
        # Start the open source IDS (e.g., Suricata, Snort, Zeek)
        logger.info(f"Starting open source IDS with command: {self.open_source_ids_cmd}")
        
        # Start the open source IDS in a subprocess
        self.ids_process = subprocess.Popen(
            self.open_source_ids_cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        logger.info("Open source IDS started successfully")

    def preprocess_flow_data(self, df):
        # 
        # Preprocess the flow data to match model input requirements
        
        # Args:
        #     df: DataFrame with flow data from CICFlowMeter
            
        # Returns:
        #     Preprocessed DataFrame ready for model input
        # 
        # Handle missing values
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)
        
        # Drop unnecessary columns if they exist
        # cols_to_drop = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 
        #                 'Protocol', 'Timestamp', 'Label']
        # for col in cols_to_drop:
        #     if col in df.columns:
        #         df = df.drop(col, axis=1)
        
        # Apply feature scaling
        return self.scaler.transform(df)

    def parse_ids_alerts(self):
        # 
        # Parse alerts from Snort IDS
        
        # Returns:
        #     Dictionary mapping flow identifiers to alert status
        # 
        alerts = {}
        
        # Snort alert log locations (check both common paths)
        possible_log_files = [
            "/var/log/snort/alert",  # Common in many Linux distros
            "/var/snort/alert",      # Alternative location
            "alert"                  # Local directory (if using -A option)
        ]
        
        # Find the first available log file
        log_file = None
        for f in possible_log_files:
            if os.path.exists(f):
                log_file = f
                break
        
        # Parse Snort alert file if found
        if log_file:
            with open(log_file, "r") as f:
                current_alert = None
                
                for line in f:
                    # Snort alert format typically looks like:
                    # [**] [1:1000:1] Snort Alert [**]
                    # [Classification: ...] [Priority: ...]
                    # MM/DD-HH:MM:SS.SSSSSS 192.168.1.1:12345 -> 192.168.1.2:80
                    
                    # Look for alert signature line
                    if "[**]" in line and not current_alert:
                        current_alert = {}
                    
                    # Look for IP information line
                    elif current_alert is not None and "->" in line and ":" in line:
                        try:
                            # Extract timestamp and IP information
                            parts = line.strip().split()
                            
                            # Find the parts with IP:port format
                            for i, part in enumerate(parts):
                                if "->" in part:
                                    # Extract source and destination
                                    src_full = parts[i-1]
                                    dst_full = parts[i+1]
                                    
                                    # Handle IPv4 and IPv6 addresses
                                    if ":" in src_full and ":" in dst_full:
                                        # Extract IP and port
                                        last_colon_src = src_full.rindex(":")
                                        last_colon_dst = dst_full.rindex(":")
                                        
                                        src_ip = src_full[:last_colon_src]
                                        src_port = src_full[last_colon_src+1:]
                                        dst_ip = dst_full[:last_colon_dst]
                                        dst_port = dst_full[last_colon_dst+1:]
                                        
                                        # Create bidirectional flow identifiers (CICFlowMeter sometimes flips src/dst)
                                        flow_id1 = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}"
                                        flow_id2 = f"{dst_ip}-{src_ip}-{dst_port}-{src_port}"
                                        
                                        alerts[flow_id1] = True
                                        alerts[flow_id2] = True
                                        
                                        # Log the alert
                                        logger.debug(f"Found Snort alert for flow: {flow_id1}")
                                        current_alert = None
                                        break
                        except Exception as e:
                            logger.warning(f"Failed to parse Snort alert line: {line} - Error: {str(e)}")
                            current_alert = None
        else:
            logger.warning("Could not find Snort alert log file. Make sure Snort is running with alert output.")
        
        return alerts

    def monitor_flows(self):
        # Monitor and process new flow files
        while not self.stop_threads:
            try:
                # List all CSV files in the output directory
                files = [f for f in os.listdir(self.flow_output_dir) 
                         if f.endswith('.csv') and "ISCX" in f]
                
                # Sort files by creation time
                files.sort(key=lambda x: os.path.getctime(
                    os.path.join(self.flow_output_dir, x)))
                
                # Process new files
                for file in files:
                    file_path = os.path.join(self.flow_output_dir, file)
                    
                    # Skip if this file has already been processed
                    if self.last_processed_file == file_path:
                        continue
                    
                    # Read the flow file
                    logger.info(f"Processing new flow file: {file}")
                    df = pd.read_csv(file_path)
                    
                    if len(df) == 0:
                        logger.warning(f"Empty flow file: {file}")
                        continue
                    
                    # Store flow IDs and timestamps for reference
                    flow_ids = df['Flow ID'].tolist() if 'Flow ID' in df.columns else []
                    timestamps = [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * len(flow_ids)
                    
                    # Preprocess the data
                    X = self.preprocess_flow_data(df.copy())
                    
                    # Make predictions with your model
                    predictions = self.model.predict(X)
                    
                    # Get alerts from the open source IDS
                    ids_alerts = self.parse_ids_alerts()
                    
                    # Record results
                    for i, flow_id in enumerate(flow_ids):
                        pred_class = 1 if predictions[i][0] > 0.5 else 0
                        confidence = float(predictions[i][0]) if pred_class == 1 else float(1 - predictions[i][0])
                        
                        # Check if this flow triggered an alert in the open source IDS
                        open_source_alert = ids_alerts.get(flow_id, False)
                        
                        # Determine if models agree
                        agreement = (pred_class == 1 and open_source_alert) or (pred_class == 0 and not open_source_alert)
                        
                        # Record the comparison
                        self.results["timestamp"].append(timestamps[i])
                        self.results["flow_id"].append(flow_id)
                        self.results["my_model_prediction"].append(int(pred_class))
                        self.results["my_model_confidence"].append(float(confidence))
                        self.results["open_source_ids_alert"].append(bool(open_source_alert))
                        self.results["agreement"].append(bool(agreement))
                        
                        # Log potential threats
                        if pred_class == 1 or open_source_alert:
                            logger.warning(f"Potential threat detected! Flow: {flow_id}, "
                                          f"Your model: {'Alert' if pred_class == 1 else 'Normal'} ({confidence:.2f}), "
                                          f"Open source IDS: {'Alert' if open_source_alert else 'Normal'}")
                    
                    # Update last processed file
                    self.last_processed_file = file_path
                    
                    # Save current results periodically
                    self.save_results()
                
                # Sleep before checking for new files
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error in flow monitoring: {str(e)}")
                time.sleep(10)  # Wait a bit longer after an error

    def save_results(self):
        # Save comparison results to CSV and JSON
        results_df = pd.DataFrame(self.results)
        
        # Save to CSV
        results_df.to_csv("ids_comparison_results.csv", index=False)
        
        # Save summary statistics
        total_flows = len(results_df)
        if total_flows > 0:
            your_model_alerts = results_df["my_model_prediction"].sum()
            opensource_alerts = sum(results_df["open_source_ids_alert"])
            agreement_rate = sum(results_df["agreement"]) / total_flows * 100
            
            summary = {
                "total_flows_analyzed": total_flows,
                "your_model_alerts": int(your_model_alerts),
                "opensource_ids_alerts": int(opensource_alerts),
                "agreement_rate": float(agreement_rate),
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            with open("ids_comparison_summary.json", "w") as f:
                json.dump(summary, f, indent=4)
            
            logger.info(f"Saved results. Total flows: {total_flows}, "
                       f"Agreement rate: {agreement_rate:.2f}%")

    def start(self):
        # Start the comparison system
        logger.info("Starting Live IDS Comparison System")
        
        # Start the components
        self.start_cicflowmeter()
        self.start_open_source_ids()
        
        # Start flow monitoring in a separate thread
        self.monitor_thread = threading.Thread(target=self.monitor_flows)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        try:
            # Keep the main thread alive
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.stop()
    
    def stop(self):
        # Stop all components gracefully
        self.stop_threads = True
        
        # Stop CICFlowMeter
        if hasattr(self, 'cicflowmeter_process'):
            self.cicflowmeter_process.terminate()
            
        # Stop open source IDS
        if hasattr(self, 'ids_process'):
            self.ids_process.terminate()
            
        # Save final results
        self.save_results()
        logger.info("Live IDS Comparison stopped")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Live IDS Comparison Tool')
    parser.add_argument('--model', required=True, help='Path to your ML model')
    parser.add_argument('--cicflowmeter', required=True, help='Path to CICFlowMeter installation')
    parser.add_argument('--interface', default='eth0', help='Network interface to monitor')
    parser.add_argument('--ids', default='snort -A console -i eth0 -c /etc/snort/snort.conf', 
                       help='Command to start Snort (default: "snort -A console -i eth0 -c /etc/snort/snort.conf")')
    parser.add_argument('--alert-file', default=None, 
                       help='Path to Snort alert file (if not using default location)')
    
    args = parser.parse_args()
    
    # Add warning about running with sufficient permissions
    if os.geteuid() != 0:
        logger.warning("This script may need root privileges to capture network traffic and access Snort logs")
        logger.warning("Consider running with sudo if you encounter permission issues")
    
    comparison = LiveIDSComparison(
        model_path=args.model,
        open_source_ids_cmd=args.ids,
        cicflowmeter_path=args.cicflowmeter,
        interface=args.interface
    )
    
    # Add custom alert file if specified
    if args.alert_file:
        comparison.snort_alert_file = args.alert_file
    
    logger.info("Starting IDS comparison system with Snort integration")
    comparison.start()
