import os
import time
import struct
import sqlite3
import pandas as pd

from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler

SCALE = 1000000

def export_oneclass_svm_binary(model, scaler, filename='model.bin'):
    """Export One-Class SVM to binary format"""

    global SCALE
    
    tempFileName = filename + ".tmp"
    with open(tempFileName, 'wb') as f:
        # Write scaler (mean, std for 6 features)
        f.write(struct.pack('I', 6))  # num features
        for mean in scaler.mean_:
            f.write(struct.pack('q', int(float(mean) * SCALE)))
        for std in scaler.scale_:
            f.write(struct.pack('q', int(float(std) * SCALE)))
        
        # Write SVM params
        f.write(struct.pack('q', int(float(model.offset_[0]) * SCALE)))
        f.write(struct.pack('I', len(model.support_vectors_)))
        
        # Write support vectors
        for sv in model.support_vectors_:
            for val in sv:
                f.write(struct.pack('q', int(float(val) * SCALE)))
        
        # Write dual coefficients
        for coef in model.dual_coef_[0]:
            f.write(struct.pack('q', int(float(coef) * SCALE)))
    
    if os.path.exists(filename):
        os.remove(filename)
    os.rename(tempFileName, filename)
    print(f"[ML] One-Class SVM exported ({len(model.support_vectors_)} support vectors)")

def watch_for_trigger():
    print("[ML] Watching for train trigger...")
    
    while True:
        if os.path.exists('train_trigger.txt'):
            print("[ML] Training triggered!")
            
            conn = sqlite3.connect('../network_logs.db')
            df = pd.read_sql_query("""
                SELECT src_port, dst_port, protocol, ttl, packet_len, tcp_flags
                FROM connections
                ORDER BY ts DESC
                LIMIT 100000
            """, conn)
            conn.close()
            
            # Normalize features
            scaler = StandardScaler()
            X = scaler.fit_transform(df[['src_port', 'dst_port', 'protocol', 'ttl', 'packet_len', 'tcp_flags']])
            
            # Train One-Class SVM (learns "normal" behavior)
            model = OneClassSVM(kernel='rbf', gamma='auto', nu=0.02)  # nu=contamination rate
            model.fit(X)
            
            export_oneclass_svm_binary(model, scaler, 'model.bin')
            
            print(f"[ML] Model trained on {len(df)} samples")
            
            os.remove('train_trigger.txt')
            time.sleep(5)
        
        time.sleep(1)

if __name__ == '__main__':
    watch_for_trigger()
