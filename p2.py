import pandas as pd
import schedule
import time
import subprocess
from pycaret.classification import load_model, predict_model
loaded = load_model('my_first_model')


def process_output_csv():
    while True:
        try:
            # Read the output.csv file
            df = pd.read_csv('output.csv')
            
            # Calculate ct_dst_sport_ltm
            df['ct_dst_sport_ltm'] = df.groupby(['DstAddr', 'Sport'])['SrcAddr'].transform('nunique')
            
            # Reindex the columns
            desired_columns = ['ct_dst_sport_ltm', 'DstLoad', 'SrcPkts', 'SrcBytes', 'DstLoss', 'DstBytes',
                               'sMeanPktSz', 'SrcLoad', 'dMeanPktSz', 'Rate', 'SrcAddr', 'Sport', 'DstAddr', 'Dport']
            df = df.reindex(columns=desired_columns)
            time.sleep(1)
            # Rename columns
            column_mapping = {
                'DstLoad': 'dload',
                'SrcPkts': 'spkts',
                'SrcBytes': 'sbytes',
                'DstLoss': 'dloss',
                'DstBytes': 'dbytes',
                'sMeanPktSz': 'smean',
                'SrcLoad': 'sload',
                'dMeanPktSz': 'dmean',
                'Rate': 'rate'
            }
            df.rename(columns=column_mapping, inplace=True)
            
            # Process the updated DataFrame
            process_dataframe(df)
            
        except FileNotFoundError:
            # If the file is not found, print an error message and continue
            print("output.csv file not found. Waiting for the file...")

def process_dataframe(df):
    prediction_columns = ['ct_dst_sport_ltm', 'dload', 'spkts', 'sbytes', 'dloss', 'dbytes',
                          'smean', 'sload', 'dmean', 'rate']
    prediction_data = df[prediction_columns]
    unseen_predictions = predict_model(loaded, data=prediction_data)
    
    for index, row in unseen_predictions.iterrows():
        if row['prediction_label'] == 1:
            display_columns = ['SrcAddr', 'Sport', 'DstAddr', 'Dport']
            display_data = df.loc[index, display_columns]
            src_addr = display_data['SrcAddr']
            src_port = display_data['Sport']
            dst_addr = display_data['DstAddr']
            dst_port = display_data['Dport']
            
            # Exclude anomalies where the source is localhost or local IP address
            if src_addr != '127.0.0.1' and not src_addr.startswith('192.168.'):
                anomaly_info = f"Anomaly detected: Source {src_addr}:{src_port} Destination to {dst_addr}:{dst_port}"
                
                # Check if the anomaly information is already printed
                if anomaly_info not in process_dataframe.previous_anomalies:
                    print(anomaly_info)
                    process_dataframe.previous_anomalies.add(anomaly_info)

# Initialize a set to store the previously detected anomalies
process_dataframe.previous_anomalies = set()
     

# Call the function to start processing the output.csv file
process_output_csv()
