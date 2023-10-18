import pandas as pd
df = pd.read_parquet('/home/ubuntu/Downloads/db/UNSW_NB15_training-set.parquet')
df.to_csv('/home/ubuntu/Downloads/db/UNSW_NB15_training-set.csv')