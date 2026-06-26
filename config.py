"""
Security Configuration Profile.
Argon2id parameters tuned to force high hardware utilization.
"""

# 64MB of RAM required per attempt
ARGON2_MEMORY = 65536  

# Number of sequential computational passes
ARGON2_TIME = 3        

# Number of parallel CPU threads to utilize
ARGON2_PARALLELISM = 4 

# Length of the derived symmetric key (32 bytes = 256 bits)
KEY_LEN = 32