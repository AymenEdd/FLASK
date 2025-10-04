import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

# Get database URL from environment
database_url = os.getenv('DATABASE_URL') or \
               os.getenv('DATABASE_PRIVATE_URL') or \
               os.getenv('PGDATABASE')

try:
    # Connect to database
    conn = psycopg2.connect(database_url)
    cur = conn.cursor()
    
    print("Connected to database successfully")
    
    # Check current column size
    cur.execute("""
        SELECT character_maximum_length 
        FROM information_schema.columns 
        WHERE table_name = 'user' 
        AND column_name = 'password_hash'
    """)
    current_length = cur.fetchone()
    print(f"Current password_hash length: {current_length[0] if current_length else 'Unknown'}")
    
    # Alter the column
    print("Altering password_hash column to VARCHAR(255)...")
    cur.execute('ALTER TABLE "user" ALTER COLUMN password_hash TYPE VARCHAR(255);')
    
    conn.commit()
    print("✅ Migration completed successfully!")
    
    # Verify the change
    cur.execute("""
        SELECT character_maximum_length 
        FROM information_schema.columns 
        WHERE table_name = 'user' 
        AND column_name = 'password_hash'
    """)
    new_length = cur.fetchone()
    print(f"New password_hash length: {new_length[0]}")
    
    cur.close()
    conn.close()
    
except Exception as e:
    print(f"❌ Error: {e}")
    if 'conn' in locals():
        conn.rollback()