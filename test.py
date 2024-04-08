import os

# Print all environment variables
print("Current Environment Variables:")
for key, value in os.environ.items():
    print(f"{key}: {value}")

# Retrieve the value of the DATABASE_URL environment variable
db_url = os.environ.get('DATABASE_URL')

print("\nRetrieved DATABASE_URL:", db_url)

if db_url:
    print("Database URL is set:", db_url)
else:
    print("DATABASE_URL environment variable is not set.")