#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Create the database tables and admin user
flask init-db
```

**Save the `build.sh` file.**

---

#### **Step 3: Update Settings on the Render Dashboard**

Go to your Web Service on Render and navigate to the **"Settings"** tab. We need to update two commands.

1.  **Build Command:** Change this to run our new script.
    * **Value:** `bash build.sh`

2.  **Start Command:** We will make your Gunicorn command more robust to prevent other potential issues.
    * **Value:** `gunicorn --bind 0.0.0.0:$PORT --worker-tmp-dir /dev/shm main:app`



**Scroll to the bottom and click "Save Changes".**

---

#### **Step 4: Push Everything to GitHub**

Now, commit and push your two new/modified files (`main.py` and `build.sh`) to GitHub. This will trigger a new deployment on Render with the correct setup.

1.  **Stage your changes:**
    ```bash
    git add main.py build.sh
    ```
2.  **Commit them:**
    ```bash
    git commit -m "Add production database initialization"
    ```
3.  **Push to GitHub:**
    ```bash
    git push origin main
    
