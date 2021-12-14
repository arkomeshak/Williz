This readme contains instructions on how to install and run Williz
over local host. These instructions are also included in the Williz documentation docx file.

1. Install python version >= 3.8
    - Update pip, and install virtualenv
    - Unix: Python -m pip install update pip
    - Windows: Python -m pip install update pip
    - Pip install virtualenv
2. Git clone clone the repo
    - The guide refers to the folder in which the project was cloned as $PROJ_DIR$
    - cd $PROJ_DIR$
    - git clone https://github.com/mkmoore3/Williz.git
3. Setup the virtual environment
    - From a terminal within $PROJ_DIR$
    - virtualenv venv
    - Unix (MacOS/Linux): source venv/bin/activate
    - Windows: .\venv\Scripts\activate
4. Install requirements from requirements.txt
    - Pip install -r requirements.txt
5. Copy the provided a settings.py into $PROJ_DIR$/Williz/CSI4999/CSI4999/
    - Edit in text editor and set the SECRET_KEY parameter
6. Make and run database migrations (sets up a simple sqlite database)
    - Cd $PROJ_DIR$/Williz/CSI4999
    - Unix:
        - python manage.py makemigrations
        - python manage.py migrate
    - Windows:
        - py manage.py makemigrations
        - py manage.py migrate
7. Setup Listing & Appraisal directory on file system
    - cd $PROJ_DIR$/CSI4999/
    - mkdir Files
    - cd Files
    - mkdir Appraisals
    - mkdir Listings
8. Creating symlink
    - cd $PROJ_DIR$/CSI4999/Williz/static/Williz
    - Unix: ln --symbolic  $PROJ_DIR$/CSI4999/Files Files
    - Windows: mklink Files $PROJ_DIR$/CSI4999/Files
        - Note: Must be done via command prompt rather than powershell
9. Collect static resources for the site
    - Unix: python manage.py collectstatic
    - Windows: py manage.py collectstatic
10. Optional: Make a DB admin user
    - Unix: python manage.py createsuperuser
    - Windows: py manage.py createsuperuser
    - This step is needed to validate realtors, mortgage lenders, and appraisers via the admin console at 127.0.0.1:8000/admin
11. Run server over local host
    - Unix: python manage.py runserver
    - Windows: py manage.py runserver

Login page should now be accessible via 127.0.0.1:8000.
Realtors, appraisers, and mortgage lenders need to be verified by the admin optinally created in step 10 to perform
their special functions (create a listing/set lending company,
    - Realtor: create listing & set the lender company
    - Mortgage Lender: Request appraisal and view appraisal(s)
    - Appraiser: Create an appraisal for a listing